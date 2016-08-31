/*
 * af_ktls: TLS/DTLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fridolin.pokorny@gmail.com>
 *   Nikos Mavrogiannopoulos <nmav@gnults.org>
 *   Dave Watson <davejwatson@fb.com>
 *   Lance Chao <lancerchao@fb.com>
 *
 * Based on RFC 5288, RFC 6347, RFC 5246, RFC 6655
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#include <crypto/aead.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/strparser.h>
#include <linux/skbuff.h>
#include <linux/log2.h>

#include "af_ktls.h"

#ifndef CHAR_BIT
# define CHAR_BIT   8
#endif
#define MAX(a, b)			((a) > (b) ? (a) : (b))

#define KTLS_RECORD_DATA		0x17

#define KTLS_KEY_SIZE			KTLS_AES_GCM_128_KEY_SIZE
#define KTLS_SALT_SIZE			KTLS_AES_GCM_128_SALT_SIZE
#define KTLS_TAG_SIZE			16
#define KTLS_IV_SIZE			KTLS_AES_GCM_128_IV_SIZE
#define KTLS_NONCE_SIZE			8

#define KTLS_DATA_PAGES			(KTLS_MAX_PAYLOAD_SIZE / PAGE_SIZE)
/* +1 for aad, +1 for tag, +1 for chaining */
#define KTLS_SG_DATA_SIZE		(KTLS_DATA_PAGES + 3)

/* RFC5288 patch requires 24 bytes allocated
 */
#define KTLS_AAD_SPACE_SIZE		24
/* RFC52888: AAD is zero-padded to 21 */
#define KTLS_PADDED_AAD_SIZE		21
#define KTLS_AAD_SIZE			13

/* TLS
 */
#define KTLS_TLS_HEADER_SIZE		5
#define KTLS_TLS_PREPEND_SIZE		(KTLS_TLS_HEADER_SIZE + KTLS_NONCE_SIZE)
#define KTLS_TLS_OVERHEAD		(KTLS_TLS_PREPEND_SIZE + KTLS_TAG_SIZE)

#define KTLS_TLS_1_2_MAJOR		0x03
#define KTLS_TLS_1_2_MINOR		0x03

/* nonce explicit offset in a record */
#define KTLS_TLS_NONCE_OFFSET		KTLS_TLS_HEADER_SIZE

#define KTLS_PREPEND_SIZE(T)          (IS_TLS(T) ?			\
					(KTLS_TLS_PREPEND_SIZE) :	\
					(KTLS_DTLS_PREPEND_SIZE))

#define KTLS_HEADER_SIZE(T)           (IS_TLS(T) ?			\
					(KTLS_TLS_HEADER_SIZE) :	\
					(KTLS_DTLS_HEADER_SIZE))

#define KTLS_OVERHEAD(T)              (IS_TLS(T) ?		\
					(KTLS_TLS_OVERHEAD) :	\
					(KTLS_DTLS_OVERHEAD))

/* DTLS
 */
#define KTLS_DTLS_HEADER_SIZE		13
#define KTLS_DTLS_PREPEND_SIZE		(KTLS_DTLS_HEADER_SIZE \
						+ KTLS_NONCE_SIZE)
#define KTLS_DTLS_OVERHEAD		(KTLS_DTLS_PREPEND_SIZE \
						+ KTLS_TAG_SIZE)

#define KTLS_DTLS_1_2_MAJOR		0xFE
#define KTLS_DTLS_1_2_MINOR		0xFD

/* we are handling epoch and seq num as one unit */
#define KTLS_DTLS_SEQ_NUM_OFFSET	3
/* nonce explicit offset in a record */
#define KTLS_DTLS_NONCE_OFFSET		KTLS_DTLS_HEADER_SIZE

/* Ensure that bind(2) was called
 */
#define KTLS_SETSOCKOPT_READY(T)	((T)->aead_send && (T)->aead_recv)
#define KTLS_GETSOCKOPT_READY(T)	KTLS_SETSOCKOPT_READY(T)

/* Ensure that we have needed key material
 */
#define KTLS_SEND_READY(T)		((T)->key_send.keylen && \
						(T)->key_send.saltlen && \
						(T)->iv_send && \
						KTLS_GETSOCKOPT_READY(T))
#define KTLS_RECV_READY(T)		((T)->key_recv.keylen && \
						(T)->key_recv.saltlen && \
						(T)->iv_recv && \
						KTLS_GETSOCKOPT_READY(T))

#define IS_TLS(T)			((T)->sk.sk_type == SOCK_STREAM)
#define IS_DTLS(T)			(!IS_TLS(T))

/* Distinguish bound socket type
 */
#define IS_INET46(S)			((S)->sk->sk_family == AF_INET || \
						(S)->sk->sk_family == AF_INET6)
#define IS_TCP(S)			(IS_INET46(S) && \
						(S)->sk->sk_type == SOCK_STREAM)
#define IS_UDP(S)			(IS_INET46(S) && \
						(S)->sk->sk_type == SOCK_DGRAM)

/* Real size of a record based on data carried
 */
#define KTLS_RECORD_SIZE(T, S)		(IS_TLS(T) ? \
						(S + KTLS_TLS_OVERHEAD) : \
						(S + KTLS_DTLS_OVERHEAD))

/* Nonce explicit offset in a record
 */
#define KTLS_NONCE_OFFSET(T)		(IS_TLS(T) ? \
						(KTLS_TLS_NONCE_OFFSET) : \
						(KTLS_DTLS_NONCE_OFFSET))

/* Async worker */
static struct workqueue_struct *tls_rx_wq;
static struct workqueue_struct *tls_tx_wq;

struct tls_key {
	char *key;
	size_t keylen;
	char salt[KTLS_SALT_SIZE];
	size_t saltlen;
};

struct tls_sock {
	/* struct sock must be the very first member */
	struct sock sk;

	/* TCP/UDP socket we are bound to */
	struct socket *socket;

	int rx_stopped;

	/* Context for {set,get}sockopt() */
	unsigned char *iv_send;
	struct tls_key key_send;

	unsigned char *iv_recv;
	struct tls_key key_recv;

	struct crypto_aead *aead_send;
	struct crypto_aead *aead_recv;

	/* Sending context */
	struct scatterlist sg_tx_data[KTLS_SG_DATA_SIZE];
	struct scatterlist sg_tx_data2[ALG_MAX_PAGES + 1];
	char aad_send[KTLS_AAD_SPACE_SIZE];
	char tag_send[KTLS_TAG_SIZE];
	struct page *pages_send;
	int send_offset;
	int send_len;
	int order_npages;
	struct scatterlist sgaad_send[2];
	struct scatterlist sgtag_send[2];
	struct work_struct send_work;

	/* Receive */
	struct scatterlist sgin[ALG_MAX_PAGES + 1];
	char aad_recv[KTLS_AAD_SPACE_SIZE];
	char header_recv[MAX(KTLS_TLS_PREPEND_SIZE, KTLS_DTLS_PREPEND_SIZE)];

	struct strparser strp;
	struct sk_buff_head rx_hold_queue;
	struct work_struct recv_work;
	void (*saved_sk_data_ready)(struct sock *sk);
	void (*saved_sk_write_space)(struct sock *sk);

	/* our cipher type and its crypto API representation (e.g. "gcm(aes)")
	 */
	unsigned int cipher_type;
	char *cipher_crypto;

	/* TLS/DTLS version for header */
	char version[2];

	/* DTLS window handling */
	struct {
		u64 bits;
		/* The starting point of the sliding window without epoch */
		u64 start;
	} dtls_window;

	int unsent;
};

struct tls_rx_msg {
	/* strp_rx_msg must be first to match strparser */
	struct strp_rx_msg rxm;
	int decrypted;
};

static inline struct tls_rx_msg *tls_rx_msg(struct sk_buff *skb)
{
	return (struct tls_rx_msg *)((void *)skb->cb +
		offsetof(struct qdisc_skb_cb, data));
}

static inline struct tls_sock *tls_sk(struct sock *sk)
{
	return (struct tls_sock *)sk;
}

static inline bool tls_stream_memory_free(const struct sock *sk)
{
	const struct tls_sock *tsk = (const struct tls_sock *)sk;

	return tsk->unsent < KTLS_MAX_PAYLOAD_SIZE;
}

static int tls_do_decryption(struct tls_sock *tsk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     char *header_recv,
			     size_t data_len);

static inline void tls_make_aad(struct tls_sock *tsk,
				int recv,
				char *buf,
				size_t size,
				char *nonce_explicit);

static int tls_post_process(struct tls_sock *tsk, struct sk_buff *skb);
static void tls_err_abort(struct tls_sock *tsk);

static void increment_seqno(unsigned char *seq, struct tls_sock *tsk)
{
	int i;

	for (i = 7; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}
	/* Check for overflow. If overflowed, connection must
	 * disconnect.  Raise an error and notify userspace.
	 */
	if (unlikely((IS_TLS(tsk) && i == -1) || (IS_DTLS(tsk) && i <= 1)))
		tls_err_abort(tsk);
}

/* Must be called with socket callback locked */
static void tls_unattach(struct tls_sock *tsk)
{
	write_lock_bh(&tsk->socket->sk->sk_callback_lock);
	tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
	tsk->socket->sk->sk_write_space = tsk->saved_sk_write_space;
	tsk->socket->sk->sk_user_data = NULL;
	write_unlock_bh(&tsk->socket->sk->sk_callback_lock);
}

static void tls_err_abort(struct tls_sock *tsk)
{
	struct sock *sk;

	sk = (struct sock *)tsk;
	xchg(&tsk->rx_stopped, 1);
	xchg(&sk->sk_err, -EBADMSG);
	sk->sk_error_report(sk);
	tsk->saved_sk_data_ready(tsk->socket->sk);
}

static void tls_abort_cb(struct strparser *strp, int err)
{
	struct tls_sock *tsk;

	tsk = strp->sk->sk_user_data;
	tls_err_abort(tsk);
}

static int decrypt_skb(struct tls_sock *tsk, struct sk_buff *skb)
{
	int ret, nsg;
	size_t prepend, overhead;
	struct strp_rx_msg *rxm;
	char header_recv[MAX(KTLS_TLS_PREPEND_SIZE, KTLS_DTLS_PREPEND_SIZE)];

	prepend = IS_TLS(tsk) ? KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	overhead = IS_TLS(tsk) ? KTLS_TLS_OVERHEAD : KTLS_DTLS_OVERHEAD;
	rxm = strp_rx_msg(skb);

	/* Copy header to pass into decryption routine.  Cannot use
	 * tsk->header_recv as that would cause a race between here
	 * and data_ready
	 */
	ret = skb_copy_bits(skb, rxm->offset, header_recv, prepend);

	if (ret < 0)
		goto decryption_fail;

	sg_init_table(tsk->sgin, ARRAY_SIZE(tsk->sgin));
	sg_set_buf(&tsk->sgin[0], tsk->aad_recv, sizeof(tsk->aad_recv));

	/* TODO: So what exactly happens if skb_to_sgvec causes more
	 * than ALG_MAX_PAGES fragments? Consider allocating kernel
	 * pages tls_read_size already copied headers and
	 * aad. Therefore this simply needs to pass the encrypted data
	 * + message
	 */
	nsg = skb_to_sgvec(skb, &tsk->sgin[1], rxm->offset +
			prepend,
			rxm->full_len - prepend);

	/* The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the payload
	 * must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > ALG_MAX_PAGES - 1) {
		ret = -EBADMSG;
		goto decryption_fail;
	}

	tls_make_aad(tsk, 1, tsk->aad_recv,
		     rxm->full_len - overhead,
		     tsk->iv_recv);

	/* Decrypt in place.  After this function call, the decrypted
	 * data will be in rxm->offset. We must therefore account for
	 * the fact that the lengths of skbuff_in and skbuff_out are
	 * different
	 */

	ret = tls_do_decryption(tsk,
				tsk->sgin,
				tsk->sgin,
				header_recv,
				rxm->full_len - overhead);

	if (ret < 0)
		goto decryption_fail;

	ret = tls_post_process(tsk, skb);

	if (ret < 0)
		goto decryption_fail;

	return 0;
decryption_fail:
	return ret;
}

/* Returns the length of the unencrypted message, plus overhead Note
 * that this function also populates tsk->header which is later used
 * for decryption. In TLS we automatically bail if we see a non-TLS
 * message. In DTLS we should determine if we got a corrupted message
 * vs a control msg Right now if the TLS magic bit got corrupted it
 * would incorrectly misinterpret it as a non-TLS message Returns 0 if
 * more data is necessary to determine length Returns <0 if error
 * occurred
 */
static inline ssize_t tls_read_size(struct tls_sock *tsk, struct sk_buff *skb)
{
	int ret;
	size_t data_len = 0;
	size_t datagram_len;
	size_t prepend;
	char first_byte;
	char *header;
	struct strp_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	header = tsk->header_recv;

	rxm = strp_rx_msg(skb);

	ret = skb_copy_bits(skb, rxm->offset, &first_byte, 1);
	if (ret < 0)
		goto read_failure;

	/* Check the first byte to see if its a TLS record */
	if (first_byte != KTLS_RECORD_DATA) {
		ret = -EBADMSG;
		goto read_failure;
	}

	/* We have a TLS record. Check that msglen is long enough to
	 * read the length of record.  We must not check this before
	 * checking the first byte, since that will cause unencrypted
	 * messages shorter than KTLS_TLS_PREPEND_SIZE to not be read
	 */
	if (rxm->offset + prepend > skb->len) {
		ret = 0;
		goto read_failure;
	}

	/* Copy header to read size.  An optimization could be to
	 * zero-copy, but you'd have to be able to walk
	 * frag_lists. This function call takes care of that.
	 * Overhead is relatively small (13 bytes for TLS, 21 for
	 * DTLS)
	 */
	ret = skb_copy_bits(skb, rxm->offset, header, prepend);

	if (ret < 0)
		goto read_failure;

	if (IS_TLS(tsk)) {
		data_len = ((header[4] & 0xFF) | (header[3] << 8));
		data_len = data_len - KTLS_TAG_SIZE - KTLS_IV_SIZE;
		datagram_len = data_len + KTLS_TLS_OVERHEAD;
	} else {
		data_len = ((header[12] & 0xFF) | (header[11] << 8));
		data_len = data_len - KTLS_TAG_SIZE - KTLS_IV_SIZE;
		datagram_len = data_len + KTLS_DTLS_OVERHEAD;
	}

	if (data_len > KTLS_MAX_PAYLOAD_SIZE) {
		ret = -E2BIG;
		goto read_failure;
	}
	return datagram_len;

read_failure:
	/* TLS couldn't handle this message. Pass it directly to userspace */
	if (ret == -EBADMSG)
		tls_err_abort(tsk);

	return ret;
}

static int tls_parse_cb(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_sock *tsk;

	tsk = strp->sk->sk_user_data;

	return tls_read_size(tsk, skb);
}

static void tls_queue(struct strparser *strp, struct sk_buff *skb)
{
	struct tls_sock *tsk;
	int ret;
	struct strp_rx_msg *rxm;

	rxm = strp_rx_msg(skb);
	tsk = strp->sk->sk_user_data;

	tls_rx_msg(skb)->decrypted = 0;

	ret = sock_queue_rcv_skb((struct sock *)tsk, skb);
	if (ret < 0) {
		/* skb receive queue is full. Apply backpressure on
		 * TCP socket
		 */
		skb_queue_tail(&tsk->rx_hold_queue, skb);
		strp->rx_paused = 1;
	}
}

/* Called with lower socket held */
static void tls_data_ready(struct sock *sk)
{
	struct tls_sock *tsk;

	read_lock_bh(&sk->sk_callback_lock);

	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->rx_stopped))
		goto out;

	if (IS_TLS(tsk))
		strp_tcp_data_ready(&tsk->strp);
	else
		queue_work(tls_rx_wq, &tsk->recv_work);

out:
	read_unlock_bh(&sk->sk_callback_lock);
}

/* Called with lower socket held */
static void tls_write_space(struct sock *sk)
{
	struct tls_sock *tsk;

	read_lock_bh(&sk->sk_callback_lock);

	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->rx_stopped))
		goto out;

	queue_work(tls_tx_wq, &tsk->send_work);

out:
	read_unlock_bh(&sk->sk_callback_lock);
}

#include "dtls-window.c"

/* Loop through the SKBs. Decrypt each one and, if valid, add it to recv queue
*/
static int dtls_udp_read_sock(struct tls_sock *tsk)
{
	struct sk_buff *p, *next, *skb;
	int ret = 0;

	skb_queue_walk_safe(&tsk->socket->sk->sk_receive_queue, p, next) {
		ssize_t len;
		struct strp_rx_msg *rxm;

		rxm = strp_rx_msg(p);
		memset(rxm, 0, sizeof(*rxm));

		/* For UDP, set the offset such that the headers are
		 * ignored.  Full_len is length of skb minus the
		 * headers
		 */
		rxm->full_len = p->len - sizeof(struct udphdr);
		rxm->offset = sizeof(struct udphdr);
		len = tls_read_size(tsk, p);

		if (!len)
			goto record_pop;
		if (len < 0) {
			if (len == -EBADMSG) {
				/* Data does not appear to be a TLS
				 * record Make userspace handle it
				 */
				ret = -EBADMSG;
				break;
			}
			/* Failed for some other reason. Drop the
			 * packet
			 */
			goto record_pop;
		}
		if (dtls_window(tsk, tsk->header_recv +
					KTLS_DTLS_SEQ_NUM_OFFSET) < 0)
			goto record_pop;

		skb = skb_clone(p, GFP_ATOMIC);
		if (!skb) {
			ret = -ENOMEM;
			break;
		}
		sock_queue_rcv_skb((struct sock *)tsk, skb);
record_pop:
		skb_unlink(p, &tsk->socket->sk->sk_receive_queue);
		kfree_skb(p);
	}
	return ret;
}

static void do_dtls_data_ready(struct tls_sock *tsk)
{
	int ret;

	ret = dtls_udp_read_sock(tsk);
	if (ret == -ENOMEM) /* No memory. Do it later */
		queue_work(tls_rx_wq, &tsk->recv_work);

	/* TLS couldn't handle this message. Pass it directly to
	 * userspace
	 */
	else if (ret == -EBADMSG)
		tls_err_abort(tsk);
}

static void do_dtls_sock_rx_work(struct tls_sock *tsk)
{
	struct sock *sk = tsk->socket->sk;

	lock_sock(sk);
	read_lock_bh(&sk->sk_callback_lock);

	if (unlikely(!tsk || sk->sk_user_data != tsk))
		goto out;

	if (unlikely(tsk->rx_stopped))
		goto out;

	if (!KTLS_RECV_READY(tsk))
		goto out;

	do_dtls_data_ready(tsk);

out:
	read_unlock_bh(&sk->sk_callback_lock);
	release_sock(sk);
}

static void check_rcv(struct tls_sock *tsk)
{
	if (IS_TLS(tsk))
		strp_check_rcv(&tsk->strp);
	else
		do_dtls_sock_rx_work(tsk);
}

static void tls_rx_work(struct work_struct *w)
{
	do_dtls_sock_rx_work(container_of(w, struct tls_sock, recv_work));
}

static void tls_kernel_sendpage(struct tls_sock *tsk);

static void tls_tx_work(struct work_struct *w)
{
	struct tls_sock *tsk = container_of(w, struct tls_sock, send_work);

	struct sock *sk = &tsk->sk;

	lock_sock(sk);
	tls_kernel_sendpage(tsk);
	release_sock(sk);
}

static int tls_set_iv(struct socket *sock,
		      int recv,
		      char __user *src,
		      size_t src_len)
{
	int ret;
	unsigned char **iv;
	struct sock *sk;
	struct tls_sock *tsk;

	sk = sock->sk;
	tsk = tls_sk(sk);

	if (!src)
		return -EBADMSG;

	if (src_len != KTLS_IV_SIZE)
		return -EBADMSG;

	iv = recv ? &tsk->iv_recv : &tsk->iv_send;

	if (!*iv) {
		*iv = kmalloc(src_len, GFP_KERNEL);
		if (!*iv)
			return -ENOMEM;
	}

	ret = copy_from_user(*iv, src, src_len);

	return ret ?: src_len;
}

static int tls_init_aead(struct tls_sock *tsk, int recv)
{
	int ret;
	struct crypto_aead *aead;
	struct tls_key *k;
	char keyval[KTLS_KEY_SIZE + KTLS_SALT_SIZE];
	size_t keyval_len;

	k = recv ? &tsk->key_recv : &tsk->key_send;
	aead = recv ? tsk->aead_recv : tsk->aead_send;

	/* We need salt and key in order to construct 20B key
	 * according to RFC5288, otherwise we will handle this once
	 * both will be provided
	 */
	if (k->keylen == 0 || k->saltlen == 0)
		return 0;

	keyval_len = k->keylen + k->saltlen;

	memcpy(keyval, k->key, k->keylen);
	memcpy(keyval + k->keylen, k->salt, k->saltlen);

	ret = crypto_aead_setkey(aead, keyval, keyval_len);
	if (ret)
		goto init_aead_end;

	ret = crypto_aead_setauthsize(aead, KTLS_TAG_SIZE);

init_aead_end:
	return ret ?: 0;
}

static int tls_set_key(struct socket *sock,
		       int recv,
		       char __user *src,
		       size_t src_len)
{
	int ret;
	struct tls_sock *tsk;
	struct tls_key *k;

	tsk = tls_sk(sock->sk);

	if (src_len == 0 || !src)
		return -EBADMSG;

	if (src_len != KTLS_KEY_SIZE)
		return -EBADMSG;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (src_len > k->keylen) {
		kfree(k->key);
		k->key = kmalloc(src_len, GFP_KERNEL);
		if (!k->key)
			return -ENOMEM;
	}

	ret = copy_from_user(k->key, src, src_len);
	if (ret)
		goto set_key_end;

	k->keylen = src_len;

	ret = tls_init_aead(tsk, recv);

set_key_end:
	return ret < 0 ? ret : src_len;
}

static int tls_set_salt(struct socket *sock,
			int recv,
			char __user *src,
			size_t src_len)
{
	int ret;
	struct tls_sock *tsk;
	struct tls_key *k;

	tsk = tls_sk(sock->sk);

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (src_len != KTLS_SALT_SIZE)
		return -EBADMSG;

	ret = copy_from_user(k->salt, src, src_len);
	if (ret)
		goto set_salt_end;

	k->saltlen = src_len;

	ret = tls_init_aead(tsk, recv);

set_salt_end:
	return ret < 0 ? ret : src_len;
}

static void tls_do_unattach(struct socket *sock)
{
	struct tls_sock *tsk;
	struct sock *sk;

	tsk = tls_sk(sock->sk);
	sk = tsk->socket->sk;

	tls_unattach(tsk);
}

static int tls_setsockopt(struct socket *sock,
			  int level, int optname,
			  char __user *optval,
			  unsigned int optlen)
{
	int ret;
	struct tls_sock *tsk;

	tsk = tls_sk(sock->sk);
	if (level != AF_KTLS)
		return -ENOPROTOOPT;

	lock_sock(sock->sk);

	ret = -EBADMSG;
	if (!KTLS_SETSOCKOPT_READY(tsk))
		goto setsockopt_end;

	switch (optname) {
	case KTLS_SET_IV_RECV:
		ret = tls_set_iv(sock, 1, optval, optlen);
		break;
	case KTLS_SET_KEY_RECV:
		ret = tls_set_key(sock, 1, optval, optlen);
		break;
	case KTLS_SET_SALT_RECV:
		ret = tls_set_salt(sock, 1, optval, optlen);
		break;
	case KTLS_SET_IV_SEND:
		ret = tls_set_iv(sock, 0, optval, optlen);
		break;
	case KTLS_SET_KEY_SEND:
		ret = tls_set_key(sock, 0, optval, optlen);
		break;
	case KTLS_SET_SALT_SEND:
		ret = tls_set_salt(sock, 0, optval, optlen);
		break;
	case KTLS_UNATTACH:
		tls_do_unattach(sock);
		ret = 0;
		break;
	default:
		break;
	}

setsockopt_end:
	release_sock(sock->sk);
	return ret < 0 ? ret : 0;
}

static int tls_get_iv(const struct tls_sock *tsk,
		      int recv,
		      char __user *dst,
		      size_t dst_len)
{
	int ret;
	char *iv;

	if (dst_len < KTLS_IV_SIZE)
		return -ENOMEM;

	iv = recv ? tsk->iv_recv : tsk->iv_send;

	if (!iv)
		return -EBADMSG;

	ret = copy_to_user(dst, iv, KTLS_IV_SIZE);
	if (ret)
		return ret;

	return KTLS_IV_SIZE;
}

static int tls_get_key(const struct tls_sock *tsk,
		       int recv,
		       char __user *dst,
		       size_t dst_len)
{
	int ret;
	const struct tls_key *k;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (k->keylen == 0)
		return -EBADMSG;

	if (dst_len < k->keylen)
		return -ENOMEM;

	ret = copy_to_user(dst, k->key, k->keylen);

	return ret ?: k->keylen;
}

static int tls_get_salt(const struct tls_sock *tsk,
			int recv,
			char __user *dst,
			size_t dst_len)
{
	int ret;
	const struct tls_key *k;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (k->saltlen == 0)
		return -EBADMSG;

	if (dst_len < k->saltlen)
		return -ENOMEM;

	ret = copy_to_user(dst, k->salt, k->saltlen);

	return ret ?: k->saltlen;
}

static int tls_getsockopt(struct socket *sock,
			  int level,
			  int optname,
			  char __user *optval,
			  int __user *optlen)
{
	int ret;
	int len;
	const struct tls_sock *tsk;

	tsk = tls_sk(sock->sk);

	if (level != AF_KTLS)
		return -ENOPROTOOPT;

	if (!optlen || !optval)
		return -EBADMSG;

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sock->sk);

	ret = -EBADMSG;
	if (!KTLS_GETSOCKOPT_READY(tsk))
		goto end;

	switch (optname) {
	case KTLS_GET_IV_RECV:
		ret = tls_get_iv(tsk, 1, optval, len);
		break;
	case KTLS_GET_KEY_RECV:
		ret = tls_get_key(tsk, 1, optval, len);
		break;
	case KTLS_GET_SALT_RECV:
		ret = tls_get_salt(tsk, 1, optval, len);
		break;
	case KTLS_GET_IV_SEND:
		ret = tls_get_iv(tsk, 0, optval, len);
		break;
	case KTLS_GET_KEY_SEND:
		ret = tls_get_key(tsk, 0, optval, len);
		break;
	case KTLS_GET_SALT_SEND:
		ret = tls_get_salt(tsk, 0, optval, len);
		break;
	default:
		ret = -EBADMSG;
		break;
	}

	if (ret < 0)
		goto end;

	ret = copy_to_user(optlen, &ret, sizeof(*optlen));

end:
	release_sock(sock->sk);
	return ret;
}

static inline void tls_make_prepend(struct tls_sock *tsk,
				    char *buf,
				    size_t plaintext_len)
{
	size_t pkt_len;

	pkt_len = plaintext_len + KTLS_IV_SIZE + KTLS_TAG_SIZE;

	/* we cover nonce explicit here as well, so buf should be of
	 * size KTLS_DTLS_HEADER_SIZE + KTLS_DTLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = KTLS_RECORD_DATA;
	buf[1] = tsk->version[0];
	buf[2] = tsk->version[1];
	/* we can use IV for nonce explicit according to spec */
	if (IS_TLS(tsk)) {
		buf[3] = pkt_len >> 8;
		buf[4] = pkt_len & 0xFF;
		memcpy(buf + KTLS_TLS_NONCE_OFFSET, tsk->iv_send, KTLS_IV_SIZE);
	} else {
		memcpy(buf + 3, tsk->iv_send, KTLS_IV_SIZE);
		buf[11] = pkt_len >> 8;
		buf[12] = pkt_len & 0xFF;
		memcpy(buf + KTLS_DTLS_NONCE_OFFSET,
		       tsk->iv_send,
		       KTLS_IV_SIZE);
	}
}

static inline void tls_make_aad(struct tls_sock *tsk,
				int recv,
				char *buf,
				size_t size,
				char *nonce_explicit)
{
	/* has to be zero padded according to RFC5288 */
	memset(buf, 0, KTLS_AAD_SPACE_SIZE);

	memcpy(buf, nonce_explicit, KTLS_NONCE_SIZE);

	buf[8] = KTLS_RECORD_DATA;
	buf[9] = tsk->version[0];
	buf[10] = tsk->version[1];
	buf[11] = size >> 8;
	buf[12] = size & 0xFF;
}

static int tls_do_encryption(struct tls_sock *tsk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     size_t data_len)
{
	int ret;
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(tsk->aead_recv);
	struct aead_request *aead_req = (void *)sock_kmalloc(&tsk->sk, req_size,
							GFP_KERNEL);
	if (!aead_req)
		return -ENOMEM;

	aead_request_set_tfm(aead_req, tsk->aead_send);
	aead_request_set_ad(aead_req, KTLS_PADDED_AAD_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout, data_len, tsk->iv_send);
	aead_request_set_callback(aead_req, 0, NULL, NULL);

	ret = crypto_aead_encrypt(aead_req);

	if (aead_req)
		sock_kfree_s(&tsk->sk, aead_req, req_size);

	return ret;
}

/* Allocates enough pages to hold the decrypted data, as well as
 * setting tsk->sg_tx_data to the pages
 */
static int tls_pre_encrypt(struct tls_sock *tsk, size_t data_len)
{
	int i;
	unsigned int npages;
	size_t aligned_size;
	size_t encrypt_len;
	struct scatterlist *sg;
	int ret = 0;

	encrypt_len = data_len + KTLS_TAG_SIZE;
	npages = encrypt_len / PAGE_SIZE;
	aligned_size = npages * PAGE_SIZE;
	if (aligned_size < encrypt_len)
		npages++;

	tsk->order_npages = order_base_2(npages);
	WARN_ON(tsk->order_npages < 0 || tsk->order_npages > 3);
	/* The first entry in sg_tx_data is AAD so skip it */
	sg_init_table(tsk->sg_tx_data, KTLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_tx_data[0], tsk->aad_send, sizeof(tsk->aad_send));
	tsk->pages_send = alloc_pages(GFP_KERNEL | __GFP_COMP,
				      tsk->order_npages);
	if (!tsk->pages_send) {
		ret = -ENOMEM;
		return ret;
	}

	sg = tsk->sg_tx_data + 1;
	/* For the first page, leave room for prepend. It will be
	 * copied into the page later
	 */
	sg_set_page(sg, tsk->pages_send, PAGE_SIZE - KTLS_PREPEND_SIZE(tsk),
		    KTLS_PREPEND_SIZE(tsk));
	for (i = 1; i < npages; i++)
		sg_set_page(sg + i, tsk->pages_send + i, PAGE_SIZE, 0);
	return ret;
}

static void tls_kernel_sendpage(struct tls_sock *tsk)
{
	int ret;
	struct sk_buff *head;

	ret = kernel_sendpage(
		tsk->socket, tsk->pages_send, /* offset */ tsk->send_offset,
		tsk->send_len + KTLS_OVERHEAD(tsk) - tsk->send_offset,
		MSG_DONTWAIT);

	if (ret > 0) {
		tsk->send_offset += ret;
		if (tsk->send_offset >= tsk->send_len + KTLS_OVERHEAD(tsk)) {
			/* Successfully sent the whole packet, account for it.*/
			head = skb_peek(&tsk->sk.sk_write_queue);
			skb_dequeue(&tsk->sk.sk_write_queue);
			kfree_skb(head);
			tsk->sk.sk_wmem_queued -= tsk->send_len;
			tsk->unsent -= tsk->send_len;
			increment_seqno(tsk->iv_send, tsk);
			__free_pages(tsk->pages_send, tsk->order_npages);
			tsk->pages_send = NULL;
			tsk->sk.sk_write_space(&tsk->sk);
		}
	} else if (ret != -EAGAIN) {
		tls_err_abort(tsk);
	}
}

static void tls_push(struct tls_sock *tsk)
{
	int bytes = min_t(int, tsk->unsent, (int)KTLS_MAX_PAYLOAD_SIZE);
	int nsg, ret = 0;
	struct sk_buff *head = skb_peek(&tsk->sk.sk_write_queue);

	if (!head)
		return;

	sg_init_table(tsk->sg_tx_data2, ARRAY_SIZE(tsk->sg_tx_data2));
	nsg = skb_to_sgvec(head, &tsk->sg_tx_data2[0], 0, bytes);

	tls_make_aad(tsk, 0, tsk->aad_send, bytes, tsk->iv_send);

	sg_chain(tsk->sgaad_send, 2, tsk->sg_tx_data2);
	sg_chain(tsk->sg_tx_data2,
		 nsg + 1,
		 tsk->sgtag_send);

	ret = tls_pre_encrypt(tsk, bytes);
	if (ret < 0)
		goto out;

	ret = tls_do_encryption(tsk,
				tsk->sgaad_send,
				tsk->sg_tx_data,
				bytes);

	if (ret < 0)
		goto out;

	tls_make_prepend(tsk, page_address(tsk->pages_send), bytes);

	tsk->send_len = bytes;
	tsk->send_offset = 0;

	tls_kernel_sendpage(tsk);

out:
	if (ret < 0)
		tsk->sk.sk_err = ret;
}

static int tls_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct tls_sock *tsk = tls_sk(sk);
	int ret = 0;
	long timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);
	bool eor = !(msg->msg_flags & MSG_MORE) || IS_DTLS(tsk);
	struct sk_buff *skb = NULL;
	size_t copy, copied = 0;

	lock_sock(sock->sk);

	if (msg->msg_flags & MSG_OOB) {
		ret = -ENOTSUPP;
		goto send_end;
	}
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	if (!KTLS_SEND_READY(tsk)) {
		ret = -EBADMSG;
		goto send_end;
	}

	if (size > KTLS_MAX_PAYLOAD_SIZE && IS_DTLS(tsk)) {
		ret = -E2BIG;
		goto send_end;
	}

	while (msg_data_left(msg)) {
		bool merge = true;
		int i;
		struct page_frag *pfrag;

		if (sk->sk_err)
			goto send_end;

		skb = tcp_write_queue_tail(sk);

		while (!skb) {
			ret = sk_stream_wait_memory(sk, &timeo);
			if (ret)
				goto send_end;

			skb = alloc_skb(0, sk->sk_allocation);
			if (skb)
				__skb_queue_tail(&sk->sk_write_queue, skb);
		}

		i = skb_shinfo(skb)->nr_frags;
		pfrag = sk_page_frag(sk);

		if (!sk_page_frag_refill(sk, pfrag))
			goto wait_for_memory;

		if (!skb_can_coalesce(skb, i, pfrag->page,
				      pfrag->offset)) {
			if (i == ALG_MAX_PAGES) {
				struct sk_buff *tskb;

				tskb = alloc_skb(0, sk->sk_allocation);
				if (!tskb)
					goto wait_for_memory;

				if (skb)
					skb->next = tskb;
				else
					__skb_queue_tail(&sk->sk_write_queue,
							 tskb);

				skb = tskb;
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				continue;
			}
			merge = false;
		}

		copy = min_t(int, msg_data_left(msg),
			     pfrag->size - pfrag->offset);
		copy = min_t(int, copy, KTLS_MAX_PAYLOAD_SIZE - tsk->unsent);

		if (!sk_wmem_schedule(sk, copy))
			goto wait_for_memory;

		ret = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,
					       pfrag->page,
					       pfrag->offset,
					       copy);
		if (ret)
			goto send_end;

		/* Update the skb. */
		if (merge) {
			skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);
		} else {
			skb_fill_page_desc(skb, i, pfrag->page,
					   pfrag->offset, copy);
			get_page(pfrag->page);
		}

		pfrag->offset += copy;
		copied += copy;
		skb->len += copy;
		skb->data_len += copy;
		tsk->unsent += copy;

		if (tsk->unsent >= KTLS_MAX_PAYLOAD_SIZE)
			tls_push(tsk);

		continue;

wait_for_memory:
		tls_push(tsk);
		ret = sk_stream_wait_memory(sk, &timeo);
		if (ret)
			goto send_end;
	}

	if (eor)
		tls_push(tsk);

send_end:
	ret = sk_stream_error(sk, msg->msg_flags, ret);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && ret == -EAGAIN))
		sk->sk_write_space(sk);

	release_sock(sk);

	return ret < 0 ? ret : size;
}

static int tls_do_decryption(struct tls_sock *tsk,
			     struct scatterlist *sgin,
			     struct scatterlist *sgout,
			     char *header_recv,
			     size_t data_len)
{
	int ret;
	unsigned int req_size = sizeof(struct aead_request) +
		crypto_aead_reqsize(tsk->aead_recv);
	struct aead_request *aead_req = (void *)sock_kmalloc(&tsk->sk, req_size,
							GFP_KERNEL);
	if (!aead_req)
		return -ENOMEM;

	aead_request_set_tfm(aead_req, tsk->aead_recv);
	aead_request_set_ad(aead_req, KTLS_PADDED_AAD_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout,
			       data_len + KTLS_TAG_SIZE,
			       (u8 *)header_recv + KTLS_NONCE_OFFSET(tsk));
	aead_request_set_callback(aead_req, 0, NULL, NULL);

	ret = crypto_aead_decrypt(aead_req);

	if (aead_req)
		sock_kfree_s(&tsk->sk, aead_req, req_size);

	return ret;
}

static int tls_post_process(struct tls_sock *tsk, struct sk_buff *skb)
{
	size_t prepend, overhead;
	struct strp_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	overhead = IS_TLS(tsk) ? KTLS_TLS_OVERHEAD : KTLS_DTLS_OVERHEAD;
	rxm = strp_rx_msg(skb);

	/* The crypto API does the following transformation.
	 * Before:
	 *   AAD(13) | DATA | TAG
	 * After:
	 *   AAD(13) | DECRYPTED | TAG
	 * The AAD and TAG is left untouched. However we don't want that
	 * returned to the user. Therefore we fix the offsets and lengths
	 */
	rxm->offset += prepend;
	rxm->full_len -= overhead;
	increment_seqno(tsk->iv_recv, tsk);
	tls_rx_msg(skb)->decrypted = 1;
	return 0;
}

static unsigned int tls_poll(struct file *file, struct socket *sock,
			     struct poll_table_struct *wait)
{
	unsigned int ret;
	struct tls_sock *tsk;
	unsigned int mask;
	struct sock *sk;

	sk = sock->sk;
	tsk = tls_sk(sock->sk);

	/* Call POLL on the underlying socket, which will call
	 * sock_poll_wait on underlying socket. Used for POLLOUT and
	 * POLLHUP
	 */
	ret = tsk->socket->ops->poll(tsk->socket->file, tsk->socket, wait);

	/* Clear POLLIN bits. Data available in the underlying socket is not
	 * necessarily ready to be read. The data could still be in the process
	 * of decryption, or it could be meant for original fd.
	 */
	ret &= ~(POLLIN | POLLRDNORM);

	/* Used for POLLIN
	 * Call generic POLL on TLS socket, which works for any
	 * sockets provided the socket receive queue is only ever
	 * holding data ready to receive.  Data ready to be read are
	 * stored in KTLS's sk_receive_queue
	 */
	mask = datagram_poll(file, sock, wait);

	/* Clear POLLOUT and POLLHUPbits. Even if KTLS is ready to
	 * send, data won't be sent if the underlying socket is not
	 * ready. in addition, even if KTLS was initialized as a
	 * stream socket, it's not actually connected to anything, so
	 * we ignore its POLLHUP.  Also, we don't support priority
	 * band writes in KTLS
	 */
	mask &= ~(POLLOUT | POLLWRNORM | POLLHUP);

	ret |= mask;

	/* POLLERR should return if either socket is received error.
	 * We don't support high-priority data atm, so clear those
	 * bits
	 */
	ret &= ~(POLLWRBAND | POLLRDBAND);
	return ret;
}

static void tls_dequeue_held_data(struct tls_sock *tsk)
{
	if (tsk->strp.rx_paused) {
		int unpause = 1;
		struct sk_buff *skb;

		while ((skb = __skb_dequeue(&tsk->rx_hold_queue))) {
			int ret = sock_queue_rcv_skb((struct sock *)tsk, skb);

			if (ret < 0) {
				skb_queue_head(&tsk->rx_hold_queue, skb);
				unpause = 0;
				break;
			}
		}
		if (unpause) {
			tsk->strp.rx_paused = 0;
			strp_check_rcv(&tsk->strp);
		}
	}
}

static struct sk_buff *tls_wait_data(struct tls_sock *tsk, int flags,
				     long timeo, int *err)
{
	struct sk_buff *skb;
	struct sock *sk;

	sk = (struct sock *)tsk;

	while (!(skb = skb_peek(&sk->sk_receive_queue))) {
		/* Don't clear sk_err since recvmsg may not return it
		 * immediately. Instead, clear it after the next
		 * attach
		 */
		if (sk->sk_err) {
			*err = sk->sk_err;
			return NULL;
		}

		if (sock_flag(sk, SOCK_DONE))
			return NULL;

		if ((flags & MSG_DONTWAIT) || !timeo) {
			*err = -EAGAIN;
			return NULL;
		}

		sk_wait_data(sk, &timeo, NULL);

		/* Handle signals */
		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			return NULL;
		}
	}

	return skb;
}

static int tls_recvmsg(struct socket *sock,
		       struct msghdr *msg,
		       size_t len,
		       int flags)
{
	ssize_t copied = 0;
	int err = 0;
	long timeo;
	struct tls_sock *tsk;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!KTLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto recv_end;
	}

	timeo = sock_rcvtimeo(&tsk->sk, flags & MSG_DONTWAIT);
	do {
		int chunk;

		tls_dequeue_held_data(tsk);
		skb = tls_wait_data(tsk, flags, timeo, &err);
		if (!skb)
			goto recv_end;

		rxm = strp_rx_msg(skb);
		/* It is possible that the message is already
		 * decrypted if the last call only read part of the
		 * message
		 */
		if (!tls_rx_msg(skb)->decrypted) {
			err = decrypt_skb(tsk, skb);
			if (err < 0) {
				tls_err_abort(tsk);
				goto recv_end;
			}
			tls_rx_msg(skb)->decrypted = 1;
		}
		chunk = min_t(unsigned int, rxm->full_len, len);
		err = skb_copy_datagram_msg(skb, rxm->offset, msg, chunk);
		if (err < 0)
			goto recv_end;
		copied += chunk;
		len -= chunk;
		if (likely(!(flags & MSG_PEEK))) {
			if (copied < rxm->full_len) {
				rxm->offset += copied;
				rxm->full_len -= copied;
			} else {
				/* Finished with message */
				skb_unlink(skb, &((struct sock *)tsk)
						->sk_receive_queue);
				kfree_skb(skb);
			}
		}

	} while (len);

recv_end:
	release_sock(sock->sk);
	ret = copied ? : err;
	return ret;
}

static int dtls_recvmsg(struct socket *sock,
			struct msghdr *msg,
			size_t len,
			int flags)
{
	ssize_t copied = 0;
	int err;
	struct tls_sock *tsk;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!KTLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto recv_end;
	}

	tls_dequeue_held_data(tsk);
	skb = skb_recv_datagram((struct sock *)tsk, flags & ~MSG_DONTWAIT,
				flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto recv_end;
	rxm = strp_rx_msg(skb);
	err = decrypt_skb(tsk, skb);
	if (err < 0) {
		tls_err_abort(tsk);
		goto recv_end;
	}
	err = skb_copy_datagram_msg(skb, rxm->offset, msg, rxm->full_len);
	if (err < 0)
		goto recv_end;
	copied = rxm->full_len;
	if (copied > len)
		msg->msg_flags |= MSG_TRUNC;
	if (likely(!(flags & MSG_PEEK))) {
		msg->msg_flags |= MSG_EOR;
		skb_free_datagram((struct sock *)tsk, skb);
	}
recv_end:

	release_sock(sock->sk);
	ret = copied ? : err;
	return ret;
}

static ssize_t tls_sock_splice(struct sock *sk,
			       struct pipe_inode_info *pipe,
			       struct splice_pipe_desc *spd)
{
	int ret;

	release_sock(sk);
	ret = splice_to_pipe(pipe, spd);
	lock_sock(sk);

	return ret;
}

static ssize_t tls_splice_read(struct socket *sock,  loff_t *ppos,
			       struct pipe_inode_info *pipe,
			       size_t len, unsigned int flags)
{
	ssize_t copied = 0;
	long timeo;
	struct tls_sock *tsk;
	struct strp_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;
	int chunk;
	int err = 0;
	struct sock *sk = sock->sk;

	tsk = tls_sk(sk);
	lock_sock(sk);

	if (!KTLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto splice_read_end;
	}

	timeo = sock_rcvtimeo(&tsk->sk, flags & MSG_DONTWAIT);

	tls_dequeue_held_data(tsk);
	skb = tls_wait_data(tsk, flags, timeo, &err);
	if (!skb)
		goto splice_read_end;

	rxm = strp_rx_msg(skb);
	/* It is possible that the message is already decrypted if the
	 * last call only read part of the message
	 */
	if (!tls_rx_msg(skb)->decrypted) {
		err = decrypt_skb(tsk, skb);
		if (err < 0) {
			tls_err_abort(tsk);
			goto splice_read_end;
		}
		tls_rx_msg(skb)->decrypted = 1;
	}
	chunk = min_t(unsigned int, rxm->full_len, len);
	copied = skb_splice_bits(skb, sk, rxm->offset, pipe, chunk,
				 flags, tls_sock_splice);
	if (ret < 0)
		goto splice_read_end;

	rxm->offset += copied;
	rxm->full_len -= copied;

splice_read_end:
	release_sock(sk);
	ret = (copied) ? copied : err;
	return ret;
}

static ssize_t tls_sendpage(struct socket *sock, struct page *page,
			    int offset, size_t size, int flags)
{
	int ret = 0, i;
	struct sock *sk = sock->sk;
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	struct tls_sock *tsk;
	bool eor;
	struct sk_buff *skb = NULL;
	size_t queued = 0;

	if (flags & MSG_SENDPAGE_NOTLAST)
		flags |= MSG_MORE;

	/* No MSG_EOR from splice, only look at MSG_MORE */
	eor = !(flags & MSG_MORE);

	tsk = tls_sk(sk);
	lock_sock(sk);

	if (!KTLS_SEND_READY(tsk)) {
		ret = -EBADMSG;
		goto sendpage_end;
	}

	if (flags & MSG_OOB) {
		ret = -ENOTSUPP;
		goto sendpage_end;
	}
	sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	/* Call the sk_stream functions to manage the sndbuf mem. */
	while (queued < size) {
		size_t send_size = min(size, KTLS_MAX_PAYLOAD_SIZE);

		if (!sk_stream_memory_free(sk) ||
		    (tsk->unsent + send_size > KTLS_MAX_PAYLOAD_SIZE)) {
			tls_push(tsk);
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			ret = sk_stream_wait_memory(sk, &timeo);
			if (ret)
				goto sendpage_end;
		}

		if (sk->sk_err)
			goto sendpage_end;

		skb = tcp_write_queue_tail(sk);
		if (skb) {
			i = skb_shinfo(skb)->nr_frags;

			if (skb_can_coalesce(skb, i, page, offset)) {
				skb_frag_size_add(
					&skb_shinfo(skb)->frags[i - 1],
					send_size);
				skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
				goto coalesced;
			}

			if (i >= ALG_MAX_PAGES) {
				struct sk_buff *tskb;

				tskb = alloc_skb(0, sk->sk_allocation);
				while (!tskb) {
					tls_push(tsk);
					if (sk->sk_err)
						goto sendpage_end;
					set_bit(SOCK_NOSPACE,
						&sk->sk_socket->flags);
					ret = sk_stream_wait_memory(sk, &timeo);
					if (ret)
						goto sendpage_end;
				}

				if (skb)
					skb->next = tskb;
				else
					__skb_queue_tail(&sk->sk_write_queue,
							 tskb);
				skb = tskb;
				i = 0;
			}
		} else {
			skb = alloc_skb(0, sk->sk_allocation);
			__skb_queue_tail(&sk->sk_write_queue, skb);
			i = 0;
		}

		get_page(page);
		skb_fill_page_desc(skb, i, page, offset, send_size);
		skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;

coalesced:
		skb->len += send_size;
		skb->data_len += send_size;
		skb->truesize += send_size;
		sk->sk_wmem_queued += send_size;
		sk_mem_charge(sk, send_size);
		tsk->unsent += send_size;

		if (eor || tsk->unsent >= KTLS_MAX_PAYLOAD_SIZE)
			tls_push(tsk);
		queued += send_size;
	}
sendpage_end:
	ret = sk_stream_error(sk, flags, ret);

	if (ret < 0)
		ret = sk_stream_error(sk, flags, ret);

	/* make sure we wake any epoll edge trigger waiter */
	if (unlikely(skb_queue_len(&sk->sk_write_queue) == 0 && ret == -EAGAIN))
		sk->sk_write_space(sk);

	release_sock(sk);

	return ret < 0 ? ret : size;
}

static int tls_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int ret;
	struct tls_sock *tsk;
	struct sockaddr_ktls *sa_ktls;
	struct strp_callbacks cb;

	if (!uaddr || sizeof(*sa_ktls) != addr_len)
		return -EBADMSG;

	tsk = tls_sk(sock->sk);
	sa_ktls = (struct sockaddr_ktls *)uaddr;

	switch (sa_ktls->sa_cipher) {
	case KTLS_CIPHER_AES_GCM_128:
		tsk->cipher_type = KTLS_CIPHER_AES_GCM_128;
		tsk->cipher_crypto = "rfc5288(gcm(aes))";
		break;
	default:
		return -ENOENT;
	}

	switch (sa_ktls->sa_version) {
	case KTLS_VERSION_LATEST:
		/* passthrough */
	case KTLS_VERSION_1_2:
		if (IS_TLS(tsk)) {
			tsk->version[0] = KTLS_TLS_1_2_MAJOR;
			tsk->version[1] = KTLS_TLS_1_2_MINOR;
		} else {
			tsk->version[0] = KTLS_DTLS_1_2_MAJOR;
			tsk->version[1] = KTLS_DTLS_1_2_MINOR;
		}
		break;
	default:
		return -ENOENT;
	}

	lock_sock(sock->sk);
	tsk->socket = sockfd_lookup(sa_ktls->sa_socket, &ret);
	if (!tsk->socket) {
		ret = -ENOENT;
		goto bind_end;
	}
	if (!IS_TCP(tsk->socket) && !IS_UDP(tsk->socket)) {
		ret = -EAFNOSUPPORT;
		goto bind_end;
	}

	/* Do not allow TLS over unreliable UDP */
	if (IS_TLS(tsk) && IS_UDP(tsk->socket)) {
		ret = -EBADF;
		goto bind_end;
	}

	if (!tsk->aead_recv) {
		tsk->aead_recv = crypto_alloc_aead(tsk->cipher_crypto,
				CRYPTO_ALG_INTERNAL, 0);
		if (IS_ERR(tsk->aead_recv)) {
			ret = PTR_ERR(tsk->aead_recv);
			tsk->aead_recv = NULL;
			goto bind_end;
		}
	}

	if (!tsk->aead_send) {
		tsk->aead_send = crypto_alloc_aead(tsk->cipher_crypto,
				CRYPTO_ALG_INTERNAL, 0);
		if (IS_ERR(tsk->aead_send)) {
			ret = PTR_ERR(tsk->aead_send);
			tsk->aead_send = NULL;
			goto bind_end;
		}
	}

	((struct sock *)tsk)->sk_err = 0;

	cb.rcv_msg = tls_queue;
	cb.abort_parser = tls_abort_cb;
	cb.parse_msg = tls_parse_cb;
	cb.read_sock_done = NULL;

	strp_init(&tsk->strp, tsk->socket->sk, &cb);

	write_lock_bh(&tsk->socket->sk->sk_callback_lock);
	tsk->rx_stopped = 0;
	tsk->saved_sk_data_ready = tsk->socket->sk->sk_data_ready;
	tsk->saved_sk_write_space = tsk->socket->sk->sk_write_space;
	tsk->socket->sk->sk_data_ready = tls_data_ready;
	tsk->socket->sk->sk_write_space = tls_write_space;
	tsk->socket->sk->sk_user_data = tsk;
	write_unlock_bh(&tsk->socket->sk->sk_callback_lock);

	release_sock(sock->sk);
	/* Check if any TLS packets have come in between the time the
	 * handshake was completed and bind() was called. If there
	 * were, the packets would have woken up TCP socket waiters,
	 * not KTLS. Therefore, pull the packets from TCP and wake up
	 * KTLS if necessary
	 */
	check_rcv(tsk);

	return 0;

bind_end:
	sockfd_put(tsk->socket);
	tsk->socket = NULL;
	release_sock(sock->sk);
	return ret;
}

static int tls_release(struct socket *sock)
{
	struct tls_sock *tsk;

	tsk = tls_sk(sock->sk);

	if (sock->sk)
		sock_put(sock->sk);

	return 0;
}

static const struct proto_ops tls_stream_ops = {
	.family		=	PF_KTLS,
	.owner		=	THIS_MODULE,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.mmap		=	sock_no_mmap,
	.poll		=	tls_poll,
	.accept		=	sock_no_accept,

	.bind		=	tls_bind,
	.setsockopt	=	tls_setsockopt,
	.getsockopt	=	tls_getsockopt,
	.sendmsg	=	tls_sendmsg,
	.recvmsg	=	tls_recvmsg,
	.sendpage	=	tls_sendpage,
	.release	=	tls_release,
	.splice_read    =	tls_splice_read,
};

static const struct proto_ops tls_dgram_ops = {
	.family		=	PF_KTLS,
	.owner		=	THIS_MODULE,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.mmap		=	sock_no_mmap,
	.poll		=	tls_poll,
	.accept		=	sock_no_accept,

	.bind		=	tls_bind,
	.setsockopt	=	tls_setsockopt,
	.getsockopt	=	tls_getsockopt,
	.sendmsg	=	tls_sendmsg,
	.recvmsg	=	dtls_recvmsg,
	.sendpage	=	tls_sendpage,
	.release	=	tls_release,
	.splice_read    =	tls_splice_read,
};

static void tls_sock_destruct(struct sock *sk)
{
	struct tls_sock *tsk;

	tsk = tls_sk(sk);

	cancel_work_sync(&tsk->recv_work);
	cancel_work_sync(&tsk->send_work);

	skb_queue_purge(&tsk->rx_hold_queue);

	/* restore callback and abandon socket */
	if (tsk->socket) {
		write_lock_bh(&tsk->socket->sk->sk_callback_lock);

		tsk->rx_stopped = 1;
		tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
		tsk->socket->sk->sk_write_space = tsk->saved_sk_write_space;
		tsk->socket->sk->sk_user_data = NULL;
		write_unlock_bh(&tsk->socket->sk->sk_callback_lock);

		sockfd_put(tsk->socket);
		tsk->socket = NULL;
	}

	kfree(tsk->iv_send);

	kfree(tsk->key_send.key);

	kfree(tsk->iv_recv);

	kfree(tsk->key_recv.key);

	crypto_free_aead(tsk->aead_send);

	crypto_free_aead(tsk->aead_recv);

	skb_queue_purge(&sk->sk_receive_queue);
}

static struct proto tls_proto = {
	.name				= "KTLS",
	.owner			= THIS_MODULE,
	.obj_size		= sizeof(struct tls_sock),
	.stream_memory_free = tls_stream_memory_free,
};

static int tls_create(struct net *net,
		      struct socket *sock,
		      int protocol,
		      int kern)
{
	int ret;
	struct sock *sk;
	struct tls_sock *tsk;

	switch (sock->type) {
	case SOCK_STREAM:
		sock->ops = &tls_stream_ops;
		break;
	case SOCK_DGRAM:
		sock->ops = &tls_dgram_ops;
		break;
	default:
		return -ESOCKTNOSUPPORT;
	}

	if (protocol != 0)
		return -EPROTONOSUPPORT;

	sk = sk_alloc(net, PF_KTLS, GFP_ATOMIC, &tls_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	sk->sk_family = PF_KTLS;
	sk->sk_destruct = tls_sock_destruct;

	/* initialize stored context */
	tsk = tls_sk(sk);

	tsk->iv_send = NULL;
	memset(&tsk->key_send, 0, sizeof(tsk->key_send));

	tsk->socket = NULL;

	tsk->iv_recv = NULL;
	memset(&tsk->key_recv, 0, sizeof(tsk->key_recv));

	tsk->cipher_crypto = NULL;
	memset(tsk->version, 0, sizeof(tsk->version));

	tsk->pages_send = NULL;
	tsk->unsent = 0;

	ret = -ENOMEM;
	/* Preallocation for sending
	 *   scatterlist: AAD | data | TAG (for crypto API)
	 *   vec: HEADER | data | TAG
	 */
	sg_init_table(tsk->sg_tx_data, KTLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_tx_data[0], tsk->aad_send, sizeof(tsk->aad_send));

	sg_set_buf(tsk->sg_tx_data + KTLS_SG_DATA_SIZE - 2,
		   tsk->tag_send, sizeof(tsk->tag_send));
	sg_mark_end(tsk->sg_tx_data + KTLS_SG_DATA_SIZE - 1);

	sg_init_table(tsk->sgaad_send, 2);
	sg_init_table(tsk->sgtag_send, 2);

	sg_set_buf(&tsk->sgaad_send[0], tsk->aad_send, sizeof(tsk->aad_send));
	/* chaining to tag is performed on actual data size when sending */
	sg_set_buf(&tsk->sgtag_send[0], tsk->tag_send, sizeof(tsk->tag_send));

	sg_unmark_end(&tsk->sgaad_send[1]);
	INIT_WORK(&tsk->recv_work, tls_rx_work);
	INIT_WORK(&tsk->send_work, tls_tx_work);

	skb_queue_head_init(&tsk->rx_hold_queue);

	return 0;
}

static const struct net_proto_family tls_family = {
	.family	=	PF_KTLS,
	.create	=	tls_create,
	.owner	=	THIS_MODULE,
};

static int __init tls_init(void)
{
	int ret = -ENOMEM;

	tls_rx_wq = create_workqueue("ktls");
	if (!tls_rx_wq)
		goto tls_init_end;

	tls_tx_wq = create_workqueue("ktls");
	if (!tls_tx_wq) {
		destroy_workqueue(tls_rx_wq);
		goto tls_init_end;
	}

	ret = proto_register(&tls_proto, 0);
	if (ret) {
		destroy_workqueue(tls_rx_wq);
		destroy_workqueue(tls_tx_wq);
		goto tls_init_end;
	}

	ret = sock_register(&tls_family);
	if (ret != 0) {
		proto_unregister(&tls_proto);
		destroy_workqueue(tls_rx_wq);
		destroy_workqueue(tls_tx_wq);
		goto tls_init_end;
	}

tls_init_end:
	return ret;
}

static void __exit tls_exit(void)
{
	sock_unregister(PF_KTLS);
	proto_unregister(&tls_proto);
	destroy_workqueue(tls_rx_wq);
	destroy_workqueue(tls_tx_wq);
}

module_init(tls_init);
module_exit(tls_exit);
MODULE_LICENSE("GPL");

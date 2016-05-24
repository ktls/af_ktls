/*
 * af_ktls: TLS/DTLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fridolin.pokorny@gmail.com>
 *   Nikos Mavrogiannopoulos <nmav@gnults.org>
 *   Dave Watson <davejwatson@fb.com>
 *
 * Based on RFC 5288, RFC 6347, RFC 5246, RFC 6655
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
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
// +1 for header, +1 for tag
#define KTLS_VEC_SIZE			(KTLS_DATA_PAGES + 2)
// +1 for aad, +1 for tag, +1 for chaining
#define KTLS_SG_DATA_SIZE		(KTLS_DATA_PAGES + 3)

/*
 * RFC5288 patch requires 24 bytes allocated
 */
#define KTLS_AAD_SPACE_SIZE		24
/* RFC52888: AAD is zero-padded to 21 */
#define KTLS_PADDED_AAD_SIZE		21
#define KTLS_AAD_SIZE			13

/*
 * TLS related stuff
 */
#define KTLS_TLS_HEADER_SIZE		5
#define KTLS_TLS_PREPEND_SIZE		(KTLS_TLS_HEADER_SIZE + KTLS_NONCE_SIZE)
#define KTLS_TLS_OVERHEAD		(KTLS_TLS_PREPEND_SIZE + KTLS_TAG_SIZE)

#define KTLS_TLS_1_2_MAJOR		0x03
#define KTLS_TLS_1_2_MINOR		0x03

// nonce explicit offset in a record
#define KTLS_TLS_NONCE_OFFSET		KTLS_TLS_HEADER_SIZE

/*
 * DTLS related stuff
 */
#define KTLS_DTLS_HEADER_SIZE		13
#define KTLS_DTLS_PREPEND_SIZE		(KTLS_DTLS_HEADER_SIZE + KTLS_NONCE_SIZE)
#define KTLS_DTLS_OVERHEAD		(KTLS_DTLS_PREPEND_SIZE + KTLS_TAG_SIZE)

#define KTLS_DTLS_1_2_MAJOR		0xFE
#define KTLS_DTLS_1_2_MINOR		0xFD

// we are handling epoch and seq num as one unit
#define KTLS_DTLS_SEQ_NUM_OFFSET	3
// nonce explicit offset in a record
#define KTLS_DTLS_NONCE_OFFSET		KTLS_DTLS_HEADER_SIZE

/*
 * Ensure that bind(2) was called
 */
#define KTLS_SETSOCKOPT_READY(T)	((T)->aead_send != NULL \
						&& (T)->aead_recv != NULL)
#define KTLS_GETSOCKOPT_READY(T)	KTLS_SETSOCKOPT_READY(T)

/*
 * Ensure that we have needed key material
 */
#define KTLS_SEND_READY(T)		((T)->key_send.keylen && \
						(T)->key_send.saltlen && \
						(T)->iv_send && \
						KTLS_GETSOCKOPT_READY(T))
#define KTLS_RECV_READY(T)		((T)->key_recv.keylen && \
						(T)->key_recv.saltlen && \
						(T)->iv_recv && \
						KTLS_GETSOCKOPT_READY(T))

#define IS_TLS(T)			(T->tls)
#define IS_DTLS(T)			(!IS_TLS(T))

/*
 * Real size of a record based on data carried
 */
#define KTLS_RECORD_SIZE(T, S)		(IS_TLS(T) ? \
						(S + KTLS_TLS_OVERHEAD) : \
						(S + KTLS_DTLS_OVERHEAD))

/*
 * Nonce explicit offset in a record
 */
#define KTLS_NONCE_OFFSET(T)		(IS_TLS(T) ? \
						(KTLS_TLS_NONCE_OFFSET) : \
						(KTLS_DTLS_NONCE_OFFSET))

/*
 * Asynchrous receive handling
 */
#define TLS_CACHE_DISCARD(T)		(T->recv_occupied = 0)
#define TLS_CACHE_SIZE(T)		(T->recv_occupied)
#define TLS_CACHE_SET_SIZE(T, S)	(T->recv_occupied = S)

/*
 * OpenConnect stuff
 *   uncompressed data can be served without user space
 */
#define OPENCONNECT_PKT_DATA		0x00

//#define KTLS_DEBUG

#if 1 // TODO: remove once ready to use
	#ifdef KTLS_DEBUG
	# define xprintk(...)  (do_xprintk(__VA_ARGS__))
	# define print_hex(...) (do_print_hex(__VA_ARGS__))
	#else
	# define xprintk(...)  ((void) 0)
	# define print_hex(...) ((void) 0)
	#endif

	#define UNUSED(X)		((void) X)

	void do_xprintk(const char *fmt, ...) {
		va_list va;
		va_start(va, fmt);
		printk("tls: ");
		vprintk(fmt, va);
		printk("\n");
		va_end(va);
	}

	void do_print_hex(const unsigned char * key, unsigned int keysize) {
		int i = 0;

		printk("kdls: hex: ");
		for (i = 0; i < keysize; i++)
			printk("%02X", (unsigned char)key[i]);
		printk("\n");
	}
#endif

/*
 * Async rx worker
 */
static struct workqueue_struct *tls_wq;

struct tls_key {
	char *key;
	size_t keylen;
	char salt[KTLS_SALT_SIZE];
	size_t saltlen;
};

struct tls_sock {
	/* struct sock must be the very first member */
	struct sock sk;

	/*
	 * TCP/UDP socket we are binded to
	 */
	struct socket *socket;

	int rx_stopped;

	/*
	 * Context for {set,get}sockopt()
	 */
	char *iv_send;
	struct tls_key key_send;

	char *iv_recv;
	struct tls_key key_recv;

	struct crypto_aead *aead_send;
	struct crypto_aead *aead_recv;

	/*
	 * Sending context
	 */
	struct scatterlist sg_tx_data[KTLS_SG_DATA_SIZE];
	struct kvec vec_send[KTLS_VEC_SIZE];
	char header_send[MAX(KTLS_TLS_PREPEND_SIZE, KTLS_DTLS_PREPEND_SIZE)];
	char aad_send[KTLS_AAD_SPACE_SIZE];
	char tag_send[KTLS_TAG_SIZE];
	struct page *pages_send;
	struct af_alg_sgl sgl_send;
	struct scatterlist sgaad_send[2];
	struct scatterlist sgtag_send[2];

	/*
	 * Receiving context, rx_lock has to be acquired before socket lock to
	 * avoid deadlock
	 */
	struct mutex rx_lock;
	struct scatterlist sg_rx_data[KTLS_SG_DATA_SIZE];
	struct kvec vec_recv[KTLS_VEC_SIZE];
	char header_recv[MAX(KTLS_TLS_PREPEND_SIZE, KTLS_DTLS_PREPEND_SIZE)];
	char aad_recv[KTLS_AAD_SPACE_SIZE];
	char tag_recv[KTLS_TAG_SIZE];
	struct page *pages_recv;
	struct af_alg_sgl sgl_recv;
	struct scatterlist sgaad_recv[2];
	struct scatterlist sgtag_recv[2];

	/*
	 * Asynchronous work to cache one record
	 */
	struct work_struct recv_work;
	void (*saved_sk_data_ready)(struct sock *sk);
	struct scatterlist sg_rx_async_work[KTLS_SG_DATA_SIZE];
	struct page *pages_work;
	size_t recv_occupied;

	/*
	 * our cipher type and its crypto API representation (e.g. "gcm(aes)")
	 */
	unsigned cipher_type;
	char *cipher_crypto;

	/*
	 * TLS/DTLS version for header
	 */
	char version[2];

	/*
	 * nonzero if TLS, zero for DTLS
	 */
	int tls;

	/*
	 * additional options, e.g. OpenConnect protocol
	 */
	unsigned opts;

	/*
	 * store mtu for raw payload -- without header, tag, (and seq num
	 * when DTLS)
	 */
	size_t mtu_payload;

	/*
	 * DTLS window handling, see DTLS_WINDOW_* macros
	 */
	struct {
		uint64_t bits;
		unsigned start;
	} dtls_window;

	/*
	 * Context used for sendpage(2) packetization
	 */
	struct {
		struct scatterlist sg[KTLS_SG_DATA_SIZE];
		size_t used;
		size_t current_size;
		size_t desired_size;
		struct page *page;
	} sendpage_ctx;

	// TODO: remove once finished benchmarking
	unsigned parallel_count_stat;
};

static inline struct tls_sock *tls_sk(struct sock *sk)
{
	return (struct tls_sock *)sk;
}

static void increment_seqno(char *s)
{
	u64 *seqno = (u64 *) s;
	u64 seq_h = be64_to_cpu(*seqno);
	seq_h++;
	*seqno = cpu_to_be64(seq_h);
}

static void tls_free_sendpage_ctx(struct tls_sock *tsk)
{
	size_t i;
	struct scatterlist *sg;
	xprintk("--> %s", __FUNCTION__);

	sg = tsk->sendpage_ctx.sg;

	for (i = 0; i < tsk->sendpage_ctx.used; i++) {
		put_page(sg_page(sg + i));
		sg_unmark_end(sg + i);
		sg_set_page(sg + i, NULL, 0, 0);
	}
	sg_mark_end(sg);

	tsk->sendpage_ctx.used = 0;
	tsk->sendpage_ctx.current_size = 0;
	tsk->sendpage_ctx.desired_size = 0;
}

/*
 * called once data are sent by sendpage() == MTU is reached or last record is
 * sent based on packetization)
 */
static void tls_update_senpage_ctx(struct tls_sock *tsk, size_t size)
{
	size_t walked_size;
	size_t put_count;
	struct scatterlist *sg;
	struct scatterlist *sg_start;

	xprintk("--> %s", __FUNCTION__);

	sg = tsk->sendpage_ctx.sg;

	BUG_ON(size > tsk->sendpage_ctx.current_size);

	if (size == tsk->sendpage_ctx.current_size) {
		tls_free_sendpage_ctx(tsk);
		return;
	}

	walked_size = 0;
	sg_start = sg;
	put_count = 0;
	while (put_count < tsk->sendpage_ctx.used && \
			walked_size + sg_start->length <= size) {
		walked_size += sg_start->length;
		put_page(sg_page(sg_start));
		sg_start++;
		put_count++;
	}

	// adjust length and offset so we can send with right offset next time
	sg_start->offset += (size - walked_size);
	sg_start->length -= (size - walked_size);
	tsk->sendpage_ctx.current_size -= size;
	tsk->sendpage_ctx.used -= put_count;

	/*
	 * we will shift freed pages so chaining from AAD is correct and we
	 * can use whole scatterlist next time
	 */
	memmove(sg, sg_start,
		(KTLS_SG_DATA_SIZE - 1 - put_count)*sizeof(tsk->sendpage_ctx.sg[0]));
	sg_mark_end(&sg[tsk->sendpage_ctx.used]);
}

#include "dtls-window.c"

static void tls_data_ready(struct sock *sk)
{
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	read_lock_bh(&sk->sk_callback_lock);

	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->rx_stopped)) {
		goto out;
	}
	queue_work(tls_wq, &tsk->recv_work);

  out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static int tls_set_iv(struct socket *sock,
		int recv,
		char __user *src,
		size_t src_len)
{
	int ret;
	char **iv;
	struct sock *sk;
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	sk = sock->sk;
	tsk = tls_sk(sk);

	if (src == NULL)
		return -EBADMSG;

	if (src_len != KTLS_IV_SIZE)
		return -EBADMSG;

	iv = recv ? &tsk->iv_recv : &tsk->iv_send;

	if (*iv == NULL) {
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

	xprintk("--> %s", __FUNCTION__);

	k = recv ? &tsk->key_recv : &tsk->key_send;
	aead = recv ? tsk->aead_recv : tsk->aead_send;

	/*
	 * We need salt and key in order to construct 20B key according to
	 * RFC5288, otherwise we will handle this once both will be provided
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

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);

	if (src_len == 0 || src == NULL)
		return -EBADMSG;

	if (src_len != KTLS_KEY_SIZE)
		return -EBADMSG;

	k = recv ? &tsk->key_recv : &tsk->key_send;

	if (src_len > k->keylen) {
		if (k->keylen)
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

	xprintk("--> %s", __FUNCTION__);

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

static int tls_set_mtu(struct socket *sock, char __user *src, size_t src_len)
{
	int ret;
	size_t mtu;
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);

	if (src_len != sizeof(tsk->mtu_payload))
		ret = -EBADMSG;

	ret = copy_from_user(&mtu, src, sizeof(tsk->mtu_payload));
	if (ret)
		return ret;

	if (mtu <= (IS_TLS(tsk) ? KTLS_TLS_OVERHEAD : KTLS_DTLS_OVERHEAD))
		return -EBADMSG;

	mtu -= (IS_TLS(tsk) ? KTLS_TLS_OVERHEAD : KTLS_DTLS_OVERHEAD);

	if (mtu > KTLS_MAX_PAYLOAD_SIZE)
		return -EBADMSG;

	tsk->mtu_payload = mtu;

	return mtu;
}

static int tls_setsockopt(struct socket *sock,
		int level, int optname,
		char __user *optval,
		unsigned int optlen)
{
	int ret;
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);

	if (level != AF_KTLS)
		return -ENOPROTOOPT;

	if (!KTLS_SETSOCKOPT_READY(tsk))
		return -EBADMSG;

	ret = -EBADMSG;

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
		case KTLS_SET_MTU:
			ret = tls_set_mtu(sock, optval, optlen);
			break;
		case KTLS_PROTO_OPENCONNECT:
			if (optval == NULL && optlen == 0) {
				tsk->opts |= KTLS_PROTO_OPENCONNECT;
				ret = 0;
			}
			break;
		default:
			break;
	}

	/*
	 * We need to discard cache every time there is a change on socket
	 * not to be in an invalid state
	 */
	TLS_CACHE_DISCARD(tsk);
	/*
	 * The same applies to DTLS window
	 */
	DTLS_WINDOW_INIT(tsk->dtls_window);

	return ret < 0 ? ret : 0;
}

static int tls_get_iv(const struct tls_sock *tsk,
		int recv,
		char __user *dst,
		size_t dst_len)
{
	int ret;
	char *iv;

	xprintk("--> %s", __FUNCTION__);

	if (dst_len < KTLS_IV_SIZE)
		return -ENOMEM;

	iv = recv ? tsk->iv_recv : tsk->iv_send;

	if (iv == NULL)
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

	xprintk("--> %s", __FUNCTION__);

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

	xprintk("--> %s", __FUNCTION__);

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
	size_t mtu;
	const struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);

	if (level != AF_KTLS)
		return -ENOPROTOOPT;

	if (!KTLS_GETSOCKOPT_READY(tsk))
		return -EBADMSG;

	if (optlen == 0 || optval == NULL)
		return -EBADMSG;

	if (get_user(len, optlen))
		return -EFAULT;

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
		case KTLS_GET_MTU:
			if (len < sizeof(tsk->mtu_payload))
				return -ENOMEM;

			if (put_user(sizeof(tsk->mtu_payload), optlen))
				return -EFAULT;

			mtu = KTLS_RECORD_SIZE(tsk, tsk->mtu_payload);
			if (copy_to_user(optval, &mtu, sizeof(mtu)))
				return -EFAULT;

			return 0;
		default:
			ret = -EBADMSG;
			break;
	}

	if (ret < 0)
		goto end;

	ret = copy_to_user(optlen, &ret, sizeof(*optlen));

end:
	return ret;
}

static inline void tls_make_prepend(struct tls_sock *tsk,
		char *buf,
		size_t plaintext_len)
{
	size_t pkt_len;

	xprintk("--> %s", __FUNCTION__);

	pkt_len = plaintext_len + KTLS_IV_SIZE + KTLS_TAG_SIZE;

	/*
	 * we cover nonce explicit here as well, so buf should be of
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
	xprintk("--> %s", __FUNCTION__);

	// has to be zero padded according to RFC5288
	memset(buf, 0, KTLS_AAD_SPACE_SIZE);

	memcpy(buf, nonce_explicit, KTLS_NONCE_SIZE);

	buf[8] = KTLS_RECORD_DATA;
	buf[9] = tsk->version[0];
	buf[10] = tsk->version[1];
	buf[11] = size >> 8;
	buf[12] = size & 0xFF;
}

static inline void tls_pop_record(struct tls_sock *tsk, size_t data_len)
{
	int ret;
	struct msghdr msg = {};

	xprintk("--> %s", __FUNCTION__);

	if (IS_TLS(tsk)) {
		ret = kernel_recvmsg(tsk->socket, &msg,
				tsk->vec_recv, KTLS_VEC_SIZE,
				KTLS_RECORD_SIZE(tsk, data_len), MSG_TRUNC);
		WARN_ON(ret != KTLS_RECORD_SIZE(tsk, data_len));
	} else {
		ret = kernel_recvmsg(tsk->socket,
				&msg, tsk->vec_recv, KTLS_VEC_SIZE,
				/*size*/0, /*flags*/0);
		WARN_ON(ret != 0);
	}
}

static int tls_do_encryption(struct tls_sock *tsk,
		struct scatterlist *sgin,
		struct scatterlist *sgout,
		size_t data_len)
{
	char aead_req_data[sizeof(struct aead_request) +
			   crypto_aead_reqsize(tsk->aead_send)]
		__aligned(__alignof__(struct aead_request));
	struct aead_request *aead_req = (void *)aead_req_data;
	struct af_alg_completion completion;

	xprintk("--> %s", __FUNCTION__);

	aead_request_set_tfm(aead_req, tsk->aead_send);
	aead_request_set_ad(aead_req, KTLS_PADDED_AAD_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout, data_len, tsk->iv_send);

	return af_alg_wait_for_completion(
			crypto_aead_encrypt(aead_req),
			&completion);
}

static int tls_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	int ret;
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!KTLS_SEND_READY(tsk)) {
		ret = -EBADMSG;
		goto send_end;
	}

	if (size > KTLS_MAX_PAYLOAD_SIZE) {
		ret = -E2BIG;
		goto send_end;
	}

	// TODO: handle flags, see issue #4

	tls_make_aad(tsk, 0, tsk->aad_send, size, tsk->iv_send);

	ret = af_alg_make_sg(&tsk->sgl_send, &msg->msg_iter, size);
	if (ret < 0)
		goto send_end;

	sg_unmark_end(&tsk->sgaad_send[1]);
	sg_chain(tsk->sgaad_send, 2, tsk->sgl_send.sg);

	sg_unmark_end(tsk->sgl_send.sg + tsk->sgl_send.npages - 1);
	sg_chain(tsk->sgl_send.sg, tsk->sgl_send.npages + 1, tsk->sgtag_send);

	ret = tls_do_encryption(tsk, tsk->sgaad_send, tsk->sg_tx_data, size);
	if (ret < 0)
		goto send_end;

	tls_make_prepend(tsk, tsk->header_send, size);

	ret = kernel_sendmsg(tsk->socket, msg, tsk->vec_send, KTLS_VEC_SIZE,
			KTLS_RECORD_SIZE(tsk, size));

	if (ret > 0) {
		increment_seqno(tsk->iv_send);
		ret = size;
	}

send_end:
	release_sock(sock->sk);
	return ret;
}

static int tls_do_decryption(const struct tls_sock *tsk,
		struct scatterlist *sgin,
		struct scatterlist *sgout,
		size_t data_len)
{
	int ret;
	char aead_req_data[sizeof(struct aead_request) +
			   crypto_aead_reqsize(tsk->aead_recv)]
		__aligned(__alignof__(struct aead_request));
	struct aead_request *aead_req = (void *)aead_req_data;
	struct af_alg_completion completion;

	xprintk("--> %s", __FUNCTION__);

	aead_request_set_tfm(aead_req, tsk->aead_recv);
	aead_request_set_ad(aead_req, KTLS_PADDED_AAD_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout,
			data_len + KTLS_TAG_SIZE,
			       (u8*)tsk->header_recv + KTLS_NONCE_OFFSET(tsk));

	ret = af_alg_wait_for_completion(
			crypto_aead_decrypt(aead_req),
			&completion);

	return ret;
}

static int tls_post_process(const struct tls_sock *tsk, struct scatterlist *sgl)
{
	int ret;
	char *bytes;
	struct scatterlist *sg;

	xprintk("--> %s", __FUNCTION__);

	ret = -EBADMSG;

	sg = sgl;

	if (tsk->opts & KTLS_PROTO_OPENCONNECT) {
		/* skip TLS/DTLS header header */
		sg = sg_next(sg);
		bytes = page_address(sg_page(sg)) + sg->offset;
		if (bytes[0] != OPENCONNECT_PKT_DATA)
			goto postprocess_failure;
	}

	return 0;

postprocess_failure:
	return ret;
}

static inline ssize_t tls_peek_data(struct tls_sock *tsk, unsigned flags)
{
	int ret;
	ssize_t peeked_size;
	size_t data_len = 0;
	size_t datagram_len;
	struct msghdr msg = {};
	char *header;

	xprintk("--> %s", __FUNCTION__);

	/*
	 * we need to peek first, so we know what will be received, we have to
	 * handle DTLS window here as well, since this is the only function that
	 * does actual recv
	 */
	do {
		peeked_size = kernel_recvmsg(tsk->socket, &msg,
				tsk->vec_recv, KTLS_VEC_SIZE,
				KTLS_RECORD_SIZE(tsk, KTLS_MAX_PAYLOAD_SIZE),
				MSG_PEEK | flags);

		if (peeked_size < 0) {
			ret = peeked_size;
			goto peek_failure;
		}

		header = tsk->header_recv;
		// we handle only application data, let user space decide what
		// to do otherwise
		//
		if (header[0] != KTLS_RECORD_DATA) {
			ret = -EBADF;
			goto peek_failure;
		}

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
			goto peek_failure;
		}

		if (IS_TLS(tsk)) {
			if (datagram_len > peeked_size) {
				ret = -EFAULT; // TODO: consider returning ENOMEM
				goto peek_failure;
			}
		} else {
			if (datagram_len != peeked_size) {
				ret = -EFAULT;
				goto peek_failure;
			}
		}
	} while (IS_DTLS(tsk) &&
			!dtls_window(tsk, tsk->header_recv + KTLS_DTLS_SEQ_NUM_OFFSET));

	return data_len;

peek_failure:
	return ret;
}

static void tls_rx_async_work(struct work_struct *w)
{
	int ret;
	ssize_t data_len;
	struct sock *sk;
	struct tls_sock *tsk = container_of(w, struct tls_sock, recv_work);

	sk = (struct sock*) tsk;

	xprintk("--> %s", __FUNCTION__);

	if (!KTLS_RECV_READY(tsk))
		return;

	if (mutex_trylock(&tsk->rx_lock)) {
		lock_sock(sk);
		read_lock_bh(&sk->sk_callback_lock);

		if (!tsk->socket || tsk->rx_stopped) {
			goto rx_work_end;
		}

		// already occupied?
		if (TLS_CACHE_SIZE(tsk) != 0)
			goto rx_work_end;

		tsk->parallel_count_stat++; // TODO: remove

		data_len = tls_peek_data(tsk, MSG_DONTWAIT);
		// nothing to process (-EAGAIN) or other error? let user space
		// ask for it (do not cache errors)
		if (data_len <= 0)
			goto rx_work_end;

		tls_make_aad(tsk, 1, tsk->aad_recv, data_len,
			     tsk->iv_recv);

		ret = tls_do_decryption(tsk, tsk->sg_rx_data,
				tsk->sg_rx_async_work, data_len);
		if (ret < 0)
			goto rx_work_end;

		TLS_CACHE_SET_SIZE(tsk, data_len);

rx_work_end:
		read_unlock_bh(&sk->sk_callback_lock);
		release_sock(sk);
		mutex_unlock(&tsk->rx_lock);
	} else {
		// wake up rx queue
		tsk->saved_sk_data_ready(tsk->socket->sk);
	}
}

static const struct pipe_buf_operations tls_pipe_buf_ops = {
	.can_merge		= 0,
	.confirm		= generic_pipe_buf_confirm,
	.release		= generic_pipe_buf_release,
	.steal			= generic_pipe_buf_steal,
	.get			= generic_pipe_buf_get,
};

static void tls_spd_release(struct splice_pipe_desc *spd, unsigned int i)
{
	put_page(spd->pages[i]);
}

static int tls_splice_read_alloc(struct splice_pipe_desc *spd,
		size_t data_len) {
	int ret;
	size_t not_allocated, to_alloc;
	size_t pages_needed, i, j;

	pages_needed = data_len / PAGE_SIZE;
	if (pages_needed * PAGE_SIZE < data_len)
		pages_needed++;

	not_allocated = data_len;
	for (i = 0; i < pages_needed; i++) {
		to_alloc = min_t(size_t, PAGE_SIZE, not_allocated);
		spd->pages[i] = alloc_page(GFP_KERNEL);
		if (!spd->pages[i]) {
			for (j = 0; j < i; j++)
				__free_page(spd->pages[j]);
			ret = -ENOMEM;
			goto splice_read_alloc_end;
		}

		spd->partial[i].len = to_alloc;
		spd->partial[i].offset = 0;
		spd->partial[i].private = 0;
		not_allocated -= to_alloc;
	}

	spd->nr_pages = pages_needed;
	spd->nr_pages_max = pages_needed;

	ret = pages_needed;

splice_read_alloc_end:
	return ret;

}

static ssize_t tls_splice_read(struct socket *sock,  loff_t *ppos,
				       struct pipe_inode_info *pipe,
				       size_t size, unsigned int flags)
{
	ssize_t ret;
	size_t copy;
	size_t to_assign, assigned;
	ssize_t data_len;
	size_t i;
	struct scatterlist sg[KTLS_DATA_PAGES + 1]; // +1 for chaining
	struct tls_sock *tsk;
	struct page *pages[KTLS_DATA_PAGES + 2]; // +1 for header, +1 for tag
	struct partial_page partial[KTLS_DATA_PAGES + 2];
	struct splice_pipe_desc spd = {
		.pages          = pages,
		.partial        = partial,
		.nr_pages       = 0, // assigned bellow
		.nr_pages_max   = 0, // assigned bellow
		.flags          = flags, // TODO: handle, see issue #4
		.ops            = &tls_pipe_buf_ops,
		.spd_release    = tls_spd_release,
	};

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);
	mutex_lock(&tsk->rx_lock);
	lock_sock(sock->sk);

	if (!KTLS_RECV_READY(tsk)) {
		ret = -EBADMSG;
		goto splice_read_end;
	}

	if (TLS_CACHE_SIZE(tsk) > 0) { // we already received asynchronously
		data_len = TLS_CACHE_SIZE(tsk);

		ret = tls_splice_read_alloc(&spd, data_len);
		if (ret < 0)
			goto splice_read_end;

		for (i = 0; data_len; i++) {
			copy = min_t(size_t,
					tsk->sg_rx_async_work[i + 1].length,
					data_len);
			memcpy(page_address(spd.pages[i]),
				page_address(sg_page(tsk->sg_rx_async_work + i + 1)),
				copy);

			spd.partial[i].len = copy;
			spd.partial[i].offset = 0;
			spd.partial[i].private = 0;
			data_len -= copy;
		}
		data_len = TLS_CACHE_SIZE(tsk);

		ret = splice_to_pipe(pipe, &spd);

		if (ret > 0)
			TLS_CACHE_DISCARD(tsk);
	} else {
		data_len = tls_peek_data(tsk, 0);

		if (data_len < 0) {
			ret = data_len;
			goto splice_read_end;
		}

		if (data_len > size) {
			ret = -E2BIG;
			goto splice_read_end;
		}

		ret = tls_splice_read_alloc(&spd, data_len);
		if (ret < 0)
			goto splice_read_end;

		// assign to sg, so we can do decryption
		sg_init_table(sg, ret + 1);
		to_assign = data_len;
		for (i = 0; to_assign; i ++) {
			assigned = min_t(size_t, PAGE_SIZE, to_assign);
			sg_set_page(sg + i, spd.pages[i], assigned, 0);
			to_assign -= assigned;
		}
		sg_chain(tsk->sgaad_recv, 2, sg);
		sg_unmark_end(&sg[ret - 1]);
		sg_chain(sg, ret + 1, tsk->sgtag_recv);

		tls_make_aad(tsk, 1, tsk->aad_recv, data_len,
			     tsk->iv_recv);

		ret = tls_do_decryption(tsk, tsk->sg_rx_data,
				tsk->sgaad_recv, data_len);
		if (ret < 0)
			goto splice_read_end;

		ret = splice_to_pipe(pipe, &spd);
	}

	if (ret > 0) {
		increment_seqno(tsk->iv_recv);
		tls_pop_record(tsk, data_len);
	}

splice_read_end:
	// restore chaining for receiving
	sg_chain(tsk->sgaad_recv, 2, tsk->sgl_recv.sg);

	if (ret > 0)
		queue_work(tls_wq, &tsk->recv_work);

	release_sock(sock->sk);
	mutex_unlock(&tsk->rx_lock);

	return ret;
}

static int tls_recvmsg(struct socket *sock,
		struct msghdr *msg,
		size_t size,
		int flags)
{
	int ret, i;
	size_t copy, copied;
	ssize_t data_len;
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);
	mutex_lock(&tsk->rx_lock);
	lock_sock(sock->sk);

	if (!KTLS_RECV_READY(tsk)) {
		ret = -EBADMSG;
		goto recv_end;
	}

	// TODO: handle flags, see issue #4

	if (TLS_CACHE_SIZE(tsk) > 0) {
		if (size < TLS_CACHE_SIZE(tsk)) {
			ret = -ENOMEM;
			goto recv_end;
		}

		data_len = TLS_CACHE_SIZE(tsk);
		for (i = 1; data_len; i++) {
			copy = min_t(size_t,
					tsk->sg_rx_async_work[i].length,
					data_len);
			copied = copy_page_to_iter(sg_page(tsk->sg_rx_async_work + i),
							tsk->sg_rx_async_work[i].offset,
							copy,
							&msg->msg_iter);
			if (copied < copy) {
				ret = -EFAULT;
				goto recv_end;
			}

			data_len -= copied;
		}

		ret = TLS_CACHE_SIZE(tsk);
		TLS_CACHE_DISCARD(tsk);
	} else {
		ret = af_alg_make_sg(&tsk->sgl_recv, &msg->msg_iter, size);
		if (ret < 0)
			goto recv_end;

		sg_unmark_end(&tsk->sgl_recv.sg[tsk->sgl_recv.npages - 1]);
		sg_chain(tsk->sgl_recv.sg, tsk->sgl_recv.npages + 1, tsk->sgtag_recv);

		data_len = tls_peek_data(tsk, 0);

		if (data_len < 0) {
			ret = data_len;
			goto recv_end;
		}

		if (size < data_len) {
			ret = -ENOMEM;
			goto recv_end;
		}

		tls_make_aad(tsk, 1, tsk->aad_recv, data_len,
			     tsk->iv_recv);

		ret = tls_do_decryption(tsk,
				tsk->sg_rx_data,
				tsk->sgaad_recv,
				data_len);
		if (ret < 0)
			goto recv_end;

		ret = tls_post_process(tsk, tsk->sgaad_recv);
		if (ret < 0)
			goto recv_end;

		ret = data_len;
	}

	tls_pop_record(tsk, ret);
	increment_seqno(tsk->iv_recv);

recv_end:
	if (ret > 0)
		queue_work(tls_wq, &tsk->recv_work);

	release_sock(sock->sk);
	mutex_unlock(&tsk->rx_lock);

	return ret;
}

static ssize_t tls_do_sendpage(struct tls_sock *tsk)
{
	int ret;
	size_t data_len;
	struct msghdr msg = {};

	xprintk("--> %s", __FUNCTION__);

	data_len = min_t(size_t,
			tsk->sendpage_ctx.current_size,
			tsk->mtu_payload);

	tls_make_prepend(tsk, tsk->header_send, data_len);
	tls_make_aad(tsk, 0, tsk->aad_send, data_len, tsk->iv_send);

	/*
	 * temporary chain sgaad_send with sg, we need to restore this once
	 * finished because of usage in tls_sendmsg()
	 */
	sg_chain(tsk->sgaad_send, 2, tsk->sendpage_ctx.sg);
	sg_chain(tsk->sendpage_ctx.sg,
			tsk->sendpage_ctx.used + 1,
			tsk->sgtag_send);

	ret = tls_do_encryption(tsk,
			tsk->sgaad_send,
			tsk->sg_tx_data,
			data_len);
	if (ret < 0)
		goto do_sendmsg_end;

	ret = kernel_sendmsg(tsk->socket, &msg, tsk->vec_send, KTLS_VEC_SIZE,
			KTLS_RECORD_SIZE(tsk, data_len));
	if (ret > 0) {
		increment_seqno(tsk->iv_send);
		tls_update_senpage_ctx(tsk, data_len);
	} else
		tls_free_sendpage_ctx(tsk);

do_sendmsg_end:
	// restore, so we can use sendmsg()
	sg_chain(tsk->sgaad_send, 2, tsk->sgl_send.sg);
	// remove chaining to sg tag
	sg_mark_end(&tsk->sendpage_ctx.sg[tsk->sendpage_ctx.used]);

	return ret;
}

static ssize_t tls_sendpage(struct socket *sock, struct page *page,
			int offset, size_t size, int flags)
{
	int ret = 0;
	size_t pages;
	unsigned i;
	size_t copy, copied;
	struct tls_sock *tsk;
	struct scatterlist *sg;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!KTLS_SEND_READY(tsk)) {
		ret = -EBADMSG;
		goto sendpage_end;
	}

	if (flags & MSG_OOB) {
		ret = -ENOTSUPP;
		goto sendpage_end;
	}

	// TODO: handle flags, see issue #4

	sg = tsk->sendpage_ctx.sg;

	pages = size / PAGE_SIZE;
	if (pages * PAGE_SIZE < size)
		pages++;

	copied = 0;
	for (i = 0; i < pages; i++) {
		get_page(page + i);
		copy = min_t(size_t, size - copied, PAGE_SIZE);
		sg_unmark_end(sg + tsk->sendpage_ctx.used);
		sg_set_page(sg + tsk->sendpage_ctx.used, page + i, copy,
				i == 0 ? offset : 0);
		tsk->sendpage_ctx.used++;
		sg_mark_end(sg + tsk->sendpage_ctx.used);
		copied += copy;
	}

	tsk->sendpage_ctx.current_size += size;

	while (tsk->sendpage_ctx.current_size >= tsk->mtu_payload ||
			(!(flags & MSG_SENDPAGE_NOTLAST) &&
				tsk->sendpage_ctx.current_size)) {
		ret = tls_do_sendpage(tsk);
		if (ret < 0)
			goto sendpage_end;
	}

sendpage_end:
	if (ret < 0)
		tls_free_sendpage_ctx(tsk);

	release_sock(sock->sk);

	return ret < 0 ? ret : size;
}

static int tls_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int ret;
	struct tls_sock *tsk;
	struct sockaddr_ktls *sa_ktls;

	xprintk("--> %s", __FUNCTION__);

	if (uaddr == NULL || sizeof(*sa_ktls) != addr_len)
		return -EBADMSG;

	tsk = tls_sk(sock->sk);
	sa_ktls = (struct sockaddr_ktls *) uaddr;

	switch (sa_ktls->sa_cipher) {
		case KTLS_CIPHER_AES_GCM_128:
			tsk->cipher_type = KTLS_CIPHER_AES_GCM_128;
			tsk->cipher_crypto = "rfc5288(gcm(aes))";
			break;
		default:
			return -ENOENT;
	}

	switch(sa_ktls->sa_version) {
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

	tsk->socket = sockfd_lookup(sa_ktls->sa_socket, &ret);
	if (tsk->socket == NULL)
		return -ENOENT;

	xprintk("--1");
	tsk->aead_recv = crypto_alloc_aead(tsk->cipher_crypto,
			CRYPTO_ALG_INTERNAL, 0);
	xprintk("--1");
	if (IS_ERR(tsk->aead_recv)) {
		ret = PTR_ERR(tsk->aead_recv);
		tsk->aead_recv = NULL;
		goto bind_end;
	}

	tsk->aead_send = crypto_alloc_aead(tsk->cipher_crypto,
			CRYPTO_ALG_INTERNAL, 0);
	if (IS_ERR(tsk->aead_send)) {
		ret = PTR_ERR(tsk->aead_send);
		tsk->aead_send = NULL;
		goto bind_end;
	}

	write_lock_bh(&tsk->socket->sk->sk_callback_lock);
	tsk->rx_stopped = 0;
	tsk->saved_sk_data_ready = tsk->socket->sk->sk_data_ready;
	tsk->socket->sk->sk_data_ready = tls_data_ready;
	tsk->socket->sk->sk_user_data = tsk;
	write_unlock_bh(&tsk->socket->sk->sk_callback_lock);

	return 0;

bind_end:
	sockfd_put(tsk->socket);
	tsk->socket = NULL;
	return ret;
}

int tls_release(struct socket *sock)
{
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sock->sk);

	tls_free_sendpage_ctx(tsk);

	if (sock->sk)
		sock_put(sock->sk);

	return 0;
}

static const struct proto_ops tls_proto_ops = {
	.family		=	PF_KTLS,
	.owner		=	THIS_MODULE,

	.connect	=	sock_no_connect,
	.socketpair	=	sock_no_socketpair,
	.getname	=	sock_no_getname,
	.ioctl		=	sock_no_ioctl,
	.listen		=	sock_no_listen,
	.shutdown	=	sock_no_shutdown,
	.mmap		=	sock_no_mmap,
	.poll		=	sock_no_poll,
	.accept		=	sock_no_accept,

	.bind		=	tls_bind,
	.setsockopt	=	tls_setsockopt,
	.getsockopt	=	tls_getsockopt,
	.sendmsg	=	tls_sendmsg,
	.recvmsg	=	tls_recvmsg,
	.sendpage	=	tls_sendpage,
	.release	=	tls_release,
	.splice_read =	tls_splice_read,
};

static void tls_sock_destruct(struct sock *sk)
{
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	tsk = tls_sk(sk);

	// TODO: remove
	printk("tls: parallel executions: %u\n", tsk->parallel_count_stat);

	cancel_work_sync(&tsk->recv_work);

	// restore callback and abandon socket
	if (tsk->socket) {
		write_lock_bh(&tsk->socket->sk->sk_callback_lock);

		tsk->rx_stopped = 1;
		tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
		tsk->socket->sk->sk_user_data = NULL;
		write_unlock_bh(&tsk->socket->sk->sk_callback_lock);

		sockfd_put(tsk->socket);
		tsk->socket = NULL;
	}

	if (tsk->iv_send)
		kfree(tsk->iv_send);

	if (tsk->key_send.key)
		kfree(tsk->key_send.key);

	if (tsk->iv_recv)
		kfree(tsk->iv_recv);

	if (tsk->key_recv.key)
		kfree(tsk->key_recv.key);

	if (tsk->aead_send)
		crypto_free_aead(tsk->aead_send);

	if (tsk->aead_recv)
		crypto_free_aead(tsk->aead_recv);

	if (tsk->pages_send)
		__free_pages(tsk->pages_send, KTLS_DATA_PAGES);
	if (tsk->pages_recv)
		__free_pages(tsk->pages_recv, KTLS_DATA_PAGES);
	if (tsk->pages_work)
		__free_pages(tsk->pages_work, KTLS_DATA_PAGES);
}

static struct proto tls_proto = {
	.name				= "KTLS",
	.owner			= THIS_MODULE,
	.obj_size		= sizeof(struct tls_sock),
};

static int tls_create(struct net *net,
		struct socket *sock,
		int protocol,
		int kern)
{
	int ret;
	int i;
	struct sock *sk;
	struct tls_sock *tsk;

	xprintk("--> %s", __FUNCTION__);

	if (sock->type != SOCK_DGRAM && sock->type != SOCK_STREAM)
		return -ESOCKTNOSUPPORT;

	if ((protocol != 0) && (protocol ^ KTLS_PROTO_OPENCONNECT))
		return -EPROTONOSUPPORT;

	sk = sk_alloc(net, PF_KTLS, GFP_ATOMIC, &tls_proto, kern);
	if (!sk)
		return -ENOMEM;

	sock->ops = &tls_proto_ops;
	sock_init_data(sock, sk);

	sk->sk_family = PF_KTLS;
	sk->sk_destruct = tls_sock_destruct;

	// initialize stored context
	tsk = tls_sk(sk);

	tsk->tls = (sock->type == SOCK_STREAM);
	tsk->iv_send = NULL;
	memset(&tsk->key_send, 0, sizeof(tsk->key_send));

	tsk->socket = NULL;

	tsk->iv_recv = NULL;
	memset(&tsk->key_recv, 0, sizeof(tsk->key_recv));

	tsk->cipher_crypto = NULL;
	memset(tsk->version, 0, sizeof(tsk->version));

	/*
	 * Use maximum MTU by default
	 */
	tsk->mtu_payload = KTLS_MAX_PAYLOAD_SIZE;

	DTLS_WINDOW_INIT(tsk->dtls_window);

	sg_init_table(tsk->sendpage_ctx.sg, KTLS_SG_DATA_SIZE);
	sg_mark_end(&tsk->sendpage_ctx.sg[0]);

	mutex_init(&tsk->rx_lock);

	tsk->opts = protocol;

	tsk->pages_send = tsk->pages_recv = tsk->pages_work = NULL;

	ret = -ENOMEM;
	/*
	 * Preallocation for sending
	 *   scatterlist: AAD | data | TAG (for crypto API)
	 *   vec: HEADER | data | TAG
	 */
	sg_init_table(tsk->sg_tx_data, KTLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_tx_data[0], tsk->aad_send, sizeof(tsk->aad_send));
	tsk->pages_send = alloc_pages(GFP_KERNEL, KTLS_DATA_PAGES);
	if (!tsk->pages_send)
		goto create_error;
	for (i = 0; i < KTLS_DATA_PAGES; i++)
		// the first is HEADER
		sg_set_page(tsk->sg_tx_data + i + 1,
				tsk->pages_send + i,
				PAGE_SIZE, 0);
	sg_set_buf(tsk->sg_tx_data + KTLS_SG_DATA_SIZE - 2,
			tsk->tag_send, sizeof(tsk->tag_send));
	sg_mark_end(tsk->sg_tx_data + KTLS_SG_DATA_SIZE - 1);

	// msg for sending
	tsk->vec_send[0].iov_base = tsk->header_send;
	tsk->vec_send[0].iov_len = IS_TLS(tsk) ?
			KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	for (i = 1; i <= KTLS_DATA_PAGES + 1; i++) {
		tsk->vec_send[i].iov_base = page_address(sg_page(tsk->sg_tx_data + i)) + tsk->sg_tx_data[i].offset;
		tsk->vec_send[i].iov_len = tsk->sg_tx_data[i].length;
	}

	memset(&tsk->sgl_send, 0, sizeof(tsk->sgl_send));
	sg_init_table(tsk->sgaad_send, 2);
	sg_init_table(tsk->sgtag_send, 2);

	sg_set_buf(&tsk->sgaad_send[0], tsk->aad_send, sizeof(tsk->aad_send));
	// chaining to tag is performed on actual data size when sending
	sg_set_buf(&tsk->sgtag_send[0], tsk->tag_send, sizeof(tsk->tag_send));

	sg_unmark_end(&tsk->sgaad_send[1]);
	sg_chain(tsk->sgaad_send, 2, tsk->sgl_send.sg);

	/*
	 * Preallocation for receiving
	 *   scatterlist: AAD | data | TAG
	 *	 (for crypto AAD, aad and TAG are untouched)
	 *   vec: HEADER | data | TAG
	 *   async vec: HEADER| data | TAG
	 *
	 * for the async vec HEADER and TAG are reused, but chaining after async
	 * operation has to be restored
	 */
	sg_init_table(tsk->sg_rx_data, KTLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_rx_data[0], tsk->aad_recv, sizeof(tsk->aad_recv));
	tsk->pages_recv = alloc_pages(GFP_KERNEL, KTLS_DATA_PAGES);
	if (!tsk->pages_recv)
		goto create_error;
	for (i = 0; i < KTLS_DATA_PAGES; i++)
		// the first is HEADER
		sg_set_page(tsk->sg_rx_data + i + 1, tsk->pages_recv + i, PAGE_SIZE, 0);
	sg_set_buf(tsk->sg_rx_data + KTLS_SG_DATA_SIZE - 2,
			tsk->tag_recv, sizeof(tsk->tag_recv));
	sg_mark_end(tsk->sg_rx_data + KTLS_SG_DATA_SIZE - 1);

	// msg for receiving
	tsk->vec_recv[0].iov_base = tsk->header_recv;
	tsk->vec_recv[0].iov_len = IS_TLS(tsk) ?
			KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	for (i = 1; i <= KTLS_DATA_PAGES + 1; i++) {
		tsk->vec_recv[i].iov_base = page_address(sg_page(tsk->sg_rx_data + i)) + tsk->sg_rx_data[i].offset;
		tsk->vec_recv[i].iov_len = tsk->sg_rx_data[i].length;
	}

	memset(&tsk->sgl_recv, 0, sizeof(tsk->sgl_recv));
	sg_init_table(tsk->sgaad_recv, 2);
	sg_init_table(tsk->sgtag_recv, 2);

	sg_set_buf(&tsk->sgaad_recv[0], tsk->aad_recv, sizeof(tsk->aad_recv));
	// chaining to tag is performed on actual data size when receiving
	sg_set_buf(&tsk->sgtag_recv[0], tsk->tag_recv, sizeof(tsk->tag_recv));

	sg_unmark_end(&tsk->sgaad_recv[1]);
	sg_chain(tsk->sgaad_recv, 2, tsk->sgl_recv.sg);

	// preallocation for asynchronous worker, where decrypted data are stored
	sg_init_table(tsk->sg_rx_async_work, KTLS_SG_DATA_SIZE);
	sg_set_buf(&tsk->sg_rx_async_work[0], tsk->aad_recv, sizeof(tsk->aad_recv));
	tsk->pages_work = alloc_pages(GFP_KERNEL, KTLS_DATA_PAGES);
	for (i = 0; i < KTLS_DATA_PAGES; i++)
		// the first is HEADER
		sg_set_page(tsk->sg_rx_async_work + i + 1, tsk->pages_work + i, PAGE_SIZE, 0);
	sg_set_buf(tsk->sg_rx_async_work + KTLS_SG_DATA_SIZE - 2,
			tsk->tag_recv,
			sizeof(tsk->tag_recv));
	sg_mark_end(tsk->sg_rx_async_work + KTLS_SG_DATA_SIZE - 1);

	INIT_WORK(&tsk->recv_work, tls_rx_async_work);

	return 0;

create_error:
	tls_sock_destruct(sk);

	return ret;
}

static const struct net_proto_family tls_family = {
	.family	=	PF_KTLS,
	.create	=	tls_create,
	.owner	=	THIS_MODULE,
};

static int __init tls_init(void)
{
	int ret = -ENOMEM;
	xprintk("--> %s", __FUNCTION__);

	tls_wq = create_workqueue("ktls");
	if (!tls_wq)
		goto out;

	ret = proto_register(&tls_proto, 0);

	if (ret)
		goto out;

	ret = sock_register(&tls_family);
	if (ret != 0)
		goto out_unregister_proto;

out:
	return ret;

out_unregister_proto:
	proto_unregister(&tls_proto);
	if (tls_wq)
		destroy_workqueue(tls_wq);
	return 0;
}

static void __exit tls_exit(void)
{
	xprintk("--> %s", __FUNCTION__);
	sock_unregister(PF_KTLS);
	proto_unregister(&tls_proto);
	destroy_workqueue(tls_wq);
}

module_init(tls_init);
module_exit(tls_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fridolin Pokorny <fridolin.pokorny@gmail.com>");
MODULE_DESCRIPTION("TLS/DTLS kernel interface");

/* vim: set foldmethod=syntax ts=8 sts=8 sw=8 noexpandtab */

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
#include <net/tcp.h>
#include <linux/skbuff.h>

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
/* +1 for header, +1 for tag */
#define KTLS_VEC_SIZE			(KTLS_DATA_PAGES + 2)
/* +1 for aad, +1 for tag, +1 for chaining */
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

/* nonce explicit offset in a record */
#define KTLS_TLS_NONCE_OFFSET		KTLS_TLS_HEADER_SIZE

/*
 * DTLS related stuff
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

#define IS_TLS(T)			((T)->sk.sk_type == SOCK_STREAM)
#define IS_DTLS(T)			(!IS_TLS(T))

/*
 * Distinguish bound socket type
 */
#define IS_INET46(S)			((S)->sk->sk_family == AF_INET || \
						(S)->sk->sk_family == AF_INET6)
#define IS_TCP(S)			(IS_INET46(S) && \
						(S)->sk->sk_type == SOCK_STREAM)
#define IS_UDP(S)			(IS_INET46(S) && \
						(S)->sk->sk_type == SOCK_DGRAM)

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


/*#define KTLS_DEBUG */

#if 1 /* TODO: remove once ready to use */
	#ifdef KTLS_DEBUG
	# define xprintk(...)  (do_xprintk(__VA_ARGS__))
	# define print_hex(...) (do_print_hex(__VA_ARGS__))
	#else
	# define xprintk(...)  ((void) 0)
	# define print_hex(...) ((void) 0)
	#endif

	#define UNUSED(X)		((void) X)

	void do_xprintk(const char *fmt, ...)
	{
		va_list va;

		va_start(va, fmt);
		pr_debug("tls: ");
		vprintk(fmt, va);
		pr_debug("\n");
		va_end(va);
	}

	void do_print_hex(const unsigned char *key, unsigned int keysize)
	{
		int i = 0;

		pr_debug("kdls: hex: ");
		for (i = 0; i < keysize; i++)
			pr_debug("%02X", (unsigned char)key[i]);
		pr_debug("\n");
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

struct tls_rx_msg {
	int full_len;
	int accum_len;
	int offset;
	int early_eaten;
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
	struct af_alg_sgl sgl_send[UIO_MAXIOV];
	struct scatterlist sgaad_send[2];
	struct scatterlist sgtag_send[2];

	/* Receive */
	struct sk_buff *rx_skb_head;
	struct sk_buff **rx_skb_nextp;
	unsigned int rx_need_bytes;
	struct scatterlist sgin[ALG_MAX_PAGES+1];
	char aad_recv[KTLS_AAD_SPACE_SIZE];
	char header_recv[MAX(KTLS_TLS_PREPEND_SIZE, KTLS_DTLS_PREPEND_SIZE)];

	/*
	 * Asynchronous work in case of low memory
	 */
	struct work_struct recv_work;
	void (*saved_sk_data_ready)(struct sock *sk);

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
	 * store mtu for raw payload -- without header, tag, (and seq num
	 * when DTLS)
	 */
	size_t mtu_payload;

	/*
	 * DTLS window handling, see DTLS_WINDOW_* macros
	 */
	struct {
		uint64_t bits;
		/* The starting point of the sliding window without epoch */
		uint64_t start;
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

	/* TODO: remove once finished benchmarking */
	unsigned parallel_count_stat;
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

static int tls_do_decryption(const struct tls_sock *tsk,
		struct scatterlist *sgin,
		struct scatterlist *sgout,
		size_t data_len);

static inline void tls_make_aad(struct tls_sock *tsk,
		int recv,
		char *buf,
		size_t size,
		char *nonce_explicit);

static int tls_post_process(const struct tls_sock *tsk, struct sk_buff *skb);

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

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

	sg = tsk->sendpage_ctx.sg;

	BUG_ON(size > tsk->sendpage_ctx.current_size);

	if (size == tsk->sendpage_ctx.current_size) {
		tls_free_sendpage_ctx(tsk);
		return;
	}

	walked_size = 0;
	sg_start = sg;
	put_count = 0;
	while (put_count < tsk->sendpage_ctx.used &&
			walked_size + sg_start->length <= size) {
		walked_size += sg_start->length;
		put_page(sg_page(sg_start));
		sg_start++;
		put_count++;
	}

	/* adjust length and offset so we can send with right offset next
	 * time
	 */
	sg_start->offset += (size - walked_size);
	sg_start->length -= (size - walked_size);
	tsk->sendpage_ctx.current_size -= size;
	tsk->sendpage_ctx.used -= put_count;

	/*
	 * we will shift freed pages so chaining from AAD is correct and we
	 * can use whole scatterlist next time
	 */
	memmove(sg, sg_start,
		(KTLS_SG_DATA_SIZE - 1 - put_count)*sizeof(
				tsk->sendpage_ctx.sg[0]));
	sg_mark_end(&sg[tsk->sendpage_ctx.used]);
}

/*Must be called with socket callback locked */
static void tls_unattach(struct tls_sock *tsk)
{
	tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
	tsk->socket->sk->sk_user_data = NULL;
}

static void tls_err_abort(struct tls_sock *tsk)
{
	struct sock *sk;

	sk = (struct sock *)tsk;
	tsk->rx_stopped = 1;
	sk->sk_err = -EBADMSG;
	sk->sk_error_report(sk);
	tsk->saved_sk_data_ready(tsk->socket->sk);
	tls_unattach(tsk);
}

static int decrypt_skb(struct tls_sock *tsk, struct sk_buff *skb)
{
	int ret, nsg;
	size_t prepend, overhead;
	struct tls_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	overhead = IS_TLS(tsk) ? KTLS_TLS_OVERHEAD : KTLS_DTLS_OVERHEAD;
	rxm = tls_rx_msg(skb);


	sg_init_table(tsk->sgin, ARRAY_SIZE(tsk->sgin));
	sg_set_buf(&tsk->sgin[0], tsk->aad_recv, sizeof(tsk->aad_recv));

	/*
	 * TODO: So what exactly happens if skb_to_sgvec causes more
	 * than ALG_MAX_PAGES fragments? Consider allocating kernel
	 * pages
	 * tls_read_size already copied headers and aad. Therefore
	 * this simply needs to pass the encrypted data + message
	 */
	nsg = skb_to_sgvec(skb, &tsk->sgin[1], rxm->offset +
			prepend,
			rxm->full_len - prepend);

	/*
	 * The length of sg into decryption must not be over
	 * ALG_MAX_PAGES. The aad takes the first sg, so the
	 * payload must be less than ALG_MAX_PAGES - 1
	 */
	if (nsg > ALG_MAX_PAGES - 1) {
		ret = -EBADMSG;
		goto decryption_fail;
	}

	tls_make_aad(tsk, 1, tsk->aad_recv,
			rxm->full_len - overhead,
			tsk->iv_recv);

	/*
	 * Decrypt in place.
	 * After this function call, the decrypted data will be in
	 * rxm->offset. We must therefore account for the fact that
	 * the lengths of skbuff_in and skbuff_out are different
	 */

	ret = tls_do_decryption(tsk,
			tsk->sgin,
			tsk->sgin,
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
/*
 * Returns the length of the unencrypted message, plus overhead
 * Note that this function also populates tsk->header which is later
 * used for decryption
 * TODO: Revisit
 * In TLS we automatically bail if we see a non-TLS message. In DTLS
 * we should determine if we got a corrupted message vs a control msg
 * Right now if the TLS magic bit got corrupted it would incorrectly
 * misinterpret it as a non-TLS message
 * Returns 0 if more data is necessary to determine length
 * Returns <0 if error occured
 */
static inline ssize_t tls_read_size(struct tls_sock *tsk, struct sk_buff *skb)
{
	int ret;
	size_t data_len = 0;
	size_t datagram_len;
	size_t prepend;
	char first_byte;
	char *header;
	struct tls_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	header = tsk->header_recv;
	xprintk("--> %s", __func__);

	rxm = tls_rx_msg(skb);

	ret = skb_copy_bits(skb, rxm->offset, &first_byte, 1);
	if (ret < 0)
		goto read_failure;

	/*Check the first byte to see if its a TLS record */
	if (first_byte != KTLS_RECORD_DATA) {
		ret = -EBADMSG;
		goto read_failure;
	}

	/*
	 *We have a TLS record. Check that msglen is long enough to read
	 *the length of record.
	 *We must not check this before checking the first byte, since
	 *that will cause unencrypted
	 *messages shorter than KTLS_TLS_PREPEND_SIZE to not be read
	 */
	if (rxm->offset + prepend > skb->len) {
		ret = 0;
		goto read_failure;
	}

	/*
	 *Copy header to use later in decryption.
	 *An optimization could be to zero-copy, but you'd
	 *have to be able to deal with frag_list bs. This function call
	 *takes care of that
	 *Overhead is relatively small (13 bytes for TLS, 21 for DTLS)
	 */
	ret = skb_copy_bits(skb, rxm->offset, tsk->header_recv,
			prepend);

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
	return ret;
}

/* Lower socket lock held */
/* Returns the number of bytes used */
/* A lot of this code was copy/pasta from KCM code. Consider abstracting this */
static int tls_tcp_recv(read_descriptor_t *desc, struct sk_buff *orig_skb,
			unsigned int orig_offset, size_t orig_len)
{
	struct tls_sock *tsk = (struct tls_sock *)desc->arg.data;
	struct sock *sk = (struct sock *)tsk;
	struct tls_rx_msg *rxm;
	struct sk_buff *head, *skb;
	size_t eaten = 0, uneaten;
	ssize_t extra;
	int err;
	bool cloned_orig = false;

	head = tsk->rx_skb_head;
	if (head) {
		/* We seem to be in the middle of a message */

		rxm = tls_rx_msg(head);

		if (unlikely(rxm->early_eaten)) {
			/* Already some number of bytes on the receive sock
			 * data saved in rx_skb_head, just indicate they
			 * are consumed.
			 */
			eaten = orig_len <= rxm->early_eaten ?
				orig_len : rxm->early_eaten;
			rxm->early_eaten -= eaten;

			return eaten;
		}

		if (unlikely(orig_offset)) {
			/* Getting data with a non-zero offset when a message is
			 * in progress is not expected. If it does happen, we
			 * need to clone and pull since we can't deal with
			 * offsets in the skbs for a message expect in the head.
			 */
			orig_skb = skb_clone(orig_skb, GFP_ATOMIC);
			if (!orig_skb) {
				desc->error = -ENOMEM;
				return 0;
			}
			if (!pskb_pull(orig_skb, orig_offset)) {
				kfree_skb(orig_skb);
				desc->error = -ENOMEM;
				return 0;
			}
			cloned_orig = true;
			orig_offset = 0;
		}

		/*We are appending to head. Unshare the frag list */
		if (!tsk->rx_skb_nextp) {
			err = skb_unclone(head, GFP_ATOMIC);
			if (err) {
				desc->error = err;
				return 0;
			}

			if (unlikely(skb_shinfo(head)->frag_list)) {
				/* We can't append to an sk_buff that already
				 * has a frag_list. We create a new head, point
				 * the frag_list of that to the old head, and
				 * then are able to use the old head->next for
				 * appending to the message.
				 */
				if (WARN_ON(head->next)) {
					desc->error = -EINVAL;
					return 0;
				}

				skb = alloc_skb(0, GFP_ATOMIC);
				if (!skb) {
					desc->error = -ENOMEM;
					return 0;
				}
				skb->len = head->len;
				skb->data_len = head->len;
				skb->truesize = head->truesize;
				*tls_rx_msg(skb) = *tls_rx_msg(head);
				tsk->rx_skb_nextp = &head->next;
				skb_shinfo(skb)->frag_list = head;
				tsk->rx_skb_head = skb;
				head = skb;
			} else {
				tsk->rx_skb_nextp =
				    &skb_shinfo(head)->frag_list;
			}
		}
	}

	while (eaten < orig_len) {
		int ret;
		/* Always clone since we will consume something */
		skb = skb_clone(orig_skb, GFP_ATOMIC);
		if (!skb) {
			desc->error = -ENOMEM;
			break;
		}

		uneaten = orig_len - eaten;

		head = tsk->rx_skb_head;
		/*head is null */
		if (!head) {
			head = skb;
			tsk->rx_skb_head = head;
			/* Will set rx_skb_nextp on next packet if needed */
			tsk->rx_skb_nextp = NULL;
			rxm = tls_rx_msg(head);
			memset(rxm, 0, sizeof(*rxm));
			rxm->offset = orig_offset + eaten;
		} else {
			/*head not null */

			rxm = tls_rx_msg(head);
			*tsk->rx_skb_nextp = skb;
			tsk->rx_skb_nextp = &skb->next;
			head->data_len += skb->len;
			head->len += skb->len;
			head->truesize += skb->truesize;
		}

		if (!rxm->full_len) {
			ssize_t len;

			len = tls_read_size(tsk, head);

			/*Is this a sane packet? */
			if (!len) {
				/* Need more header to determine length */

				rxm->accum_len += uneaten;
				eaten += uneaten;
				WARN_ON(eaten != orig_len);
				break;
			} else if (len < 0) {
				/* Data does not appear to be a TLS record
				 * Make userspace handle it
				 */
				goto decryption_fail;
			} else if (len <= (ssize_t)head->len -
					  skb->len - rxm->offset) {
				/* Length must be into new skb (and also
				 * greater than zero)
				 */
				goto decryption_fail;
			}

			rxm->full_len = len;
		}

		extra = (ssize_t)(rxm->accum_len + uneaten) - rxm->full_len;

		if (extra < 0) {
			/* Message not complete yet. */
			if (rxm->full_len - rxm->accum_len >
			    tcp_inq((struct sock *)tsk)) {
				/* Don't have the whole messages in the socket
				 * buffer. Set tsk->rx_need_bytes to wait for
				 * the rest of the message. Also, set "early
				 * eaten" since we've already buffered the skb
				 * but don't consume yet per tcp_read_sock.
				 * If function returns 0, does not consume
				 */

				/* Wait. Why doesn't this code path just set
				 * eaten? Then tcp_read_sock will eat and
				 * profit!
				 */
				if (!rxm->accum_len) {
					/* Start RX timer for new message */
					/*kcm_start_rx_timer(tsk); */
				}

				tsk->rx_need_bytes = rxm->full_len -
						       rxm->accum_len;
				rxm->accum_len += uneaten;
				rxm->early_eaten = uneaten;
				desc->count = 0; /* Stop reading socket */
				break;
			}
			rxm->accum_len += uneaten;
			eaten += uneaten;
			WARN_ON(eaten != orig_len);
			break;
		}

		/* Positive extra indicates ore bytes than needed for the
		 * message
		 */

		WARN_ON(extra > uneaten);

		ret = decrypt_skb(tsk, head);
		if (ret < 0)
			goto decryption_fail;

		/* Hurray, we have a new message! */
		tsk->rx_skb_head = NULL;
		eaten += (uneaten - extra);

		sock_queue_rcv_skb(sk, head);
	}
done:
	if (cloned_orig)
		kfree_skb(orig_skb);
	return eaten;
decryption_fail:
	kfree_skb(skb);
	desc->error = -EBADMSG;
	tsk->rx_skb_head = NULL;
	desc->count = 0;
	goto done;
}

static int tls_tcp_read_sock(struct tls_sock *tsk)
{
	read_descriptor_t desc;

	desc.arg.data = tsk;
	desc.error = 0;
	desc.count = 1; /* give more than one skb per call */

	/* sk should be locked here, so okay to do tcp_read_sock */
	tcp_read_sock(tsk->socket->sk, &desc, tls_tcp_recv);

	return desc.error;
}

static void do_tls_data_ready(struct tls_sock *tsk)
{
	int ret;

	if (tsk->rx_need_bytes) {
		if (tcp_inq(tsk->socket->sk) >= tsk->rx_need_bytes)
			tsk->rx_need_bytes = 0;
		else
			return;
	}

	ret = tls_tcp_read_sock(tsk);
	if (ret == -ENOMEM) /* No memory. Do it later */
		queue_work(tls_wq, &tsk->recv_work);
	/*queue_delayed_work(tls_wq, &tsk->recv_work, 0); */

	/* TLS couldn't handle this message. Pass it directly to userspace */
	else if (ret == -EBADMSG)
		tls_err_abort(tsk);

}

/* Called with lower socket held */
static void tls_data_ready(struct sock *sk)
{
	struct tls_sock *tsk;

	xprintk("--> %s", __func__);

	read_lock_bh(&sk->sk_callback_lock);
	//TODO: forgot to lock tsk?
	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->rx_stopped))
		goto out;

	if (!KTLS_RECV_READY(tsk)) {
		queue_work(tls_wq, &tsk->recv_work);
		goto out;
	}

	do_tls_data_ready(tsk);

out:
	read_unlock_bh(&sk->sk_callback_lock);
}

#include "dtls-window.c"

//Loop through the SKBs. Decrypt each one and, if valid, add it to recv queue
static int dtls_udp_read_sock(struct tls_sock *tsk)
{
	struct sk_buff *p, *next, *skb;
	int ret = 0;

	skb_queue_walk_safe(&tsk->socket->sk->sk_receive_queue, p, next) {

		ssize_t len;
		struct tls_rx_msg *rxm;

		rxm = tls_rx_msg(p);
		memset(rxm, 0, sizeof(*rxm));

		/* For UDP, set the offset such that the headers are ignored.
		 * Full_len is length of skb minus the headers
		 */
		rxm->full_len = p->len - sizeof(struct udphdr);
		rxm->offset = sizeof(struct udphdr);
		len = tls_read_size(tsk, p);

		/*Is this a sane packet? */
		WARN_ON(!len);
		if (!len)
			goto record_pop;
		if (len < 0) {
			if (len == -EBADMSG) {
				/* Data does not appear to be a TLS record
				 * Make userspace handle it
				 * TODO: Of course, we are using DTLS therefore
				 * it may be that the headers were corrupted
				 *
				 */
				ret = -EBADMSG;
				break;
			}
			/* Failed for some other reason. Drop the packet */
			goto record_pop;
		}
		if (dtls_window(tsk, tsk->header_recv + KTLS_DTLS_SEQ_NUM_OFFSET) < 0)
			goto record_pop;

		skb = skb_clone(p, GFP_ATOMIC);
		if (!skb) {
			ret = -ENOMEM;
			break;
		}
		ret = decrypt_skb(tsk, skb);

		if (ret < 0)
			goto decryption_fail;

		sock_queue_rcv_skb((struct sock *)tsk, skb);
		goto record_pop;
decryption_fail:
		kfree_skb(skb);
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
		queue_work(tls_wq, &tsk->recv_work);
	/*queue_delayed_work(tls_wq, &tsk->recv_work, 0); */
	/* TLS couldn't handle this message. Pass it directly to userspace */
	else if (ret == -EBADMSG)
		tls_err_abort(tsk);
}
/* Called with lower socket held */
static void dtls_data_ready(struct sock *sk)
{
	struct tls_sock *tsk;
	xprintk("--> %s", __func__);

	read_lock_bh(&sk->sk_callback_lock);

	tsk = (struct tls_sock *)sk->sk_user_data;
	if (unlikely(!tsk || tsk->rx_stopped))
		goto out;

	if (!KTLS_RECV_READY(tsk)) {
		queue_work(tls_wq, &tsk->recv_work);
		goto out;
	}

	do_dtls_data_ready(tsk);
out:
	read_unlock_bh(&sk->sk_callback_lock);
}

static void do_tls_sock_rx_work(struct tls_sock *tsk)
{
	struct sock *sk = tsk->socket->sk;

	/* We need the read lock to synchronize with tls_sock_tcp_data_ready.
	 * We need the socket lock for calling tcp_read_sock.
	 */
	lock_sock(sk);
	read_lock_bh(&sk->sk_callback_lock);

	if (unlikely(sk->sk_user_data != tsk))
		goto out;

	if (unlikely(tsk->rx_stopped))
		goto out;

	if (!KTLS_RECV_READY(tsk)) {
		queue_work(tls_wq, &tsk->recv_work);
		goto out;
	}

	if (IS_TLS(tsk))
		do_tls_data_ready(tsk);
	else
		do_dtls_data_ready(tsk);

out:
	read_unlock_bh(&sk->sk_callback_lock);
	release_sock(sk);
}

static void tls_rx_work(struct work_struct *w)
{
	do_tls_sock_rx_work(container_of(w, struct tls_sock, recv_work));
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

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

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

/*TODO: No lock? */
static int tls_set_key(struct socket *sock,
		int recv,
		char __user *src,
		size_t src_len)
{
	int ret;
	struct tls_sock *tsk;
	struct tls_key *k;

	xprintk("--> %s", __func__);

	tsk = tls_sk(sock->sk);

	if (src_len == 0 || src == NULL)
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

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

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

static void tls_do_unattach(struct socket *sock)
{
	struct tls_sock *tsk;
	struct sock *sk;

	tsk = tls_sk(sock->sk);
	sk = tsk->socket->sk;

	read_lock_bh(&sk->sk_callback_lock);
	tls_err_abort(tsk);
	read_unlock_bh(&sk->sk_callback_lock);
}
static int tls_setsockopt(struct socket *sock,
		int level, int optname,
		char __user *optval,
		unsigned int optlen)
{
	int ret;
	struct tls_sock *tsk;

	xprintk("--> %s", __func__);

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
	case KTLS_UNATTACH:
		tls_do_unattach(sock);
		ret = 0;
		break;
	default:
		break;
	}
	return ret < 0 ? ret : 0;
}

static int tls_get_iv(const struct tls_sock *tsk,
		int recv,
		char __user *dst,
		size_t dst_len)
{
	int ret;
	char *iv;

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

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

	xprintk("--> %s", __func__);

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
	xprintk("--> %s", __func__);

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
	char aead_req_data[sizeof(struct aead_request) +
			   crypto_aead_reqsize(tsk->aead_send)]
		__aligned(__alignof__(struct aead_request));
	struct aead_request *aead_req = (void *)aead_req_data;
	struct af_alg_completion completion;

	xprintk("--> %s", __func__);

	aead_request_set_tfm(aead_req, tsk->aead_send);
	aead_request_set_ad(aead_req, KTLS_PADDED_AAD_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout, data_len, tsk->iv_send);

	return af_alg_wait_for_completion(
			crypto_aead_encrypt(aead_req),
			&completion);
}

/*TODO: Avoid kernel_sendmsg */
static int tls_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct tls_sock *tsk;
	unsigned int i;
	unsigned int cnt = 0;
	int ret = 0;

	xprintk("--> %s", __func__);

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

	/* TODO: handle flags, see issue #4 */

	tls_make_aad(tsk, 0, tsk->aad_send, size, tsk->iv_send);

	while (iov_iter_count(&msg->msg_iter)) {
		size_t seglen = iov_iter_count(&msg->msg_iter);
		int len = af_alg_make_sg(&tsk->sgl_send[cnt],
				&msg->msg_iter, seglen);
		if (len < 0)
			goto send_end;
		ret += len;
		if (cnt)
			af_alg_link_sg(&tsk->sgl_send[cnt-1],
					&tsk->sgl_send[cnt]);
		iov_iter_advance(&msg->msg_iter, len);
		cnt++;
	}
	sg_unmark_end(&tsk->sgaad_send[1]);
	sg_chain(tsk->sgaad_send, 2, tsk->sgl_send[0].sg);

	sg_unmark_end(tsk->sgl_send[cnt-1].sg +
			tsk->sgl_send[cnt-1].npages - 1);
	sg_chain(tsk->sgl_send[cnt-1].sg, tsk->sgl_send[cnt-1].npages + 1,
			tsk->sgtag_send);

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
	for (i = 0; i < cnt; i++)
		af_alg_free_sg(&tsk->sgl_send[i]);
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

	xprintk("--> %s", __func__);

	aead_request_set_tfm(aead_req, tsk->aead_recv);
	aead_request_set_ad(aead_req, KTLS_PADDED_AAD_SIZE);
	aead_request_set_crypt(aead_req, sgin, sgout,
			data_len + KTLS_TAG_SIZE,
			       (u8 *)tsk->header_recv + KTLS_NONCE_OFFSET(tsk));

	ret = af_alg_wait_for_completion(
			crypto_aead_decrypt(aead_req),
			&completion);

	return ret;
}

static int tls_post_process(const struct tls_sock *tsk, struct sk_buff *skb)
{
	size_t prepend, overhead;
	struct tls_rx_msg *rxm;

	prepend = IS_TLS(tsk) ? KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	overhead = IS_TLS(tsk) ? KTLS_TLS_OVERHEAD : KTLS_DTLS_OVERHEAD;
	rxm = tls_rx_msg(skb);

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
	increment_seqno(tsk->iv_recv);
	return 0;
}

static unsigned int tls_poll(struct file *file, struct socket *sock,
		struct poll_table_struct *wait) {

	unsigned int ret;
	struct tls_sock *tsk;
	unsigned int mask;
	struct sock *sk;

	sk = sock->sk;
	tsk = tls_sk(sock->sk);

	/*
	 *Call POLL on the underlying socket, which will call sock_poll_wait
	 *on underlying socket. Used for POLLOUT and POLLHUP
	 *TODO: Should we be passing underlying socket file in?
	 */
	ret = tsk->socket->ops->poll(tsk->socket->file, tsk->socket, wait);

	/*
	 * Clear POLLIN bits. Data available in the underlying socket is not
	 * necessarily ready to be read. The data could still be in the process
	 * of decryption, or it could be meant for original fd.
	 */
	ret &= ~(POLLIN | POLLRDNORM);

	/*
	 * Used for POLLIN
	 * Call generic POLL on TLS socket, which works for any sockets provided
	 * the socket receive queue is only ever holding data ready to receive.
	 * Data ready to be read are stored in KTLS's sk_receive_queue
	 */
	mask = datagram_poll(file, sock, wait);

	/*
	 * Clear POLLOUT and POLLHUPbits. Even if KTLS is ready to send, data
	 * won't be sent if the underlying socket is not ready. in addition,
	 * even if KTLS was initialized as a stream socket, it's not actually
	 * connected to anything, so we ignore its POLLHUP.
	 * Also, we don't support priority band writes in KTLS
	 */
	mask &= ~(POLLOUT | POLLWRNORM | POLLHUP);

	ret |= mask;

	/*
	 * POLLERR should return if either socket is received error.
	 * We don't support high-priority data atm, so clear those bits
	 */
	ret &= ~(POLLWRBAND | POLLRDBAND);
	return ret;
}

static struct sk_buff *tls_wait_data(struct tls_sock *tsk, int flags,
				     long timeo, int *err)
{
	struct sk_buff *skb;
	struct sock *sk;

	sk = (struct sock *)tsk;

	while (!(skb = skb_peek(&sk->sk_receive_queue))) {
		/* Don't clear sk_err since recvmsg may not return
		 * it immediately. Instead, clear it after the next
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
	struct tls_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	xprintk("--> %s", __func__);

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!KTLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto recv_end;
	}

	timeo = sock_rcvtimeo(&tsk->sk, flags & MSG_DONTWAIT);

	do {
		int chunk;
		/*TODO: Consider helping with decryption */
		skb = tls_wait_data(tsk, flags, timeo, &err);
		if (!skb)
			goto recv_end;
		rxm = tls_rx_msg(skb);
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
	struct tls_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;

	xprintk("--> %s", __func__);

	tsk = tls_sk(sock->sk);
	lock_sock(sock->sk);

	if (!KTLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto recv_end;
	}

	skb = skb_recv_datagram((struct sock *)tsk, flags & ~MSG_DONTWAIT,
			flags & MSG_DONTWAIT, &err);
	if (!skb)
		goto recv_end;
	rxm = tls_rx_msg(skb);
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
	ret = copied? : err;
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
	struct tls_rx_msg *rxm;
	int ret = 0;
	struct sk_buff *skb;
	int chunk;
	int err = 0;
	struct sock *sk = sock->sk;

	xprintk("--> %s", __func__);

	tsk = tls_sk(sk);
	lock_sock(sk);

	if (!KTLS_RECV_READY(tsk)) {
		err = -EBADMSG;
		goto splice_read_end;
	}

	timeo = sock_rcvtimeo(&tsk->sk, flags & MSG_DONTWAIT);

	skb = tls_wait_data(tsk, flags, timeo, &err);
	if (!skb)
		goto splice_read_end;

	rxm = tls_rx_msg(skb);
	chunk = min_t(unsigned int, rxm->full_len, len);
	copied = skb_splice_bits(skb, sk, rxm->offset, pipe, chunk,
			flags, tls_sock_splice);
	if (ret < 0)
		goto splice_read_end;

	rxm->offset += copied;
	rxm->full_len -= copied;

splice_read_end:
	release_sock(sk);
	ret = (copied)?copied:err;
	return ret;
}

static ssize_t tls_do_sendpage(struct tls_sock *tsk)
{
	int ret;
	size_t data_len;
	struct msghdr msg = {};

	xprintk("--> %s", __func__);

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
	/* restore, so we can use sendmsg() */
	sg_chain(tsk->sgaad_send, 2, tsk->sgl_send[0].sg);
	/* remove chaining to sg tag */
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

	xprintk("--> %s", __func__);

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

	/* TODO: handle flags, see issue #4 */

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

/*TODO: When binding, blow away all skbs from underlying socket */
static int tls_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	int ret;
	struct tls_sock *tsk;
	struct sockaddr_ktls *sa_ktls;

	xprintk("--> %s", __func__);

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

	tsk->socket = sockfd_lookup(sa_ktls->sa_socket, &ret);
	if (tsk->socket == NULL)
		return -ENOENT;

	if (!IS_TCP(tsk->socket) && !IS_UDP(tsk->socket)) {
		ret = -EAFNOSUPPORT;
		goto bind_end;
	}

	/*
	 * Do not allow TLS over unreliable UDP
	 */
	if (IS_TLS(tsk) && IS_UDP(tsk->socket)) {
		ret = -EBADF;
		goto bind_end;
	}

	xprintk("--1");
	if (!tsk->aead_recv) {
		tsk->aead_recv = crypto_alloc_aead(tsk->cipher_crypto,
				CRYPTO_ALG_INTERNAL, 0);
		xprintk("--1");
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

	write_lock_bh(&tsk->socket->sk->sk_callback_lock);
	tsk->rx_stopped = 0;
	tsk->saved_sk_data_ready = tsk->socket->sk->sk_data_ready;
	if (IS_TLS(tsk))
		tsk->socket->sk->sk_data_ready = tls_data_ready;
	else
		tsk->socket->sk->sk_data_ready = dtls_data_ready;
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

	xprintk("--> %s", __func__);

	tsk = tls_sk(sock->sk);

	tls_free_sendpage_ctx(tsk);

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

	xprintk("--> %s", __func__);

	tsk = tls_sk(sk);

	/* TODO: remove */
	pr_debug("tls: parallel executions: %u\n", tsk->parallel_count_stat);

	cancel_work_sync(&tsk->recv_work);

	/* restore callback and abandon socket */
	if (tsk->socket) {
		write_lock_bh(&tsk->socket->sk->sk_callback_lock);

		tsk->rx_stopped = 1;
		tsk->socket->sk->sk_data_ready = tsk->saved_sk_data_ready;
		tsk->socket->sk->sk_user_data = NULL;
		write_unlock_bh(&tsk->socket->sk->sk_callback_lock);

		sockfd_put(tsk->socket);
		tsk->socket = NULL;
	}

	/* kfree(NULL) is safe */
	kfree(tsk->iv_send);

	kfree(tsk->key_send.key);

	kfree(tsk->iv_recv);

	kfree(tsk->key_recv.key);

	crypto_free_aead(tsk->aead_send);

	crypto_free_aead(tsk->aead_recv);

	if (tsk->pages_send)
		__free_pages(tsk->pages_send, KTLS_DATA_PAGES);
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

	xprintk("--> %s", __func__);

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

	/*
	 * Use maximum MTU by default
	 */
	tsk->mtu_payload = KTLS_MAX_PAYLOAD_SIZE;

	sg_init_table(tsk->sendpage_ctx.sg, KTLS_SG_DATA_SIZE);
	sg_mark_end(&tsk->sendpage_ctx.sg[0]);

	tsk->pages_send = NULL;

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
		/* the first is HEADER */
		sg_set_page(tsk->sg_tx_data + i + 1,
				tsk->pages_send + i,
				PAGE_SIZE, 0);
	sg_set_buf(tsk->sg_tx_data + KTLS_SG_DATA_SIZE - 2,
			tsk->tag_send, sizeof(tsk->tag_send));
	sg_mark_end(tsk->sg_tx_data + KTLS_SG_DATA_SIZE - 1);

	/* msg for sending */
	tsk->vec_send[0].iov_base = tsk->header_send;
	tsk->vec_send[0].iov_len = IS_TLS(tsk) ?
			KTLS_TLS_PREPEND_SIZE : KTLS_DTLS_PREPEND_SIZE;
	for (i = 1; i <= KTLS_DATA_PAGES + 1; i++) {
		tsk->vec_send[i].iov_base = page_address(sg_page
				(tsk->sg_tx_data + i)) + tsk->
				sg_tx_data[i].offset;
		tsk->vec_send[i].iov_len = tsk->sg_tx_data[i].length;
	}

	for (i = 0; i < UIO_MAXIOV; i++)
		memset(&tsk->sgl_send[i], 0, sizeof(tsk->sgl_send[i]));
	sg_init_table(tsk->sgaad_send, 2);
	sg_init_table(tsk->sgtag_send, 2);

	sg_set_buf(&tsk->sgaad_send[0], tsk->aad_send, sizeof(tsk->aad_send));
	/* chaining to tag is performed on actual data size when sending */
	sg_set_buf(&tsk->sgtag_send[0], tsk->tag_send, sizeof(tsk->tag_send));

	sg_unmark_end(&tsk->sgaad_send[1]);
	sg_chain(tsk->sgaad_send, 2, tsk->sgl_send[0].sg);
	INIT_WORK(&tsk->recv_work, tls_rx_work);

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

	xprintk("--> %s", __func__);

	tls_wq = create_workqueue("ktls");
	if (!tls_wq)
		goto tls_init_end;

	ret = proto_register(&tls_proto, 0);
	if (ret) {
		destroy_workqueue(tls_wq);
		goto tls_init_end;
	}

	ret = sock_register(&tls_family);
	if (ret != 0) {
		proto_unregister(&tls_proto);
		destroy_workqueue(tls_wq);
		goto tls_init_end;
	}

tls_init_end:
	return ret;
}

static void __exit tls_exit(void)
{
	xprintk("--> %s", __func__);
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

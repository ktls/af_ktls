/*
 * DTLS sliding window handling
 */
#define DTLS_EPOCH_SHIFT		(6*CHAR_BIT)
#define DTLS_SEQ_NUM_MASK		0x0000FFFFFFFFFFFF

#define DTLS_WINDOW_INIT(W)		((W).bits = (W.start) = 0)

#define DTLS_SAME_EPOCH(S1, S2)		(((S1) >> DTLS_EPOCH_SHIFT) == ((S2) >> DTLS_EPOCH_SHIFT))

#define DTLS_WINDOW_INSIDE(W, S)	((((S) & DTLS_SEQ_NUM_MASK) > (W).start) && \
						(((S)  & DTLS_SEQ_NUM_MASK) - (W).start <= (sizeof((W).bits) * CHAR_BIT)))

#define DTLS_WINDOW_OFFSET(W, S)	((((S) & DTLS_SEQ_NUM_MASK) - (W).start) - 1)

#define DTLS_WINDOW_RECEIVED(W, S)	(((W).bits & ((u64) 1 << DTLS_WINDOW_OFFSET(W, S))) != 0)

#define DTLS_WINDOW_MARK(W, S)		((W).bits |= ((u64) 1 << DTLS_WINDOW_OFFSET(W, S)))

#define DTLS_WINDOW_UPDATE(W)		while ((W).bits & (u64) 1) { \
						(W).bits = (W).bits >> 1; \
						(W).start++; \
					}
/*
 * Handle DTLS sliding window
 * rv: rv < 0  drop packet
 *     rv == 0 OK
 */
static int dtls_window(struct tls_sock *tsk, const char * sn)
{
	uint64_t *seq_num_ptr, *seq_num_last_ptr;
	uint64_t seq_num, seq_num_last;

	seq_num_ptr = (uint64_t *) sn;
	seq_num_last_ptr = (uint64_t *) tsk->iv_recv;
	
	seq_num = be64_to_cpu(*seq_num_ptr);
	seq_num_last = be64_to_cpu(*seq_num_last_ptr);

	if (!DTLS_SAME_EPOCH(seq_num_last, seq_num))
		return -1;

	/* are we inside sliding window? */
	if (!DTLS_WINDOW_INSIDE(tsk->dtls_window, seq_num))
		return -2;

	/* already received? */
	if (DTLS_WINDOW_RECEIVED(tsk->dtls_window, seq_num))
		return -3;

	DTLS_WINDOW_MARK(tsk->dtls_window, seq_num);
	DTLS_WINDOW_UPDATE(tsk->dtls_window);

	return 0;
}

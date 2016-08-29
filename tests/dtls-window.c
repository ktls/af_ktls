#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#define LARGE_INT 4194304
#define INT_OVER_32_BITS 281474976708836LL

#define u64 __u64
#define be64_to_cpu __be64_to_cpu
#define cpu_to_be64 __cpu_to_be64

struct tls_sock {
	char iv_recv[32];
	struct {
		uint64_t bits;
		uint64_t start;
	} dtls_window;
};

#include "../dtls-window.c"

#define RESET_WINDOW \
	memset(&state, 0, sizeof(state))

#define SET_WINDOW_START(x) \
	state.dtls_window.start = (x&DTLS_SEQ_NUM_MASK)

#define SET_WINDOW_LAST_RECV(x) \
	t = cpu_to_be64(x); \
	memcpy(&state.iv_recv[0], &t, 8)

static void check_dtls_window_12(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(0);
	SET_WINDOW_LAST_RECV(1);

	t = cpu_to_be64(2);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_19(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(0);
	SET_WINDOW_LAST_RECV(1);

	t = cpu_to_be64(9);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_21(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(0);
	SET_WINDOW_LAST_RECV(2);

	t = cpu_to_be64(1);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_91(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(0);
	SET_WINDOW_LAST_RECV(9);

	t = cpu_to_be64(1);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_large_21(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT);
	SET_WINDOW_LAST_RECV(LARGE_INT+2);

	t = cpu_to_be64(LARGE_INT+1);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_large_12(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT);
	SET_WINDOW_LAST_RECV(LARGE_INT+1);

	t = cpu_to_be64(LARGE_INT+2);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_large_91(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT);
	SET_WINDOW_LAST_RECV(LARGE_INT+9);

	t = cpu_to_be64(LARGE_INT+1);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_large_19(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT);
	SET_WINDOW_LAST_RECV(LARGE_INT+1);

	t = cpu_to_be64(LARGE_INT+9);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_very_large_12(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(INT_OVER_32_BITS);
	SET_WINDOW_LAST_RECV(INT_OVER_32_BITS+1);

	t = cpu_to_be64(INT_OVER_32_BITS+2);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_very_large_91(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(INT_OVER_32_BITS);
	SET_WINDOW_LAST_RECV(INT_OVER_32_BITS+9);

	t = cpu_to_be64(INT_OVER_32_BITS+1);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_very_large_19(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(INT_OVER_32_BITS);
	SET_WINDOW_LAST_RECV(INT_OVER_32_BITS+1);

	t = cpu_to_be64(INT_OVER_32_BITS+9);

	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_outside(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(0);
	SET_WINDOW_LAST_RECV(1);

	t = cpu_to_be64(1+64);

	assert_int_equal(dtls_window(&state, (char*)&t), -2);
}

static void check_dtls_window_large_outside(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT);
	SET_WINDOW_LAST_RECV(LARGE_INT+1);

	t = cpu_to_be64(LARGE_INT+1+64);

	assert_int_equal(dtls_window(&state, (char*)&t), -2);
}

static void check_dtls_window_very_large_outside(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(INT_OVER_32_BITS);
	SET_WINDOW_LAST_RECV(INT_OVER_32_BITS+1);

	t = cpu_to_be64(INT_OVER_32_BITS+1+64);

	assert_int_equal(dtls_window(&state, (char*)&t), -2);
}

static void check_dtls_window_dup1(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT-1);
	SET_WINDOW_LAST_RECV(LARGE_INT);

	t = cpu_to_be64(LARGE_INT);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+1);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+16);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+1);
	assert_int_equal(dtls_window(&state, (char*)&t), -2);
}

static void check_dtls_window_dup2(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT-1);
	SET_WINDOW_LAST_RECV(LARGE_INT);

	t = cpu_to_be64(LARGE_INT);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+16);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+1);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+16);
	assert_int_equal(dtls_window(&state, (char*)&t), -3);
}

static void check_dtls_window_dup3(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT-1);
	SET_WINDOW_LAST_RECV(LARGE_INT);

	t = cpu_to_be64(LARGE_INT);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+16);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+15);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+14);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+5);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+5);
	assert_int_equal(dtls_window(&state, (char*)&t), -3);
}

static void check_dtls_window_out_of_order(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT-1);
	SET_WINDOW_LAST_RECV(LARGE_INT);

	t = cpu_to_be64(LARGE_INT);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+8);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+7);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+6);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+5);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+4);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+3);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+2);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+1);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(LARGE_INT+9);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);
}

static void check_dtls_window_epoch_higher(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	SET_WINDOW_START(LARGE_INT-1);
	SET_WINDOW_LAST_RECV(LARGE_INT);

	t = cpu_to_be64(LARGE_INT);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64((LARGE_INT+8)|0x1000000000000LL);
	assert_int_equal(dtls_window(&state, (char*)&t), -1);
}

static void check_dtls_window_epoch_lower(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;

	RESET_WINDOW;
	t = 0;
	t |= 0x1000000000000LL;
	SET_WINDOW_START(t);
	SET_WINDOW_LAST_RECV(t+1);

	t = cpu_to_be64(2 | 0x1000000000000LL);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(3 | 0x1000000000000LL);
	assert_int_equal(dtls_window(&state, (char*)&t), 0);

	t = cpu_to_be64(5);
	assert_int_equal(dtls_window(&state, (char*)&t), -1);
}

static void check_dtls_window_skip1(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;
	unsigned i;

	RESET_WINDOW;
	t = 0;
	SET_WINDOW_START(t);
	SET_WINDOW_LAST_RECV(t+1);

	for (i=2;i<256;i+=2) {
		t = cpu_to_be64(i);
		assert_int_equal(dtls_window(&state, (char*)&t), 0);
	}
}

static void check_dtls_window_skip3(void **glob_state)
{
	struct tls_sock state;
	uint64_t t;
	unsigned i;

	RESET_WINDOW;
	t = 0;
	SET_WINDOW_START(t);
	SET_WINDOW_LAST_RECV(t+1);

	for (i=5;i<256;i++) {
		t = cpu_to_be64(i);
		assert_int_equal(dtls_window(&state, (char*)&t), 0);
	}
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(check_dtls_window_12),
		cmocka_unit_test(check_dtls_window_21),
		cmocka_unit_test(check_dtls_window_19),
		cmocka_unit_test(check_dtls_window_91),
		cmocka_unit_test(check_dtls_window_large_21),
		cmocka_unit_test(check_dtls_window_large_12),
		cmocka_unit_test(check_dtls_window_large_19),
		cmocka_unit_test(check_dtls_window_large_91),
		cmocka_unit_test(check_dtls_window_dup1),
		cmocka_unit_test(check_dtls_window_dup2),
		cmocka_unit_test(check_dtls_window_dup3),
		cmocka_unit_test(check_dtls_window_outside),
		cmocka_unit_test(check_dtls_window_large_outside),
		cmocka_unit_test(check_dtls_window_out_of_order),
		cmocka_unit_test(check_dtls_window_epoch_lower),
		cmocka_unit_test(check_dtls_window_epoch_higher),
		cmocka_unit_test(check_dtls_window_very_large_12),
		cmocka_unit_test(check_dtls_window_very_large_19),
		cmocka_unit_test(check_dtls_window_very_large_91),
		cmocka_unit_test(check_dtls_window_very_large_outside),
		cmocka_unit_test(check_dtls_window_skip1),
		cmocka_unit_test(check_dtls_window_skip3)
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}

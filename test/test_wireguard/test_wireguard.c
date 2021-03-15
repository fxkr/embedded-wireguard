#include <unity.h>

#include "wireguard/wireguard.h"

void test_window_check(void)
{
	struct wg_window window = {
	    .bitmap = ~0U,
	    .last_seq = ~0ULL};

	// The reset state should be equal to a zero-initialized struct
	TEST_ASSERT_EQUAL(0, wg_window_init(&window));
	TEST_ASSERT_EACH_EQUAL_UINT8(0, &window, sizeof(window));

	// Normal counting is valid
	for (int i = 1; i <= 100; i++) {
		TEST_ASSERT_EQUAL(0, wg_window_check(&window, i));
	}

	// Re-using is not valid
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 101));
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 101));
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 101));
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 101));

	// Continuing after bad packets is valid
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 102));

	// Small jumps are valid
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 120));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 140));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 160));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 180));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 200));

	// Back-filling within the window is valid
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 190));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 191));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 193));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 197));

	// Back-filling outside the window is invalid
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 130));

	// Large jumps are valid
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 10000));

	// Back-filling outside the window is not valid after large jumps as well
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 9000));

	// Re-using is still not valid
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 10000));

	// The absolute maximum possible sequence number (2^64-1) is valid
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, ~0ULL));

	// Wrapping is not valid
	TEST_ASSERT_EQUAL(1, wg_window_check(&window, 1));

	// Reset should allow old values
	TEST_ASSERT_EQUAL(0, wg_window_init(&window));
	TEST_ASSERT_EQUAL(0, wg_window_check(&window, 101));
}

int main(int argc, char **argv)
{
	UNITY_BEGIN();
	RUN_TEST(test_window_check);
	UNITY_END();

	return 0;
}

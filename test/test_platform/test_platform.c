#include <unity.h>

#include "wireguard.h"
#include "wireguard/platform.h"

void test_platform_timestamp(void)
{
	union wg_timestamp ts1;
	union wg_timestamp ts2;

	// Current time is not the epoch
	TEST_ASSERT_EQUAL(0, wg_timestamp(&ts1));
	TEST_ASSERT_NOT_EQUAL(0, ts1.as_fields.seconds_be64);

	// Eventually the time must change.
	// If this test were to break, this would be an infinite loop.
	do {
		TEST_ASSERT_EQUAL(0, wg_timestamp(&ts2));
		if (ts1.as_fields.seconds_be64 != ts2.as_fields.seconds_be64 ||
		    ts1.as_fields.nanoseconds_be32 != ts2.as_fields.nanoseconds_be32) {
			break;
		}
	} while (true);

	// New time must be after old time
	TEST_ASSERT_TRUE(wg_be64toh(ts1.as_fields.seconds_be64) < wg_be64toh(ts2.as_fields.seconds_be64) ||
			 (ts1.as_fields.seconds_be64 == ts2.as_fields.seconds_be64 &&
			  wg_be32toh(ts1.as_fields.nanoseconds_be32) < wg_be32toh(ts2.as_fields.nanoseconds_be32)));
}

int main(int argc, char **argv)
{
	if (0 != wg_init()) {
		return 1;
	}

	UNITY_BEGIN();
	RUN_TEST(test_platform_timestamp);
	UNITY_END();

	return 0;
}

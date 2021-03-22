#include <stdbool.h>

#include "wireguard/debug.h"
#include "wireguard/platform.h"

static const uint64_t nanosec_per_sec = 1000000000UL;

int wg_timestamp(union wg_timestamp *out)
{
	struct wg_time now;

	if (0 != wg_time(&now)) {
		return 1;
	}

	out->as_fields.seconds_be64 = htobe64(now.seconds);
	out->as_fields.nanoseconds_be32 = htobe32(now.nanoseconds);

	return 0;
}

struct wg_time wg_time_add(struct wg_time a, struct wg_time b)
{

	wg_debug_assert(a.nanoseconds < nanosec_per_sec);
	wg_debug_assert(b.nanoseconds < nanosec_per_sec);

	struct wg_time result = {
	    .seconds = a.seconds + b.seconds,
	    .nanoseconds = a.nanoseconds + b.nanoseconds,
	};

	// Normalize so that nanoseconds represent less than one second.
	if (result.nanoseconds > nanosec_per_sec) {
		result.nanoseconds -= nanosec_per_sec;
		result.seconds += 1;
	}

	return result;
}

bool wg_time_before(struct wg_time a, struct wg_time b)
{
	wg_debug_assert(a.nanoseconds < nanosec_per_sec);
	wg_debug_assert(b.nanoseconds < nanosec_per_sec);

	return a.seconds < b.seconds || (a.seconds == b.seconds && a.nanoseconds < b.nanoseconds);
}

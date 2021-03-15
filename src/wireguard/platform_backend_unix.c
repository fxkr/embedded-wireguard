#include <time.h>

#include "wireguard/platform.h"

int wg_timestamp(union wg_timestamp *out)
{
	struct timespec ts = {};
	if (0 != clock_gettime(CLOCK_MONOTONIC, &ts)) {
		return 1; // Error
	}

	memset(out, 0, sizeof(union wg_timestamp));
	out->as_fields.seconds_be64 = wg_htobe64(ts.tv_sec);
	out->as_fields.nanoseconds_be32 = wg_htobe32(ts.tv_nsec);

	// Success
	return 0;
}
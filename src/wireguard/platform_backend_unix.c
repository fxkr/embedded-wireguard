#include <time.h>

#include "wireguard/platform.h"

int wg_time(struct wg_time *out)
{
	struct timespec ts = {};
	if (0 != clock_gettime(CLOCK_MONOTONIC, &ts)) {
		return 1; // Error
	}

	out->seconds = ts.tv_sec;
	out->nanoseconds = ts.tv_nsec;

	// Success
	return 0;
}
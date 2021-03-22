#include <Arduino.h>

#include "wireguard/platform.h"

// This implementation violates the WireGuard spec!
// Arduino's have no RTC, so we don't know the wall clock time.
// Instead we use the time since boot.
int wg_time(struct wg_time *out)
{
	uint64_t micros64_value = micros64();

	const uint64_t us_per_s = 1e6;
	const uint64_t ns_per_us = 1e3;

	out->seconds = wg_htobe64(micros64_value / us_per_s);
	out->nanoseconds = wg_htobe32((micros64_value % us_per_s) * ns_per_us);

	return 0;
}
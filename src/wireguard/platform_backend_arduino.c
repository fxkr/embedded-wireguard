#include <Arduino.h>

#include "wireguard/platform.h"

static int set_micros64(union wg_timestamp *out, uint64_t micros64_value)
{
	memset(out, 0, sizeof(union wg_timestamp));
	const uint64_t us_per_s = 1e6;
	const uint64_t ns_per_us = 1e3;
	out->as_fields.seconds_be64 = wg_htobe64(micros64_value / us_per_s);
	out->as_fields.nanoseconds_be32 = wg_htobe32((micros64_value % us_per_s) * ns_per_us);
	return 0;
}

// This implementation violates the WireGuard spec!
// Arduino's have no RTC, so we don't know the wall clock time.
// Instead we use the time since boot.
int wg_timestamp(union wg_timestamp *out)
{
	return set_micros64(out, micros64());
}
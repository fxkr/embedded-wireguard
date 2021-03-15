#ifndef WG_PLATFORM_H
#define WG_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// TAI64N format as specified by WireGuard spec.
struct wg_timestamp_fields {
	// Seconds since 1970 TAI. Big endian.
	uint64_t seconds_be64;
	// Nanoseconds since begin of seconds. Big endian.
	uint32_t nanoseconds_be32;
} __attribute__((packed));

// TAI64N format as specified by WireGuard spec.
union wg_timestamp {
	uint8_t as_bytes[sizeof(struct wg_timestamp_fields)];
	struct wg_timestamp_fields as_fields;
} __attribute__((packed));

#define wg_timestamp_len (sizeof(union wg_timestamp))
_Static_assert(wg_timestamp_len == 12, "");

#endif
#ifndef WG_PLATFORM_H
#define WG_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Byte order handling functions
#ifndef __BYTE_ORDER__
#error __BYTE_ORDER__ is undefined
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define wg_htole32(x) (x)
#define wg_le32toh(x) (x)
#define wg_htole64(x) (x)
#define wg_le64toh(x) (x)
#define wg_htobe32(x) __builtin_bswap32(x)
#define wg_be32toh(x) __builtin_bswap32(x)
#define wg_htobe64(x) __builtin_bswap64(x)
#define wg_be64toh(x) __builtin_bswap64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define wg_htole32(x) __builtin_bswap32(x)
#define wg_le32toh(x) __builtin_bswap32(x)
#define wg_htole64(x) __builtin_bswap64(x)
#define wg_le64toh(x) __builtin_bswap64(x)
#define wg_htobe32(x) (x)
#define wg_be32toh(x) (x)
#define wg_htobe64(x) (x)
#define wg_be64toh(x) (x)
#else
#error Bad __BYTE_ORDER__
#endif
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
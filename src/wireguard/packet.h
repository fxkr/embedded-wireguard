#ifndef WG_PACKET_H
#define WG_PACKET_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wireguard/platform.h"

struct wg_ipv4_hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint8_t header_len : 4,
	    version : 4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint8_t version : 4,
	    header_len : 4;
#else
#error __BYTE_ORDER__ invalid
#endif
	uint8_t tos;
	uint16_t len;
	uint16_t ident;
	uint16_t frag_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	union wg_ipv4_addr src;
	union wg_ipv4_addr dst;
};

// Packet abstraction.
//
// Roughly follows naming conventions of Linux's struct sk_buff as that is
// what most people will be familiar with.
//
// It is always linear / never fragmented (in contrast to struct sk_buff).
// Its operations assume enough space is available. It does not automatically reallocate.
struct wg_packet {

	// head points to beginning of head room.
	uint8_t *head;

	// data points to beginning of packet data, after end of headroom.
	uint8_t *data;

	// tail points to beginning of tail room, after end of packet data.
	uint8_t *tail;

	// end points after end of tail room.
	uint8_t *end;
};

// Initialize packet structure.
// Initially the headroom and data sections are empty,
// and all available buffer space is allocated to the tailroom.
void wg_packet_init(struct wg_packet *pkt, uint8_t *buffer, size_t buffer_len);

// Returns the number of bytes currently in the headroom after the data section.
size_t wg_packet_headroom_len(struct wg_packet *pkt);

// Returns the number of bytes currently in the data section between headroom and tailroom.
size_t wg_packet_data_len(struct wg_packet *pkt);

// Returns the number of bytes currently in the tailroom after the data section.
size_t wg_packet_tailroom_len(struct wg_packet *pkt);

// Increase headroom size.
// Does not move data!
// Assumes enough tailroom is available.
void wg_packet_reserve(struct wg_packet *pkt, size_t len_delta);

// Expand data area into tailroom.
// Assumes enough tailroom is available.
// Returns a pointer to the new data.
uint8_t *wg_packet_put(struct wg_packet *pkt, size_t len_delta);

// Same as wg_packet_put, but zeroes the new data.
uint8_t *wg_packet_put_zero(struct wg_packet *pkt, size_t len_delta);

// Expand data area into headroom.
// Assumes enough headroom is available.
// Does not move data!
// Returns a pointer to the new data.
uint8_t *wg_packet_push(struct wg_packet *pkt, size_t len_delta);

// Remove data from start of buffer and return it into headroom.
// Returns a pointer to the new start of the data.
// Does not move data!
uint8_t *wg_packet_pull(struct wg_packet *pkt, size_t len_delta);

// Sets the data length to a shorter value.
void wg_packet_trim(struct wg_packet *pkt, size_t len_absolute);

#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"

#include "wireguard/packet.h"

void wg_packet_init(struct wg_packet *pkt, uint8_t *buffer, size_t buffer_len)
{
	memset(pkt, 0, sizeof(struct wg_packet));

	pkt->head = buffer;
	pkt->data = buffer;
	pkt->tail = buffer;
	pkt->end = buffer + buffer_len;

	wg_debug_assert(pkt->end >= pkt->head);
}

size_t wg_packet_headroom_len(struct wg_packet *pkt)
{
	return pkt->data - pkt->head;
}

size_t wg_packet_data_len(struct wg_packet *pkt)
{
	return pkt->tail - pkt->data;
}

size_t wg_packet_tailroom_len(struct wg_packet *pkt)
{
	return pkt->end - pkt->tail;
}

void wg_packet_reserve(struct wg_packet *pkt, size_t len_delta)
{
	pkt->data += len_delta;
	pkt->tail += len_delta;

	wg_debug_assert(pkt->data <= pkt->end);
	wg_debug_assert(pkt->tail <= pkt->end);
}

uint8_t *wg_packet_put(struct wg_packet *pkt, size_t len_delta)
{
	uint8_t *tail = pkt->tail;

	pkt->tail += len_delta;

	wg_debug_assert(pkt->tail <= pkt->end);

	return tail;
}

uint8_t *wg_packet_put_zero(struct wg_packet *pkt, size_t len_delta)
{
	uint8_t *tail = wg_packet_put(pkt, len_delta);
	memset(tail, 0, len_delta);
	return tail;
}

uint8_t *wg_packet_push(struct wg_packet *pkt, size_t len_delta)
{
	pkt->data -= len_delta;

	wg_debug_assert(pkt->data >= pkt->head);

	return pkt->data;
}

uint8_t *wg_packet_pull(struct wg_packet *pkt, size_t len_delta)
{
	pkt->data += len_delta;

	return pkt->data;
}

void wg_packet_trim(struct wg_packet *pkt, size_t len_absolute)
{
	pkt->tail = pkt->data + len_absolute;
}
#ifndef WG_CRYPTO_BLAKE2S_H
#define WG_CRYPTO_BLAKE2S_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct wg_blake2s_state {
	uint32_t state[16];
	uint8_t block[64];
	uint32_t h[8];
	uint32_t t[2];
	size_t block_fill_len;
	bool no_key;
};

void wg_blake2s_init(
    struct wg_blake2s_state *state,
    uint8_t *out, size_t out_len,
    const uint8_t *key, size_t key_len);

void wg_blake2s_update(
    struct wg_blake2s_state *state,
    const uint8_t *in, uint8_t in_len);

void wg_blake2s_finalize(
    struct wg_blake2s_state *state,
    uint8_t *out, uint8_t out_len);

#endif
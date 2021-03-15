// BLAKE2S implementation (core only, struct to uint8_t* glue functions are separate).
//
// This file contains code derived from https://github.com/jedisct1/hashseq
// which is Copyright (c) 2019-2021, Frank Denis and BSD 2-Clause licensed.
//
// Main changes:
// * Add multi step hashing.
// * Simplify #ifdefs and inline some #defines.
//
// Sadly, libsodium does not have a BLAKE2S implementation anymore.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wireguard/crypto.h"
#include "wireguard/crypto_blake2s.h"

#define ROTR32(X, B) (uint32_t)(((X) >> (B)) | ((X) << (32 - (B))))

static inline uint32_t load32_le(const uint8_t src[4])
{
#ifndef __BYTE_ORDER__
#error __BYTE_ORDER__ is undefined
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t w;
	memcpy(&w, src, sizeof w);
	return w;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint32_t w = (uint32_t)src[0];
	w |= (uint32_t)src[1] << 8;
	w |= (uint32_t)src[2] << 16;
	w |= (uint32_t)src[3] << 24;
	return w;
#else
#error Bad __BYTE_ORDER__
#endif
}

static inline void store32_le(uint8_t dst[4], uint32_t w)
{
#ifndef __BYTE_ORDER__
#error __BYTE_ORDER__ is undefined
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	memcpy(dst, &w, sizeof w);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	dst[0] = (uint8_t)w;
	w >>= 8;
	dst[1] = (uint8_t)w;
	w >>= 8;
	dst[2] = (uint8_t)w;
	w >>= 8;
	dst[3] = (uint8_t)w;
#else
#error Bad __BYTE_ORDER__
#endif
}

#define G(A, B, C, D)                        \
	do {                                 \
		(A) += (B);                  \
		(D) = ROTR32((D) ^ (A), 16); \
		(C) += (D);                  \
		(B) = ROTR32((B) ^ (C), 12); \
		(A) += (B);                  \
		(D) = ROTR32((D) ^ (A), 8);  \
		(C) += (D);                  \
		(B) = ROTR32((B) ^ (C), 7);  \
	} while (0)

static const uint32_t IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static const uint8_t BLAKE2S_SIGMA[10][8] = {
    {1, 35, 69, 103, 137, 171, 205, 239},
    {234, 72, 159, 214, 28, 2, 183, 83},
    {184, 192, 82, 253, 174, 54, 113, 148},
    {121, 49, 220, 190, 38, 90, 64, 248},
    {144, 87, 36, 175, 225, 188, 104, 61},
    {44, 106, 11, 131, 77, 117, 254, 25},
    {197, 31, 237, 74, 7, 99, 146, 139},
    {219, 126, 193, 57, 80, 244, 134, 42},
    {111, 233, 179, 8, 194, 215, 20, 165},
    {162, 132, 118, 21, 251, 158, 60, 208}};

#define BLAKE2S_G(M, R, I, A, B, C, D)                 \
	do {                                           \
		const uint8_t x = BLAKE2S_SIGMA[R][I]; \
		(A) += (B) + (M)[(x >> 4) & 0xf];      \
		(D) = ROTR32((D) ^ (A), 16);           \
		(C) += (D);                            \
		(B) = ROTR32((B) ^ (C), 12);           \
		(A) += (B) + (M)[x & 0xf];             \
		(D) = ROTR32((D) ^ (A), 8);            \
		(C) += (D);                            \
		(B) = ROTR32((B) ^ (C), 7);            \
	} while (0)

static inline void blake2s_round(uint32_t state[16], const uint32_t mb32[16], int round)
{
	BLAKE2S_G(mb32, round, 0, state[0], state[4], state[8], state[12]);
	BLAKE2S_G(mb32, round, 1, state[1], state[5], state[9], state[13]);
	BLAKE2S_G(mb32, round, 2, state[2], state[6], state[10], state[14]);
	BLAKE2S_G(mb32, round, 3, state[3], state[7], state[11], state[15]);

	BLAKE2S_G(mb32, round, 4, state[0], state[5], state[10], state[15]);
	BLAKE2S_G(mb32, round, 5, state[1], state[6], state[11], state[12]);
	BLAKE2S_G(mb32, round, 6, state[2], state[7], state[8], state[13]);
	BLAKE2S_G(mb32, round, 7, state[3], state[4], state[9], state[14]);
}

static void blake2s_hashblock(uint32_t state[16], uint32_t h[8], uint32_t t[2],
			      const uint8_t message_block[64], uint32_t inc, int is_last)
{
	uint32_t mb32[16];
	int round;
	int i;

	for (i = 0; i < 16; i++) {
		mb32[i] = load32_le(&message_block[(size_t)i * sizeof mb32[0]]);
	}
	memcpy(&state[0], h, 8 * sizeof state[0]);
	memcpy(&state[8], IV, 8 * sizeof state[0]);
	t[0] += inc;
	if (t[0] < inc) {
		t[1]++;
	}
	state[12] ^= t[0];
	state[13] ^= t[1];
	if (is_last) {
		state[14] = ~state[14];
	}
	for (round = 0; round < 10; round++) {
		blake2s_round(state, mb32, round);
	}
	for (i = 0; i < 8; i++) {
		h[i] ^= state[i] ^ state[i + 8];
	}
}

void wg_blake2s_init(
    struct wg_blake2s_state *st,
    uint8_t *out, size_t out_len,
    const uint8_t *key, size_t key_len)
{
	memset(st, 0, sizeof(struct wg_blake2s_state));

	memcpy(st->h, IV, sizeof(st->h));
	st->h[0] ^= (out_len | (key_len << 8) | (1 << 16) | (1 << 24));

	if (key_len > 0) {
		memset(st->block, 0, sizeof(st->block));
		memcpy(st->block, key, key_len);
		st->block_fill_len = 64;
		// Cannot hash block yet; we don't know if it is the last one yet
	} else {
		st->no_key = true;
	}
}

void wg_blake2s_update(
    struct wg_blake2s_state *st,
    const uint8_t *in, uint8_t in_len)
{
again:
	// This return covers two cases:
	// a) We're passed nothing, so do nothing. Block may or may not be empty.
	// b) We've copied into the block buffer. It may even be full.
	//    We have no more data right now, but more may come, so we can't
	//    hash the current block yet even if it is full.
	if (in_len == 0) {
		return;
	}

	// If we get here, there is more data.
	// If block is already full, then we know that it is not the last. So we can hash it.
	if (st->block_fill_len == sizeof(st->block)) {
		blake2s_hashblock(st->state, st->h, st->t, st->block, st->block_fill_len, 0);
		memset(st->block, 0, sizeof(st->block));
		st->block_fill_len = 0;
	}

	// Copy into block buffer if
	// a) Block already has some data, or
	// b) Remaining data is less than block size, or
	// c) Remaining data exactly fits block size, so we can copy it but not hash it.
	if (st->block_fill_len > 0 || in_len <= sizeof(st->block)) {

		// Copy lesser of:
		// a) Remaining space in block
		// b) Remaining available data
		size_t copy_len = sizeof(st->block) - st->block_fill_len;
		if (in_len < copy_len) {
			copy_len = in_len;
		}
		memcpy(&st->block[st->block_fill_len], in, copy_len);
		st->block_fill_len += copy_len;
		in_len -= copy_len;
		in += copy_len;

		goto again;
	}

	// Handle non-last full block directly (no copying)
	while (in_len > sizeof(st->block)) {
		blake2s_hashblock(st->state, st->h, st->t, in, sizeof(st->block), 0);
		in_len -= sizeof(st->block);
		in += sizeof(st->block);
	}

	goto again;
}

void wg_blake2s_finalize(
    struct wg_blake2s_state *st,
    uint8_t *out, uint8_t out_len)
{
	// Hash last block
	if (st->block_fill_len) {
		// Remaining data
		blake2s_hashblock(st->state, st->h, st->t, st->block, st->block_fill_len, 1);
		st->block_fill_len = 0;
	} else if (st->no_key) {
		// If nothing else has been hashed (no data and no key), hash a zero block
		memset(st->block, 0, sizeof(st->block));
		blake2s_hashblock(st->state, st->h, st->t, st->block, st->block_fill_len, 1);
		st->block_fill_len = 0;
	}

	uint8_t out_tmp[32];
	for (int i = 0; i < 8; i++) {
		store32_le(&out_tmp[(size_t)i * sizeof(st->h[0])], st->h[i]);
	}
	memcpy(out, out_tmp, out_len);

	wg_secure_memzero(out_tmp, sizeof(out_tmp));
	wg_secure_memzero(st, sizeof(struct wg_blake2s_state));
}
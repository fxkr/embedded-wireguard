#ifndef WG_CRYPTO_H
#define WG_CRYPTO_H

#include "wireguard/platform.h"

#define WG_CURVE25519_KEY_SIZE 32
#define WG_CHACHA20POLY1305_KEY_SIZE 32
#define WG_CHACHA20POLY1305_AUTHTAG_SIZE 16
#define WG_BLAKE2S_HASH_SIZE 32

#define wg_key_len (WG_CURVE25519_KEY_SIZE)
#define wg_symmetric_key_len (WG_CHACHA20POLY1305_KEY_SIZE)
#define wg_authtag_len (WG_CHACHA20POLY1305_AUTHTAG_SIZE)
#define wg_hash_len (WG_BLAKE2S_HASH_SIZE)
#define wg_xaead_nonce_len 24
#define wg_aead_len(plain_len) ((plain_len) + 16)
#define wg_mac_len 16
#define wg_cookie_len 16

union wg_mac {
	uint8_t as_bytes[wg_mac_len];
} __attribute__((packed));

union wg_hash {
	uint8_t as_bytes[wg_hash_len];
} __attribute__((packed));

union wg_key {
	uint8_t as_bytes[wg_key_len];
	union wg_hash as_hash;
} __attribute__((packed));

union wg_symmetric_key {
	uint8_t as_bytes[wg_symmetric_key_len];
	union wg_hash as_hash;
} __attribute__((packed));

union wg_xaead_nonce {
	uint8_t as_bytes[wg_xaead_nonce_len];
} __attribute__((packed));

union wg_cookie {
	uint8_t as_bytes[wg_cookie_len];
	union wg_mac as_mac;
} __attribute__((packed));

struct wg_aead_nonce_fields {
	uint32_t zeroes;
	uint64_t counter_le64;
} __attribute__((packed));

union wg_aead_nonce {
	struct wg_aead_nonce_fields as_fields;
	uint8_t as_bytes[sizeof(struct wg_aead_nonce_fields)];
} __attribute__((packed));

#endif
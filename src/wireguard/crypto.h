#ifndef WG_CRYPTO_H
#define WG_CRYPTO_H

#include "wireguard/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

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

_Static_assert(sizeof(union wg_mac) == wg_mac_len, "");
_Static_assert(sizeof(union wg_hash) == wg_hash_len, "");
_Static_assert(sizeof(union wg_key) == wg_key_len, "");
_Static_assert(sizeof(union wg_symmetric_key) == wg_symmetric_key_len, "");
_Static_assert(sizeof(union wg_xaead_nonce) == wg_xaead_nonce_len, "");
_Static_assert(sizeof(union wg_cookie) == wg_cookie_len, "");

// Zeroes the memory indicated by ptr and size and performs a memory barrier
// to guarantee the zeroization is not optimized away.
// Implemented as a static inline header function to keep LTO from removing it as well.
// See libsodium's sodium_memzero for alternative approaches.
static inline void wg_secure_memzero(void *ptr, size_t size)
{
	memset(ptr, 0, size);
	asm volatile("" ::"r"(ptr)
		     : "memory");
#if !defined(__GNUC__) && !defined(__clang__)
#error Cannot guarantee wg_secure_memzero works for this compiler
#endif
}

// Returns whether the two symmetric keys are equal.
// The comparison is constant time (ie, cryptophically secure).
// Returns 0 on success, non-zero (usually 1) on error.
bool __attribute__((warn_unused_result)) wg_symmetric_key_equals(
    const union wg_symmetric_key *a,
    const union wg_symmetric_key *b);

// Returns whether the two keys are equal.
// The comparison is constant time (ie, cryptophically secure).
// Returns 0 on success, non-zero (usually 1) on error.
bool __attribute__((warn_unused_result)) wg_key_equals(
    const union wg_key *a,
    const union wg_key *b);

// Returns whether the two MAC's are equal.
// The comparison is constant time (ie, cryptophically secure).
// Returns 0 on success, non-zero (usually 1) on error.
bool __attribute__((warn_unused_result)) wg_mac_equals(
    const union wg_mac *a,
    const union wg_mac *b);

// Returns whether the two hashes are equal.
// The comparison is constant time (ie, cryptophically secure).
// Returns 0 on success, non-zero (usually 1) on error.
bool __attribute__((warn_unused_result)) wg_hash_equals(
    const union wg_hash *a,
    const union wg_hash *b);

// BLAKE2S hash.
// Using the same memory location for input and output is ok.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_hash(
    union wg_hash *out,
    const uint8_t *in, size_t in_len);

// BLAKE2S hash in an HMAC construction.
// Using the same memory location for input and output is ok.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_hmac(
    union wg_hash *out,
    const union wg_key *key,
    const uint8_t *in1, size_t in1_len);

// Keyed BLAKE2S hash.
// Using the same memory location for input and output is ok.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_mac(
    union wg_mac *out,
    const union wg_key *key,
    const uint8_t *in1, size_t in1_len);

// Keyed BLAKE2S hash.
// Using the same memory location for input and output is ok.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_mac_with_cookie(
    union wg_mac *out,
    const union wg_cookie *key,
    const uint8_t *in1, size_t in1_len);

// BLAKE2S hash in an HMAC construction, hashing the concatenation of two inputs.
// Using the same memory location for input(s) and output is ok.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_concat_hmac(
    union wg_hash *out,
    const union wg_key *key,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len);

// BLAKE2S hash in an HMAC construction, hashing the concatenation of two inputs.
// Using the same memory location for input(s) and output is ok.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_concat_hash(
    union wg_hash *out,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len);

// Generate random Curve25519 private and public keys.
// Part of Diffie-Hellman key exchange.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_dh_generate(
    union wg_key *out_priv,
    union wg_key *out_pub);

// Curve25519 point multiplication of a private key and a public key.
// Part of Diffie-Hellman key exchange.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_dh(
    union wg_key *dh_key,
    const union wg_key *priv_key,
    const union wg_key *public_key);

// Populates memory with random bytes for a cryptographically secure PRNG.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_secure_random(
    uint8_t *out, size_t out_len);

// XChaCha20Poly1305 AEAD authenticated encryption.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_xaead(
    uint8_t *out, size_t out_len,
    const union wg_symmetric_key *key,
    const union wg_xaead_nonce *nonce,
    const uint8_t *plain_text, size_t plain_text_len,
    const uint8_t *auth_text, size_t auth_text_len);

// XChaCha20Poly1305 AEAD authenticated decryption.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_xaead_decrypt(
    uint8_t *out_plaintext, size_t out_plaintext_len,
    const union wg_symmetric_key *key,
    const union wg_xaead_nonce *nonce,
    const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
    const uint8_t *auth_text, size_t auth_text_len);

// ChaCha20Poly1305 AEAD authenticated encryption.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_aead_encrypt(
    uint8_t *out, size_t out_len,
    const union wg_symmetric_key *key,
    uint64_t counter,
    const uint8_t *plain_text, size_t plain_text_len,
    const uint8_t *auth_text, size_t auth_text_len);

// ChaCha20Poly1305 AEAD authenticated decryption.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_aead_decrypt(
    uint8_t *out_plain_text, size_t out_plain_text_len,
    const union wg_symmetric_key *key,
    uint64_t counter,
    const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
    const uint8_t *auth_text, size_t auth_text_len);

// HKDF key derivation function with one output.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_kdf1(
    union wg_hash *out,
    const union wg_key *key,
    const uint8_t *input, size_t input_len);

// HKDF key derivation function with two outputs.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_kdf2(
    union wg_hash *out1,
    union wg_hash *out2,
    const union wg_key *key,
    const uint8_t *input, size_t input_len);

// HKDF key derivation function with three outputs.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_kdf3(
    union wg_hash *out1,
    union wg_hash *out2,
    union wg_hash *out3,
    const union wg_key *key,
    const uint8_t *input, size_t input_len);

// Encode a binary key to BASE64.
// Returns 0 on success, non-zero (usually 1) on error.
int __attribute__((warn_unused_result)) wg_key_to_base64(
    char *out_str,
    size_t out_str_len,
    const union wg_key *key);

// Decode BASE64 to a binary key.
// The key the input represents is expected to have the length of a WireGuard public or private key.
// The str_len parameter is the length of the string not including any zero termination.
int __attribute__((warn_unused_result)) wg_base64_to_key(
    union wg_key *key,
    const char *str,
    size_t str_len);

// This function must be called at least once before any other function
// from Embedded WireGuard's cryptographic subsystem are used.
// It is safe to call it any number of times.
int __attribute__((warn_unused_result)) wg_crypto_init(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
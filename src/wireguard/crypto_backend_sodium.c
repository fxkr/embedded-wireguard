// Bindings for https://github.com/jedisct1/libsodium

#include <stdbool.h>
#include <stdio.h>

#include <sodium.h>

#include "wireguard/crypto.h"

int wg_key_to_base64(
    char *out_str,
    size_t out_str_len,
    const union wg_key *key)
{
	// Its return value is _not_ an error indication!
	sodium_bin2base64(
	    out_str, out_str_len,
	    key->as_bytes, sizeof(key->as_bytes),
	    sodium_base64_VARIANT_ORIGINAL);

	return 0; // Succes
}

// str_len does _not_ include null termination!
int wg_base64_to_key(
    union wg_key *key,
    const const char *str,
    size_t str_len)
{
	size_t bin_len = 0;

	if (0 != sodium_base642bin(
		     key->as_bytes, sizeof(key->as_bytes),
		     str, str_len,
		     NULL,
		     &bin_len,
		     NULL,
		     sodium_base64_VARIANT_ORIGINAL)) {
		return 1; // Error
	}

	if (bin_len != sizeof(key->as_bytes)) {
		return 1; // Error
	}

	return 0; // Success
}

int wg_xaead(
    uint8_t *out, size_t out_len,
    const union wg_symmetric_key *key,
    const union wg_xaead_nonce *nonce,
    const uint8_t *plain_text, size_t plain_text_len,
    const uint8_t *auth_text, size_t auth_text_len)
{
	// out_len not is used, as libsodium doesn't take it as input parameter
	return 0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
			out, NULL,
			plain_text, plain_text_len,
			auth_text, auth_text_len,
			NULL,
			nonce->as_bytes,
			key->as_bytes);
}

int wg_xaead_decrypt(
    uint8_t *out_plaintext, size_t out_plaintext_len,
    const union wg_symmetric_key *key,
    const union wg_xaead_nonce *nonce,
    const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
    const uint8_t *auth_text, size_t auth_text_len)
{
	// out_len not is used, as libsodium doesn't take it as input parameter
	return 0 != crypto_aead_xchacha20poly1305_ietf_decrypt(
			out_plaintext, NULL,
			NULL,
			ciphertext_with_tag, ciphertext_with_tag_len,
			auth_text, auth_text_len,
			nonce->as_bytes,
			key->as_bytes);
}

int wg_aead_encrypt(
    uint8_t *out, size_t out_len,
    const union wg_symmetric_key *key,
    uint64_t counter,
    const uint8_t *plain_text, size_t plain_text_len,
    const uint8_t *auth_text, size_t auth_text_len)
{
	union wg_aead_nonce nonce = {
	    .as_fields = {
		.zeroes = 0,
		.counter_le64 = wg_htole64(counter),
	    }};

	// out_len not is used, as libsodium doesn't take it as input parameter
	return 0 != crypto_aead_chacha20poly1305_ietf_encrypt(
			out, NULL,
			plain_text, plain_text_len,
			auth_text, auth_text_len,
			NULL,
			nonce.as_bytes,
			key->as_bytes);
}

int wg_aead_decrypt(
    uint8_t *out_plaintext, size_t out_plaintext_len,
    const union wg_symmetric_key *key,
    uint64_t counter,
    const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
    const uint8_t *auth_text, size_t auth_text_len)
{
	union wg_aead_nonce nonce = {
	    .as_fields = {
		.zeroes = 0,
		.counter_le64 = wg_htole64(counter),
	    }};

	// out_plaintext_len is not used, as libsodium doesn't take it as input parameter
	return 0 != crypto_aead_chacha20poly1305_ietf_decrypt(
			out_plaintext, NULL,
			NULL,
			ciphertext_with_tag, ciphertext_with_tag_len,
			auth_text, auth_text_len,
			nonce.as_bytes,
			key->as_bytes);
}

int wg_dh_generate(
    union wg_key *out_priv,
    union wg_key *out_pub)
{
	return 0 != crypto_box_curve25519xchacha20poly1305_keypair(
			out_pub->as_bytes,
			out_priv->as_bytes);
}

int wg_dh(
    union wg_key *dh_key,
    const union wg_key *priv_key,
    const union wg_key *public_key)
{
	return 0 != crypto_scalarmult_curve25519(
			dh_key->as_bytes,
			priv_key->as_bytes,
			public_key->as_bytes);
}

int wg_secure_random(uint8_t *out, size_t out_len)
{
	randombytes_buf(out, out_len);
	return 0;
}

bool wg_symmetric_key_equals(
    const union wg_symmetric_key *a,
    const union wg_symmetric_key *b)
{
	return 0 == sodium_memcmp(a->as_bytes, b->as_bytes, sizeof(a->as_bytes));
}

bool wg_key_equals(
    const union wg_key *a,
    const union wg_key *b)
{
	return 0 == sodium_memcmp(a->as_bytes, b->as_bytes, sizeof(a->as_bytes));
}

bool wg_hash_equals(
    const union wg_hash *a,
    const union wg_hash *b)
{
	return 0 == sodium_memcmp(a->as_bytes, b->as_bytes, sizeof(a->as_bytes));
}

bool wg_mac_equals(
    const union wg_mac *a,
    const union wg_mac *b)
{
	return 0 == sodium_memcmp(a->as_bytes, b->as_bytes, sizeof(a->as_bytes));
}

int wg_crypto_init(void)
{
	if (sodium_init() < 0) {
		return 1; // Error
	}

	return 0;
}
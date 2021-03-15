// Bindings for https://github.com/rweather/arduinolibs

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ChaChaPoly.h>
#include <Crypto.h>
#include <Curve25519.h>
#include <RingOscillatorNoiseSource.h>

#include "wireguard/crypto.h"
#include "wireguard/platform.h"

RNGClass rng;
RingOscillatorNoiseSource noise;

int wg_aead_encrypt(
    uint8_t *out_ciphertext_with_tag, size_t out_ciphertext_with_tag_len,
    const union wg_symmetric_key *key,
    uint64_t counter,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *auth_text, size_t auth_text_len)
{
	int ret = 1; // Error
	ChaChaPoly chachapoly;

	union wg_aead_nonce nonce = {
	    .as_fields = {
		.zeroes = 0,
		.counter_le64 = wg_htole64(counter),
	    }};

	// Ciphertext is encrypted plaintext + authentication tag
	if (out_ciphertext_with_tag_len != wg_aead_len(plaintext_len)) {
		goto out;
	}

	if (!chachapoly.setKey(key->as_bytes, sizeof(key->as_bytes))) {
		goto out; // Error
	}

	if (!chachapoly.setIV(nonce.as_bytes, sizeof(nonce.as_bytes))) {
		goto out; // Error
	}

	chachapoly.addAuthData(auth_text, auth_text_len);
	chachapoly.encrypt(out_ciphertext_with_tag, plaintext, out_ciphertext_with_tag_len);
	chachapoly.computeTag(out_ciphertext_with_tag + plaintext_len, wg_aead_len(0));

	ret = 0; // Success

out:
	return ret; // Success
}

int wg_aead_decrypt(
    uint8_t *out_plaintext, size_t out_plaintext_len,
    const union wg_symmetric_key *key,
    uint64_t counter,
    const uint8_t *ciphertext_with_tag, size_t ciphertext_with_tag_len,
    const uint8_t *auth_text, size_t auth_text_len)
{
	int ret = 1; // Error
	const uint8_t *tag = ciphertext_with_tag + ciphertext_with_tag_len - wg_aead_len(0);
	size_t tag_len = wg_aead_len(0);
	ChaChaPoly chachapoly;

	union wg_aead_nonce nonce = {
	    .as_fields = {
		.zeroes = 0,
		.counter_le64 = wg_htole64(counter),
	    }};

	// Ciphertext is encrypted plaintext + authentication tag
	if (ciphertext_with_tag_len != wg_aead_len(out_plaintext_len)) {
		goto out; // Error
	}

	if (!chachapoly.setKey(key->as_bytes, sizeof(key->as_bytes))) {
		goto out; // Error
	}

	if (!chachapoly.setIV(nonce.as_bytes, sizeof(nonce.as_bytes))) {
		goto out; // Error
	}

	chachapoly.addAuthData(auth_text, auth_text_len);
	chachapoly.decrypt(out_plaintext, ciphertext_with_tag, out_plaintext_len);

	if (!chachapoly.checkTag(tag, tag_len)) {
		goto out; // Error
	}

out:
	return ret;
}

int wg_dh_generate(
    union wg_key *out_priv,
    union wg_key *out_pub)
{
	// Beware: Arduino Crypto Lib and WireGuard spec use different order
	Curve25519::dh1(out_pub->as_bytes, out_priv->as_bytes);
	return 0; // Success
}

int wg_dh(
    union wg_key *out,
    const union wg_key *priv,
    const union wg_key *pub)
{
	// Beware: Arduino Crypto Lib overwrites private key during calculation
	union wg_key priv_copy;
	int ret = 1; // Error

	wg_safe_memcpy(
	    &priv_copy.as_bytes, sizeof(priv_copy.as_bytes),
	    &priv->as_bytes, sizeof(priv->as_bytes));
	wg_safe_memcpy(
	    &out->as_bytes, sizeof(pub->as_bytes),
	    &pub->as_bytes, sizeof(pub->as_bytes));

	if (!Curve25519::dh2(out->as_bytes, priv_copy.as_bytes)) {
		wg_secure_memzero(out->as_bytes, sizeof(out->as_bytes));
		goto out; // Error
	}

	err = 0; // Success

out:
	wg_secure_memzero(&priv_copy.as_bytes, sizeof(priv_copy.as_bytes));

	return ret;
}

bool wg_hash_equals(
    const union wg_hash *a,
    const union wg_hash *b)
{
	return 0 == secure_compare(a->as_bytes, b->as_bytes, sizeof(a->as_bytes));
}

bool wg_mac_equals(
    const union wg_mac *a,
    const union wg_mac *b)
{
	return 0 == secure_compare(a->as_bytes, b->as_bytes, sizeof(a->as_bytes));
}

int wg_secure_random(uint8_t *out, size_t out_len)
{
	rng.rand(out, len);
	return 0; // Success
}

int wg_crypto_init(void)
{
	rng.begin("Embedded WireGuard");
	rng.addNoiseSource(noise);

	return 0; // Success
}
// 1. High level cryptographic primitives (KDF, HMAC).
// 2. Type safe wrapper functions around byte array based low level functions.

#include <stddef.h>

#include "wireguard/crypto_blake2s.h"
#include "wireguard/platform.h"

#include "wireguard/crypto.h"

int wg_kdf1(
    union wg_hash *out,
    const union wg_key *key,
    const uint8_t *input, size_t input_len)
{
	const uint8_t one[] = {0x1};
	union wg_key temp;
	int ret = 1; // Error

	if (0 != wg_hmac(&temp.as_hash, key,
			 input, input_len)) {
		goto out; // Error
	}

	if (0 != wg_hmac(out, &temp,
			 one, sizeof(one))) {
		goto out; // Error
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&temp, sizeof(temp));

	return ret;
}

int wg_kdf2(
    union wg_hash *out1,
    union wg_hash *out2,
    const union wg_key *key,
    const uint8_t *input, size_t input_len)
{
	const uint8_t one[] = {0x1};
	const uint8_t two[] = {0x2};
	union wg_key temp;
	int ret = 1; // Error

	if (0 != wg_hmac(&temp.as_hash, key,
			 input, input_len)) {
		goto out; // Error
	}

	if (0 != wg_hmac(out1, &temp,
			 one, sizeof(one))) {
		goto out; // Error
	}

	if (0 != wg_concat_hmac(
		     out2,
		     &temp,
		     out1->as_bytes, sizeof(out1->as_bytes),
		     two, sizeof(two))) {
		goto out; // Error
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&temp, sizeof(temp));

	return ret;
}

int wg_kdf3(
    union wg_hash *out1,
    union wg_hash *out2,
    union wg_hash *out3,
    const union wg_key *key,
    const uint8_t *input, size_t input_len)
{
	const uint8_t one[] = {0x1};
	const uint8_t two[] = {0x2};
	const uint8_t three[] = {0x3};
	union wg_key temp;
	int ret = 1; // Error

	if (0 != wg_hmac(&temp.as_hash, key, input, input_len)) {
		goto out; // Error
	}

	if (0 != wg_hmac(out1, &temp, one, sizeof(one))) {
		goto out; // Error
	}

	if (0 != wg_concat_hmac(
		     out2,
		     &temp,
		     out1->as_bytes, sizeof(out1->as_bytes),
		     two, sizeof(two))) {
		goto out; // Error
	}

	if (0 != wg_concat_hmac(
		     out3,
		     &temp,
		     out2->as_bytes, sizeof(out2->as_bytes),
		     three, sizeof(three))) {
		goto out; // Error
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&temp, sizeof(temp));

	return ret;
}

int wg_hash(
    union wg_hash *out,
    const uint8_t *in, size_t in_len)
{
	struct wg_blake2s_state state;
	wg_blake2s_init(
	    &state,
	    out->as_bytes, sizeof(out->as_bytes),
	    NULL, 0);
	wg_blake2s_update(
	    &state,
	    in, in_len);
	wg_blake2s_finalize(
	    &state,
	    out->as_bytes,
	    sizeof(out->as_bytes));
	wg_secure_memzero(&state, sizeof(state));
	return 0;
}

int wg_mac(
    union wg_mac *out,
    const union wg_key *key,
    const uint8_t *in1, size_t in1_len)
{
	struct wg_blake2s_state state;
	wg_blake2s_init(
	    &state,
	    out->as_bytes, sizeof(out->as_bytes),
	    key->as_bytes, sizeof(key->as_bytes));
	wg_blake2s_update(
	    &state,
	    in1, in1_len);
	wg_blake2s_finalize(
	    &state,
	    out->as_bytes,
	    sizeof(out->as_bytes));
	wg_secure_memzero(&state, sizeof(state));
	return 0;
}

int wg_mac_with_cookie(
    union wg_mac *out,
    const union wg_cookie *key,
    const uint8_t *in1, size_t in1_len)
{
	struct wg_blake2s_state state;
	wg_blake2s_init(
	    &state,
	    out->as_bytes, sizeof(out->as_bytes),
	    key->as_bytes, sizeof(key->as_bytes));
	wg_blake2s_update(
	    &state,
	    in1, in1_len);
	wg_blake2s_finalize(
	    &state,
	    out->as_bytes,
	    sizeof(out->as_bytes));
	wg_secure_memzero(&state, sizeof(state));
	return 0;
}

int wg_concat_hash(
    union wg_hash *out,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len)
{
	struct wg_blake2s_state state;
	wg_blake2s_init(
	    &state,
	    out->as_bytes, sizeof(out->as_bytes),
	    NULL, 0);
	wg_blake2s_update(
	    &state,
	    in1, in1_len);
	wg_blake2s_update(
	    &state,
	    in2, in2_len);
	wg_blake2s_finalize(
	    &state,
	    out->as_bytes,
	    sizeof(out->as_bytes));
	wg_secure_memzero(&state, sizeof(state));
	return 0;
}

int wg_hmac(
    union wg_hash *out,
    const union wg_key *key,
    const uint8_t *in1, size_t in1_len)
{
	return wg_concat_hmac(out, key, in1, in1_len, NULL, 0);
}

int wg_concat_hmac(
    union wg_hash *out,
    const union wg_key *key,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len)
{
	struct wg_blake2s_state state;
	uint8_t key_xor_pad[wg_hash_len];
	uint8_t ihash[wg_hash_len];

	// Eliminates need to hash key to compress to block size. See HMAC definition.
	_Static_assert(sizeof(key->as_bytes) == wg_hash_len, "");

	for (int i = 0; i < wg_hash_len; i++) {
		key_xor_pad[i] = key->as_bytes[i] ^ 0x36;
	}

	wg_blake2s_init(&state, ihash, sizeof(ihash), key->as_bytes, sizeof(key->as_bytes));
	wg_blake2s_update(&state, key_xor_pad, sizeof(key_xor_pad));
	wg_blake2s_update(&state, in1, in1_len);
	wg_blake2s_update(&state, in2, in2_len);
	wg_blake2s_finalize(&state, ihash, sizeof(ihash));

	for (int i = 0; i < wg_hash_len; i++) {
		key_xor_pad[i] = key->as_bytes[i] ^ 0x5c;
	}

	wg_blake2s_init(&state, out->as_bytes, sizeof(out->as_bytes), key->as_bytes, sizeof(key->as_bytes));
	wg_blake2s_update(&state, key_xor_pad, sizeof(key_xor_pad));
	wg_blake2s_update(&state, ihash, sizeof(ihash));
	wg_blake2s_finalize(&state, out->as_bytes, sizeof(out->as_bytes));

	wg_secure_memzero(&key_xor_pad, sizeof(key_xor_pad));
	wg_secure_memzero(&ihash, sizeof(ihash));
	wg_secure_memzero(&state, sizeof(state));

	return 0;
}
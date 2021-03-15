#include "wireguard/crypto.h"
#include "wireguard/platform.h"

#include "wireguard.h"
#include "wireguard/wireguard.h"

// No zero termination! Lengths are also declared in header; keep in sync.
const uint8_t wg_construction[37] = {"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"};
const uint8_t wg_identifier[34] = {"WireGuard v1 zx2c4 Jason@zx2c4.com"};
const uint8_t wg_label_mac1[8] = {"mac1----"};
const uint8_t wg_label_cookie[8] = {"cookie--"};

int wg_init(void)
{
	if (0 != wg_crypto_init()) {
		return 1; // Error
	}

	return 0; // Success
}

int wg_peer_init(struct wg_peer *peer)
{
	wg_secure_memzero(peer, sizeof(struct wg_peer));

	return 0; // Success
}

int wg_peer_fini(struct wg_peer *peer)
{
	wg_secure_memzero(peer, sizeof(struct wg_peer));

	return 0; // Success
}

int wg_peer_set_local_public_key_base64(struct wg_peer *peer, const char *base64_key, size_t base64_key_len)
{
	union wg_key key;
	int ret = 1; // Error

	if (0 != wg_base64_to_key(&key, base64_key, base64_key_len)) {
		goto out;
	}

	if (0 != wg_peer_set_local_public_key(peer, &key)) {
		goto out;
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&key, sizeof(key));
	return ret;
}

int wg_peer_set_local_private_key_base64(struct wg_peer *peer, const char *base64_key, size_t base64_key_len)
{
	union wg_key key;
	int ret = 1; // Error

	if (0 != wg_base64_to_key(&key, base64_key, base64_key_len)) {
		goto out;
	}

	if (0 != wg_peer_set_local_private_key(peer, &key)) {
		goto out;
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&key, sizeof(key));
	return ret;
}

int wg_peer_set_remote_public_key_base64(struct wg_peer *peer, const char *base64_key, size_t base64_key_len)
{
	union wg_key key;
	int ret = 1; // Error

	if (0 != wg_base64_to_key(&key, base64_key, base64_key_len)) {
		goto out;
	}

	if (0 != wg_peer_set_remote_public_key(peer, &key)) {
		goto out;
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&key, sizeof(key));
	return ret;
}

int wg_peer_set_local_public_key(struct wg_peer *peer, union wg_key *key)
{
	peer->local_static_public = *key;
	return 0;
}

int wg_peer_set_local_private_key(struct wg_peer *peer, union wg_key *key)
{
	peer->local_static_private = *key;
	return 0;
}

int wg_peer_set_remote_public_key(struct wg_peer *peer, union wg_key *key)
{
	peer->remote_static_public = *key;
	return 0;
}

int wg_peer_set_mtu(struct wg_peer *peer, int mtu)
{
	peer->mtu = mtu;
	return 0;
}

int wg_peer_set_busy(struct wg_peer *peer, bool busy)
{
	peer->cookie_required = busy;
	return 0;
}
int wg_window_init(struct wg_window *window)
{
	memset(window, 0, sizeof(struct wg_window));
	return 0;
}

// Checks whether the received sequence number / nonce is still valid.
// Returns 0 if valid, 1 if invalid.
// Must be used after authentication tag verification.
//
// The spec allows two algorithms. This implements the one from RFC2401 appendix C,
// which is simpler and has slightly lower memory requirements than the one from RFC6479.
//
// Changes from RFC version:
//
// 1. uint64_t sequence number
// 2. accept sequence number 0
// 3. invert return code meaning
int wg_window_check(struct wg_window *window, uint64_t seq)
{
	uint64_t const replay_window_size = 32;

	// New, larger sequence number?
	if (seq > window->last_seq) {
		uint64_t diff = seq - window->last_seq;

		// In window?
		if (diff < replay_window_size) {
			window->bitmap <<= diff;

			// Set bit for this packet
			window->bitmap |= 1;
		} else {
			// This packet has a "way larger" sequence number
			window->bitmap = 1;
		}

		window->last_seq = seq;

		return 0; // Valid

	} else { // Not larger
		uint64_t diff = window->last_seq - seq;

		// Too old, or wrapped?
		if (diff > replay_window_size) {
			return 1; // Invalid
		}

		// Already seen?
		if (window->bitmap & ((uint64_t)1 << diff)) {
			return 1; // Invalid
		}

		// Mark as seen
		window->bitmap |= ((uint64_t)1 << diff);

		// Out of order, but in window
		return 0; // Valid
	}
}

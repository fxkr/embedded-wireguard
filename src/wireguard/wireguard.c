#include "wireguard/crypto.h"
#include "wireguard/platform.h"

#include "wireguard/wireguard.h"

// No zero termination! Lengths are also declared in header; keep in sync.
const uint8_t wg_construction[37] = {"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"};
const uint8_t wg_identifier[34] = {"WireGuard v1 zx2c4 Jason@zx2c4.com"};
const uint8_t wg_label_mac1[8] = {"mac1----"};
const uint8_t wg_label_cookie[8] = {"cookie--"};

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

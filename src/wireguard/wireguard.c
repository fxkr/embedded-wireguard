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

int wg_peer_verify_mac1(struct wg_peer *peer, uint8_t *data, size_t data_len, union wg_mac *mac1)
{
	int ret = 1; // Error
	union wg_mac temp_mac;
	union wg_key temp_key;

	if (0 != wg_concat_hash(
		     &temp_key.as_hash,
		     wg_label_mac1, sizeof(wg_label_mac1),
		     peer->local_static_public.as_bytes, sizeof(peer->local_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_mac(
		     &temp_mac,
		     &temp_key,
		     data, data_len)) {
		goto out;
	}
	if (!wg_mac_equals(&temp_mac, mac1)) {
		goto out;
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&temp_key, sizeof(temp_key));
	wg_secure_memzero(&temp_mac, sizeof(temp_mac));

	return ret;
}

int wg_peer_verify_mac2(struct wg_peer *peer, const struct wg_sockaddr *src, uint8_t *data, size_t data_len, union wg_mac *mac2)
{
	int ret = 1; // Error
	union wg_mac temp_mac;
	union wg_cookie temp_cookie;

	if (0 != wg_mac(&temp_cookie.as_mac,
			&peer->cookie_secret,
			(uint8_t *)src, sizeof(*src))) {
		goto out;
	}

	if (0 != wg_mac_with_cookie(
		     &temp_mac,
		     &temp_cookie,
		     data, data_len)) {
		goto out;
	}

	if (!wg_mac_equals(&temp_mac, mac2)) {
		goto out;
	}

	ret = 0; // Success

out:
	wg_secure_memzero(&temp_mac, sizeof(temp_mac));
	wg_secure_memzero(&temp_cookie, sizeof(temp_cookie));

	return ret;
}

int wg_peer_generate_handshake_initiation(struct wg_peer *peer, union wg_message_handshake_initiation *msg)
{
	int ret = 1; // Error
	struct wg_session new_session = {};
	union wg_key dh_key;
	union wg_symmetric_key symmetric_msg_key;
	union wg_timestamp timestamp;
	union wg_key temp;

	memset(msg, 0, sizeof(union wg_message_handshake_initiation));
	msg->as_fields.message_type = WG_MESSAGE_HANDSHAKE_INITIATION;

	if (0 != wg_secure_random((uint8_t *)&new_session.local_index, sizeof(new_session.local_index))) {
		goto out;
	}
	msg->as_fields.sender_index_le32 = wg_htole64(new_session.local_index);

	if (0 != wg_hash(
		     &new_session.chaining_key.as_hash,
		     wg_construction, sizeof(wg_construction))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.chaining_key.as_bytes, sizeof(new_session.chaining_key.as_bytes),
		     wg_identifier, sizeof(wg_identifier))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     peer->remote_static_public.as_bytes, sizeof(peer->remote_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh_generate(
		     &new_session.local_ephemeral_private,
		     &new_session.local_ephemeral_public)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &new_session.chaining_key,
		     new_session.local_ephemeral_public.as_bytes, sizeof(new_session.local_ephemeral_public.as_bytes))) {
		goto out;
	}

	msg->as_fields.unencrypted_ephemeral = new_session.local_ephemeral_public;

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     msg->as_fields.unencrypted_ephemeral.as_bytes, sizeof(msg->as_fields.unencrypted_ephemeral.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh(
		     &dh_key,
		     &new_session.local_ephemeral_private,
		     &peer->remote_static_public)) {
		goto out;
	}

	if (0 != wg_kdf2(
		     &new_session.chaining_key.as_hash,
		     &symmetric_msg_key.as_hash,
		     &new_session.chaining_key,
		     dh_key.as_bytes, sizeof(dh_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_aead_encrypt(
		     msg->as_fields.encrypted_static, sizeof(msg->as_fields.encrypted_static),
		     &symmetric_msg_key, 0,
		     peer->local_static_public.as_bytes, sizeof(peer->local_static_public.as_bytes),
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     msg->as_fields.encrypted_static, sizeof(msg->as_fields.encrypted_static))) {
		goto out;
	}

	if (0 != wg_dh(
		     &dh_key,
		     &peer->local_static_private,
		     &peer->remote_static_public)) {
		goto out;
	}

	if (0 != wg_kdf2(
		     &new_session.chaining_key.as_hash,
		     &symmetric_msg_key.as_hash,
		     &new_session.chaining_key,
		     dh_key.as_bytes, sizeof(dh_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_timestamp(&timestamp)) {
		goto out;
	}

	if (0 != wg_aead_encrypt(
		     msg->as_fields.encrypted_timestamp, sizeof(msg->as_fields.encrypted_timestamp),
		     &symmetric_msg_key,
		     0,
		     timestamp.as_bytes, sizeof(timestamp.as_bytes),
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     timestamp.as_bytes, sizeof(timestamp.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &temp.as_hash,
		     wg_label_mac1, sizeof(wg_label_mac1),
		     peer->remote_static_public.as_bytes, sizeof(peer->remote_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_mac(
		     &msg->as_fields.mac1,
		     &temp,
		     msg->as_bytes,
		     offsetof(struct wg_message_handshake_initiation_fields, mac1))) {
		goto out;
	}
	new_session.last_sent_mac1 = msg->as_fields.mac1;

	if (peer->session.received_cookie_valid) {

		// TODO: 120 time time limit not implemented yet, see whitepaper section 5.4.4
		if (0 != wg_mac_with_cookie(
			     &msg->as_fields.mac2,
			     &peer->session.received_cookie,
			     msg->as_bytes, offsetof(struct wg_message_handshake_initiation_fields, mac2))) {
			goto out;
		}
	}

	if (0 != wg_window_init(&new_session.window)) {
		goto out;
	}

	// Success. Persist state changes
	peer->session.local_index = new_session.local_index;
	peer->session.last_sent_mac1 = new_session.last_sent_mac1;
	peer->session.chaining_key = new_session.chaining_key;
	peer->session.window = new_session.window;
	peer->session.local_hash = new_session.local_hash;
	peer->session.local_ephemeral_private = new_session.local_ephemeral_private;
	peer->session.local_ephemeral_public = new_session.local_ephemeral_public;

	ret = 0; // Success

out:
	wg_secure_memzero(&new_session, sizeof(new_session));
	wg_secure_memzero(&dh_key, sizeof(dh_key));
	wg_secure_memzero(&symmetric_msg_key, sizeof(symmetric_msg_key));
	wg_secure_memzero(&timestamp, sizeof(timestamp));
	wg_secure_memzero(&temp, sizeof(temp));

	return ret;
}

int wg_peer_handle_handshake_initiation(struct wg_peer *peer, union wg_message_handshake_initiation *msg, const struct wg_sockaddr *src, bool *out_cookie_required)
{
	int ret = 1; // Error
	struct wg_session new_session = {};
	union wg_symmetric_key symmetric_msg_key;
	union wg_mac temp_mac;
	union wg_key dh_key;
	union wg_timestamp timestamp;
	union wg_key temp;
	union wg_key remote_static_public;

	// Always initialize out parameters for safety reasons
	*out_cookie_required = false;

	if (msg->as_fields.message_type != WG_MESSAGE_HANDSHAKE_INITIATION) {
		goto out;
	}

	if (0 != wg_peer_verify_mac1(
		     peer,
		     msg->as_bytes, offsetof(struct wg_message_handshake_initiation_fields, mac1),
		     &msg->as_fields.mac1)) {
		goto out;
	}

	if (peer->cookie_required) {
		if (0 != wg_peer_verify_mac2(
			     peer,
			     src,
			     msg->as_bytes, offsetof(struct wg_message_handshake_initiation_fields, mac2),
			     &msg->as_fields.mac2)) {

			// MAC2 required and invalid. Caller should send cookie reply
			*out_cookie_required = true;
			goto out;
		}
	}

	if (0 != wg_hash(
		     &new_session.chaining_key.as_hash,
		     wg_construction, sizeof(wg_construction))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.chaining_key.as_bytes, sizeof(new_session.chaining_key.as_bytes),
		     wg_identifier, sizeof(wg_identifier))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes),
		     peer->local_static_public.as_bytes, sizeof(peer->local_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes),
		     msg->as_fields.unencrypted_ephemeral.as_bytes, sizeof(msg->as_fields.unencrypted_ephemeral.as_bytes))) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &new_session.chaining_key,
		     msg->as_fields.unencrypted_ephemeral.as_bytes, sizeof(msg->as_fields.unencrypted_ephemeral.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh(
		     &dh_key,
		     &peer->local_static_private,
		     &msg->as_fields.unencrypted_ephemeral)) {
		goto out;
	}

	if (0 != wg_kdf2(
		     &new_session.chaining_key.as_hash,
		     &symmetric_msg_key.as_hash,
		     &new_session.chaining_key,
		     dh_key.as_bytes, sizeof(dh_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_aead_decrypt(
		     remote_static_public.as_bytes, sizeof(remote_static_public.as_bytes),
		     &symmetric_msg_key, 0,
		     msg->as_fields.encrypted_static, sizeof(msg->as_fields.encrypted_static),
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes))) {
		goto out;
	}

	if (!wg_key_equals(&remote_static_public, &peer->remote_static_public)) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes),
		     msg->as_fields.encrypted_static, sizeof(msg->as_fields.encrypted_static))) {
		goto out;
	}

	if (0 != wg_dh(
		     &dh_key,
		     &peer->local_static_private,
		     &peer->remote_static_public)) {
		goto out;
	}

	if (0 != wg_kdf2(
		     &new_session.chaining_key.as_hash,
		     &symmetric_msg_key.as_hash,
		     &new_session.chaining_key,
		     dh_key.as_bytes, sizeof(dh_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_aead_decrypt(
		     timestamp.as_bytes, sizeof(timestamp.as_bytes),
		     &symmetric_msg_key,
		     0,
		     msg->as_fields.encrypted_timestamp, sizeof(msg->as_fields.encrypted_timestamp),
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes),
		     timestamp.as_bytes, sizeof(timestamp.as_bytes))) {
		goto out;
	}

	// TODO: Handle timestamp
	new_session.remote_index = wg_le32toh(msg->as_fields.sender_index_le32);
	new_session.remote_ephemeral_public = msg->as_fields.unencrypted_ephemeral;

	if (0 != wg_window_init(&new_session.window)) {
		goto out;
	}

	// Success. Persist state changes
	peer->session.chaining_key = new_session.chaining_key;
	peer->session.window = new_session.window;
	peer->session.remote_hash = new_session.remote_hash;
	peer->session.remote_index = new_session.remote_index;
	peer->session.remote_ephemeral_public = new_session.remote_ephemeral_public;

	ret = 0; // Success

out:
	wg_secure_memzero(&remote_static_public, sizeof(remote_static_public));
	wg_secure_memzero(&new_session, sizeof(new_session));
	wg_secure_memzero(&symmetric_msg_key, sizeof(symmetric_msg_key));
	wg_secure_memzero(&temp_mac, sizeof(temp_mac));
	wg_secure_memzero(&dh_key, sizeof(dh_key));
	wg_secure_memzero(&timestamp, sizeof(timestamp));
	wg_secure_memzero(&temp, sizeof(temp));

	return ret;
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

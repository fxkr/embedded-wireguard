#include "wireguard/crypto.h"
#include "wireguard/packet.h"
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

int wg_peer_generate_handshake_response(struct wg_peer *peer, union wg_message_handshake_response *msg)
{
	int ret = 1; // Error

	struct wg_session new_session = {};
	union wg_key temp_key;
	union wg_symmetric_key symmetric_msg_key;

	if (0 != wg_secure_random((uint8_t *)&new_session.local_index, sizeof(new_session.local_index))) {
		goto out;
	}

	memset(msg, 0, sizeof(union wg_message_handshake_response));
	msg->as_fields.message_type = WG_MESSAGE_HANDSHAKE_RESPONSE;
	msg->as_fields.sender_index_le32 = wg_htole32(new_session.local_index);
	msg->as_fields.receiver_index_le32 = wg_htole32(peer->session.remote_index);

	if (0 != wg_dh_generate(
		     &new_session.local_ephemeral_private,
		     &new_session.local_ephemeral_public)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &peer->session.chaining_key,
		     new_session.local_ephemeral_public.as_bytes, sizeof(new_session.local_ephemeral_public.as_bytes))) {
		goto out;
	}

	msg->as_fields.unencrypted_ephemeral = new_session.local_ephemeral_public;

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     new_session.local_ephemeral_public.as_bytes, sizeof(new_session.local_ephemeral_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh(
		     &temp_key,
		     &new_session.local_ephemeral_private,
		     &peer->session.remote_ephemeral_public)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &new_session.chaining_key,
		     temp_key.as_bytes, sizeof(temp_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh(
		     &temp_key,
		     &new_session.local_ephemeral_private,
		     &peer->remote_static_public)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &new_session.chaining_key,
		     temp_key.as_bytes, sizeof(temp_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_kdf3(
		     &new_session.chaining_key.as_hash,
		     &temp_key.as_hash,
		     &symmetric_msg_key.as_hash,
		     &new_session.chaining_key,
		     peer->preshared_key.as_bytes, sizeof(peer->preshared_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     temp_key.as_bytes, sizeof(temp_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_aead_encrypt(
		     msg->as_fields.encrypted_nothing, sizeof(msg->as_fields.encrypted_nothing),
		     &symmetric_msg_key,
		     0,
		     NULL, 0,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.local_hash,
		     new_session.local_hash.as_bytes, sizeof(new_session.local_hash.as_bytes),
		     msg->as_fields.encrypted_nothing, sizeof(msg->as_fields.encrypted_nothing))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &temp_key.as_hash,
		     wg_label_mac1, sizeof(wg_label_mac1),
		     peer->remote_static_public.as_bytes, sizeof(peer->remote_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_mac(
		     &msg->as_fields.mac1,
		     &temp_key,
		     msg->as_bytes,
		     offsetof(struct wg_message_handshake_response_fields, mac1))) {
		goto out;
	}

	if (peer->session.received_cookie_valid) {

		// TODO: 120 time time limit not implemented yet, see whitepaper section 5.4.4
		if (0 != wg_mac_with_cookie(
			     &msg->as_fields.mac2,
			     &peer->session.received_cookie,
			     msg->as_bytes, offsetof(struct wg_message_handshake_response_fields, mac2))) {
			goto out;
		}
	}

	// Transport data key derivation
	if (0 != wg_kdf2(
		     &new_session.receiving_key.as_hash,
		     &new_session.sending_key.as_hash,
		     &new_session.chaining_key,
		     NULL, 0)) {
		goto out;
	}
	new_session.sending_key_valid = true;
	new_session.receiving_key_valid = true;
	new_session.sending_key_counter = 0;
	new_session.receiving_key_counter = 0;
	new_session.last_sent_mac1 = msg->as_fields.mac1;

	// Success. Persist state changes and zeroize fields
	peer->session.local_index = new_session.local_index;
	peer->session.receiving_key = new_session.receiving_key;
	peer->session.sending_key = new_session.sending_key;
	peer->session.receiving_key_valid = new_session.receiving_key_valid;
	peer->session.sending_key_valid = new_session.sending_key_valid;
	peer->session.sending_key_counter = new_session.sending_key_counter;
	peer->session.receiving_key_counter = new_session.receiving_key_counter;
	peer->session.last_sent_mac1 = new_session.last_sent_mac1;
	wg_secure_memzero(&peer->session.local_ephemeral_private, sizeof(peer->session.local_ephemeral_private));
	wg_secure_memzero(&peer->session.local_ephemeral_public, sizeof(peer->session.local_ephemeral_public));
	wg_secure_memzero(&peer->session.remote_ephemeral_public, sizeof(peer->session.remote_ephemeral_public));
	wg_secure_memzero(&peer->session.chaining_key, sizeof(peer->session.chaining_key));
	wg_secure_memzero(&peer->session.local_hash, sizeof(peer->session.local_hash));
	wg_secure_memzero(&peer->session.remote_hash, sizeof(peer->session.remote_hash));

	ret = 0; // Success

out:
	wg_secure_memzero(&new_session, sizeof(new_session));
	wg_secure_memzero(&temp_key, sizeof(temp_key));
	wg_secure_memzero(&symmetric_msg_key, sizeof(symmetric_msg_key));

	return ret;
}

int wg_peer_handle_handshake_response(struct wg_peer *peer, union wg_message_handshake_response *msg, const struct wg_sockaddr *src, bool *out_cookie_required)
{
	int ret = 1; // Error
	struct wg_session new_session = {};
	union wg_key temp_key;
	union wg_mac temp_mac;
	union wg_symmetric_key symmetric_msg_key;

	// Always initialize out parameters for safety reasons
	*out_cookie_required = false;

	if (msg->as_fields.message_type != WG_MESSAGE_HANDSHAKE_RESPONSE) {
		goto out;
	}

	if (peer->session.local_index != wg_le32toh(msg->as_fields.receiver_index_le32)) {
		goto out;
	}

	if (0 != wg_peer_verify_mac1(
		     peer,
		     msg->as_bytes, offsetof(struct wg_message_handshake_response_fields, mac1),
		     &msg->as_fields.mac1)) {
		goto out;
	}

	if (peer->cookie_required) {
		if (0 != wg_peer_verify_mac2(
			     peer,
			     src,
			     msg->as_bytes, offsetof(struct wg_message_handshake_response_fields, mac2),
			     &msg->as_fields.mac2)) {

			// MAC2 required and invalid. Caller should send cookie reply
			*out_cookie_required = true;
			goto out;
		}
	}

	if (0 != wg_concat_hash(
		     &temp_key.as_hash,
		     wg_label_mac1, sizeof(wg_label_mac1),
		     peer->local_static_public.as_bytes, sizeof(peer->local_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_mac(
		     &temp_mac,
		     &temp_key,
		     msg->as_bytes,
		     offsetof(struct wg_message_handshake_response_fields, mac1))) {
		goto out;
	}

	if (!wg_mac_equals(&temp_mac, &msg->as_fields.mac1)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &peer->session.chaining_key,
		     msg->as_fields.unencrypted_ephemeral.as_bytes, sizeof(msg->as_fields.unencrypted_ephemeral.as_bytes))) {
		goto out;
	}

	new_session.remote_ephemeral_public = msg->as_fields.unencrypted_ephemeral;

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     peer->session.remote_hash.as_bytes, sizeof(peer->session.remote_hash.as_bytes),
		     msg->as_fields.unencrypted_ephemeral.as_bytes, sizeof(msg->as_fields.unencrypted_ephemeral.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh(
		     &temp_key,
		     &peer->session.local_ephemeral_private,
		     &new_session.remote_ephemeral_public)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &new_session.chaining_key,
		     temp_key.as_bytes, sizeof(temp_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_dh(
		     &temp_key,
		     &peer->local_static_private,
		     &new_session.remote_ephemeral_public)) {
		goto out;
	}

	if (0 != wg_kdf1(
		     &new_session.chaining_key.as_hash,
		     &new_session.chaining_key,
		     temp_key.as_bytes, sizeof(temp_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_kdf3(
		     &new_session.chaining_key.as_hash,
		     &temp_key.as_hash,
		     &symmetric_msg_key.as_hash,
		     &new_session.chaining_key,
		     peer->preshared_key.as_bytes, sizeof(peer->preshared_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes),
		     temp_key.as_bytes, sizeof(temp_key.as_bytes))) {
		goto out;
	}

	if (0 != wg_aead_decrypt(
		     NULL, 0,
		     &symmetric_msg_key,
		     0,
		     msg->as_fields.encrypted_nothing, sizeof(msg->as_fields.encrypted_nothing),
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &new_session.remote_hash,
		     new_session.remote_hash.as_bytes, sizeof(new_session.remote_hash.as_bytes),
		     msg->as_fields.encrypted_nothing, sizeof(msg->as_fields.encrypted_nothing))) {
		goto out;
	}

	new_session.remote_index = wg_le32toh(msg->as_fields.sender_index_le32);

	// Transport data key derivation
	if (0 != wg_kdf2(
		     &new_session.sending_key.as_hash,
		     &new_session.receiving_key.as_hash,
		     &new_session.chaining_key,
		     NULL, 0)) {
		goto out;
	}
	new_session.sending_key_valid = true;
	new_session.receiving_key_valid = true;
	new_session.sending_key_counter = 0;
	new_session.receiving_key_counter = 0;

	// Success. Persist state changes and zeroize fields
	peer->session.remote_index = new_session.remote_index;
	peer->session.sending_key = new_session.sending_key;
	peer->session.receiving_key = new_session.receiving_key;
	peer->session.sending_key_valid = new_session.sending_key_valid;
	peer->session.receiving_key_valid = new_session.receiving_key_valid;
	peer->session.sending_key_counter = new_session.sending_key_counter;
	peer->session.receiving_key_counter = new_session.receiving_key_counter;
	wg_secure_memzero(&peer->session.local_ephemeral_private, sizeof(peer->session.local_ephemeral_private));
	wg_secure_memzero(&peer->session.local_ephemeral_public, sizeof(peer->session.local_ephemeral_public));
	wg_secure_memzero(&peer->session.remote_ephemeral_public, sizeof(peer->session.remote_ephemeral_public));
	wg_secure_memzero(&peer->session.chaining_key, sizeof(peer->session.chaining_key));
	wg_secure_memzero(&peer->session.local_hash, sizeof(peer->session.local_hash));
	wg_secure_memzero(&peer->session.remote_hash, sizeof(peer->session.remote_hash));

	ret = 0;

out:
	wg_secure_memzero(&new_session, sizeof(new_session));
	wg_secure_memzero(&temp_key, sizeof(temp_key));
	wg_secure_memzero(&temp_mac, sizeof(temp_mac));
	wg_secure_memzero(&symmetric_msg_key, sizeof(symmetric_msg_key));

	return ret;
}

int wg_peer_generate_message_data(struct wg_peer *peer, struct wg_packet *pkt)
{
	int ret = 1; // Error

	if (!peer->session.sending_key_valid) {
		goto out;
	}

	size_t plaintext_len = wg_packet_data_len(pkt);
	size_t ciphertext_len = wg_aead_len(plaintext_len);
	if (ciphertext_len > peer->mtu) {
		goto out;
	}

	size_t padding_len = (-ciphertext_len & 15); // Round up to multiple of 16
	if (ciphertext_len + padding_len > peer->mtu) {
		// TODO: Account for outer IP and UDP headers
		padding_len = peer->mtu - ciphertext_len;
	}

	wg_packet_put_zero(pkt, padding_len + wg_aead_len(0));
	plaintext_len += padding_len;
	ciphertext_len += padding_len;

	// Prepend WireGuard header
	uint8_t *payload = pkt->data;
	union wg_message_data *wg_hdr = (union wg_message_data *)wg_packet_push(pkt, sizeof(union wg_message_data));
	wg_hdr->as_fields.message_type = WG_MESSAGE_DATA;
	memset(wg_hdr->as_fields.reserved_zero, 0, sizeof(wg_hdr->as_fields.reserved_zero));
	wg_hdr->as_fields.receiver_index_le32 = wg_htole32(peer->session.remote_index);
	wg_hdr->as_fields.counter_le64 = wg_htole64(peer->session.sending_key_counter);

	// Encrypt payload in-place
	if (0 != wg_aead_encrypt(
		     payload, ciphertext_len,
		     &peer->session.sending_key,
		     peer->session.sending_key_counter,
		     payload, plaintext_len,
		     NULL, 0)) {
		goto out;
	}

	peer->session.sending_key_counter++;

	ret = 0; // Success

out:
	return ret;
}

int wg_peer_handle_message_data(struct wg_peer *peer, struct wg_packet *pkt)
{
	int ret = 1; // Error

	if (!peer->session.receiving_key_valid) {
		goto out;
	}

	// Get header and payload pointers
	if (wg_packet_data_len(pkt) < sizeof(union wg_message_data)) {
		goto out;
	}
	union wg_message_data *wg_hdr = (union wg_message_data *)pkt->data;
	if (wg_hdr->as_fields.message_type != WG_MESSAGE_DATA) {
		goto out;
	}
	if (wg_le32toh(wg_hdr->as_fields.receiver_index_le32) != peer->session.local_index) {
		goto out;
	}
	uint8_t *payload = wg_packet_pull(pkt, sizeof(union wg_message_data));

	// Calculate expected payload length
	size_t plaintext_payload_len = wg_packet_data_len(pkt) - wg_aead_len(0);
	if (wg_packet_data_len(pkt) < wg_aead_len(0)) {
		goto out;
	}

	// Decrypt payload in-place
	if (0 != wg_aead_decrypt(
		     payload, plaintext_payload_len,
		     &peer->session.receiving_key,
		     wg_le64toh(wg_hdr->as_fields.counter_le64),
		     payload, wg_packet_data_len(pkt),
		     NULL, 0)) {
		goto out;
	}

	// Verify sequence number (_after_ authentication!)
	if (0 != wg_window_check(&peer->session.window, wg_le64toh(wg_hdr->as_fields.counter_le64))) {
		goto out;
	}

	// Payload is shorter than ciphertext due to authentication tag
	wg_packet_trim(pkt, plaintext_payload_len);

	ret = 0; // Success

out:
	return ret;
}

int wg_generate_message_cookie_reply(struct wg_peer *peer, union wg_message_cookie_reply *msg,
				     const struct wg_sockaddr *remote_addr, uint64_t remote_index, union wg_mac *remote_mac1)
{
	int ret = 1; // Error
	union wg_mac temp_mac;
	union wg_symmetric_key temp_key;

	memset(msg, 0, sizeof(union wg_message_cookie_reply));
	msg->as_fields.message_type = WG_MESSAGE_HANDSHAKE_COOKIE;
	msg->as_fields.receiver_index_le32 = wg_htole64(remote_index);

	if (0 != wg_secure_random(msg->as_fields.nonce.as_bytes, sizeof(msg->as_fields.nonce.as_bytes))) {
		goto out;
	}

	if (0 != wg_mac(&temp_mac,
			&peer->cookie_secret,
			(uint8_t *)remote_addr, sizeof(*remote_addr))) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &temp_key.as_hash,
		     wg_label_cookie, sizeof(wg_label_cookie),
		     peer->local_static_public.as_bytes, sizeof(peer->local_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_xaead(
		     msg->as_fields.encrypted_cookie, sizeof(msg->as_fields.encrypted_cookie),
		     &temp_key,
		     &msg->as_fields.nonce,
		     temp_mac.as_bytes, sizeof(temp_mac.as_bytes),
		     remote_mac1->as_bytes, sizeof(remote_mac1->as_bytes))) {
		goto out;
	}

	ret = 0; // Success

out:
	return ret;
}

int wg_handle_message_cookie_reply(struct wg_peer *peer, union wg_message_cookie_reply *msg)
{
	int ret = 1; // Error
	union wg_cookie received_cookie;
	union wg_timestamp received_cookie_timestamp;
	union wg_symmetric_key temp_key;

	if (msg->as_fields.message_type != WG_MESSAGE_HANDSHAKE_COOKIE) {
		goto out;
	}

	if (0 != wg_concat_hash(
		     &temp_key.as_hash,
		     wg_label_cookie, sizeof(wg_label_cookie),
		     peer->remote_static_public.as_bytes, sizeof(peer->remote_static_public.as_bytes))) {
		goto out;
	}

	if (0 != wg_xaead_decrypt(
		     received_cookie.as_bytes, sizeof(received_cookie.as_bytes),
		     &temp_key,
		     &msg->as_fields.nonce,
		     msg->as_fields.encrypted_cookie, sizeof(msg->as_fields.encrypted_cookie),
		     peer->session.last_sent_mac1.as_bytes, sizeof(peer->session.last_sent_mac1.as_bytes))) {
		goto out;
	}

	if (0 != wg_timestamp(&received_cookie_timestamp)) {
		goto out;
	}

	// Success. persist state changes
	peer->session.received_cookie = received_cookie;
	peer->session.received_cookie_timestamp = received_cookie_timestamp;
	peer->session.received_cookie_valid = true;

	ret = 0; // Success

out:
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

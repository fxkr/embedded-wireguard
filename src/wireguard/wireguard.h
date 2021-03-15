#ifndef WG_WIREGUARD_H
#define WG_WIREGUARD_H

// This is core of the internal API of Embedded WireGuard.

#include "wireguard/crypto.h"
#include "wireguard/packet.h"
#include "wireguard/platform.h"

enum wg_message_type {
	WG_MESSAGE_INVALID = 0,
	WG_MESSAGE_HANDSHAKE_INITIATION = 1,
	WG_MESSAGE_HANDSHAKE_RESPONSE = 2,
	WG_MESSAGE_HANDSHAKE_COOKIE = 3,
	WG_MESSAGE_DATA = 4
};

struct wg_message_handshake_initiation_fields {
	uint8_t message_type;
	uint8_t reserved_zero[3];
	uint32_t sender_index_le32;
	union wg_key unencrypted_ephemeral;
	uint8_t encrypted_static[wg_aead_len(wg_key_len)];
	uint8_t encrypted_timestamp[wg_aead_len(wg_timestamp_len)];
	union wg_mac mac1;
	union wg_mac mac2;
} __attribute__((packed));

struct wg_message_handshake_response_fields {
	uint8_t message_type;
	uint8_t reserved_zero[3];
	uint32_t sender_index_le32;
	uint32_t receiver_index_le32;
	union wg_key unencrypted_ephemeral;
	uint8_t encrypted_nothing[wg_aead_len(0)];
	union wg_mac mac1;
	union wg_mac mac2;
} __attribute__((packed));

struct wg_message_data_fields {
	uint8_t message_type;
	uint8_t reserved_zero[3];
	uint32_t receiver_index_le32;
	uint64_t counter_le64;
	uint8_t encrypted_encapsulated_packet[0];
} __attribute__((packed));

struct wg_message_cookie_reply_fields {
	uint8_t message_type;
	uint8_t reserved_zero[3];
	uint32_t receiver_index_le32;
	union wg_xaead_nonce nonce;
	uint8_t encrypted_cookie[wg_aead_len(16)];
} __attribute__((packed));

union wg_message_handshake_initiation {
	uint8_t as_bytes[sizeof(struct wg_message_handshake_initiation_fields)];
	struct wg_message_handshake_initiation_fields as_fields;
} __attribute__((packed));

union wg_message_handshake_response {
	uint8_t as_bytes[sizeof(struct wg_message_handshake_response_fields)];
	struct wg_message_handshake_response_fields as_fields;
} __attribute__((packed));

union wg_message_data {
	uint8_t as_bytes[sizeof(struct wg_message_data_fields)];
	struct wg_message_data_fields as_fields;
} __attribute__((packed));

union wg_message_cookie_reply {
	uint8_t as_bytes[sizeof(struct wg_message_cookie_reply_fields)];
	struct wg_message_cookie_reply_fields as_fields;
} __attribute__((packed));

// Used to track sequence numbers seen, so that we can defend against replay attacks.
struct wg_window {
	uint32_t bitmap;
	uint64_t last_seq;
};

// Dynamic state that is calculated during and after a handshake,
// such as ephemeral keys, transport keys and counters.
// Any handshake will start with all of these fields zeroed.
//
// We deviate from the whitepaper in that we split variables by local/remote,
// not initiator/responder. This simplifies the code because each peer can act
// either as initiator or as responder. But it means variable names don't quite
// map 1:1 to the whitepaper.
struct wg_session {
	uint32_t local_index;  // Name in whitepaper: I_*
	uint32_t remote_index; // Name in whitepaper: I_*

	union wg_key local_ephemeral_private; // Name in whitepaper: E^priv_*
	union wg_key local_ephemeral_public;  // Name in whitepaper: E^pub_*
	union wg_key remote_ephemeral_public; // Name in whitepaper: E^pub_*

	uint64_t sending_key_counter;	    // Name in whitepaper: N^send_*
	union wg_symmetric_key sending_key; // Name in whitepaper: T^send_*
	bool sending_key_valid;		    // False until sending key has been derived.

	uint64_t receiving_key_counter;	      // Name in whitepaper: N^recv_*
	union wg_symmetric_key receiving_key; // Name in whitepaper: T^recv_*
	bool receiving_key_valid;	      // False until receiving key has been derived.

	union wg_hash local_hash;  // Name in whitepaper: H_*
	union wg_hash remote_hash; // Name in whitepaper: H_*
	union wg_key chaining_key; // Name in whitepaper: C_*

	// The MAC1 of the last handshake initiation or reply we sent.
	/// Used to verify incoming cookie message.
	union wg_mac last_sent_mac1;
	bool received_cookie_valid; // False until last_sent_mac1 has been set.

	// Last correctly received cookie, used to calculate MAC2 in sent handshake messages.
	union wg_cookie received_cookie;
	union wg_timestamp received_cookie_timestamp; // When received_cookie was received.

	// Used to track received sequence numbers to prevent replay attacks.
	struct wg_window window;
};

// Represents a tunnel to a specific peer. Contains both static configuration
// and more dynamic session state.
struct wg_peer {
	struct wg_session session;

	union wg_symmetric_key preshared_key; // Name in whitepaper: Q. Optional - may be all zeroes.
	union wg_key local_static_public;     // Name in whitepaper: S^pub_*
	union wg_key local_static_private;    // Name in whitepaper: S^priv_*
	union wg_key remote_static_public;    // Name in whitepaper: S^pub_*

	// Maximum MTU we can use to send packets to the peer.
	// This is the underlay MTU. The useable overlay MTU will be less than this by:
	//
	// * Underlay IP header (20 bytes IPv4, or 40 bytes IPv6, plus options respectively)
	// * Underlay UDP header (8 byte)
	// * WireGuard transport header (32 byte)
	size_t mtu;

	// True if the local peer currently requires valid MAC2 on received handshake messages.
	bool cookie_required;

	// Random data used to generate cookies. Supposed to change every 2 minutes.
	// Name in whitepaper: R_m
	union wg_key cookie_secret;
};

extern const uint8_t wg_construction[37]; // No zero termination!
extern const uint8_t wg_identifier[34];	  // No zero termination!
extern const uint8_t wg_label_mac1[8];	  // No zero termination!
extern const uint8_t wg_label_cookie[8];  // No zero termination!
extern const uint8_t wg_zero[1];	  // No zero termination!

_Static_assert(sizeof(struct wg_message_handshake_initiation_fields) == sizeof(union wg_message_handshake_initiation), "");
_Static_assert(sizeof(struct wg_message_handshake_response_fields) == sizeof(union wg_message_handshake_response), "");
_Static_assert(sizeof(struct wg_message_data_fields) == sizeof(union wg_message_data), "");
_Static_assert(sizeof(struct wg_message_cookie_reply_fields) == sizeof(union wg_message_cookie_reply), "");

_Static_assert(sizeof(struct wg_message_handshake_initiation_fields) == 148, "");
_Static_assert(sizeof(struct wg_message_handshake_response_fields) == 92, "");
_Static_assert(sizeof(struct wg_message_data_fields) == 16, "");
_Static_assert(sizeof(struct wg_message_cookie_reply_fields) == 64, "");

_Static_assert(offsetof(struct wg_message_handshake_initiation_fields, mac1) == 116, "");
_Static_assert(offsetof(struct wg_message_handshake_initiation_fields, mac2) == 132, "");
_Static_assert(offsetof(struct wg_message_handshake_response_fields, mac1) == 60, "");
_Static_assert(offsetof(struct wg_message_handshake_response_fields, mac2) == 76, "");

int __attribute__((warn_unused_result)) wg_init(void);

int __attribute__((warn_unused_result)) wg_peer_init(struct wg_peer *peer);
int __attribute__((warn_unused_result)) wg_peer_fini(struct wg_peer *peer);

int __attribute__((warn_unused_result)) wg_peer_verify_mac1(struct wg_peer *peer, uint8_t *data, size_t data_len, union wg_mac *mac1);
int __attribute__((warn_unused_result)) wg_peer_verify_mac2(struct wg_peer *peer, const struct wg_sockaddr *src, uint8_t *data, size_t data_len, union wg_mac *mac2);

int __attribute__((warn_unused_result)) wg_peer_generate_handshake_initiation(struct wg_peer *peer, union wg_message_handshake_initiation *msg);
int __attribute__((warn_unused_result)) wg_peer_handle_handshake_initiation(struct wg_peer *peer, union wg_message_handshake_initiation *msg, const struct wg_sockaddr *src, bool *out_cookie_required);

int __attribute__((warn_unused_result)) wg_peer_generate_handshake_response(struct wg_peer *peer, union wg_message_handshake_response *msg);
int __attribute__((warn_unused_result)) wg_peer_handle_handshake_response(struct wg_peer *peer, union wg_message_handshake_response *msg, const struct wg_sockaddr *src, bool *out_cookie_required);

int __attribute__((warn_unused_result)) wg_peer_generate_message_data(struct wg_peer *peer, struct wg_packet *pkt);
int __attribute__((warn_unused_result)) wg_peer_handle_message_data(struct wg_peer *peer, struct wg_packet *pkt);

int __attribute__((warn_unused_result)) wg_generate_message_cookie_reply(struct wg_peer *peer, union wg_message_cookie_reply *msg, const struct wg_sockaddr *remote_addr, uint64_t remote_index, union wg_mac *remote_mac1);
int __attribute__((warn_unused_result)) wg_handle_message_cookie_reply(struct wg_peer *peer, union wg_message_cookie_reply *msg);

int __attribute__((warn_unused_result)) wg_peer_set_local_public_key(struct wg_peer *peer, union wg_key *key);
int __attribute__((warn_unused_result)) wg_peer_set_local_private_key(struct wg_peer *peer, union wg_key *key);
int __attribute__((warn_unused_result)) wg_peer_set_remote_public_key(struct wg_peer *peer, union wg_key *key);

int __attribute__((warn_unused_result)) wg_peer_set_local_public_key_base64(struct wg_peer *peer, const char *base64_key, size_t base64_key_len);
int __attribute__((warn_unused_result)) wg_peer_set_local_private_key_base64(struct wg_peer *peer, const char *base64_key, size_t base64_key_len);
int __attribute__((warn_unused_result)) wg_peer_set_remote_public_key_base64(struct wg_peer *peer, const char *base64_key, size_t base64_key_len);

int __attribute__((warn_unused_result)) wg_peer_set_mtu(struct wg_peer *peer, int mtu);

int __attribute__((warn_unused_result)) wg_peer_set_busy(struct wg_peer *peer, bool busy);

int __attribute__((warn_unused_result)) wg_window_init(struct wg_window *window);
int __attribute__((warn_unused_result)) wg_window_check(struct wg_window *window, uint64_t seq);

#endif
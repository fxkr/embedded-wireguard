#ifndef WG_WIREGUARD_H
#define WG_WIREGUARD_H

// This is core of the internal API of Embedded WireGuard.

#include "wireguard/crypto.h"
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
int __attribute__((warn_unused_result)) wg_window_init(struct wg_window *window);
int __attribute__((warn_unused_result)) wg_window_check(struct wg_window *window, uint64_t seq);

#endif
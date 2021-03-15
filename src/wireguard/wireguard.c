#include "wireguard/crypto.h"
#include "wireguard/platform.h"

#include "wireguard/wireguard.h"

// No zero termination! Lengths are also declared in header; keep in sync.
const uint8_t wg_construction[37] = {"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"};
const uint8_t wg_identifier[34] = {"WireGuard v1 zx2c4 Jason@zx2c4.com"};
const uint8_t wg_label_mac1[8] = {"mac1----"};
const uint8_t wg_label_cookie[8] = {"cookie--"};

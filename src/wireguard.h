#ifndef WG_WIREGUARD_API_H
#define WG_WIREGUARD_API_H

#ifdef __cplusplus
extern "C" {
#endif

// This is the public interface to Embedded WireGuard.
// Include only this header: #include <wireguard.h>
//
// Unless documented differently, any function with an int return type
// returns 0 for success, and a non-zero value for failure.
// That value is currently always 1, however callers must not depend on this
// and must treat any non-zero value as a failure.
//
// Unless documented differently, functions have all-or-nothing behavior.
// In other words, any function that returns an error has no side effects.

// This function must be called at least once before any other Embedded WireGuard
// functions are used. It is safe to call it any number of times.
int __attribute__((warn_unused_result)) wg_init(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif
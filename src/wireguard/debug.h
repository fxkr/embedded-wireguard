#ifndef WG_DEBUG_H
#define WG_DEBUG_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

// Don't use; use the wg_debug_assert macro instead.
static inline void wg_debug_assert_func(bool condition, char *file, long line)
{
#ifdef WG_DEBUG
	if (!condition) {
		printf("%s:%ld - assertion failed\n", file, line);
		abort();
	}
#endif
}

// If debug mode enabled _and_ condition not met, log and abort. Otherwise do nothing.
#define wg_debug_assert(CONDITION) wg_debug_assert_func((CONDITION), __FILE__, __LINE__)

#endif
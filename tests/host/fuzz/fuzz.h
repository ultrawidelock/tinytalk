/* SPDX-License-Identifier: ISC */

/**
 * @file fuzz.h — what every libFuzzer target here shares.
 *
 * libFuzzer hands each input over in a heap block of exactly that size, so a
 * parser that reads one byte past its input is an AddressSanitizer report.
 * A decoder can also hand back a pointer and a length into the input; touch()
 * reads every byte of such a span, so a span that runs past the input fails
 * in the same way.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static inline void touch(const void *p, size_t n)
{
	const volatile uint8_t *b = (const volatile uint8_t *)p;
	uint8_t acc = 0u;

	for (size_t i = 0u; i < n; i++) {
		acc ^= b[i];
	}
	(void)acc;
}

/* An invariant the parser promised and broke. */
#define FUZZ_REQUIRE(cond)                                                                         \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			__builtin_trap();                                                          \
		}                                                                                  \
	} while (0)

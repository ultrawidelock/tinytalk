/* SPDX-License-Identifier: ISC */

/**
 * @file fuzz_btp.c — BTP reassembly over a stream of fragments.
 *
 * Input: one byte choosing the reassembly area size, one byte for the first
 * sequence number, then fragments, each prefixed by its one-byte length.
 */
#include <tinymatter/matter_btp.h>

#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static uint8_t area[1024];
	struct matter_btp_rx rx;
	size_t cap;
	size_t off = 2u;

	if (size < 2u) {
		return 0;
	}
	cap = 1u + (size_t)data[0] * 4u;
	matter_btp_rx_init(&rx, area, cap, data[1]);

	while (off < size) {
		size_t n = data[off++];
		int rc;

		if (n > size - off) {
			n = size - off;
		}
		rc = matter_btp_rx_fragment(&rx, data + off, n);
		off += n;
		FUZZ_REQUIRE(rx.len <= cap);
		if (rc == MATTER_END) {
			touch(rx.buf, rx.len);
			matter_btp_rx_reset(&rx);
		} else if (rc != MATTER_OK) {
			/* What the transport does after an error latches. */
			matter_btp_rx_init(&rx, area, cap, data[1]);
		}
	}
	return 0;
}

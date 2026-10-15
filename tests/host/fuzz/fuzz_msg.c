/* SPDX-License-Identifier: ISC */

/** @file fuzz_msg.c — the message header, then the protocol header behind it. */
#include <tinymatter/matter_msg.h>

#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct matter_msg_header h;
	struct matter_proto_header ph;
	size_t used = 0u;
	size_t pused = 0u;
	uint8_t out[64];
	size_t written = 0u;

	if (matter_msg_header_decode(data, size, &h, &used) != MATTER_OK) {
		return 0;
	}
	FUZZ_REQUIRE(used <= size);
	(void)matter_msg_header_encode(&h, out, sizeof(out), &written);
	FUZZ_REQUIRE(written <= sizeof(out));

	if (matter_proto_header_decode(data + used, size - used, &ph, &pused) == MATTER_OK) {
		FUZZ_REQUIRE(pused <= size - used);
		(void)matter_proto_header_encode(&ph, out, sizeof(out), &written);
		FUZZ_REQUIRE(written <= sizeof(out));
	}
	return 0;
}

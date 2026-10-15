/* SPDX-License-Identifier: ISC */

/**
 * @file fuzz_im.c — the Interaction Model request decoders.
 *
 * Input: one byte choosing the decoder, then the payload it is handed.
 */
#include <tinymatter/matter_im.h>

#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *p = data + 1;
	size_t n;

	if (size < 1u) {
		return 0;
	}
	n = size - 1u;

	switch (data[0] % 6u) {
	case 0: {
		struct matter_im_read rd;

		if (matter_im_read_request_decode(p, n, &rd) == MATTER_OK) {
			FUZZ_REQUIRE(rd.n_paths <= MATTER_IM_MAX_PATHS);
		}
		break;
	}
	case 1: {
		struct matter_im_subscribe sub;

		if (matter_im_subscribe_request_decode(p, n, &sub) == MATTER_OK) {
			FUZZ_REQUIRE(sub.read.n_paths <= MATTER_IM_MAX_PATHS);
		}
		break;
	}
	case 2: {
		struct matter_im_write wr;

		(void)matter_im_write_request_decode(p, n, &wr);
		break;
	}
	case 3: {
		struct matter_im_invoke inv;

		(void)matter_im_invoke_request_decode(p, n, &inv);
		break;
	}
	case 4: {
		uint8_t status;

		(void)matter_im_status_response_decode(p, n, &status);
		break;
	}
	default: {
		uint16_t timeout_ms;

		(void)matter_im_timed_request_decode(p, n, &timeout_ms);
		break;
	}
	}
	return 0;
}

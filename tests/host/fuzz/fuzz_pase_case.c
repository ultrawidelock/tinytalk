/* SPDX-License-Identifier: ISC */

/**
 * @file fuzz_pase_case.c — the first message of each handshake: PASE's
 * PBKDFParamRequest and CASE's Sigma1.
 *
 * Input: one byte choosing the decoder, then the payload it is handed.
 */
#include <tinymatter/matter_case.h>
#include <tinymatter/matter_pase.h>

#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *p = data + 1;
	size_t n;

	if (size < 1u) {
		return 0;
	}
	n = size - 1u;

	if ((data[0] & 1u) == 0u) {
		struct matter_pase_pbkdf_req req;

		(void)matter_pase_pbkdf_req_decode(p, n, &req);
	} else {
		struct matter_case_sigma1 s1;

		if (matter_case_sigma1_decode(p, n, &s1) == MATTER_OK) {
			/* Every span points into the input; reading it all is the check. */
			touch(s1.initiator_random, 32u);
			touch(s1.destination_id, 32u);
			touch(s1.initiator_pubkey, 65u);
			if (s1.has_resumption) {
				touch(s1.resumption_id, s1.resumption_id_len);
			}
		}
	}
	return 0;
}

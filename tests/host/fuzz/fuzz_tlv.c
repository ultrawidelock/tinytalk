/* SPDX-License-Identifier: ISC */

/** @file fuzz_tlv.c — the TLV reader, walked to the bottom of every container. */
#include <tinymatter/matter_tlv.h>

#include "fuzz.h"

static void walk(struct matter_tlv_reader *r, unsigned depth)
{
	while (matter_tlv_next(r) == MATTER_TLV_OK) {
		bool b;
		uint64_t u;
		int64_t i;
		const uint8_t *p;
		const char *s;
		size_t n;

		(void)matter_tlv_tag(r);
		(void)matter_tlv_element_type(r);
		(void)matter_tlv_get_bool(r, &b);
		(void)matter_tlv_get_u64(r, &u);
		(void)matter_tlv_get_i64(r, &i);
		if (matter_tlv_get_bytes(r, &p, &n) == MATTER_TLV_OK) {
			touch(p, n);
		}
		if (matter_tlv_get_utf8(r, &s, &n) == MATTER_TLV_OK) {
			touch(s, n);
		}
		if (matter_tlv_is_container(r) && depth < 64u &&
		    matter_tlv_enter(r) == MATTER_TLV_OK) {
			walk(r, depth + 1u);
			if (matter_tlv_exit(r) != MATTER_TLV_OK) {
				return;
			}
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct matter_tlv_reader r;

	matter_tlv_reader_init(&r, data, size);
	walk(&r, 0u);

	/* Again with implicit-profile tags allowed, which takes another path. */
	matter_tlv_reader_init(&r, data, size);
	matter_tlv_reader_set_implicit_profile(&r, 0x0000FFF1u);
	walk(&r, 0u);
	return 0;
}

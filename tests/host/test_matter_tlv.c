/**
 * @file test_matter_tlv.c — Matter TLV encoder against CHIP's own golden bytes.
 *
 * The two multi-container vectors are copied from the vendored CHIP SDK,
 * workspace/modules/lib/matter/src/lib/core/tests/TestTLV.cpp: Encoding3 at
 * :2042-2048 and Encoding2 at :1898-1910, with TestProfile_1 = 0xAABBCCDD and
 * TestProfile_2 = 0x11223344 from :54-55. Pinning a foreign implementation's
 * output is the point -- a round-trip against our own reader would pass just as
 * happily if both halves shared a misreading of the spec.
 *
 * The single-element cases are derived from the constant tables (TLVTypes.h:60-86
 * element types, TLVTags.h:105-112 tag controls) rather than quoted, and are
 * marked as such below.
 */
#include <string.h>

#include <tinymatter/matter_tlv.h>

#include "test.h"

#define TEST_PROFILE_1 0xAABBCCDDu
#define TEST_PROFILE_2 0x11223344u

/**
 * Walk a whole document, entering every container and TOUCHING every value.
 *
 * The touching is the point: a decoder that hands back a pointer past the end
 * of the buffer looks perfectly healthy until something dereferences it, so the
 * last byte of every string is read here and `make test-san` turns that into a
 * hard failure. Iterative, like the decoder itself.
 */
static int walk_all(const uint8_t *doc, size_t n, uint32_t implicit)
{
	struct matter_tlv_reader r;

	matter_tlv_reader_init(&r, doc, n);
	matter_tlv_reader_set_implicit_profile(&r, implicit);

	for (;;) {
		bool b;
		uint64_t u;
		int64_t i;
		const uint8_t *p;
		const char *s;
		size_t l;
		int rc = matter_tlv_next(&r);

		if (rc == MATTER_TLV_END) {
			if (r.depth == 0u) {
				return MATTER_TLV_OK;
			}
			rc = matter_tlv_exit(&r);
			if (rc != MATTER_TLV_OK) {
				return rc;
			}
			continue;
		}
		if (rc != MATTER_TLV_OK) {
			return rc;
		}
		if (matter_tlv_is_container(&r)) {
			rc = matter_tlv_enter(&r);
			if (rc != MATTER_TLV_OK) {
				return rc;
			}
			continue;
		}
		(void)matter_tlv_get_bool(&r, &b);
		(void)matter_tlv_get_u64(&r, &u);
		(void)matter_tlv_get_i64(&r, &i);
		if (matter_tlv_get_bytes(&r, &p, &l) == MATTER_TLV_OK && l != 0u) {
			volatile uint8_t touch = p[l - 1u];
			(void)touch;
		}
		if (matter_tlv_get_utf8(&r, &s, &l) == MATTER_TLV_OK && l != 0u) {
			volatile char touch = s[l - 1u];
			(void)touch;
		}
	}
}

/** Every value the decoder is allowed to return from walk_all. */
static int known_code(int rc)
{
	return rc == MATTER_TLV_OK || rc == MATTER_TLV_E_INVAL || rc == MATTER_TLV_E_DEPTH ||
	       rc == MATTER_TLV_E_STATE || rc == MATTER_TLV_E_TRUNC || rc == MATTER_TLV_E_TYPE;
}

void test_matter_tlv(void)
{
	uint8_t buf[64];
	struct matter_tlv_writer w;
	size_t len;

	t_group("single elements (derived from the constant tables)");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	T_EQ("bool true rc", matter_tlv_put_bool(&w, MATTER_TLV_ANON, true), MATTER_TLV_OK);
	T_EQ("bool true finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("anon bool true", buf, len, "09");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_null(&w, MATTER_TLV_ANON);
	T_EQ("null finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("anon null", buf, len, "14");

	/* Context tag 1 + UInt8 = 0x20 | 0x04, one tag octet, then the value. */
	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1), 42u);
	T_EQ("ctx u8 finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("ctx1 uint 42", buf, len, "24012a");

	/* Signed values pick the narrowest width: -17 fits Int8, so 0x20 | 0x00. */
	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_i64(&w, MATTER_TLV_CTX(0), -17);
	T_EQ("ctx i8 finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("ctx0 int -17", buf, len, "2000ef");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 0x1234u);
	T_EQ("u16 finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("anon uint 0x1234 is 2-octet", buf, len, "053412");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_utf8(&w, MATTER_TLV_ANON, "Hello!", 6u);
	T_EQ("utf8 finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("anon utf8 Hello!", buf, len, "0c0648656c6c6f21");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_ANON, (const uint8_t *)"\x00\x01\x02\x03\x04",
				   5u);
	T_EQ("bytes finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("anon octets 0..4", buf, len, "10050001020304");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_end_container(&w);
	T_EQ("empty struct finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	t_vec("empty anon structure", buf, len, "1518");

	t_group("CHIP TestTLV.cpp Encoding3 (:2042-2048)");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	matter_tlv_writer_set_implicit_profile(&w, TEST_PROFILE_2);
	(void)matter_tlv_start_container(&w, MATTER_TLV_PROFILE(TEST_PROFILE_1, 1),
					 MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_PROFILE(TEST_PROFILE_2, 2), false);
	(void)matter_tlv_end_container(&w);
	T_EQ("Encoding3 finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	T_EQ("Encoding3 length", (long)len, 11L);
	t_vec("Encoding3", buf, len, "d5bbaaddcc010088020018");

	t_group("CHIP TestTLV.cpp Encoding2 (:1898-1910)");

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	matter_tlv_writer_set_implicit_profile(&w, TEST_PROFILE_2);
	(void)matter_tlv_start_container(&w, MATTER_TLV_PROFILE(TEST_PROFILE_1, 1),
					 MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_PROFILE(TEST_PROFILE_1, 2), true);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_PROFILE(TEST_PROFILE_2, 2), false);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_start_container(&w, MATTER_TLV_PROFILE(TEST_PROFILE_2, 1),
					 MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_PROFILE(TEST_PROFILE_2, 2), false);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_PROFILE(TEST_PROFILE_1, 2), true);
	(void)matter_tlv_end_container(&w);
	T_EQ("Encoding2 finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	T_EQ("Encoding2 length", (long)len, 32L);
	t_vec("Encoding2", buf, len,
	      "d5bbaaddcc0100c9bbaaddcc020088020018950100880200c9bbaaddcc020018");

	t_group("implicit profile is opt-in");

	/* Same tag, no implicit profile nominated, so it must go fully qualified. */
	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_put_bool(&w, MATTER_TLV_PROFILE(TEST_PROFILE_2, 2), false);
	T_EQ("no-implicit finish", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
	/* 0x11223344 splits vendor 0x1122 then profile 0x3344, each little-endian,
	 * the same way Encoding3 splits 0xAABBCCDD into bb aa dd cc. */
	t_vec("profile tag without implicit", buf, len, "c8221144330200");

	t_group("errors are latched, not silent");

	/* One byte short of the two an anonymous 1-octet uint needs. */
	matter_tlv_writer_init(&w, buf, 1u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 42u);
	T_EQ("overflow latches NOSPACE", matter_tlv_writer_finish(&w, &len), MATTER_TLV_E_NOSPACE);

	/* Sticky: a later put on a failed writer must not resurrect it. */
	T_EQ("later put keeps the error", matter_tlv_put_bool(&w, MATTER_TLV_ANON, true),
	     MATTER_TLV_E_NOSPACE);

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	T_EQ("unclosed container fails finish", matter_tlv_writer_finish(&w, &len),
	     MATTER_TLV_E_STATE);

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	T_EQ("end without start", matter_tlv_end_container(&w), MATTER_TLV_E_STATE);

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	T_EQ("bad container type", matter_tlv_start_container(&w, MATTER_TLV_ANON, 0x04u),
	     MATTER_TLV_E_INVAL);

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	for (int i = 0; i < MATTER_TLV_MAX_DEPTH; i++) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
	}
	T_EQ("depth cap holds", w.rc, MATTER_TLV_OK);
	T_EQ("one past the cap fails",
	     matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY), MATTER_TLV_E_DEPTH);
	t_group("decode: CHIP Encoding3 round-trips structurally");
	{
		static const uint8_t doc[] = {0xd5, 0xbb, 0xaa, 0xdd, 0xcc, 0x01,
					      0x00, 0x88, 0x02, 0x00, 0x18};
		struct matter_tlv_reader r;
		bool b = true;

		matter_tlv_reader_init(&r, doc, sizeof(doc));
		matter_tlv_reader_set_implicit_profile(&r, TEST_PROFILE_2);

		T_EQ("d3 next", matter_tlv_next(&r), MATTER_TLV_OK);
		T_OK("d3 is container", matter_tlv_is_container(&r));
		T_EQ("d3 container type", matter_tlv_element_type(&r), MATTER_TLV_STRUCTURE);
		T_OK("d3 container tag",
		     matter_tlv_tag(&r) == MATTER_TLV_PROFILE(TEST_PROFILE_1, 1));
		T_EQ("d3 enter", matter_tlv_enter(&r), MATTER_TLV_OK);
		T_EQ("d3 child", matter_tlv_next(&r), MATTER_TLV_OK);
		T_OK("d3 child tag decodes implicit",
		     matter_tlv_tag(&r) == MATTER_TLV_PROFILE(TEST_PROFILE_2, 2));
		T_EQ("d3 child bool", matter_tlv_get_bool(&r, &b), MATTER_TLV_OK);
		T_EQ("d3 child value", (long)b, 0L);
		T_EQ("d3 level ends", matter_tlv_next(&r), MATTER_TLV_END);
		T_EQ("d3 exit", matter_tlv_exit(&r), MATTER_TLV_OK);
		T_EQ("d3 document ends", matter_tlv_next(&r), MATTER_TLV_END);
	}

	t_group("decode: CHIP Encoding2, and skipping a container is not entering it");
	{
		static const uint8_t doc[] = {0xd5, 0xbb, 0xaa, 0xdd, 0xcc, 0x01, 0x00, 0xc9,
					      0xbb, 0xaa, 0xdd, 0xcc, 0x02, 0x00, 0x88, 0x02,
					      0x00, 0x18, 0x95, 0x01, 0x00, 0x88, 0x02, 0x00,
					      0xc9, 0xbb, 0xaa, 0xdd, 0xcc, 0x02, 0x00, 0x18};
		struct matter_tlv_reader r;

		matter_tlv_reader_init(&r, doc, sizeof(doc));
		matter_tlv_reader_set_implicit_profile(&r, TEST_PROFILE_2);

		/* Never enter either container: next() must step over the whole of the
		 * first one and land on the second. */
		T_EQ("d2 first", matter_tlv_next(&r), MATTER_TLV_OK);
		T_OK("d2 first tag", matter_tlv_tag(&r) == MATTER_TLV_PROFILE(TEST_PROFILE_1, 1));
		T_EQ("d2 skips to second", matter_tlv_next(&r), MATTER_TLV_OK);
		T_OK("d2 second tag", matter_tlv_tag(&r) == MATTER_TLV_PROFILE(TEST_PROFILE_2, 1));
		T_OK("d2 second is container", matter_tlv_is_container(&r));
		T_EQ("d2 ends", matter_tlv_next(&r), MATTER_TLV_END);

		T_EQ("d2 full walk", walk_all(doc, sizeof(doc), TEST_PROFILE_2), MATTER_TLV_OK);

		t_group("decode: every truncation of Encoding2 is refused, never over-read");
		{
			int bad = 0;

			for (size_t n = 0; n < sizeof(doc); n++) {
				int rc = walk_all(doc, n, TEST_PROFILE_2);

				if (!known_code(rc)) {
					bad++;
				}
			}
			T_EQ("no unknown status from any prefix", bad, 0);
			/* 18 bytes is the first container, complete. It is the one strict
			 * prefix that is a valid document, and it must parse. */
			T_EQ("prefix 18 is a whole document", walk_all(doc, 18u, TEST_PROFILE_2),
			     MATTER_TLV_OK);
			T_EQ("prefix 17 is truncated", walk_all(doc, 17u, TEST_PROFILE_2),
			     MATTER_TLV_E_TRUNC);
		}
	}

	t_group("decode: scalars round-trip through the writer");
	{
		static const int64_t signed_cases[] = {0,
						       -1,
						       42,
						       -17,
						       127,
						       -128,
						       128,
						       -129,
						       32767,
						       -32768,
						       2147483647LL,
						       -2147483648LL,
						       9223372036854775807LL};
		static const uint64_t unsigned_cases[] = {
			0u,          1u,          255u,
			256u,        65535u,      65536u,
			4294967295u, 4294967296u, 18446744073709551615ull};
		struct matter_tlv_reader r;

		for (size_t k = 0; k < sizeof(signed_cases) / sizeof(signed_cases[0]); k++) {
			int64_t got = 0;

			matter_tlv_writer_init(&w, buf, sizeof(buf));
			(void)matter_tlv_put_i64(&w, MATTER_TLV_CTX(3), signed_cases[k]);
			T_EQ("i64 encode", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
			matter_tlv_reader_init(&r, buf, len);
			T_EQ("i64 next", matter_tlv_next(&r), MATTER_TLV_OK);
			T_EQ("i64 get", matter_tlv_get_i64(&r, &got), MATTER_TLV_OK);
			T_OK("i64 value survives", got == signed_cases[k]);
		}

		for (size_t k = 0; k < sizeof(unsigned_cases) / sizeof(unsigned_cases[0]); k++) {
			uint64_t got = 0;

			matter_tlv_writer_init(&w, buf, sizeof(buf));
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4), unsigned_cases[k]);
			T_EQ("u64 encode", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);
			matter_tlv_reader_init(&r, buf, len);
			T_EQ("u64 next", matter_tlv_next(&r), MATTER_TLV_OK);
			T_EQ("u64 get", matter_tlv_get_u64(&r, &got), MATTER_TLV_OK);
			T_OK("u64 value survives", got == unsigned_cases[k]);
		}
	}

	t_group("decode: strings are borrowed, not copied");
	{
		struct matter_tlv_reader r;
		const char *s = NULL;
		const uint8_t *p = NULL;
		size_t l = 0;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_put_utf8(&w, MATTER_TLV_CTX(1), "Hello!", 6u);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(2), (const uint8_t *)"\xde\xad", 2u);
		T_EQ("strings encode", matter_tlv_writer_finish(&w, &len), MATTER_TLV_OK);

		matter_tlv_reader_init(&r, buf, len);
		T_EQ("utf8 next", matter_tlv_next(&r), MATTER_TLV_OK);
		T_EQ("utf8 get", matter_tlv_get_utf8(&r, &s, &l), MATTER_TLV_OK);
		T_EQ("utf8 len", (long)l, 6L);
		T_OK("utf8 content", memcmp(s, "Hello!", 6u) == 0);
		T_OK("utf8 points into the caller's buffer", s >= (const char *)buf);
		T_EQ("utf8 not readable as bytes", matter_tlv_get_bytes(&r, &p, &l),
		     MATTER_TLV_E_TYPE);

		T_EQ("bytes next", matter_tlv_next(&r), MATTER_TLV_OK);
		T_EQ("bytes get", matter_tlv_get_bytes(&r, &p, &l), MATTER_TLV_OK);
		T_EQ("bytes len", (long)l, 2L);
		T_EQ("bytes content", (long)p[0], 0xdeL);
		T_EQ("bytes not readable as utf8", matter_tlv_get_utf8(&r, &s, &l),
		     MATTER_TLV_E_TYPE);
	}

	t_group("decode: hostile input");
	{
		struct matter_tlv_reader r;
		uint64_t u = 0;

		/* Octet string claiming 200 bytes with 2 present. */
		static const uint8_t liar[] = {0x10, 0xc8, 0x01, 0x02};

		T_EQ("declared length past the buffer", walk_all(liar, sizeof(liar), 0u),
		     MATTER_TLV_E_TRUNC);

		/* 4-octet length field claiming almost 4 GiB. */
		static const uint8_t huge[] = {0x12, 0xff, 0xff, 0xff, 0xff, 0x00};

		T_EQ("4-octet length is bounded", walk_all(huge, sizeof(huge), 0u),
		     MATTER_TLV_E_TRUNC);

		/* End-of-container with nothing open. */
		static const uint8_t stray[] = {0x18};

		T_EQ("stray end marker", walk_all(stray, sizeof(stray), 0u), MATTER_TLV_E_INVAL);

		/* Unassigned element type 0x19. */
		static const uint8_t bogus[] = {0x19};

		T_EQ("unassigned element type", walk_all(bogus, sizeof(bogus), 0u),
		     MATTER_TLV_E_INVAL);

		/* Implicit-profile tag with no implicit profile supplied: refused, not
		 * guessed, because there is no correct value to guess. */
		static const uint8_t implicit[] = {0x88, 0x02, 0x00};

		matter_tlv_reader_init(&r, implicit, sizeof(implicit));
		T_EQ("implicit tag without a profile", matter_tlv_next(&r), MATTER_TLV_E_INVAL);

		/* Nesting deeper than the cap, never closed. Skipping it must hit the
		 * counter, not the call stack. */
		static const uint8_t deep[] = {0x16, 0x16, 0x16, 0x16, 0x16, 0x16,
					       0x16, 0x16, 0x16, 0x16, 0x16, 0x16};

		matter_tlv_reader_init(&r, deep, sizeof(deep));
		T_EQ("deep nest loads", matter_tlv_next(&r), MATTER_TLV_OK);
		T_EQ("skipping a too-deep nest is refused", matter_tlv_next(&r),
		     MATTER_TLV_E_DEPTH);

		/* Reading before any next(). */
		matter_tlv_reader_init(&r, implicit, sizeof(implicit));
		T_EQ("get before next", matter_tlv_get_u64(&r, &u), MATTER_TLV_E_STATE);
		T_EQ("exit at top level", matter_tlv_exit(&r), MATTER_TLV_E_STATE);
	}
}

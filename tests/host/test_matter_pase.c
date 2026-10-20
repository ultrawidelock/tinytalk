/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_matter_pase.c — the five PASE commissioning messages.
 *
 * The golden bytes are not ours. They were produced by CircuitMatter's OWN TLV
 * encoder (circuitmatter/tlv.py), driven by the structures at
 * circuitmatter/pase.py:31-85, in a script that never touches this code. So
 * this suite checks two things at once: that our PASE field numbering matches
 * an independent implementation, and that matter_tlv.c produces the same bytes
 * a different TLV writer does. PASE is the first real consumer of that codec.
 *
 * The tag numbers are additionally confirmed against CHIP
 * (PASESession.cpp:60-95), so every number here has two sources.
 */
#include <string.h>

#include <tinytalk/matter_mrp.h>
#include <tinytalk/matter_pase.h>

#include "test.h"

/* Produced by CircuitMatter's tlv.py; see the file comment. */
static const char *const K_REQ =
	"15300120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2502341224030028"
	"0418";
static const char *const K_RESP =
	"15300120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f3002204041424344"
	"45464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f2503a55a35042501e80330021080818283"
	"8485868788898a8b8c8d8e8f1818";
static const char *const K_PAKE1 =
	"1530014104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"
	"2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f18";
static const char *const K_PAKE2 =
	"1530014104000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526"
	"2728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f300220202122232425262728292a2b2c2d2e2f"
	"303132333435363738393a3b3c3d3e3f18";
/*
 * REAL WIRE BYTES. Extracted from adafruit/circuitmatter's
 * test_data/apple_recorded_packets.jsonl, a recorded commissioning by an actual
 * iPhone against a real node. These are the PASE payloads only -- the Secure
 * Channel protocol headers were stripped and no addresses are reproduced.
 *
 * Everything else in this suite is derived: from CHIP's source, from
 * CircuitMatter's encoder, from the spec. These five are the only bytes here
 * that an Apple controller actually put on a wire.
 */
static const char *const K_APPLE_REQ =
	"15300120a882bce8bfdeab50e04ac596bfc05024db5902b7512ed9b278cfaacc125230122502b6e424030028"
	"0435052501f40125022c012503a00f24041224050b2606000004012407011818";
static const char *const K_APPLE_RESP =
	"15300120a882bce8bfdeab50e04ac596bfc05024db5902b7512ed9b278cfaacc12523012300220b09aea1140"
	"9a97cfc3b5079e0bde89d0f230145383475974c560a505efb25969240301350425011027300220e6e08fd084"
	"c763323da8111eea17d4e077d8df2ed5a294a4d2a36f86fce786241818";
static const char *const K_APPLE_PAKE1 =
	"1530014104eed348b3b4afab1b33b4b421cbc6deea8a1d832bf9e0b955d8253edb1f8b2c199750ee0b24fc5e"
	"b90d5f44483b05c05a3098b9a4908ddcbaf961e6f87cbcd72b18";
static const char *const K_APPLE_PAKE2 =
	"153001410492f502e899ae0a85367551053f49f1e0d4f8c3437f8550fe99af51c734ddb1ae7c6c388fe60986"
	"c2c1232e773427f97fc3a578820b901c28fa10a5dd5d5550d2300220445f2918b40b5f8571c6e6eb3b74cb60"
	"6b14f20cf36fd8b09e6b98b9336bd68418";
static const char *const K_APPLE_PAKE3 =
	"15300120f04ed65efe58a197035f89f6daa79878779cf82912928a407ec2aeb5cf1311a118";

static const char *const K_PAKE3 =
	"15300120202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f18";

void test_matter_pase(void)
{
	uint8_t vec[256];
	uint8_t out[256];
	int vlen;
	size_t n = 0;

	t_group("PBKDFParamRequest");
	{
		struct matter_pase_pbkdf_req req;

		vlen = t_unhex(vec, K_REQ, sizeof(vec));
		T_EQ("vector parses", vlen, 46L);

		T_EQ("decode", matter_pase_pbkdf_req_decode(vec, (size_t)vlen, &req), MATTER_OK);
		T_EQ("session id", req.initiator_session_id, 0x1234L);
		T_EQ("passcode id", req.passcode_id, 0L);
		T_OK("has params is false", !req.has_pbkdf_params);
		T_EQ("random[0]", req.initiator_random[0], 0x00L);
		T_EQ("random[31]", req.initiator_random[31], 0x1FL);

		T_EQ("re-encode", matter_pase_pbkdf_req_encode(&req, out, sizeof(out), &n),
		     MATTER_OK);
		T_EQ("same length", (long)n, (long)vlen);
		T_OK("byte-identical to CircuitMatter", memcmp(out, vec, n) == 0);
	}

	t_group("PBKDFParamResponse");
	{
		struct matter_pase_pbkdf_resp resp;

		vlen = t_unhex(vec, K_RESP, sizeof(vec));
		T_EQ("vector parses", vlen, 102L);

		T_EQ("decode", matter_pase_pbkdf_resp_decode(vec, (size_t)vlen, &resp), MATTER_OK);
		T_EQ("responder session id", resp.responder_session_id, 0x5AA5L);
		T_OK("pbkdf params present", resp.pbkdf_params_present);
		T_EQ("iterations", (long)resp.iterations, 1000L);
		T_EQ("salt length", resp.salt_len, 16L);
		T_EQ("salt[0]", resp.salt[0], 0x80L);
		T_EQ("salt[15]", resp.salt[15], 0x8FL);
		T_EQ("initiator random echoed", resp.initiator_random[31], 0x1FL);
		T_EQ("responder random", resp.responder_random[0], 0x40L);

		T_EQ("re-encode", matter_pase_pbkdf_resp_encode(&resp, out, sizeof(out), &n),
		     MATTER_OK);
		T_EQ("same length", (long)n, (long)vlen);
		T_OK("byte-identical to CircuitMatter", memcmp(out, vec, n) == 0);
	}

	t_group("Pake1, Pake2, Pake3");
	{
		struct matter_pase_pake1 p1;
		struct matter_pase_pake2 p2;
		struct matter_pase_pake3 p3;

		vlen = t_unhex(vec, K_PAKE1, sizeof(vec));
		T_EQ("decode pake1", matter_pase_pake1_decode(vec, (size_t)vlen, &p1), MATTER_OK);
		T_EQ("pA is an uncompressed point", p1.pa[0], 0x04L);
		T_EQ("pA[64]", p1.pa[64], 0x3FL);
		T_EQ("re-encode", matter_pase_pake1_encode(&p1, out, sizeof(out), &n), MATTER_OK);
		T_OK("byte-identical", (long)n == (long)vlen && memcmp(out, vec, n) == 0);

		vlen = t_unhex(vec, K_PAKE2, sizeof(vec));
		T_EQ("decode pake2", matter_pase_pake2_decode(vec, (size_t)vlen, &p2), MATTER_OK);
		T_EQ("pB", p2.pb[0], 0x04L);
		T_EQ("cB[0]", p2.cb[0], 0x20L);
		T_EQ("cB[31]", p2.cb[31], 0x3FL);
		T_EQ("re-encode", matter_pase_pake2_encode(&p2, out, sizeof(out), &n), MATTER_OK);
		T_OK("byte-identical", (long)n == (long)vlen && memcmp(out, vec, n) == 0);

		vlen = t_unhex(vec, K_PAKE3, sizeof(vec));
		T_EQ("decode pake3", matter_pase_pake3_decode(vec, (size_t)vlen, &p3), MATTER_OK);
		T_EQ("cA[0]", p3.ca[0], 0x20L);
		T_EQ("re-encode", matter_pase_pake3_encode(&p3, out, sizeof(out), &n), MATTER_OK);
		T_OK("byte-identical", (long)n == (long)vlen && memcmp(out, vec, n) == 0);
	}

	t_group("the response omits PBKDF parameters when the peer has them");
	{
		/* CHIP leaves the whole structure out in that case
		 * (PASESession.cpp:494-502); CircuitMatter cannot express it. Ours
		 * round-trips both shapes. */
		struct matter_pase_pbkdf_resp resp;
		struct matter_pase_pbkdf_resp back;

		memset(&resp, 0, sizeof(resp));
		memset(resp.initiator_random, 0xAA, sizeof(resp.initiator_random));
		memset(resp.responder_random, 0xBB, sizeof(resp.responder_random));
		resp.responder_session_id = 7u;
		resp.pbkdf_params_present = false;

		T_EQ("encode without params",
		     matter_pase_pbkdf_resp_encode(&resp, out, sizeof(out), &n), MATTER_OK);
		T_EQ("decode it back", matter_pase_pbkdf_resp_decode(out, n, &back), MATTER_OK);
		T_OK("still absent", !back.pbkdf_params_present);
		T_EQ("session id survived", back.responder_session_id, 7L);
		T_EQ("iterations left alone", (long)back.iterations, 0L);
	}

	t_group("session parameters are read when present");
	{
		/* Built by hand in the shape SessionParameters.h:52-54 describes:
		 * an inner structure at context tag 5, idle at 1, active at 2.
		 *   15 300120<32 bytes> 250234 12 240300 2804 3505 2501f401 25022c01 18 18 */
		static const char *const with_params = "15300120000102030405060708090a0b0c0d0e0f101"
						       "112131415161718191a1b1c1d1e1f2502"
						       "34122403002804350525"
						       "01f40125022c011818";
		struct matter_pase_pbkdf_req req;

		vlen = t_unhex(vec, with_params, sizeof(vec));
		T_OK("vector parses", vlen > 0);
		T_EQ("decode", matter_pase_pbkdf_req_decode(vec, (size_t)vlen, &req), MATTER_OK);
		T_OK("idle interval seen", req.params.have_idle);
		T_EQ("idle interval", (long)req.params.idle_interval_ms, 500L);
		T_OK("active interval seen", req.params.have_active);
		T_EQ("active interval", (long)req.params.active_interval_ms, 300L);
		/* The fields before and after the nested structure still land. */
		T_EQ("session id", req.initiator_session_id, 0x1234L);
	}

	t_group("real Apple wire capture");
	{
		struct matter_pase_pbkdf_req req;
		struct matter_pase_pbkdf_resp resp;
		struct matter_pase_pake1 p1;
		struct matter_pase_pake2 p2;
		struct matter_pase_pake3 p3;

		vlen = t_unhex(vec, K_APPLE_REQ, sizeof(vec));
		T_EQ("request is 76 bytes", vlen, 76L);
		T_EQ("decode", matter_pase_pbkdf_req_decode(vec, (size_t)vlen, &req), MATTER_OK);
		T_EQ("iPhone session id", req.initiator_session_id, 0xE4B6L);
		T_EQ("passcode id", req.passcode_id, 0L);
		T_OK("does not have PBKDF params", !req.has_pbkdf_params);
		/* The intervals a real iPhone advertises are exactly the defaults
		 * matter_mrp.h took from CHIP and CircuitMatter. */
		T_OK("idle interval present", req.params.have_idle);
		T_EQ("idle 500 ms", (long)req.params.idle_interval_ms,
		     (long)MATTER_MRP_IDLE_INTERVAL_MS);
		T_OK("active interval present", req.params.have_active);
		T_EQ("active 300 ms", (long)req.params.active_interval_ms,
		     (long)MATTER_MRP_ACTIVE_INTERVAL_MS);

		vlen = t_unhex(vec, K_APPLE_RESP, sizeof(vec));
		T_EQ("response is 117 bytes", vlen, 117L);
		T_EQ("decode", matter_pase_pbkdf_resp_decode(vec, (size_t)vlen, &resp), MATTER_OK);
		T_OK("initiator random echoed back",
		     memcmp(resp.initiator_random, req.initiator_random, MATTER_PASE_RANDOM_LEN) ==
			     0);
		T_EQ("responder session id", resp.responder_session_id, 1L);
		T_OK("params present", resp.pbkdf_params_present);
		/* A real exchange uses 10000 iterations and a 32-byte salt. Both sit
		 * inside the bounds this decoder enforces; a tighter ceiling would
		 * have refused a genuine commissioning. */
		T_EQ("iterations", (long)resp.iterations, 10000L);
		T_EQ("salt is the maximum length", resp.salt_len, (long)MATTER_PASE_SALT_MAX);
		T_OK("iterations within our bounds",
		     resp.iterations >= MATTER_PASE_ITER_MIN &&
			     resp.iterations <= MATTER_PASE_ITER_MAX);

		vlen = t_unhex(vec, K_APPLE_PAKE1, sizeof(vec));
		T_EQ("pake1 is 70 bytes", vlen, 70L);
		T_EQ("decode", matter_pase_pake1_decode(vec, (size_t)vlen, &p1), MATTER_OK);
		T_EQ("pA is an uncompressed point", p1.pa[0], 0x04L);

		vlen = t_unhex(vec, K_APPLE_PAKE2, sizeof(vec));
		T_EQ("pake2 is 105 bytes", vlen, 105L);
		T_EQ("decode", matter_pase_pake2_decode(vec, (size_t)vlen, &p2), MATTER_OK);
		T_EQ("pB is an uncompressed point", p2.pb[0], 0x04L);

		vlen = t_unhex(vec, K_APPLE_PAKE3, sizeof(vec));
		T_EQ("pake3 is 37 bytes", vlen, 37L);
		T_EQ("decode", matter_pase_pake3_decode(vec, (size_t)vlen, &p3), MATTER_OK);

		/* Re-encoding must reproduce the wire bytes, or we would be sending
		 * something an iPhone did not send. */
		T_EQ("re-encode pake1", matter_pase_pake1_encode(&p1, out, sizeof(out), &n),
		     MATTER_OK);
		vlen = t_unhex(vec, K_APPLE_PAKE1, sizeof(vec));
		T_OK("pake1 byte-identical", (long)n == (long)vlen && memcmp(out, vec, n) == 0);
		T_EQ("re-encode pake3", matter_pase_pake3_encode(&p3, out, sizeof(out), &n),
		     MATTER_OK);
		vlen = t_unhex(vec, K_APPLE_PAKE3, sizeof(vec));
		T_OK("pake3 byte-identical", (long)n == (long)vlen && memcmp(out, vec, n) == 0);
	}

	t_group("refusals: the peer is not trusted yet");
	{
		struct matter_pase_pbkdf_req req;
		struct matter_pase_pbkdf_resp resp;

		/* Only passcode ID 0 is used for commissioning. */
		vlen = t_unhex(vec, K_REQ, sizeof(vec));
		vec[42] = 0x01u; /* the passcodeId value byte */
		T_EQ("non-zero passcode id", matter_pase_pbkdf_req_decode(vec, (size_t)vlen, &req),
		     MATTER_E_INVAL);

		/* Truncation at every length must be refused, never half-parsed. */
		vlen = t_unhex(vec, K_REQ, sizeof(vec));
		for (int k = 0; k < vlen; k++) {
			T_OK("short request refused",
			     matter_pase_pbkdf_req_decode(vec, (size_t)k, &req) != MATTER_OK);
		}
		T_EQ("full length parses", matter_pase_pbkdf_req_decode(vec, (size_t)vlen, &req),
		     MATTER_OK);

		vlen = t_unhex(vec, K_RESP, sizeof(vec));
		for (int k = 0; k < vlen; k++) {
			T_OK("short response refused",
			     matter_pase_pbkdf_resp_decode(vec, (size_t)k, &resp) != MATTER_OK);
		}

		/* A work factor below the floor makes a stolen salt cheap to attack. */
		{
			static const char *const weak =
				"15300120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
				"1d1e1f300220404142434445464748494a4b4c4d4e4f505152535455565758595a"
				"5b"
				"5c5d5e5f2503a55a35042401013002108081828384858687"
				"88898a8b8c8d8e8f1818";

			vlen = t_unhex(vec, weak, sizeof(vec));
			T_OK("vector parses", vlen > 0);
			T_EQ("one iteration is refused",
			     matter_pase_pbkdf_resp_decode(vec, (size_t)vlen, &resp),
			     MATTER_E_INVAL);
		}

		/* A salt shorter than the minimum, likewise. */
		{
			static const char *const shortsalt =
				"15300120000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
				"1d1e1f300220404142434445464748494a4b4c4d4e4f505152535455565758595a"
				"5b"
				"5c5d5e5f2503a55a35042501e8033002080102030405060708"
				"1818";

			vlen = t_unhex(vec, shortsalt, sizeof(vec));
			T_OK("vector parses", vlen > 0);
			T_EQ("8-byte salt is refused",
			     matter_pase_pbkdf_resp_decode(vec, (size_t)vlen, &resp),
			     MATTER_E_INVAL);
		}

		T_EQ("null buffer", matter_pase_pbkdf_req_decode(NULL, 8u, &req), MATTER_E_INVAL);
		T_EQ("null out", matter_pase_pbkdf_req_decode(vec, 8u, NULL), MATTER_E_INVAL);
		T_EQ("null encode", matter_pase_pake1_encode(NULL, out, sizeof(out), &n),
		     MATTER_E_INVAL);
	}

	t_group("refusals: encoding out-of-range parameters");
	{
		struct matter_pase_pbkdf_resp resp;

		memset(&resp, 0, sizeof(resp));
		resp.pbkdf_params_present = true;
		resp.iterations = 999u; /* below the floor */
		resp.salt_len = 16u;
		T_EQ("iterations too low",
		     matter_pase_pbkdf_resp_encode(&resp, out, sizeof(out), &n), MATTER_E_INVAL);

		resp.iterations = 1000u;
		resp.salt_len = 8u;
		T_EQ("salt too short", matter_pase_pbkdf_resp_encode(&resp, out, sizeof(out), &n),
		     MATTER_E_INVAL);

		resp.salt_len = 33u;
		T_EQ("salt too long", matter_pase_pbkdf_resp_encode(&resp, out, sizeof(out), &n),
		     MATTER_E_INVAL);

		resp.salt_len = 32u;
		T_EQ("in range now", matter_pase_pbkdf_resp_encode(&resp, out, sizeof(out), &n),
		     MATTER_OK);
		T_EQ("no room", matter_pase_pbkdf_resp_encode(&resp, out, 8u, &n),
		     MATTER_E_NOSPACE);
	}
}

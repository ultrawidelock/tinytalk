/**
 * @file test_matter_spake2p.c — PBKDF2, w0/w1, the transcript and the confirmations.
 *
 * The golden values come from python: hashlib's PBKDF2, and a reimplementation
 * of the transcript and Crypto_P2 written from the spec's description rather
 * than from this C. Two of the four things checked here have published
 * definitions independent of Matter entirely (PBKDF2-HMAC-SHA256, and reduction
 * mod the P-256 group order), which is why they are pinned separately from the
 * Matter-specific parts built on them.
 *
 * WHAT IS NOT TESTED HERE: the elliptic curve. matter_spake2p.c calls exactly
 * one oberon primitive, the modular reduction: the real backend's by default,
 * and with SPAKE=fake a plain shift-and-subtract version in tests/host/spakefake.
 * The three curve operations -- check_key, get_key_share, get_ZV -- are never
 * invoked by our glue; test_spake2p_mbedtls.c is where the curve is checked.
 * Z and V therefore arrive as opaque inputs, and this suite treats them so.
 */
#include <string.h>

#include <tinytalk/tm_hash.h>
#include <tinytalk/matter_spake2p.h>

#include "test.h"

void test_matter_spake2p(void)
{
	uint8_t buf[64];
	uint8_t w0[MATTER_SPAKE_SCALAR_LEN];
	uint8_t w1[MATTER_SPAKE_SCALAR_LEN];
	uint8_t salt[32];

	t_group("PBKDF2-HMAC-SHA256 against python's hashlib");
	{
		/* RFC 6070 shapes, recomputed for SHA-256: password "password",
		 * salt "salt", 1 and 2 iterations, 32 bytes out. */
		static const struct {
			const char *pw;
			const char *salt;
			uint32_t iter;
			const char *want;
		} v[] = {
			{"password", "salt", 1u,
			 "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
			{"password", "salt", 2u,
			 "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		};

		for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
			T_EQ("derive",
			     matter_pbkdf2_sha256((const uint8_t *)v[i].pw, strlen(v[i].pw),
						  (const uint8_t *)v[i].salt, strlen(v[i].salt),
						  v[i].iter, buf, 32u),
			     MATTER_OK);
			t_vec("pbkdf2", buf, 32u, v[i].want);
		}

		/* Output longer than one hash block exercises the block counter. */
		T_EQ("80 bytes out",
		     matter_pbkdf2_sha256((const uint8_t *)"password", 8u, (const uint8_t *)"salt",
					  4u, 1u, buf, 48u),
		     MATTER_OK);
		t_vec("first 32 match the single-block case", buf, 32u,
		      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");

		T_EQ("zero iterations refused",
		     matter_pbkdf2_sha256((const uint8_t *)"p", 1u, (const uint8_t *)"s", 1u, 0u,
					  buf, 32u),
		     MATTER_E_INVAL);
		T_EQ("null output refused",
		     matter_pbkdf2_sha256((const uint8_t *)"p", 1u, (const uint8_t *)"s", 1u, 1u,
					  NULL, 32u),
		     MATTER_E_INVAL);
	}

	t_group("reduction mod the P-256 group order");
	{
		/* The host stand-in for oberon's reduce. Pinned on its own so a
		 * failure here is not mistaken for a SPAKE2+ bug. */
		uint8_t xs[40];
		uint8_t r[32];

		memset(xs, 0xFF, sizeof(xs));
		ocrypto_spake2p_p256_reduce(r, xs, sizeof(xs));
		t_vec("all ones", r, sizeof(r),
		      "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550");

		for (size_t i = 0; i < sizeof(xs); i++) {
			xs[i] = (uint8_t)i;
		}
		ocrypto_spake2p_p256_reduce(r, xs, sizeof(xs));
		t_vec("0..39", r, sizeof(r),
		      "0c0e101208070605101155b315cb1c6f2586bfe1f3ca45251f4095c70b3528fd");

		memset(xs, 0, sizeof(xs));
		ocrypto_spake2p_p256_reduce(r, xs, sizeof(xs));
		t_vec("zero", r, sizeof(r),
		      "0000000000000000000000000000000000000000000000000000000000000000");
	}

	t_group("w0 and w1 from a setup passcode");
	{
		/* 20202021 is the standard Matter test passcode. The salt is 32 bytes
		 * of 0x80..0x9f and the work factor 1000, the spec minimum. */
		for (size_t i = 0; i < sizeof(salt); i++) {
			salt[i] = (uint8_t)(0x80u + i);
		}
		T_EQ("derive", matter_spake2p_w0w1(20202021u, salt, sizeof(salt), 1000u, w0, w1),
		     MATTER_OK);
		t_vec("w0", w0, sizeof(w0),
		      "f72aa24219ef2dd5d304817fd0a1f29bac30be2df02c3326c035dcd021233915");
		t_vec("w1", w1, sizeof(w1),
		      "f7e05b6b11db9afffd404e6dc6c030f7344a5c7d5c1159da558456fdee53ffac");

		/* The passcode is hashed LITTLE-endian. Feeding the byte-swapped value
		 * must not land on the same w0, or the endianness would be untested. */
		{
			uint8_t other0[MATTER_SPAKE_SCALAR_LEN];
			uint8_t other1[MATTER_SPAKE_SCALAR_LEN];

			T_EQ("byte-swapped passcode",
			     matter_spake2p_w0w1(0x25D3341u, salt, sizeof(salt), 1000u, other0,
						 other1),
			     MATTER_OK);
			T_OK("gives a different w0", memcmp(other0, w0, sizeof(w0)) != 0);
		}

		T_EQ("null out", matter_spake2p_w0w1(1u, salt, sizeof(salt), 1000u, NULL, w1),
		     MATTER_E_INVAL);
	}

	t_group("commissioning context");
	{
		uint8_t req[20];
		uint8_t resp[32];
		uint8_t ctx[MATTER_SPAKE_HASH_LEN];

		for (size_t i = 0; i < sizeof(req); i++) {
			req[i] = (uint8_t)i;
		}
		for (size_t i = 0; i < sizeof(resp); i++) {
			resp[i] = (uint8_t)(0x40u + i);
		}
		T_EQ("hash", matter_spake2p_context(req, sizeof(req), resp, sizeof(resp), ctx),
		     MATTER_OK);
		t_vec("SHA256(context || req || resp)", ctx, sizeof(ctx),
		      "e2a1cc7dc30d724539fe8dbb8bddf07a67e9d1112c7cf0715d649890a024946e");

		/* It covers the earlier messages, so changing either changes it. */
		{
			uint8_t other[MATTER_SPAKE_HASH_LEN];

			req[0] ^= 0x01u;
			T_EQ("perturbed request",
			     matter_spake2p_context(req, sizeof(req), resp, sizeof(resp), other),
			     MATTER_OK);
			T_OK("changes the context", memcmp(other, ctx, sizeof(ctx)) != 0);
		}

		T_EQ("null out", matter_spake2p_context(req, 4u, resp, 4u, NULL), MATTER_E_INVAL);
	}

	t_group("transcript and confirmations");
	{
		uint8_t ctx[MATTER_SPAKE_HASH_LEN];
		uint8_t pa[MATTER_SPAKE_POINT_LEN];
		uint8_t pb[MATTER_SPAKE_POINT_LEN];
		uint8_t z[MATTER_SPAKE_POINT_LEN];
		uint8_t v[MATTER_SPAKE_POINT_LEN];
		uint8_t tt[600];
		struct matter_spake2p_result res;
		size_t tt_len = sizeof(tt);

		T_EQ("context parses",
		     t_unhex(ctx,
			     "e2a1cc7dc30d724539fe8dbb8bddf07a67e9d1112c7cf0715d649890a024946e",
			     sizeof(ctx)),
		     32L);
		memset(pa, 0x11, sizeof(pa));
		pa[0] = 0x04u;
		memset(pb, 0x22, sizeof(pb));
		pb[0] = 0x04u;
		memset(z, 0x33, sizeof(z));
		z[0] = 0x04u;
		memset(v, 0x44, sizeof(v));
		v[0] = 0x04u;

		T_EQ("build", matter_spake2p_transcript(ctx, pa, pb, z, v, w0, tt, &tt_len),
		     MATTER_OK);
		/* 10 length prefixes + 32 context + 6 points + 32 scalar. */
		T_EQ("length", (long)tt_len, 534L);

		/* The whole transcript pinned by its hash, which is also what P2
		 * consumes -- so a single wrong prefix shows up here first. */
		{
			uint8_t digest[MATTER_SPAKE_HASH_LEN];

			tm_sha256(tt, tt_len, digest);
			t_vec("SHA256(TT)", digest, sizeof(digest),
			      "f4b00baab8ceefecb46539991c7cc9dd4d67d1b9b43f946c82cd2c61f443dc9f");
		}

		/* The two empty identities are still length-prefixed: eight zero bytes
		 * each, right after the context. */
		T_EQ("context prefix", tt[0], 32L);
		for (size_t i = 8u + 32u; i < 8u + 32u + 16u; i++) {
			T_EQ("two empty length prefixes", tt[i], 0L);
		}
		/* M follows them, and it starts with the uncompressed point marker. */
		T_EQ("M length prefix", tt[8u + 32u + 16u], 65L);
		T_EQ("M begins", tt[8u + 32u + 16u + 8u], 0x04L);

		T_EQ("p2", matter_spake2p_p2(tt, tt_len, pa, pb, &res), MATTER_OK);
		t_vec("cA", res.ca, sizeof(res.ca),
		      "44ff0d5911805c4c8afb982d03a1b25225893a83d04116e15209d7c8d9f48877");
		t_vec("cB", res.cb, sizeof(res.cb),
		      "e8210a8c82f850a2a85ed4f4ead5e257ce3f23f718c7a143b3e76d2ad4c73da4");
		t_vec("Ke", res.ke, sizeof(res.ke), "4d67d1b9b43f946c82cd2c61f443dc9f");

		/* cA and cB are over the OTHER side's share. Swapping the arguments
		 * must swap the outputs, which is what proves they are not symmetric. */
		{
			struct matter_spake2p_result swapped;

			T_EQ("p2 swapped", matter_spake2p_p2(tt, tt_len, pb, pa, &swapped),
			     MATTER_OK);
			T_OK("cA changes", memcmp(swapped.ca, res.ca, sizeof(res.ca)) != 0);
			T_OK("cB changes", memcmp(swapped.cb, res.cb, sizeof(res.cb)) != 0);
			T_OK("Ke does not, it comes from the transcript alone",
			     memcmp(swapped.ke, res.ke, sizeof(res.ke)) == 0);
		}

		tt_len = 100u;
		T_EQ("no room", matter_spake2p_transcript(ctx, pa, pb, z, v, w0, tt, &tt_len),
		     MATTER_E_NOSPACE);
		tt_len = sizeof(tt);
		T_EQ("null element",
		     matter_spake2p_transcript(ctx, NULL, pb, z, v, w0, tt, &tt_len),
		     MATTER_E_INVAL);
		T_EQ("null p2", matter_spake2p_p2(NULL, 10u, pa, pb, &res), MATTER_E_INVAL);
	}

	t_group("confirmation compare is constant time");
	{
		uint8_t a[MATTER_SPAKE_HASH_LEN];
		uint8_t b[MATTER_SPAKE_HASH_LEN];

		memset(a, 0x5A, sizeof(a));
		memcpy(b, a, sizeof(b));
		T_OK("equal", matter_spake2p_verify(a, b));

		/* Differences at either end must be caught; an early-exit compare
		 * would still pass this, but the loop has no early exit to leak. */
		b[0] ^= 0x01u;
		T_OK("first byte differs", !matter_spake2p_verify(a, b));
		b[0] ^= 0x01u;
		b[MATTER_SPAKE_HASH_LEN - 1u] ^= 0x01u;
		T_OK("last byte differs", !matter_spake2p_verify(a, b));

		T_OK("null", !matter_spake2p_verify(NULL, b));
	}
}

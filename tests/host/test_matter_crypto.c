/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_matter_crypto.c — AES-128-CCM, the Matter nonce, the key schedule.
 *
 * The golden bytes here came from OpenSSL, via python `cryptography`'s AESCCM
 * and HKDF, generated before the C was written. That is a third independent
 * source: CHIP and CircuitMatter agree on the LAYOUT (which field goes where,
 * what the info string is), but neither hands over test vectors for it, and a
 * cipher that is wrong in a self-consistent way still round-trips.
 *
 * The layout citations are in matter_crypto.h. What this file adds is proof
 * that the bytes leaving this code are the bytes a different AES-CCM produces.
 */
#include <string.h>

#include <tinytalk/matter_crypto.h>

#include "test.h"

/* Fixed inputs; every vector below is over these two. */
static const char *const K_KEY = "000102030405060708090a0b0c0d0e0f";
static const char *const K_NONCE = "202122232425262728292a2b2c";

void test_matter_crypto(void)
{
	uint8_t key[MATTER_KEY_LEN];
	uint8_t nonce[MATTER_NONCE_LEN];
	uint8_t aad[64];
	uint8_t pt[64];
	uint8_t ct[64];
	uint8_t tag[MATTER_TAG_LEN];
	uint8_t out[128];
	struct matter_session_keys keys;
	struct matter_msg_header h;
	size_t n;

	T_EQ("key parses", t_unhex(key, K_KEY, sizeof(key)), (long)sizeof(key));
	T_EQ("nonce parses", t_unhex(nonce, K_NONCE, sizeof(nonce)), (long)sizeof(nonce));

	t_group("nonce: security flags, counter, node id, all little-endian");

	T_EQ("build", matter_build_nonce(0x00u, 0x11223344u, 0x8899AABBCCDDEEFFull, nonce),
	     MATTER_OK);
	t_vec("counter and node id are little-endian", nonce, sizeof(nonce),
	      "0044332211ffeeddccbbaa9988");

	T_EQ("build again", matter_build_nonce(0xC1u, 1u, 0u, nonce), MATTER_OK);
	t_vec("flags lead, zero node id", nonce, sizeof(nonce), "c1010000000000000000000000");
	T_EQ("null out", matter_build_nonce(0u, 0u, 0u, NULL), MATTER_E_INVAL);

	T_EQ("restore nonce", t_unhex(nonce, K_NONCE, sizeof(nonce)), (long)sizeof(nonce));

	t_group("CCM: empty payload still authenticates");

	T_EQ("no aad, no payload", matter_aead_encrypt(key, nonce, NULL, 0u, NULL, 0u, NULL, tag),
	     MATTER_OK);
	t_vec("tag over nothing", tag, sizeof(tag), "382a68ddf01eb18ef032f1d237a8acec");

	T_EQ("aad only", t_unhex(aad, "0001020304050607", sizeof(aad)), 8L);
	T_EQ("aad, no payload", matter_aead_encrypt(key, nonce, aad, 8u, NULL, 0u, NULL, tag),
	     MATTER_OK);
	t_vec("tag covers the aad", tag, sizeof(tag), "2cb6691b9db178b0510dd0b04c41952e");

	t_group("CCM: payload lengths around the block boundary");

	pt[0] = 0xA5u;
	T_EQ("one byte", matter_aead_encrypt(key, nonce, NULL, 0u, pt, 1u, ct, tag), MATTER_OK);
	t_vec("ciphertext", ct, 1u, "cf");
	t_vec("tag", tag, sizeof(tag), "9f97417863b8aa63e414a27353a63b38");

	T_EQ("aad parses", t_unhex(aad, "00010203", sizeof(aad)), 4L);

	T_EQ("15 bytes in", t_unhex(pt, "404142434445464748494a4b4c4d4e", sizeof(pt)), 15L);
	T_EQ("15 bytes", matter_aead_encrypt(key, nonce, aad, 4u, pt, 15u, ct, tag), MATTER_OK);
	t_vec("one short of a block", ct, 15u, "2af4d0857f37e8267afc963d186a54");
	t_vec("tag", tag, sizeof(tag), "53fcad6231e3af2273971fe1ce3e99f8");

	T_EQ("16 bytes in", t_unhex(pt, "404142434445464748494a4b4c4d4e4f", sizeof(pt)), 16L);
	T_EQ("16 bytes", matter_aead_encrypt(key, nonce, aad, 4u, pt, 16u, ct, tag), MATTER_OK);
	t_vec("exactly a block", ct, 16u, "2af4d0857f37e8267afc963d186a542c");
	t_vec("tag", tag, sizeof(tag), "de7cba772ef5d4568804f4c2c6417ee9");

	T_EQ("17 bytes in", t_unhex(pt, "404142434445464748494a4b4c4d4e4f50", sizeof(pt)), 17L);
	T_EQ("17 bytes", matter_aead_encrypt(key, nonce, aad, 4u, pt, 17u, ct, tag), MATTER_OK);
	t_vec("a block and a byte", ct, 17u, "2af4d0857f37e8267afc963d186a542c4c");
	t_vec("tag", tag, sizeof(tag), "9e40d30208f6672e2041c9c77e369b86");

	t_group("CCM: multi-block payload with a full-header aad");

	T_EQ("24-byte aad",
	     t_unhex(aad, "000102030405060708090a0b0c0d0e0f1011121314151617", sizeof(aad)), 24L);
	T_EQ("35-byte payload",
	     t_unhex(pt, "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162",
		     sizeof(pt)),
	     35L);
	T_EQ("encrypt", matter_aead_encrypt(key, nonce, aad, 24u, pt, 35u, ct, tag), MATTER_OK);
	t_vec("ciphertext", ct, 35u,
	      "2af4d0857f37e8267afc963d186a542c4cbadcf8221b37c08291c2f39111c8fbaf548d");
	t_vec("tag", tag, sizeof(tag), "0d78c8e3741c34d15078155ebe6fe637");

	t_group("CCM: decrypt returns the plaintext and refuses tampering");
	{
		uint8_t got[64];
		uint8_t bad[MATTER_TAG_LEN];

		memset(got, 0xEE, sizeof(got));
		T_EQ("decrypt", matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, tag, got),
		     MATTER_OK);
		T_OK("plaintext recovered", memcmp(got, pt, 35u) == 0);

		/* Every input to the MAC must be load-bearing. */
		ct[0] ^= 0x01u;
		memset(got, 0xEE, sizeof(got));
		T_EQ("flipped ciphertext",
		     matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, tag, got), MATTER_E_TYPE);
		T_OK("and the plaintext was wiped, not handed back", got[0] == 0x00u);
		ct[0] ^= 0x01u;

		aad[0] ^= 0x01u;
		T_EQ("flipped aad", matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, tag, got),
		     MATTER_E_TYPE);
		aad[0] ^= 0x01u;

		nonce[0] ^= 0x01u;
		T_EQ("flipped nonce", matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, tag, got),
		     MATTER_E_TYPE);
		nonce[0] ^= 0x01u;

		key[0] ^= 0x01u;
		T_EQ("wrong key", matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, tag, got),
		     MATTER_E_TYPE);
		key[0] ^= 0x01u;

		memcpy(bad, tag, sizeof(bad));
		bad[MATTER_TAG_LEN - 1u] ^= 0x01u;
		T_EQ("flipped tag, last byte",
		     matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, bad, got), MATTER_E_TYPE);

		T_EQ("decrypt after the round trip still works",
		     matter_aead_decrypt(key, nonce, aad, 24u, ct, 35u, tag, got), MATTER_OK);
	}

	t_group("CCM: ciphertext may alias the plaintext");
	{
		uint8_t buf[64];
		uint8_t tag2[MATTER_TAG_LEN];

		memcpy(buf, pt, 35u);
		T_EQ("encrypt in place",
		     matter_aead_encrypt(key, nonce, aad, 24u, buf, 35u, buf, tag2), MATTER_OK);
		T_OK("same ciphertext as the out-of-place run", memcmp(buf, ct, 35u) == 0);
		T_OK("same tag", memcmp(tag2, tag, sizeof(tag2)) == 0);

		T_EQ("decrypt in place",
		     matter_aead_decrypt(key, nonce, aad, 24u, buf, 35u, tag2, buf), MATTER_OK);
		T_OK("plaintext back", memcmp(buf, pt, 35u) == 0);
	}

	t_group("CCM: refusals");

	T_EQ("null key", matter_aead_encrypt(NULL, nonce, NULL, 0u, NULL, 0u, NULL, tag),
	     MATTER_E_INVAL);
	T_EQ("null nonce", matter_aead_encrypt(key, NULL, NULL, 0u, NULL, 0u, NULL, tag),
	     MATTER_E_INVAL);
	T_EQ("null tag", matter_aead_encrypt(key, nonce, NULL, 0u, NULL, 0u, NULL, NULL),
	     MATTER_E_INVAL);
	/* A NULL aad with a non-zero length, or the reverse, is a caller bug that
	 * would otherwise silently authenticate the wrong thing. */
	T_EQ("aad length without aad",
	     matter_aead_encrypt(key, nonce, NULL, 4u, NULL, 0u, NULL, tag), MATTER_E_INVAL);
	T_EQ("aad without a length", matter_aead_encrypt(key, nonce, aad, 0u, NULL, 0u, NULL, tag),
	     MATTER_E_INVAL);
	T_EQ("payload without a buffer",
	     matter_aead_encrypt(key, nonce, NULL, 0u, NULL, 4u, ct, tag), MATTER_E_INVAL);
	T_EQ("aad past the two-byte encoding",
	     matter_aead_encrypt(key, nonce, aad, (size_t)MATTER_AAD_MAX + 1u, NULL, 0u, NULL, tag),
	     MATTER_E_INVAL);
	T_EQ("payload past what L=2 can express",
	     matter_aead_encrypt(key, nonce, NULL, 0u, pt, 0x10000u, ct, tag), MATTER_E_INVAL);
	T_EQ("null key on decrypt", matter_aead_decrypt(NULL, nonce, aad, 24u, ct, 35u, tag, pt),
	     MATTER_E_INVAL);

	t_group("session keys: one HKDF output, three keys");

	{
		static const char *const secret_hex = "808182838485868788898a8b8c8d8e8f";
		uint8_t secret[16];
		uint8_t salt[32];

		T_EQ("secret parses", t_unhex(secret, secret_hex, sizeof(secret)), 16L);

		/* PASE derives with an empty salt. */
		T_EQ("derive, no salt",
		     matter_derive_session_keys(secret, sizeof(secret), NULL, 0u, false, &keys),
		     MATTER_OK);
		t_vec("i2r", keys.i2r, sizeof(keys.i2r), "a3a9e8a1f65b6e8d44a7c4ebfd796335");
		t_vec("r2i", keys.r2i, sizeof(keys.r2i), "dd02c743a4d247fbfd2d576a3c5459a3");
		t_vec("attestation challenge", keys.attestation_challenge,
		      sizeof(keys.attestation_challenge), "9d5d10ad3285e10b9b394a9c18424155");

		/* CASE derives with a salt, and every key must change. */
		T_EQ("salt parses",
		     t_unhex(salt,
			     "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			     sizeof(salt)),
		     32L);
		T_EQ("derive, salted",
		     matter_derive_session_keys(secret, sizeof(secret), salt, sizeof(salt), false,
						&keys),
		     MATTER_OK);
		t_vec("salted i2r", keys.i2r, sizeof(keys.i2r), "ccc5a8a83fee37ec978135324c2f5012");
		t_vec("salted r2i", keys.r2i, sizeof(keys.r2i), "d6f2b4fd3958690617d5a00783bacc7b");
		t_vec("salted challenge", keys.attestation_challenge,
		      sizeof(keys.attestation_challenge), "7f3b40649c0fa497037ebe2ebb219bf2");

		/* The resumption info string must produce different keys from the
		 * same secret, or resumption would reuse a nonce space. */
		{
			struct matter_session_keys resumed;

			T_EQ("derive, resumption",
			     matter_derive_session_keys(secret, sizeof(secret), salt, sizeof(salt),
							true, &resumed),
			     MATTER_OK);
			T_OK("resumption keys differ", memcmp(resumed.i2r, keys.i2r, 16u) != 0);
			T_OK("i2r and r2i are not the same key",
			     memcmp(resumed.i2r, resumed.r2i, 16u) != 0);
		}

		T_EQ("null secret", matter_derive_session_keys(NULL, 4u, NULL, 0u, false, &keys),
		     MATTER_E_INVAL);
		T_EQ("empty secret", matter_derive_session_keys(secret, 0u, NULL, 0u, false, &keys),
		     MATTER_E_INVAL);
		T_EQ("null out",
		     matter_derive_session_keys(secret, sizeof(secret), NULL, 0u, false, NULL),
		     MATTER_E_INVAL);
		T_EQ("salt length without a salt",
		     matter_derive_session_keys(secret, sizeof(secret), NULL, 8u, false, &keys),
		     MATTER_E_INVAL);
	}

	t_group("seal and open: the header is authenticated, not just carried");
	{
		static const char *const msg = "hello matter";
		uint8_t got[64];
		size_t got_len = 0u;
		size_t sealed = 0u;

		memset(&h, 0, sizeof(h));
		h.flags = MATTER_MSG_FLAG_S;
		h.session_id = 0x1234u;
		h.message_counter = 7u;
		h.source_node_id = 0x0102030405060708ull;

		T_EQ("seal",
		     matter_crypto_seal(&h, key, 0x0102030405060708ull, (const uint8_t *)msg,
					strlen(msg), out, sizeof(out), &sealed),
		     MATTER_OK);
		/* 16-byte header (flags say a source node ID is present) + 12 + 16. */
		T_EQ("header + payload + tag", (long)sealed, 44L);

		{
			struct matter_msg_header back;

			memset(&back, 0, sizeof(back));
			T_EQ("open",
			     matter_crypto_open(out, sealed, key, 0x0102030405060708ull, &back, got,
						sizeof(got), &got_len),
			     MATTER_OK);
			T_EQ("payload length", (long)got_len, (long)strlen(msg));
			T_OK("payload matches", memcmp(got, msg, strlen(msg)) == 0);
			T_EQ("session id survived", back.session_id, 0x1234L);
			T_EQ("counter survived", (long)back.message_counter, 7L);

			/* The header is AAD, so editing any of it must break the tag --
			 * this is what stops a relay rewriting the routing fields. */
			out[1] ^= 0x01u; /* session ID */
			T_EQ("edited session id is refused",
			     matter_crypto_open(out, sealed, key, 0x0102030405060708ull, &back, got,
						sizeof(got), &got_len),
			     MATTER_E_TYPE);
			out[1] ^= 0x01u;

			out[4] ^= 0x01u; /* message counter */
			T_EQ("edited counter is refused",
			     matter_crypto_open(out, sealed, key, 0x0102030405060708ull, &back, got,
						sizeof(got), &got_len),
			     MATTER_E_TYPE);
			out[4] ^= 0x01u;

			/* The node ID is not on the wire for the nonce's purposes; it
			 * comes from the session, so the wrong one must fail. */
			T_EQ("wrong peer node id is refused",
			     matter_crypto_open(out, sealed, key, 0x0102030405060709ull, &back, got,
						sizeof(got), &got_len),
			     MATTER_E_TYPE);

			T_EQ("and it still opens with the right one",
			     matter_crypto_open(out, sealed, key, 0x0102030405060708ull, &back, got,
						sizeof(got), &got_len),
			     MATTER_OK);
		}

		t_group("seal and open: refusals");

		T_EQ("no room for the tag",
		     matter_crypto_seal(&h, key, 0u, (const uint8_t *)msg, strlen(msg), out,
					16u + strlen(msg) + MATTER_TAG_LEN - 1u, &sealed),
		     MATTER_E_NOSPACE);
		T_EQ("no room for the header",
		     matter_crypto_seal(&h, key, 0u, (const uint8_t *)msg, strlen(msg), out, 4u,
					&sealed),
		     MATTER_E_NOSPACE);

		/* A message shorter than header + tag cannot be authenticated at all. */
		for (size_t k = 0; k < MATTER_TAG_LEN; k++) {
			struct matter_msg_header back;

			T_EQ("too short to hold a tag",
			     matter_crypto_open(out, 16u + k, key, 0u, &back, got, sizeof(got),
						&got_len),
			     MATTER_E_TRUNC);
		}

		{
			struct matter_msg_header back;

			T_EQ("plaintext buffer too small",
			     matter_crypto_open(out, sealed, key, 0x0102030405060708ull, &back, got,
						2u, &got_len),
			     MATTER_E_NOSPACE);
			T_EQ("null buffer",
			     matter_crypto_open(NULL, sealed, key, 0u, &back, got, sizeof(got),
						&got_len),
			     MATTER_E_INVAL);
		}
		T_EQ("null header",
		     matter_crypto_seal(NULL, key, 0u, NULL, 0u, out, sizeof(out), &n),
		     MATTER_E_INVAL);
	}

	t_group("seal and open: an empty payload is still a valid message");
	{
		struct matter_msg_header back;
		uint8_t got[16];
		size_t got_len = 1u;
		size_t sealed = 0u;

		memset(&h, 0, sizeof(h));
		h.session_id = 9u;
		h.message_counter = 3u;

		T_EQ("seal nothing",
		     matter_crypto_seal(&h, key, 0u, NULL, 0u, out, sizeof(out), &sealed),
		     MATTER_OK);
		T_EQ("header plus tag only", (long)sealed, 24L);
		T_EQ("open nothing",
		     matter_crypto_open(out, sealed, key, 0u, &back, got, sizeof(got), &got_len),
		     MATTER_OK);
		T_EQ("no payload", (long)got_len, 0L);
	}
}

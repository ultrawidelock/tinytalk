/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/** @file test_tm_hash.c — SHA-256 / HMAC / HKDF / X9.63 KATs.
 *
 * tm_hash.c is the portable crypto the presence assertion (and the whole
 * credential key schedule) of the project this was extracted from leans on, but it had no host coverage. Pin it against the
 * published standard vectors so a regression in the primitive is caught here,
 * not on wire. Vectors: FIPS 180-4 (SHA-256), RFC 4231 (HMAC), RFC 5869 (HKDF).
 */
#include <string.h>

#include <tinytalk/tm_hash.h>
#include "test.h"

void test_tm_hash(void)
{
	t_group("SHA-256 (FIPS 180-4)");
	uint8_t d[TM_SHA256_LEN];
	tm_sha256("abc", 3, d);
	t_vec("sha.abc", d, sizeof(d),
	      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	tm_sha256("", 0, d);
	t_vec("sha.empty", d, sizeof(d),
	      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	t_group("SHA-256 streaming == one-shot");
	struct tm_sha256 s;
	uint8_t d2[TM_SHA256_LEN];
	tm_sha256_init(&s);
	tm_sha256_update(&s, "a", 1);
	tm_sha256_update(&s, "bc", 2);
	tm_sha256_final(&s, d2);
	tm_sha256("abc", 3, d);
	T_OK("stream.eq_oneshot", memcmp(d, d2, sizeof(d)) == 0);
	/* Multi-block message to exercise the block-buffer flush path. */
	uint8_t big[200];
	memset(big, 0x61, sizeof(big)); /* 200 * 'a' */
	struct tm_sha256 s2;
	tm_sha256_init(&s2);
	for (unsigned i = 0; i < sizeof(big); i++) {
		tm_sha256_update(&s2, &big[i], 1); /* one byte at a time */
	}
	tm_sha256_final(&s2, d2);
	tm_sha256(big, sizeof(big), d);
	T_OK("stream.bytewise_eq", memcmp(d, d2, sizeof(d)) == 0);

	t_group("HMAC-SHA256 (RFC 4231 TC1)");
	uint8_t key20[20];
	memset(key20, 0x0b, sizeof(key20));
	uint8_t mac[TM_SHA256_LEN];
	tm_hmac_sha256(key20, sizeof(key20), "Hi There", 8, mac);
	t_vec("hmac.tc1", mac, sizeof(mac),
	      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

	t_group("HKDF-SHA256 (RFC 5869 TC1)");
	uint8_t ikm[22];
	memset(ikm, 0x0b, sizeof(ikm));
	static const uint8_t salt[13] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
					  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
	static const uint8_t info[10] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
					  0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
	uint8_t okm[42];
	T_EQ("hkdf.rc", tm_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm,
				  sizeof(okm)),
	     0);
	t_vec("hkdf.tc1", okm, sizeof(okm),
	      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf3"
	      "4007208d5b887185865");

	t_group("HKDF length guard");
	uint8_t toobig[1];
	/* expand caps at 255*32 bytes; ask for more -> -1. */
	uint8_t prk[TM_SHA256_LEN];
	tm_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
	T_EQ("hkdf.expand_overflow",
	     tm_hkdf_expand(prk, info, sizeof(info), toobig, 255u * 32u + 1u), -1);

	t_group("X9.63 KDF self-consistency");
	/* SEC1 KDF2: first 32 bytes = SHA-256(Z || be32(1) || info). Re-derive that
	 * block independently and compare. */
	static const uint8_t z[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	uint8_t out[32];
	T_EQ("x963.rc", tm_x963_kdf(z, sizeof(z), info, sizeof(info), out, sizeof(out)), 0);
	struct tm_sha256 xs;
	uint8_t expect[TM_SHA256_LEN];
	static const uint8_t ctr1[4] = { 0x00, 0x00, 0x00, 0x01 };
	tm_sha256_init(&xs);
	tm_sha256_update(&xs, z, sizeof(z));
	tm_sha256_update(&xs, ctr1, sizeof(ctr1));
	tm_sha256_update(&xs, info, sizeof(info));
	tm_sha256_final(&xs, expect);
	T_OK("x963.block1", memcmp(out, expect, sizeof(out)) == 0);
}

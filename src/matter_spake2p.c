/* SPDX-License-Identifier: ISC */

/**
 * @file matter_spake2p.c — PBKDF2, the SPAKE2+ transcript and confirmations.
 */
/*
 * No elliptic curve arithmetic in this file. The four operations SPAKE2+ needs
 * come from nrf_oberon, which is already linked; the seam is declared in
 * matter_spake2p.h and the host suite pins it against oberon's own header.
 *
 * What IS here is the part where a wrong byte order or a dropped length prefix
 * produces a value that is wrong silently -- the peer's confirmation simply
 * fails and nothing says why. Both the passcode encoding (little-endian
 * uint32) and the transcript's length prefixes (little-endian uint64) are
 * spelled out for that reason.
 */
#include <string.h>

#include <tinytalk/matter_spake2p.h>

#include <tinytalk/tm_hash.h>

/* CHIPCryptoPAL.h:186-197. Constants of the protocol. */
const uint8_t matter_spake2p_M[MATTER_SPAKE_POINT_LEN] = {
	0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24,
	0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf,
	0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43,
	0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0,
	0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20,
};

const uint8_t matter_spake2p_N[MATTER_SPAKE_POINT_LEN] = {
	0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f,
	0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b,
	0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad,
	0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3,
	0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7,
};

/* PASESession.cpp:106. Not NUL-terminated on the wire. */
static const char k_context[] = "CHIP PAKE V1 Commissioning";
/* CHIPCryptoPAL.cpp:458-468 / pase.py:167. */
static const char k_confirmation_info[] = "ConfirmationKeys";

/**
 * Derive an output key using PBKDF2-SHA256 with the given password, salt, and iteration count;
 * returns MATTER_E_INVAL if parameters are invalid or MATTER_E_NOSPACE if the salt is too long.
 */
int matter_pbkdf2_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
			 size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len)
{
	uint8_t u[TM_SHA256_LEN];
	uint8_t t[TM_SHA256_LEN];
	/* One salt block: the salt plus the 4-byte big-endian block index that
	 * PBKDF2 appends. The salt is bounded by the caller's protocol; 64 covers
	 * Matter's 32-byte maximum with room to spare. */
	uint8_t block[64 + 4];
	uint32_t counter = 1u;
	size_t done = 0u;

	if (out == NULL || out_len == 0u || iterations == 0u) {
		return MATTER_E_INVAL;
	}
	if ((password == NULL && password_len != 0u) || (salt == NULL && salt_len != 0u)) {
		return MATTER_E_INVAL;
	}
	if (salt_len > sizeof(block) - 4u) {
		return MATTER_E_NOSPACE;
	}

	while (done < out_len) {
		size_t take = out_len - done;

		if (take > TM_SHA256_LEN) {
			take = TM_SHA256_LEN;
		}

		/* U1 = HMAC(P, S || INT_32_BE(i)) */
		if (salt_len != 0u) {
			memcpy(block, salt, salt_len);
		}
		block[salt_len + 0u] = (uint8_t)(counter >> 24);
		block[salt_len + 1u] = (uint8_t)(counter >> 16);
		block[salt_len + 2u] = (uint8_t)(counter >> 8);
		block[salt_len + 3u] = (uint8_t)counter;
		tm_hmac_sha256(password, password_len, block, salt_len + 4u, u);
		memcpy(t, u, TM_SHA256_LEN);

		/* T = U1 xor U2 xor ... xor Uc */
		for (uint32_t i = 1u; i < iterations; i++) {
			tm_hmac_sha256(password, password_len, u, TM_SHA256_LEN, u);
			for (size_t j = 0; j < TM_SHA256_LEN; j++) {
				t[j] ^= u[j];
			}
		}

		memcpy(&out[done], t, take);
		done += take;
		counter++;
	}

	memset(u, 0, sizeof(u));
	memset(t, 0, sizeof(t));
	return MATTER_OK;
}

/**
 * Derive SPAKE2+ w0 and w1 scalars from a 32-bit passcode using PBKDF2-SHA256 with salt and
 * iterations. Passcode is encoded little-endian; each result is reduced modulo the P-256 order
 * using 40 bytes of derived material (8 bytes extra for negligible bias). Returns MATTER_OK on
 * success.
 */
int matter_spake2p_w0w1(uint32_t passcode, const uint8_t *salt, size_t salt_len,
			uint32_t iterations, uint8_t w0[MATTER_SPAKE_SCALAR_LEN],
			uint8_t w1[MATTER_SPAKE_SCALAR_LEN])
{
	uint8_t pw[4];
	uint8_t ws[MATTER_SPAKE_WS_LEN * 2u];
	int rc;

	if (w0 == NULL || w1 == NULL) {
		return MATTER_E_INVAL;
	}

	/* LITTLE-endian, unlike the big-endian reduction that follows it. The two
	 * orders in one function are not a mistake; they are what the spec says
	 * and what both reference implementations do (pase.py:105-108). */
	pw[0] = (uint8_t)passcode;
	pw[1] = (uint8_t)(passcode >> 8);
	pw[2] = (uint8_t)(passcode >> 16);
	pw[3] = (uint8_t)(passcode >> 24);

	rc = matter_pbkdf2_sha256(pw, sizeof(pw), salt, salt_len, iterations, ws, sizeof(ws));
	if (rc != MATTER_OK) {
		memset(pw, 0, sizeof(pw));
		return rc;
	}

	/* Each 40-byte half is a big-endian integer reduced mod the group order.
	 * The extra 8 bytes over the 32-byte order are what makes the reduction
	 * bias negligible. */
	ocrypto_spake2p_p256_reduce(w0, &ws[0], MATTER_SPAKE_WS_LEN);
	ocrypto_spake2p_p256_reduce(w1, &ws[MATTER_SPAKE_WS_LEN], MATTER_SPAKE_WS_LEN);

	memset(pw, 0, sizeof(pw));
	memset(ws, 0, sizeof(ws));
	return MATTER_OK;
}

/**
 * Hash the SPAKE2+ context from optional request and response payloads; context is always hashed
 * but payloads are only included if present.
 */
int matter_spake2p_context(const uint8_t *req, size_t req_len, const uint8_t *resp, size_t resp_len,
			   uint8_t out[MATTER_SPAKE_HASH_LEN])
{
	struct tm_sha256 h;

	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	if ((req == NULL && req_len != 0u) || (resp == NULL && resp_len != 0u)) {
		return MATTER_E_INVAL;
	}

	tm_sha256_init(&h);
	/* sizeof - 1: the NUL is not part of the context. */
	tm_sha256_update(&h, k_context, sizeof(k_context) - 1u);
	if (req_len != 0u) {
		tm_sha256_update(&h, req, req_len);
	}
	if (resp_len != 0u) {
		tm_sha256_update(&h, resp, resp_len);
	}
	tm_sha256_final(&h, out);
	return MATTER_OK;
}

/** Append one length-prefixed transcript element. */
static void tt_put(uint8_t *out, size_t *off, const uint8_t *data, size_t len)
{
	uint8_t *p = &out[*off];

	/* Length as a little-endian uint64, always eight bytes even for the two
	 * empty identities (pase.py:145-147). */
	for (size_t i = 0; i < 8u; i++) {
		p[i] = (uint8_t)((uint64_t)len >> (8u * i));
	}
	*off += 8u;
	if (len != 0u) {
		memcpy(&out[*off], data, len);
		*off += len;
	}
}

/**
 * Assemble the SPAKE2+ transcript from context, identity empty strings, M, N, exchange points,
 * shared secret Z, ephemeral V, and w0 scalar; returns MATTER_E_NOSPACE if output buffer is too
 * small.
 */
int matter_spake2p_transcript(const uint8_t context[MATTER_SPAKE_HASH_LEN],
			      const uint8_t pa[MATTER_SPAKE_POINT_LEN],
			      const uint8_t pb[MATTER_SPAKE_POINT_LEN],
			      const uint8_t z[MATTER_SPAKE_POINT_LEN],
			      const uint8_t v[MATTER_SPAKE_POINT_LEN],
			      const uint8_t w0[MATTER_SPAKE_SCALAR_LEN], uint8_t *out,
			      size_t *out_len)
{
	/* 10 prefixes, then context + M + N + pA + pB + Z + V + w0. */
	const size_t need = (10u * 8u) + MATTER_SPAKE_HASH_LEN + (6u * MATTER_SPAKE_POINT_LEN) +
			    MATTER_SPAKE_SCALAR_LEN;
	size_t off = 0u;

	if (context == NULL || pa == NULL || pb == NULL || z == NULL || v == NULL || w0 == NULL ||
	    out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (*out_len < need) {
		return MATTER_E_NOSPACE;
	}

	tt_put(out, &off, context, MATTER_SPAKE_HASH_LEN);
	/* idProver and idVerifier, empty in Matter but still length-prefixed. */
	tt_put(out, &off, NULL, 0u);
	tt_put(out, &off, NULL, 0u);
	tt_put(out, &off, matter_spake2p_M, MATTER_SPAKE_POINT_LEN);
	tt_put(out, &off, matter_spake2p_N, MATTER_SPAKE_POINT_LEN);
	tt_put(out, &off, pa, MATTER_SPAKE_POINT_LEN);
	tt_put(out, &off, pb, MATTER_SPAKE_POINT_LEN);
	tt_put(out, &off, z, MATTER_SPAKE_POINT_LEN);
	tt_put(out, &off, v, MATTER_SPAKE_POINT_LEN);
	tt_put(out, &off, w0, MATTER_SPAKE_SCALAR_LEN);

	*out_len = off;
	return MATTER_OK;
}

/**
 * Derive confirmation and session keys from the SPAKE2+ transcript and exchange points; swaps Ka
 * and Ke derivation order and produces confirmation codes Ca over peer's point and Cb over own
 * point.
 */
int matter_spake2p_p2(const uint8_t *tt, size_t tt_len, const uint8_t pa[MATTER_SPAKE_POINT_LEN],
		      const uint8_t pb[MATTER_SPAKE_POINT_LEN], struct matter_spake2p_result *out)
{
	uint8_t kake[TM_SHA256_LEN];
	uint8_t kcakcb[TM_SHA256_LEN];

	if (tt == NULL || tt_len == 0u || pa == NULL || pb == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	/* Ka is the first half of SHA256(TT), Ke the second. */
	tm_sha256(tt, tt_len, kake);

	/* KcA ‖ KcB = HKDF(Ka, "ConfirmationKeys") with an empty salt. */
	if (tm_hkdf(NULL, 0u, kake, MATTER_SPAKE_HALF_LEN, (const uint8_t *)k_confirmation_info,
		       sizeof(k_confirmation_info) - 1u, kcakcb, sizeof(kcakcb)) != 0) {
		memset(kake, 0, sizeof(kake));
		return MATTER_E_STATE;
	}

	/* Each side confirms with the OTHER side's share: cA over pB, cB over pA.
	 * Swapping them produces two values that both look plausible and neither
	 * of which the peer accepts. */
	tm_hmac_sha256(&kcakcb[0], MATTER_SPAKE_HALF_LEN, pb, MATTER_SPAKE_POINT_LEN, out->ca);
	tm_hmac_sha256(&kcakcb[MATTER_SPAKE_HALF_LEN], MATTER_SPAKE_HALF_LEN, pa,
			  MATTER_SPAKE_POINT_LEN, out->cb);
	memcpy(out->ke, &kake[MATTER_SPAKE_HALF_LEN], MATTER_SPAKE_HALF_LEN);

	memset(kake, 0, sizeof(kake));
	memset(kcakcb, 0, sizeof(kcakcb));
	return MATTER_OK;
}

/**
 * Compare two SPAKE2+ hash values in constant time; returns true if they match exactly.
 */
bool matter_spake2p_verify(const uint8_t expected[MATTER_SPAKE_HASH_LEN],
			   const uint8_t got[MATTER_SPAKE_HASH_LEN])
{
	uint8_t diff = 0u;

	if (expected == NULL || got == NULL) {
		return false;
	}
	for (size_t i = 0; i < MATTER_SPAKE_HASH_LEN; i++) {
		diff |= (uint8_t)(expected[i] ^ got[i]);
	}
	return diff == 0u;
}

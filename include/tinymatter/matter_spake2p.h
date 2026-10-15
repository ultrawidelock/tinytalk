/* SPDX-License-Identifier: ISC */

/**
 * @file matter_spake2p.h — SPAKE2+ glue: PBKDF2, transcript, confirmations.
 *
 * SPAKE2+ is how PASE turns a short setup passcode into a session key without
 * ever putting the passcode on the wire. The elliptic-curve arithmetic is NOT
 * here: it comes from nrf_oberon, which ships four primitives that do exactly
 * the operations SPAKE2+ needs. Everything around them -- deriving w0 and w1
 * from the passcode, building the transcript, and turning it into the
 * confirmation values -- is this file, and all of it is byte manipulation and
 * hashing that the host suite can check.
 *
 *   w0, w1   PBKDF2-HMAC-SHA256(passcode, salt, iterations) -> 80 B -> two
 *            40-byte halves, each reduced mod the P-256 group order
 *   TT       ten elements, each prefixed with its length as a little-endian
 *            uint64: context, "", "", M, N, pA, pB, Z, V, w0
 *   Ka|Ke    SHA256(TT), first half and second half
 *   KcA|KcB  HKDF(Ka, "ConfirmationKeys")
 *   cA, cB   HMAC(KcA, pB) and HMAC(KcB, pA)
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Uncompressed P-256 point. */
#define MATTER_SPAKE_POINT_LEN  65u
/** A scalar mod the group order. */
#define MATTER_SPAKE_SCALAR_LEN 32u
/**
 * The extended secret before reduction: group size + 8, so the modular bias
 * from reducing it is negligible (pase.py:96, CHIPCryptoPAL.h kSpake2p_WS_Length).
 */
#define MATTER_SPAKE_WS_LEN     40u
#define MATTER_SPAKE_HASH_LEN   32u
/** Ka, Ke, KcA and KcB are each half of a SHA-256 output. */
#define MATTER_SPAKE_HALF_LEN   16u
/**
 * The whole transcript: ten little-endian uint64 length prefixes ahead of
 * 32 + 6*65 + 32 bytes of elements, the two empty identities contributing their
 * prefixes and nothing else.
 */
#define MATTER_SPAKE_TT_LEN     534u

/**
 * The fixed SPAKE2+ points for P-256, uncompressed (CHIPCryptoPAL.h:186-197).
 * They are constants of the protocol, not of any deployment.
 */
extern const uint8_t matter_spake2p_M[MATTER_SPAKE_POINT_LEN];
extern const uint8_t matter_spake2p_N[MATTER_SPAKE_POINT_LEN];

/*
 * ------------------------------------------------------------ oberon seam ---
 *
 * Declared here rather than by including ocrypto_spake2p_p256.h so this module
 * keeps building on the host, where no elliptic curve implementation is linked.
 * The signatures are copied verbatim from
 * nrfxlib/crypto/nrf_oberon/include/ocrypto_spake2p_p256.h; the host suite
 * includes that header alongside this one so the compiler rejects any drift,
 * exactly as tests/host/test_matter_crypto.c does for the AES seam.
 *
 * These four are the only elliptic-curve operations SPAKE2+ needs, and none of
 * them is reimplemented here. Hand-writing P-256 to save a dependency that is
 * already linked would be the wrong trade at any size.
 */
void ocrypto_spake2p_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len);
int ocrypto_spake2p_p256_check_key(const uint8_t K[65]);
int ocrypto_spake2p_p256_get_key_share(uint8_t XY[65], const uint8_t w0[32], const uint8_t xy[32],
				       const uint8_t MN[65]);
int ocrypto_spake2p_p256_get_ZV(uint8_t Z[65], uint8_t V[65], const uint8_t w0[32],
				const uint8_t w1[32], const uint8_t xy[32], const uint8_t YX[65],
				const uint8_t NM[65], const uint8_t L[65]);

/**
 * PBKDF2-HMAC-SHA256.
 *
 * Separate and public because it is independently testable against published
 * vectors, and because it is the one expensive thing here: 10000 iterations
 * over 80 bytes of output is roughly 60,000 SHA-256 compressions, which on a
 * 64 MHz M4 with no hardware hash is on the order of a second.
 *
 * That cost is NOT on the commissioning path. A Matter device stores the
 * SPAKE2+ verifier (w0 and L) rather than the passcode, so this runs once when
 * the verifier is generated, not when a commissioner connects.
 */
int matter_pbkdf2_sha256(const uint8_t *password, size_t password_len, const uint8_t *salt,
			 size_t salt_len, uint32_t iterations, uint8_t *out, size_t out_len);

/**
 * Derive w0 and w1 from a setup passcode.
 *
 * @param passcode the 27-bit setup passcode, hashed as a LITTLE-ENDIAN uint32
 *        (pase.py:106). Getting that endianness wrong produces a w0 that is
 *        wrong in a way nothing detects until the peer's confirmation fails.
 */
int matter_spake2p_w0w1(uint32_t passcode, const uint8_t *salt, size_t salt_len,
			uint32_t iterations, uint8_t w0[MATTER_SPAKE_SCALAR_LEN],
			uint8_t w1[MATTER_SPAKE_SCALAR_LEN]);

/**
 * The commissioning context: SHA256("CHIP PAKE V1 Commissioning" ‖ request ‖
 * response), where request and response are the TLV payloads of
 * PBKDFParamRequest and PBKDFParamResponse exactly as they went over the wire.
 *
 * It is a hash over the earlier messages, so the confirmation at the end of
 * PASE also proves the two sides agreed about the beginning of it.
 */
int matter_spake2p_context(const uint8_t *req, size_t req_len, const uint8_t *resp, size_t resp_len,
			   uint8_t out[MATTER_SPAKE_HASH_LEN]);

/**
 * Build the transcript TT.
 *
 * Ten elements, each preceded by its length as a little-endian uint64. Two of
 * them are the empty prover and verifier identities, which Matter leaves empty
 * but still length-prefixes -- dropping them shifts everything after.
 *
 * @param out_len in: capacity; out: bytes written. Needs 10*8 prefix bytes plus
 *        32 + 6*65 + 32 of elements, so 534 in total.
 */
int matter_spake2p_transcript(const uint8_t context[MATTER_SPAKE_HASH_LEN],
			      const uint8_t pa[MATTER_SPAKE_POINT_LEN],
			      const uint8_t pb[MATTER_SPAKE_POINT_LEN],
			      const uint8_t z[MATTER_SPAKE_POINT_LEN],
			      const uint8_t v[MATTER_SPAKE_POINT_LEN],
			      const uint8_t w0[MATTER_SPAKE_SCALAR_LEN], uint8_t *out,
			      size_t *out_len);

/** What the transcript yields: the two confirmations and the shared secret. */
struct matter_spake2p_result {
	uint8_t ca[MATTER_SPAKE_HASH_LEN];
	uint8_t cb[MATTER_SPAKE_HASH_LEN];
	/** Ke, the input to the session key schedule. */
	uint8_t ke[MATTER_SPAKE_HALF_LEN];
};

/**
 * Turn a transcript into cA, cB and Ke.
 *
 * @param tt the transcript from matter_spake2p_transcript().
 */
int matter_spake2p_p2(const uint8_t *tt, size_t tt_len, const uint8_t pa[MATTER_SPAKE_POINT_LEN],
		      const uint8_t pb[MATTER_SPAKE_POINT_LEN], struct matter_spake2p_result *out);

/**
 * Constant-time compare for a peer's confirmation value.
 *
 * A byte-by-byte memcmp on cA would leak how much of a guess was right, which
 * is the one thing a passcode-derived protocol must not give away.
 */
bool matter_spake2p_verify(const uint8_t expected[MATTER_SPAKE_HASH_LEN],
			   const uint8_t got[MATTER_SPAKE_HASH_LEN]);

#ifdef __cplusplus
}
#endif

/* SPDX-License-Identifier: ISC */

/**
 * @file matter_pase.h — PASE message codec (the five commissioning messages).
 *
 * PASE is how a commissioner proves it knows the setup passcode. Five messages,
 * all Matter TLV structures on the Secure Channel protocol:
 *
 *   PBKDFParamRequest   initiatorRandom, initiatorSessionId, passcodeId,
 *                       hasPBKDFParameters, [initiatorSessionParams]
 *   PBKDFParamResponse  initiatorRandom, responderRandom, responderSessionId,
 *                       [pbkdfParameters{iterations, salt}], [responderSessionParams]
 *   Pake1               pA
 *   Pake2               pB, cB
 *   Pake3               cA
 *
 * This file is the codec only. The SPAKE2+ arithmetic that produces pA/pB/cA/cB
 * comes from nrf_oberon (ocrypto_spake2p_p256.h), which already ships in every
 * image here.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** PASESession.h:53. */
#define MATTER_PASE_RANDOM_LEN 32u
/** Uncompressed P-256 point, 2*32+1 (crypto.py:23-24). */
#define MATTER_PASE_POINT_LEN  65u
/** SHA-256 confirmation value. */
#define MATTER_PASE_HASH_LEN   32u

/* PBKDF bounds, CHIPCryptoPAL.h:86-89. Peer-supplied, so they are enforced. */
#define MATTER_PASE_SALT_MIN 16u
#define MATTER_PASE_SALT_MAX 32u
#define MATTER_PASE_ITER_MIN 1000u
#define MATTER_PASE_ITER_MAX 100000u

/**
 * The only passcode ID commissioning uses. CHIP refuses anything else
 * (PASESession.cpp:433) and so does this.
 */
#define MATTER_PASE_PASSCODE_ID 0u

/** Secure Channel opcodes for the five messages. */
#define MATTER_PASE_OP_PBKDF_REQ  0x20u
#define MATTER_PASE_OP_PBKDF_RESP 0x21u
#define MATTER_PASE_OP_PAKE1      0x22u
#define MATTER_PASE_OP_PAKE2      0x23u
#define MATTER_PASE_OP_PAKE3      0x24u

/**
 * MRP parameters a peer advertises for itself. Absent means "use the defaults",
 * which is why presence is tracked rather than defaulted here.
 */
struct matter_session_params {
	uint32_t idle_interval_ms;
	uint32_t active_interval_ms;
	bool have_idle;
	bool have_active;
};

/**
 * PASE PBKDFParamRequest message holding initiator random, session ID, passcode ID, and optional
 * PBKDF session parameters.
 */
struct matter_pase_pbkdf_req {
	uint8_t initiator_random[MATTER_PASE_RANDOM_LEN];
	uint16_t initiator_session_id;
	uint16_t passcode_id;
	bool has_pbkdf_params;
	struct matter_session_params params;
};

/**
 * PASE PBKDFParamResponse message holding initiator and responder randoms, session ID, and optional
 * PBKDF parameters (iterations and salt) if the initiator did not already have them.
 */
struct matter_pase_pbkdf_resp {
	uint8_t initiator_random[MATTER_PASE_RANDOM_LEN];
	uint8_t responder_random[MATTER_PASE_RANDOM_LEN];
	uint16_t responder_session_id;
	/**
	 * CHIP omits the whole pbkdfParameters structure when the initiator said
	 * it already has them (PASESession.cpp:494-502). CircuitMatter declares it
	 * non-optional (pase.py:68) and would fail to parse such a response. CHIP
	 * matches the spec's intent, so it is optional here; the flag says whether
	 * iterations and salt below mean anything.
	 */
	bool pbkdf_params_present;
	uint32_t iterations;
	uint8_t salt[MATTER_PASE_SALT_MAX];
	uint8_t salt_len;
	struct matter_session_params params;
};

/**
 * PASE Sigma1 message payload holding the initiator's ephemeral public key point.
 */
struct matter_pase_pake1 {
	uint8_t pa[MATTER_PASE_POINT_LEN];
};

/**
 * PASE Sigma2 message payload holding the responder's ephemeral public key point and hash.
 */
struct matter_pase_pake2 {
	uint8_t pb[MATTER_PASE_POINT_LEN];
	uint8_t cb[MATTER_PASE_HASH_LEN];
};

/**
 * PASE Sigma3 message payload holding the initiator's hash for mutual authentication.
 */
struct matter_pase_pake3 {
	uint8_t ca[MATTER_PASE_HASH_LEN];
};

/*
 * Decoders validate rather than trust: exact lengths for the fixed-size fields,
 * the PBKDF bounds, and the passcode ID. Every one of these arrives from an
 * unauthenticated peer -- PASE is what establishes trust, so nothing is
 * established yet when these are parsed.
 *
 * @return MATTER_OK, MATTER_E_TRUNC on a short buffer, MATTER_E_INVAL for a
 *         value out of range, MATTER_E_TYPE for the wrong element type, or
 *         MATTER_E_STATE when a required field is missing.
 */
int matter_pase_pbkdf_req_decode(const uint8_t *buf, size_t len, struct matter_pase_pbkdf_req *out);
int matter_pase_pbkdf_req_encode(const struct matter_pase_pbkdf_req *r, uint8_t *buf, size_t cap,
				 size_t *written);

int matter_pase_pbkdf_resp_decode(const uint8_t *buf, size_t len,
				  struct matter_pase_pbkdf_resp *out);
int matter_pase_pbkdf_resp_encode(const struct matter_pase_pbkdf_resp *r, uint8_t *buf, size_t cap,
				  size_t *written);

int matter_pase_pake1_decode(const uint8_t *buf, size_t len, struct matter_pase_pake1 *out);
int matter_pase_pake1_encode(const struct matter_pase_pake1 *r, uint8_t *buf, size_t cap,
			     size_t *written);

int matter_pase_pake2_decode(const uint8_t *buf, size_t len, struct matter_pase_pake2 *out);
int matter_pase_pake2_encode(const struct matter_pase_pake2 *r, uint8_t *buf, size_t cap,
			     size_t *written);

int matter_pase_pake3_decode(const uint8_t *buf, size_t len, struct matter_pase_pake3 *out);
int matter_pase_pake3_encode(const struct matter_pase_pake3 *r, uint8_t *buf, size_t cap,
			     size_t *written);

#ifdef __cplusplus
}
#endif

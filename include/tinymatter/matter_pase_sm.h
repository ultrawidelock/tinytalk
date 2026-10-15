/* SPDX-License-Identifier: ISC */

/**
 * @file matter_pase_sm.h — PASE responder: the device side of the five messages.
 *
 * matter_pase.h is the codec and matter_spake2p.h is the arithmetic; this is
 * what drives them. A commissioner opens with PBKDFParamRequest and this
 * answers, receives Pake1, answers Pake2, receives Pake3, and ends with a
 * StatusReport. What comes out the far side is a session key schedule.
 *
 *   -> PBKDFParamRequest    <- PBKDFParamResponse   (context hash fixed here)
 *   -> Pake1 (pA)           <- Pake2 (pB, cB)
 *   -> Pake3 (cA)           <- StatusReport(success)
 *
 * The device never holds the setup passcode -- only the SPAKE2+ verifier (w0,
 * L), provisioned in, so reading flash cannot impersonate a commissioner. No
 * time or randomness is taken from the environment: MRP owns retransmission and
 * the two random values are arguments. Every PASE failure is answered with
 * kProtocolCodeInvalidParam (0x0002), as CHIP does -- telling an
 * unauthenticated peer which step failed is free information about the verifier.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_crypto.h>
#include <tinymatter/matter_pase.h>
#include <tinymatter/matter_spake2p.h>
#include <tinymatter/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Secure Channel StatusReport, 0x40. Not a PASE opcode; PASE ends with one. */
#define MATTER_SC_OP_STATUS_REPORT 0x40u
/** u16 general code, u32 protocol id, u16 protocol code (StatusReport.cpp). */
#define MATTER_SC_STATUS_LEN       8u

/** GeneralStatusCode, Constants.h:116-138. Only the two PASE can produce. */
#define MATTER_SC_GENERAL_SUCCESS 0u
#define MATTER_SC_GENERAL_FAILURE 1u

/** Constants.h:79-84. */
#define MATTER_SC_CODE_SUCCESS       0x0000u
#define MATTER_SC_CODE_INVALID_PARAM 0x0002u

/**
 * Largest reply this produces.
 *
 * PBKDFParamResponse is the big one: two 32-byte randoms with their headers, a
 * session id, and the pbkdfParameters structure carrying a 32-byte salt, which
 * comes to 120 bytes. Pake2 is 105 and a StatusReport is 8.
 */
#define MATTER_PASE_REPLY_MAX 128u

/** Random bytes the caller supplies for the ephemeral scalar, before reduction. */
#define MATTER_PASE_Y_ENTROPY_LEN MATTER_SPAKE_WS_LEN

/**
 * The provisioned SPAKE2+ verifier, plus the PBKDF parameters that produced it.
 *
 * All four travel together because they have to agree: w0 and L are what
 * PBKDF2(passcode, salt, iterations) yields, and the salt and iteration count go
 * out in PBKDFParamResponse so the commissioner can repeat the derivation. A
 * verifier stored without the parameters that made it is unusable.
 *
 * Deriving this needs a scalar multiply against the P-256 base point to get
 * L = w1*G, which is not one of the four operations nrf_oberon exposes here, so
 * it is generated off-device and provisioned -- which is how Matter intends it
 * anyway (the passcode is on the label, the verifier is in the flash).
 */
struct matter_pase_verifier {
	uint8_t w0[MATTER_SPAKE_SCALAR_LEN];
	/** w1*G, uncompressed. */
	uint8_t l[MATTER_SPAKE_POINT_LEN];
	uint8_t salt[MATTER_PASE_SALT_MAX];
	uint8_t salt_len;
	uint32_t iterations;
};

enum matter_pase_state {
	/** Nothing received; the only acceptable message is PBKDFParamRequest. */
	MATTER_PASE_ST_IDLE = 0,
	MATTER_PASE_ST_WAIT_PAKE1,
	MATTER_PASE_ST_WAIT_PAKE3,
	/** cA verified. keys are valid and nothing further is accepted. */
	MATTER_PASE_ST_DONE,
	/** Terminal. Every later message is refused without inspection. */
	MATTER_PASE_ST_FAILED,
};

/**
 * PASE responder state machine: tracks the verifier, session IDs, ephemeral scalar y, random nonce,
 * SPAKE2+ context, expected commitment cA, shared secret ke, derived session keys, and the 534-byte
 * transcript live only during Pake1 handling.
 */
struct matter_pase_responder {
	struct matter_pase_verifier v;
	uint8_t state;
	uint16_t local_session_id;
	/** The commissioner's session id, for the secure session this sets up. */
	uint16_t peer_session_id;
	uint8_t responder_random[MATTER_PASE_RANDOM_LEN];
	/** The ephemeral scalar, already reduced mod the group order. */
	uint8_t y[MATTER_SPAKE_SCALAR_LEN];
	uint8_t context[MATTER_SPAKE_HASH_LEN];
	/** What Pake3 has to carry. Compared in constant time when it arrives. */
	uint8_t expect_ca[MATTER_SPAKE_HASH_LEN];
	/** The shared secret, held between Pake2 and Pake3. */
	uint8_t ke[MATTER_SPAKE_HALF_LEN];
	/**
	 * Valid only in MATTER_PASE_ST_DONE, and that is literal: the schedule is
	 * derived after cA verifies, not before, so an exchange that never
	 * completes leaves nothing usable here.
	 */
	struct matter_session_keys keys;
	/**
	 * The SPAKE2+ transcript, 534 bytes, live only while Pake1 is handled.
	 *
	 * It is here rather than on the stack deliberately. The frame that builds
	 * it also calls into oberon's elliptic curve code, and two stack sizes in
	 * this project were guessed low and both faulted on hardware; 534 bytes of
	 * BSS shows up in a size report, whereas 534 bytes of stack shows up as a
	 * fault. See CONFIG_TINYMATTER_BLE_WQ_STACK.
	 */
	uint8_t tt[MATTER_SPAKE_TT_LEN];
};

/**
 * Prepare a responder for one commissioning attempt.
 *
 * @param local_session_id the session id this device wants the commissioner to
 *        use when addressing it. Announced in PBKDFParamResponse.
 * @param responder_random 32 fresh random bytes. Goes on the wire, and into the
 *        context hash, so it is what stops a recorded exchange being replayed.
 * @param y_entropy MATTER_PASE_Y_ENTROPY_LEN fresh random bytes, reduced here
 *        rather than by the caller: taking 40 bytes and reducing them mod the
 *        group order is uniform to within 2^-64, whereas a caller handing over
 *        32 bytes it generated itself may or may not be in range at all.
 * @return MATTER_OK, or MATTER_E_INVAL for a null argument or a verifier whose
 *         salt length or iteration count is outside what PASE permits.
 */
int matter_pase_responder_init(struct matter_pase_responder *r,
			       const struct matter_pase_verifier *v, uint16_t local_session_id,
			       const uint8_t responder_random[MATTER_PASE_RANDOM_LEN],
			       const uint8_t y_entropy[MATTER_PASE_Y_ENTROPY_LEN]);

/**
 * Feed one received Secure Channel message and collect the reply.
 *
 * @param opcode  the Secure Channel opcode, 0x20..0x24.
 * @param payload the decrypted message payload: PASE runs unencrypted, so this
 *        is the TLV structure with no header in front of it.
 * @param out receives the reply, up to MATTER_PASE_REPLY_MAX bytes.
 * @param out_opcode receives the reply's opcode.
 *
 * @return MATTER_OK when the exchange advanced. On a negative return the
 *         responder is in MATTER_PASE_ST_FAILED and stays there -- but @p out
 *         may still hold a StatusReport, so the caller should send whatever
 *         @p out_len describes BEFORE acting on the return code. That is the
 *         only way the commissioner learns it failed rather than timing out:
 *
 *             rc = matter_pase_responder_recv(...);
 *             if (out_len > 0) { send(out_opcode, out, out_len); }
 *             if (rc != MATTER_OK) { drop_session(); }
 *
 *         MATTER_E_STATE for a message that does not fit the current state,
 *         MATTER_E_INVAL for a value the peer should not have sent,
 *         MATTER_E_TYPE when cA does not verify, MATTER_E_NOSPACE if @p cap is
 *         under MATTER_PASE_REPLY_MAX, or whatever the codec returned.
 */
int matter_pase_responder_recv(struct matter_pase_responder *r, uint8_t opcode,
			       const uint8_t *payload, size_t len, uint8_t *out, size_t cap,
			       size_t *out_len, uint8_t *out_opcode);

/** @return the current state; MATTER_PASE_ST_DONE means keys are usable. */
static inline enum matter_pase_state
matter_pase_responder_state(const struct matter_pase_responder *r)
{
	return (enum matter_pase_state)r->state;
}

/**
 * Encode a Secure Channel StatusReport.
 *
 * Exposed because it is not PASE's alone: CASE ends the same way, and a node
 * that cannot answer at all still owes the peer one of these.
 *
 * @param protocol_code MATTER_SC_CODE_*. The general code is derived from it,
 *        success for 0x0000 and failure otherwise, which is the rule
 *        PairingSession.h:147-149 applies.
 */
int matter_sc_status_report(uint16_t protocol_code, uint8_t *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

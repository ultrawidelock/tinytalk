/* SPDX-License-Identifier: ISC */

/**
 * @file matter_pase_sm.c — PASE responder state machine. See matter_pase_sm.h.
 */
#include <tinymatter/matter_pase_sm.h>

#include <string.h>

/**
 * Forget everything an unfinished exchange derived.
 *
 * A failed PAKE is the case where key material is most worth clearing: the
 * responder struct outlives the attempt, and the next commissioner to connect
 * gets the same memory.
 */
static void wipe_secrets(struct matter_pase_responder *r)
{
	memset(r->y, 0, sizeof(r->y));
	memset(r->ke, 0, sizeof(r->ke));
	memset(&r->keys, 0, sizeof(r->keys));
	memset(r->expect_ca, 0, sizeof(r->expect_ca));
}

/**
 * Enter the terminal state and answer with the one failure code PASE uses.
 *
 * @return @p rc, so callers can `return fail(r, rc, ...)`.
 */
static int fail(struct matter_pase_responder *r, int rc, uint8_t *out, size_t cap, size_t *out_len,
		uint8_t *out_opcode)
{
	r->state = (uint8_t)MATTER_PASE_ST_FAILED;
	wipe_secrets(r);

	/* Whatever a half-finished encode left behind is not a message. */
	*out_len = 0u;
	if (matter_sc_status_report(MATTER_SC_CODE_INVALID_PARAM, out, cap, out_len) == MATTER_OK) {
		*out_opcode = MATTER_SC_OP_STATUS_REPORT;
	}
	return rc;
}

/**
 * Encode a Matter secure channel status report with protocol result code.
 * Wraps result code (success or failure) in TLV with general status, vendor/protocol identifiers
 * all zero.
 * Returns MATTER_E_INVAL if out or out_len is NULL; returns MATTER_E_NOSPACE if cap is less than
 * MATTER_SC_STATUS_LEN.
 */
int matter_sc_status_report(uint16_t protocol_code, uint8_t *out, size_t cap, size_t *out_len)
{
	uint16_t general;

	if (out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}
	if (cap < MATTER_SC_STATUS_LEN) {
		return MATTER_E_NOSPACE;
	}

	general = (protocol_code == MATTER_SC_CODE_SUCCESS) ? MATTER_SC_GENERAL_SUCCESS
							    : MATTER_SC_GENERAL_FAILURE;

	out[0] = (uint8_t)general;
	out[1] = (uint8_t)(general >> 8);
	/* ProtocolId, fully qualified: vendor 0x0000, protocol 0x0000. */
	out[2] = 0u;
	out[3] = 0u;
	out[4] = 0u;
	out[5] = 0u;
	out[6] = (uint8_t)protocol_code;
	out[7] = (uint8_t)(protocol_code >> 8);

	*out_len = MATTER_SC_STATUS_LEN;
	return MATTER_OK;
}

/**
 * Initialize a PASE responder state machine with verifier and entropy.
 * Validates PBKDF salt and iteration count against protocol bounds before storing; derives y value
 * from entropy.
 * Returns MATTER_E_INVAL if any parameter is NULL, or if salt_len or iterations fall outside
 * allowed ranges.
 */
int matter_pase_responder_init(struct matter_pase_responder *r,
			       const struct matter_pase_verifier *v, uint16_t local_session_id,
			       const uint8_t responder_random[MATTER_PASE_RANDOM_LEN],
			       const uint8_t y_entropy[MATTER_PASE_Y_ENTROPY_LEN])
{
	if (r == NULL || v == NULL || responder_random == NULL || y_entropy == NULL) {
		return MATTER_E_INVAL;
	}
	/* The salt and iteration count go out on the wire in
	 * PBKDFParamResponse, so a verifier carrying values a commissioner would
	 * reject is caught here rather than three messages later. */
	if (v->salt_len < MATTER_PASE_SALT_MIN || v->salt_len > MATTER_PASE_SALT_MAX) {
		return MATTER_E_INVAL;
	}
	if (v->iterations < MATTER_PASE_ITER_MIN || v->iterations > MATTER_PASE_ITER_MAX) {
		return MATTER_E_INVAL;
	}

	memset(r, 0, sizeof(*r));
	r->v = *v;
	r->local_session_id = local_session_id;
	memcpy(r->responder_random, responder_random, MATTER_PASE_RANDOM_LEN);
	ocrypto_spake2p_p256_reduce(r->y, y_entropy, MATTER_PASE_Y_ENTROPY_LEN);
	r->state = (uint8_t)MATTER_PASE_ST_IDLE;

	return MATTER_OK;
}

/**
 * PBKDFParamRequest -> PBKDFParamResponse, and fix the context hash.
 *
 * The hash covers the request as received and the response as encoded, so it is
 * taken here where both are in hand: @p payload is still the peer's bytes and
 * @p out has just become ours. Re-encoding either one later to recompute this
 * would be the classic way to end up hashing something the peer never saw.
 */
static int on_pbkdf_req(struct matter_pase_responder *r, const uint8_t *payload, size_t len,
			uint8_t *out, size_t cap, size_t *out_len, uint8_t *out_opcode)
{
	struct matter_pase_pbkdf_req req;
	struct matter_pase_pbkdf_resp resp;
	int rc;

	rc = matter_pase_pbkdf_req_decode(payload, len, &req);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	r->peer_session_id = req.initiator_session_id;

	memset(&resp, 0, sizeof(resp));
	memcpy(resp.initiator_random, req.initiator_random, MATTER_PASE_RANDOM_LEN);
	memcpy(resp.responder_random, r->responder_random, MATTER_PASE_RANDOM_LEN);
	resp.responder_session_id = r->local_session_id;
	/* Send the parameters unless the commissioner told us it already has
	 * them (PASESession.cpp:494-502). */
	resp.pbkdf_params_present = !req.has_pbkdf_params;
	resp.iterations = r->v.iterations;
	resp.salt_len = r->v.salt_len;
	memcpy(resp.salt, r->v.salt, r->v.salt_len);

	rc = matter_pase_pbkdf_resp_encode(&resp, out, cap, out_len);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	rc = matter_spake2p_context(payload, len, out, *out_len, r->context);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	*out_opcode = MATTER_PASE_OP_PBKDF_RESP;
	r->state = (uint8_t)MATTER_PASE_ST_WAIT_PAKE1;
	return MATTER_OK;
}

/**
 * Pake1 (pA) -> Pake2 (pB, cB).
 *
 * This is the only place the elliptic curve is touched. w1 is NULL and L is
 * supplied, which is what selects the verifier side of get_ZV
 * (ocrypto_spake2p_p256.h:83,87); passing both, or neither, would silently
 * compute the wrong side.
 */
static int on_pake1(struct matter_pase_responder *r, const uint8_t *payload, size_t len,
		    uint8_t *out, size_t cap, size_t *out_len, uint8_t *out_opcode)
{
	struct matter_pase_pake1 in;
	struct matter_pase_pake2 reply;
	struct matter_spake2p_result res;
	uint8_t z[MATTER_SPAKE_POINT_LEN];
	uint8_t v[MATTER_SPAKE_POINT_LEN];
	size_t tt_len = sizeof(r->tt);
	int rc;

	rc = matter_pase_pake1_decode(payload, len, &in);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	/* pA arrives from a peer that has proved nothing yet. An off-curve or
	 * small-order point here is the standard way to attack a PAKE, and the
	 * check is one call. */
	if (ocrypto_spake2p_p256_check_key(in.pa) != 0) {
		return fail(r, MATTER_E_INVAL, out, cap, out_len, out_opcode);
	}

	if (ocrypto_spake2p_p256_get_key_share(reply.pb, r->v.w0, r->y, matter_spake2p_N) != 0) {
		return fail(r, MATTER_E_STATE, out, cap, out_len, out_opcode);
	}
	if (ocrypto_spake2p_p256_get_ZV(z, v, r->v.w0, NULL, r->y, in.pa, matter_spake2p_M,
					r->v.l) != 0) {
		return fail(r, MATTER_E_STATE, out, cap, out_len, out_opcode);
	}

	rc = matter_spake2p_transcript(r->context, in.pa, reply.pb, z, v, r->v.w0, r->tt, &tt_len);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}
	rc = matter_spake2p_p2(r->tt, tt_len, in.pa, reply.pb, &res);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	memcpy(reply.cb, res.cb, MATTER_PASE_HASH_LEN);
	memcpy(r->expect_ca, res.ca, MATTER_SPAKE_HASH_LEN);
	memcpy(r->ke, res.ke, MATTER_SPAKE_HALF_LEN);

	rc = matter_pase_pake2_encode(&reply, out, cap, out_len);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	*out_opcode = MATTER_PASE_OP_PAKE2;
	r->state = (uint8_t)MATTER_PASE_ST_WAIT_PAKE3;
	return MATTER_OK;
}

/** Pake3 (cA) -> StatusReport, and the session keys if cA is right. */
static int on_pake3(struct matter_pase_responder *r, const uint8_t *payload, size_t len,
		    uint8_t *out, size_t cap, size_t *out_len, uint8_t *out_opcode)
{
	struct matter_pase_pake3 in;
	int rc;

	rc = matter_pase_pake3_decode(payload, len, &in);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	if (!matter_spake2p_verify(r->expect_ca, in.ca)) {
		return fail(r, MATTER_E_TYPE, out, cap, out_len, out_opcode);
	}

	/* PASE derives with an empty salt; the randomness is already inside Ke
	 * by way of the context hash (matter_crypto.h). */
	rc = matter_derive_session_keys(r->ke, MATTER_SPAKE_HALF_LEN, NULL, 0u, false, &r->keys);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	rc = matter_sc_status_report(MATTER_SC_CODE_SUCCESS, out, cap, out_len);
	if (rc != MATTER_OK) {
		return fail(r, rc, out, cap, out_len, out_opcode);
	}

	*out_opcode = MATTER_SC_OP_STATUS_REPORT;
	r->state = (uint8_t)MATTER_PASE_ST_DONE;
	return MATTER_OK;
}

/**
 * Process one inbound PASE message and generate the appropriate response.
 * Dispatches by opcode (PBKDFParamRequest, Pake1, Pake3) to the corresponding state handler; enters
 * terminal failure state for out-of-sequence messages.
 * Returns MATTER_E_INVAL if r, payload, out, out_opcode is NULL; returns MATTER_E_NOSPACE if cap is
 * less than MATTER_PASE_REPLY_MAX; returns MATTER_E_STATE if opcode does not match current state.
 */
int matter_pase_responder_recv(struct matter_pase_responder *r, uint8_t opcode,
			       const uint8_t *payload, size_t len, uint8_t *out, size_t cap,
			       size_t *out_len, uint8_t *out_opcode)
{
	if (r == NULL || payload == NULL || out == NULL || out_len == NULL || out_opcode == NULL) {
		return MATTER_E_INVAL;
	}
	*out_len = 0u;
	*out_opcode = 0u;

	/* Checked once here rather than at each encode: every reply fits, so a
	 * caller with a short buffer is a caller bug, not a peer one, and it
	 * should not be reported to the peer as a protocol failure. */
	if (cap < MATTER_PASE_REPLY_MAX) {
		return MATTER_E_NOSPACE;
	}

	/* An opcode that does not belong to the current state ends the exchange
	 * rather than being ignored. A commissioner that replays Pake1 after
	 * Pake2 is not a commissioner that got confused; it is one probing for a
	 * second transcript against the same y. */
	switch (r->state) {
	case MATTER_PASE_ST_IDLE:
		if (opcode != MATTER_PASE_OP_PBKDF_REQ) {
			break;
		}
		return on_pbkdf_req(r, payload, len, out, cap, out_len, out_opcode);
	case MATTER_PASE_ST_WAIT_PAKE1:
		if (opcode != MATTER_PASE_OP_PAKE1) {
			break;
		}
		return on_pake1(r, payload, len, out, cap, out_len, out_opcode);
	case MATTER_PASE_ST_WAIT_PAKE3:
		if (opcode != MATTER_PASE_OP_PAKE3) {
			break;
		}
		return on_pake3(r, payload, len, out, cap, out_len, out_opcode);
	default:
		break;
	}

	return fail(r, MATTER_E_STATE, out, cap, out_len, out_opcode);
}

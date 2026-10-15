/* SPDX-License-Identifier: ISC */

/**
 * @file matter_pase.c — PASE message codec over Matter TLV.
 */
/*
 * The first real consumer of matter_tlv.c, which is worth saying because it is
 * also the first thing that would expose a bug in it.
 *
 * Every field here arrives before PASE has proved anything, so the decoders are
 * written to refuse rather than to cope: fixed-size fields must be exactly
 * their size, the PBKDF work factor must be inside the range the spec allows,
 * and a missing required field is an error rather than a zero. An attacker who
 * can reach the 0xFFF6 characteristic can send any of these.
 *
 * Tags are read by number rather than by position. The spec lets optional
 * fields be absent, so a positional reader would mis-assign every field after
 * the first gap.
 */
#include <string.h>

#include <tinymatter/matter_pase.h>

#include <tinymatter/matter_tlv.h>

/* Tag numbers, identical in CHIP (PASESession.cpp:60-95) and CircuitMatter. */
#define REQ_INITIATOR_RANDOM 1u
#define REQ_SESSION_ID       2u
#define REQ_PASSCODE_ID      3u
#define REQ_HAS_PBKDF        4u
#define REQ_SESSION_PARAMS   5u

#define RESP_INITIATOR_RANDOM 1u
#define RESP_RESPONDER_RANDOM 2u
#define RESP_SESSION_ID       3u
#define RESP_PBKDF_PARAMS     4u
#define RESP_SESSION_PARAMS   5u

#define PBKDF_ITERATIONS 1u
#define PBKDF_SALT       2u

#define PAKE_PA 1u
#define PAKE_PB 1u
#define PAKE_CB 2u
#define PAKE_CA 1u

/* Session parameters (SessionParameters.h:52-54 / session.py:25-26). */
#define SP_IDLE_INTERVAL   1u
#define SP_ACTIVE_INTERVAL 2u

/** Context tag number of the loaded element, or -1 if it is not a context tag. */
static int ctx_tag(const struct matter_tlv_reader *r)
{
	matter_tlv_tag_t tag = matter_tlv_tag(r);

	if ((uint32_t)(tag >> 32) != MATTER_TLV_SPECIAL_PROFILE) {
		return -1;
	}
	uint32_t num = (uint32_t)tag;

	if (num > 0xFFu) {
		return -1; /* anonymous, which uses a number above the context range */
	}
	return (int)num;
}

/** Copy a byte string that must be exactly @p want long. */
static int get_fixed(const struct matter_tlv_reader *r, uint8_t *dst, size_t want)
{
	const uint8_t *p = NULL;
	size_t n = 0;
	int rc = matter_tlv_get_bytes(r, &p, &n);

	if (rc != MATTER_OK) {
		return rc;
	}
	if (n != want) {
		return MATTER_E_INVAL;
	}
	memcpy(dst, p, want);
	return MATTER_OK;
}

/** Read a session-parameters structure the reader is currently sitting on. */
static int read_session_params(struct matter_tlv_reader *r, struct matter_session_params *out)
{
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}
	while ((rc = matter_tlv_next(r)) == MATTER_OK) {
		uint64_t v = 0;

		switch (ctx_tag(r)) {
		case SP_IDLE_INTERVAL:
			if (matter_tlv_get_u64(r, &v) == MATTER_OK && v <= 0xFFFFFFFFu) {
				out->idle_interval_ms = (uint32_t)v;
				out->have_idle = true;
			}
			break;
		case SP_ACTIVE_INTERVAL:
			if (matter_tlv_get_u64(r, &v) == MATTER_OK && v <= 0xFFFFFFFFu) {
				out->active_interval_ms = (uint32_t)v;
				out->have_active = true;
			}
			break;
		default:
			/* Later spec versions add fields here; skipping them is how a
			 * newer commissioner stays compatible with this node. */
			break;
		}
	}
	if (rc != MATTER_END) {
		return rc;
	}
	return matter_tlv_exit(r);
}

/** Open the outer anonymous structure every PASE message is wrapped in. */
static int open_message(struct matter_tlv_reader *r, const uint8_t *buf, size_t len)
{
	int rc;

	if (buf == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_reader_init(r, buf, len);
	rc = matter_tlv_next(r);
	if (rc != MATTER_OK) {
		return (rc == MATTER_END) ? MATTER_E_TRUNC : rc;
	}
	if (matter_tlv_element_type(r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	return matter_tlv_enter(r);
}

/**
 * Decode a PBKDF request message; extracts initiator random, session ID, and optional PBKDF
 * parameters; returns MATTER_E_STATE if required fields are missing and MATTER_E_INVAL if passcode
 * ID is not 0.
 */
int matter_pase_pbkdf_req_decode(const uint8_t *buf, size_t len, struct matter_pase_pbkdf_req *out)
{
	struct matter_tlv_reader r;
	bool got_random = false;
	bool got_session = false;
	int rc;

	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	rc = open_message(&r, buf, len);
	if (rc != MATTER_OK) {
		return rc;
	}

	while ((rc = matter_tlv_next(&r)) == MATTER_OK) {
		uint64_t v = 0;
		bool b = false;

		switch (ctx_tag(&r)) {
		case REQ_INITIATOR_RANDOM:
			rc = get_fixed(&r, out->initiator_random, MATTER_PASE_RANDOM_LEN);
			if (rc != MATTER_OK) {
				return rc;
			}
			got_random = true;
			break;
		case REQ_SESSION_ID:
			rc = matter_tlv_get_u64(&r, &v);
			if (rc != MATTER_OK || v > 0xFFFFu) {
				return MATTER_E_INVAL;
			}
			out->initiator_session_id = (uint16_t)v;
			got_session = true;
			break;
		case REQ_PASSCODE_ID:
			rc = matter_tlv_get_u64(&r, &v);
			if (rc != MATTER_OK || v > 0xFFFFu) {
				return MATTER_E_INVAL;
			}
			out->passcode_id = (uint16_t)v;
			break;
		case REQ_HAS_PBKDF:
			rc = matter_tlv_get_bool(&r, &b);
			if (rc != MATTER_OK) {
				return rc;
			}
			out->has_pbkdf_params = b;
			break;
		case REQ_SESSION_PARAMS:
			rc = read_session_params(&r, &out->params);
			if (rc != MATTER_OK) {
				return rc;
			}
			break;
		default:
			break;
		}
	}
	if (rc != MATTER_END) {
		return rc;
	}

	if (!got_random || !got_session) {
		return MATTER_E_STATE;
	}
	/* Commissioning only ever uses passcode ID 0 (PASESession.cpp:433). */
	if (out->passcode_id != MATTER_PASE_PASSCODE_ID) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/**
 * Encode a PBKDF request message with initiator random, session ID, optional passcode and session
 * parameters.
 */
int matter_pase_pbkdf_req_encode(const struct matter_pase_pbkdf_req *r, uint8_t *buf, size_t cap,
				 size_t *written)
{
	struct matter_tlv_writer w;

	if (r == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_writer_init(&w, buf, cap);
	matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(REQ_INITIATOR_RANDOM), r->initiator_random,
			     MATTER_PASE_RANDOM_LEN);
	matter_tlv_put_u64(&w, MATTER_TLV_CTX(REQ_SESSION_ID), r->initiator_session_id);
	matter_tlv_put_u64(&w, MATTER_TLV_CTX(REQ_PASSCODE_ID), r->passcode_id);
	matter_tlv_put_bool(&w, MATTER_TLV_CTX(REQ_HAS_PBKDF), r->has_pbkdf_params);
	matter_tlv_end_container(&w);
	return matter_tlv_writer_finish(&w, written);
}

/**
 * Decode a PBKDF parameters structure from the reader's current position; extracts iteration count
 * and salt, validating that iteration count is within the minimum and maximum allowed range;
 * returns MATTER_E_STATE if either field is missing.
 */
static int read_pbkdf_params(struct matter_tlv_reader *r, struct matter_pase_pbkdf_resp *out)
{
	bool got_iter = false;
	bool got_salt = false;
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}
	while ((rc = matter_tlv_next(r)) == MATTER_OK) {
		uint64_t v = 0;
		const uint8_t *p = NULL;
		size_t n = 0;

		switch (ctx_tag(r)) {
		case PBKDF_ITERATIONS:
			rc = matter_tlv_get_u64(r, &v);
			if (rc != MATTER_OK) {
				return rc;
			}
			/* The work factor is what makes a stolen salt expensive to use;
			 * a peer offering 1 iteration is refused, not accommodated. */
			if (v < MATTER_PASE_ITER_MIN || v > MATTER_PASE_ITER_MAX) {
				return MATTER_E_INVAL;
			}
			out->iterations = (uint32_t)v;
			got_iter = true;
			break;
		case PBKDF_SALT:
			rc = matter_tlv_get_bytes(r, &p, &n);
			if (rc != MATTER_OK) {
				return rc;
			}
			if (n < MATTER_PASE_SALT_MIN || n > MATTER_PASE_SALT_MAX) {
				return MATTER_E_INVAL;
			}
			memcpy(out->salt, p, n);
			out->salt_len = (uint8_t)n;
			got_salt = true;
			break;
		default:
			break;
		}
	}
	if (rc != MATTER_END) {
		return rc;
	}
	if (!got_iter || !got_salt) {
		return MATTER_E_STATE;
	}
	out->pbkdf_params_present = true;
	return matter_tlv_exit(r);
}

/**
 * Decode a PBKDF response message: extract initiator and responder randomness, responder session
 * ID, PBKDF parameters, and session parameters. Require all three random and session ID fields.
 */
int matter_pase_pbkdf_resp_decode(const uint8_t *buf, size_t len,
				  struct matter_pase_pbkdf_resp *out)
{
	struct matter_tlv_reader r;
	bool got_init = false;
	bool got_resp = false;
	bool got_session = false;
	int rc;

	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	rc = open_message(&r, buf, len);
	if (rc != MATTER_OK) {
		return rc;
	}

	while ((rc = matter_tlv_next(&r)) == MATTER_OK) {
		uint64_t v = 0;

		switch (ctx_tag(&r)) {
		case RESP_INITIATOR_RANDOM:
			rc = get_fixed(&r, out->initiator_random, MATTER_PASE_RANDOM_LEN);
			if (rc != MATTER_OK) {
				return rc;
			}
			got_init = true;
			break;
		case RESP_RESPONDER_RANDOM:
			rc = get_fixed(&r, out->responder_random, MATTER_PASE_RANDOM_LEN);
			if (rc != MATTER_OK) {
				return rc;
			}
			got_resp = true;
			break;
		case RESP_SESSION_ID:
			rc = matter_tlv_get_u64(&r, &v);
			if (rc != MATTER_OK || v > 0xFFFFu) {
				return MATTER_E_INVAL;
			}
			out->responder_session_id = (uint16_t)v;
			got_session = true;
			break;
		case RESP_PBKDF_PARAMS:
			rc = read_pbkdf_params(&r, out);
			if (rc != MATTER_OK) {
				return rc;
			}
			break;
		case RESP_SESSION_PARAMS:
			rc = read_session_params(&r, &out->params);
			if (rc != MATTER_OK) {
				return rc;
			}
			break;
		default:
			break;
		}
	}
	if (rc != MATTER_END) {
		return rc;
	}
	if (!got_init || !got_resp || !got_session) {
		return MATTER_E_STATE;
	}
	return MATTER_OK;
}

/**
 * Encode a PBKDF response message with responder random, session ID, and optional PBKDF parameters
 * (salt and iteration count); validates that salt and iteration counts are within allowed ranges if
 * present.
 */
int matter_pase_pbkdf_resp_encode(const struct matter_pase_pbkdf_resp *r, uint8_t *buf, size_t cap,
				  size_t *written)
{
	struct matter_tlv_writer w;

	if (r == NULL) {
		return MATTER_E_INVAL;
	}
	if (r->pbkdf_params_present &&
	    (r->salt_len < MATTER_PASE_SALT_MIN || r->salt_len > MATTER_PASE_SALT_MAX ||
	     r->iterations < MATTER_PASE_ITER_MIN || r->iterations > MATTER_PASE_ITER_MAX)) {
		return MATTER_E_INVAL;
	}

	matter_tlv_writer_init(&w, buf, cap);
	matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(RESP_INITIATOR_RANDOM), r->initiator_random,
			     MATTER_PASE_RANDOM_LEN);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(RESP_RESPONDER_RANDOM), r->responder_random,
			     MATTER_PASE_RANDOM_LEN);
	matter_tlv_put_u64(&w, MATTER_TLV_CTX(RESP_SESSION_ID), r->responder_session_id);
	if (r->pbkdf_params_present) {
		matter_tlv_start_container(&w, MATTER_TLV_CTX(RESP_PBKDF_PARAMS),
					   MATTER_TLV_STRUCTURE);
		matter_tlv_put_u64(&w, MATTER_TLV_CTX(PBKDF_ITERATIONS), r->iterations);
		matter_tlv_put_bytes(&w, MATTER_TLV_CTX(PBKDF_SALT), r->salt, r->salt_len);
		matter_tlv_end_container(&w);
	}
	matter_tlv_end_container(&w);
	return matter_tlv_writer_finish(&w, written);
}

/* ---- Pake1/2/3, which are just fixed-size byte strings -------------------- */

/**
 * Decode a single context-tagged field from a PASE message; scans the entire message for the given
 * tag and copies its fixed-length value to dst, returning MATTER_E_STATE if the tag is not found.
 */
static int decode_one(const uint8_t *buf, size_t len, unsigned int tag, uint8_t *dst, size_t want)
{
	struct matter_tlv_reader r;
	bool got = false;
	int rc = open_message(&r, buf, len);

	if (rc != MATTER_OK) {
		return rc;
	}
	while ((rc = matter_tlv_next(&r)) == MATTER_OK) {
		if (ctx_tag(&r) == (int)tag) {
			rc = get_fixed(&r, dst, want);
			if (rc != MATTER_OK) {
				return rc;
			}
			got = true;
		}
	}
	if (rc != MATTER_END) {
		return rc;
	}
	return got ? MATTER_OK : MATTER_E_STATE;
}

/**
 * Decode the initiator's P_A point from a PASE Pake1 message.
 */
int matter_pase_pake1_decode(const uint8_t *buf, size_t len, struct matter_pase_pake1 *out)
{
	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));
	return decode_one(buf, len, PAKE_PA, out->pa, MATTER_PASE_POINT_LEN);
}

/**
 * Encode a PAKE1 message containing the initiator's ephemeral public point.
 */
int matter_pase_pake1_encode(const struct matter_pase_pake1 *r, uint8_t *buf, size_t cap,
			     size_t *written)
{
	struct matter_tlv_writer w;

	if (r == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_writer_init(&w, buf, cap);
	matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(PAKE_PA), r->pa, MATTER_PASE_POINT_LEN);
	matter_tlv_end_container(&w);
	return matter_tlv_writer_finish(&w, written);
}

/**
 * Decode a PAKE2 message containing the responder's ephemeral public point and confirmation hash;
 * returns MATTER_E_STATE if either field is missing.
 */
int matter_pase_pake2_decode(const uint8_t *buf, size_t len, struct matter_pase_pake2 *out)
{
	struct matter_tlv_reader r;
	bool got_pb = false;
	bool got_cb = false;
	int rc;

	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	rc = open_message(&r, buf, len);
	if (rc != MATTER_OK) {
		return rc;
	}
	while ((rc = matter_tlv_next(&r)) == MATTER_OK) {
		switch (ctx_tag(&r)) {
		case PAKE_PB:
			rc = get_fixed(&r, out->pb, MATTER_PASE_POINT_LEN);
			if (rc != MATTER_OK) {
				return rc;
			}
			got_pb = true;
			break;
		case PAKE_CB:
			rc = get_fixed(&r, out->cb, MATTER_PASE_HASH_LEN);
			if (rc != MATTER_OK) {
				return rc;
			}
			got_cb = true;
			break;
		default:
			break;
		}
	}
	if (rc != MATTER_END) {
		return rc;
	}
	return (got_pb && got_cb) ? MATTER_OK : MATTER_E_STATE;
}

/**
 * Encode a PAKE2 message containing the responder's ephemeral public point and confirmation hash.
 */
int matter_pase_pake2_encode(const struct matter_pase_pake2 *r, uint8_t *buf, size_t cap,
			     size_t *written)
{
	struct matter_tlv_writer w;

	if (r == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_writer_init(&w, buf, cap);
	matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(PAKE_PB), r->pb, MATTER_PASE_POINT_LEN);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(PAKE_CB), r->cb, MATTER_PASE_HASH_LEN);
	matter_tlv_end_container(&w);
	return matter_tlv_writer_finish(&w, written);
}

/**
 * Decode the committer's C_A hash from a PASE Pake3 message.
 */
int matter_pase_pake3_decode(const uint8_t *buf, size_t len, struct matter_pase_pake3 *out)
{
	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));
	return decode_one(buf, len, PAKE_CA, out->ca, MATTER_PASE_HASH_LEN);
}

/**
 * Encode a PAKE3 message containing the initiator's confirmation hash.
 */
int matter_pase_pake3_encode(const struct matter_pase_pake3 *r, uint8_t *buf, size_t cap,
			     size_t *written)
{
	struct matter_tlv_writer w;

	if (r == NULL) {
		return MATTER_E_INVAL;
	}
	matter_tlv_writer_init(&w, buf, cap);
	matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	matter_tlv_put_bytes(&w, MATTER_TLV_CTX(PAKE_CA), r->ca, MATTER_PASE_HASH_LEN);
	matter_tlv_end_container(&w);
	return matter_tlv_writer_finish(&w, written);
}

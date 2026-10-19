/* SPDX-License-Identifier: Apache-2.0 */

/*
 * See matter_case.h.
 */
#include <tinytalk/matter_case.h>

#include <string.h>

#include <tinytalk/tm_hash.h>
#include <tinytalk/matter_crypto.h>
#include <tinytalk/matter_fabric.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_tlv.h>

/* Sigma1 field tags (CASESession.cpp:74-83). */
#define TAG_S1_INITIATOR_RANDOM  1u
#define TAG_S1_INITIATOR_SESSION 2u
#define TAG_S1_DESTINATION_ID    3u
#define TAG_S1_INITIATOR_PUBKEY  4u
#define TAG_S1_RESUMPTION_ID     6u

/**
 * Derive the CASE operational IPK from an epoch key and compressed fabric ID using HKDF with the
 * "GroupKey v1.0" info string; returns MATTER_OK on success.
 */
int matter_case_operational_ipk(const uint8_t epoch_key[MATTER_CASE_IPK_LEN],
				const uint8_t compressed_fabric_id[8],
				uint8_t out[MATTER_CASE_IPK_LEN])
{
	/* "GroupKey v1.0" (crypto/CHIPCryptoPAL.cpp:848). Spelled out so no NUL
	 * can creep into the length -- it is 13 bytes, not 14. */
	static const uint8_t k_info[] = {0x47, 0x72, 0x6F, 0x75, 0x70, 0x4B, 0x65,
					 0x79, 0x20, 0x76, 0x31, 0x2E, 0x30};

	if (epoch_key == NULL || compressed_fabric_id == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (tm_hkdf(compressed_fabric_id, 8u, epoch_key, MATTER_CASE_IPK_LEN, k_info,
		       sizeof(k_info), out, MATTER_CASE_IPK_LEN) != 0) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/**
 * Compute a CASE destination ID by hashing the initiator random, root public key, fabric ID, and
 * node ID with the IPK as the HMAC key; returns MATTER_OK on success.
 */
int matter_case_destination_id(const uint8_t ipk[MATTER_CASE_IPK_LEN],
			       const uint8_t initiator_random[MATTER_CASE_RANDOM_LEN],
			       const uint8_t root_pub[MATTER_CASE_PUBKEY_LEN], uint64_t fabric_id,
			       uint64_t node_id, uint8_t out[MATTER_CASE_DEST_ID_LEN])
{
	uint8_t msg[MATTER_CASE_RANDOM_LEN + MATTER_CASE_PUBKEY_LEN + 8u + 8u];
	size_t n = 0u;
	size_t i;

	if (ipk == NULL || initiator_random == NULL || root_pub == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	memcpy(&msg[n], initiator_random, MATTER_CASE_RANDOM_LEN);
	n += MATTER_CASE_RANDOM_LEN;
	memcpy(&msg[n], root_pub, MATTER_CASE_PUBKEY_LEN);
	n += MATTER_CASE_PUBKEY_LEN;
	/* LITTLE-endian, both of them. */
	for (i = 0u; i < 8u; i++) {
		msg[n + i] = (uint8_t)(fabric_id >> (8u * i));
	}
	n += 8u;
	for (i = 0u; i < 8u; i++) {
		msg[n + i] = (uint8_t)(node_id >> (8u * i));
	}
	n += 8u;

	tm_hmac_sha256(ipk, MATTER_CASE_IPK_LEN, msg, n, out);
	return MATTER_OK;
}

/** Borrow one octet string of an expected length out of the loaded element. */
static int take_bytes(const struct matter_tlv_reader *r, const uint8_t **out, size_t want)
{
	const uint8_t *p = NULL;
	size_t len = 0u;

	if (matter_tlv_get_bytes(r, &p, &len) != MATTER_OK) {
		return MATTER_E_TYPE;
	}
	if (len != want) {
		return MATTER_E_INVAL;
	}
	*out = p;
	return MATTER_OK;
}

/**
 * Decode a Sigma1 message from TLV, extracting initiator random, destination ID, initiator public
 * key, session ID, and optional resumption ID; skips unknown fields and returns MATTER_E_INVAL if
 * mandatory fields are missing.
 */
int matter_case_sigma1_decode(const uint8_t *tlv, size_t len, struct matter_case_sigma1 *out)
{
	struct matter_tlv_reader r;
	int rc;

	if (tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != MATTER_OK ||
	    matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		uint64_t v = 0u;

		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_INITIATOR_RANDOM)) {
			rc = take_bytes(&r, &out->initiator_random, MATTER_CASE_RANDOM_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_DESTINATION_ID)) {
			rc = take_bytes(&r, &out->destination_id, MATTER_CASE_DEST_ID_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_INITIATOR_PUBKEY)) {
			rc = take_bytes(&r, &out->initiator_pubkey, MATTER_CASE_PUBKEY_LEN);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_INITIATOR_SESSION)) {
			if (matter_tlv_get_u64(&r, &v) != MATTER_OK || v > UINT16_MAX) {
				return MATTER_E_INVAL;
			}
			out->initiator_session_id = (uint16_t)v;
			rc = MATTER_OK;
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S1_RESUMPTION_ID)) {
			if (matter_tlv_get_bytes(&r, &out->resumption_id,
						 &out->resumption_id_len) != MATTER_OK) {
				return MATTER_E_TYPE;
			}
			out->has_resumption = true;
			rc = MATTER_OK;
		} else {
			/* Session parameters and the resumption MIC are skipped
			 * rather than refused: a newer initiator may send fields
			 * this node has never heard of, and none of them changes
			 * whether the identity below is the right one. */
			rc = MATTER_OK;
		}

		if (rc != MATTER_OK) {
			return rc;
		}
	}

	/* All three are mandatory, and each has exactly one legal length. A
	 * Sigma1 missing any of them cannot be answered. */
	if (out->initiator_random == NULL || out->destination_id == NULL ||
	    out->initiator_pubkey == NULL) {
		return MATTER_E_INVAL;
	}
	return MATTER_OK;
}

/* --------------------------------------------------------- Sigma2 --- */

/* Sigma2 field tags (CASESession.cpp:85-92). */
#define TAG_S2_RESPONDER_RANDOM  1u
#define TAG_S2_RESPONDER_SESSION 2u
#define TAG_S2_RESPONDER_PUBKEY  3u
#define TAG_S2_ENCRYPTED         4u
#define TAG_S2_SESSION_PARAMS    5u

/* SessionParameters (PairingSession.cpp:120-144, SessionParameters::Tag). */
#define TAG_SP_IDLE_INTERVAL         1u
#define TAG_SP_ACTIVE_INTERVAL       2u
#define TAG_SP_ACTIVE_THRESHOLD      3u
#define TAG_SP_INTERACTION_MODEL_REV 5u
#define TAG_SP_MAX_PATHS_PER_INVOKE  7u

/* TBSData and TBEData tags, shared by Sigma2 and Sigma3 (CASESession.cpp:56-72). */
#define TAG_TBS_NOC           1u
#define TAG_TBS_ICAC          2u
#define TAG_TBS_SENDER_PUBKEY 3u
#define TAG_TBS_RECV_PUBKEY   4u

#define TAG_TBE_NOC           1u
#define TAG_TBE_ICAC          2u
#define TAG_TBE_SIGNATURE     3u
#define TAG_TBE_RESUMPTION_ID 4u

/** Length of the S2K salt: IPK, random, ephemeral key, transcript hash. */
#define S2K_SALT_LEN (MATTER_CASE_IPK_LEN + MATTER_CASE_RANDOM_LEN + MATTER_CASE_PUBKEY_LEN + 32u)

/** Resumption identifiers are 16 bytes (CASESession.cpp, kCASEResumptionIDSize). */
#define RESUMPTION_ID_LEN 16u

/*
 * Certificates, signatures and the TLV around them, for whichever of Sigma2 and
 * Sigma3 is in hand. One buffer serves both: Sigma2 is built, sent and finished
 * with before its Sigma3 can arrive, and both run on the OpenThread thread, so
 * the two are never live at once. A second kilobyte of scratch is a real cost
 * on a node with 128 KB of RAM; this is the reason it is not spent.
 *
 * Sigma2 uses it twice in turn -- TBSData2 is signed and then no longer needed,
 * so TBEData2 is built over it.
 */
static uint8_t s_scratch[MATTER_CASE_SIGMA2_MAX];

/**
 * Encode a Sigma2 message by computing ECDH, deriving S2K from a salt, signing TBSData2, encrypting
 * TBEData2, and wrapping both in TLV with session parameters; returns MATTER_OK on success.
 */
int matter_case_sigma2_encode(const struct matter_case_sigma2_in *in, uint8_t *out, size_t cap,
			      size_t *out_len, uint8_t shared_out[MATTER_CASE_SECRET_LEN])
{
	/* "Sigma2" and "NCASE_Sigma2N" (CASESession.cpp:128,138). */
	static const uint8_t k_info[] = {0x53, 0x69, 0x67, 0x6D, 0x61, 0x32};
	static const uint8_t k_nonce[MATTER_NONCE_LEN] = {0x4E, 0x43, 0x41, 0x53, 0x45, 0x5F, 0x53,
							  0x69, 0x67, 0x6D, 0x61, 0x32, 0x4E};
	uint8_t salt[S2K_SALT_LEN];
	uint8_t s2k[MATTER_KEY_LEN];
	uint8_t sig[MATTER_CASE_SIG_LEN];
	struct matter_tlv_writer w;
	size_t n = 0u;
	size_t off = 0u;
	int rc;

	if (in == NULL || out == NULL || out_len == NULL || shared_out == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->initiator_pubkey == NULL || in->transcript_hash == NULL || in->ipk == NULL ||
	    in->noc == NULL || in->op_priv == NULL || in->responder_random == NULL ||
	    in->responder_eph_priv == NULL || in->responder_eph_pub == NULL ||
	    in->resumption_id == NULL) {
		return MATTER_E_INVAL;
	}

	if (matter_case_ecdh(in->responder_eph_priv, in->initiator_pubkey, shared_out) != 0) {
		return MATTER_E_STATE;
	}

	memcpy(&salt[off], in->ipk, MATTER_CASE_IPK_LEN);
	off += MATTER_CASE_IPK_LEN;
	memcpy(&salt[off], in->responder_random, MATTER_CASE_RANDOM_LEN);
	off += MATTER_CASE_RANDOM_LEN;
	memcpy(&salt[off], in->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
	off += MATTER_CASE_PUBKEY_LEN;
	memcpy(&salt[off], in->transcript_hash, 32u);
	off += 32u;

	rc = tm_hkdf(salt, off, shared_out, MATTER_CASE_SECRET_LEN, k_info, sizeof(k_info), s2k,
			sizeof(s2k));
	memset(salt, 0, sizeof(salt));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	/*
	 * TBSData2. Signed, never transmitted: the peer rebuilds it from what it
	 * already has, which is what makes the signature bind this exchange's
	 * ephemeral keys rather than merely the certificate chain.
	 */
	matter_tlv_writer_init(&w, s_scratch, sizeof(s_scratch));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_NOC), in->noc, in->noc_len);
	if (in->icac != NULL && in->icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_ICAC), in->icac,
					   in->icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_SENDER_PUBKEY), in->responder_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_RECV_PUBKEY), in->initiator_pubkey,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		memset(s2k, 0, sizeof(s2k));
		return rc;
	}

	if (matter_case_sign(in->op_priv, s_scratch, n, sig) != 0) {
		memset(s2k, 0, sizeof(s2k));
		return MATTER_E_STATE;
	}
	/*
	 * Verify it here, against the public key out of the very NOC that is
	 * about to be sent alongside it. A peer that rejects a signature says
	 * nothing about why, so this is the only place "signed wrongly" and
	 * "derived a different key" can be told apart.
	 */
	if (in->verify_pub != NULL && matter_case_verify(in->verify_pub, s_scratch, n, sig) != 0) {
		memset(s2k, 0, sizeof(s2k));
		return MATTER_E_STATE;
	}

	/* TBEData2, over the same s_scratch now that the signature exists. */
	matter_tlv_writer_init(&w, s_scratch, sizeof(s_scratch) - MATTER_TAG_LEN);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_NOC), in->noc, in->noc_len);
	if (in->icac != NULL && in->icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_ICAC), in->icac,
					   in->icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_SIGNATURE), sig, sizeof(sig));
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBE_RESUMPTION_ID), in->resumption_id,
				   RESUMPTION_ID_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		memset(s2k, 0, sizeof(s2k));
		return rc;
	}

	/* Encrypted in place, tag appended. No AAD: Sigma2 has none. */
	rc = matter_aead_encrypt(s2k, k_nonce, NULL, 0u, s_scratch, n, s_scratch, s_scratch + n);
	memset(s2k, 0, sizeof(s2k));
	if (rc != MATTER_OK) {
		return rc;
	}
	n += MATTER_TAG_LEN;

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S2_RESPONDER_RANDOM),
				   in->responder_random, MATTER_CASE_RANDOM_LEN);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_S2_RESPONDER_SESSION),
				 in->responder_session_id);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S2_RESPONDER_PUBKEY),
				   in->responder_eph_pub, MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_S2_ENCRYPTED), s_scratch, n);

	/*
	 * Session parameters. Optional in the spec and ALWAYS sent by CHIP
	 * (PairingSession.cpp:120-144), which is reason enough on its own -- but
	 * two of these are load-bearing for this node in particular.
	 *
	 * The idle interval matches the radio. This node is an rx-on MED
	 * (samples/door-lock/overlay-thread.conf), so the spec-default 500 ms is
	 * honest; it was 3000 while the node was a sleepy end device, and the
	 * value must follow the link mode. The SRP TXT record in
	 * ports/zephyr/thread/matter_thread_port.c advertises the same pair.
	 *
	 * MaxPathsPerInvoke is 1 because matter_im_invoke_request_decode()
	 * genuinely refuses a batch. Saying nothing lets a commissioner batch
	 * two commands and be refused for a reason it was never told.
	 */
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_S2_SESSION_PARAMS),
					 MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_IDLE_INTERVAL), 500u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_ACTIVE_INTERVAL), 300u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_ACTIVE_THRESHOLD), 4000u);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_INTERACTION_MODEL_REV),
				 MATTER_IM_REVISION);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_SP_MAX_PATHS_PER_INVOKE), 1u);
	(void)matter_tlv_end_container(&w);

	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/* --------------------------------------------------------- Sigma3 --- */

/* The only field a Sigma3 has (CASESession.cpp:101-104, Sigma3Tags). */
#define TAG_S3_ENCRYPTED 1u

/** Length of the S3K salt: the IPK and the transcript hash, and nothing else. */
#define S3K_SALT_LEN (MATTER_CASE_IPK_LEN + 32u)

/**
 * Open and validate a Sigma3 message by decrypting TBEData3, verifying the signature over TBSData3
 * against the initiator's NOC, and extracting the node ID, fabric ID, and public key; returns
 * MATTER_OK on success.
 */
int matter_case_sigma3_open(const struct matter_case_sigma3_in *in, const uint8_t *tlv, size_t len,
			    struct matter_case_sigma3_out *out)
{
	/* "Sigma3" and "NCASE_Sigma3N" (CASESession.cpp:129,140). */
	static const uint8_t k_info[] = {0x53, 0x69, 0x67, 0x6D, 0x61, 0x33};
	static const uint8_t k_nonce[MATTER_NONCE_LEN] = {0x4E, 0x43, 0x41, 0x53, 0x45, 0x5F, 0x53,
							  0x69, 0x67, 0x6D, 0x61, 0x33, 0x4E};
	/*
	 * TBSData3 is rebuilt here rather than received, so it needs a buffer of
	 * its own: the certificates it copies are still sitting in the decrypted
	 * TBEData3, so unlike Sigma2's two structures these two ARE live at the
	 * same moment and cannot share.
	 */
	static uint8_t tbs[MATTER_CASE_SIGMA3_MAX];
	uint8_t salt[S3K_SALT_LEN];
	uint8_t s3k[MATTER_KEY_LEN];
	struct matter_cert_info cert;
	struct matter_tlv_reader r;
	struct matter_tlv_writer w;
	const uint8_t *enc = NULL;
	const uint8_t *noc = NULL;
	const uint8_t *icac = NULL;
	const uint8_t *sig = NULL;
	size_t enc_len = 0u;
	size_t noc_len = 0u;
	size_t icac_len = 0u;
	size_t sig_len = 0u;
	size_t n = 0u;
	int rc;

	if (in == NULL || tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (in->shared == NULL || in->ipk == NULL || in->transcript_hash == NULL ||
	    in->initiator_eph_pub == NULL || in->responder_eph_pub == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	/* The outer message: one octet string, everything else is inside it. */
	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != MATTER_OK ||
	    matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_S3_ENCRYPTED) &&
		    matter_tlv_get_bytes(&r, &enc, &enc_len) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
	}
	/* Shorter than its own authentication tag means there is no ciphertext
	 * at all, and the subtraction below would wrap. */
	if (enc == NULL || enc_len <= MATTER_TAG_LEN) {
		return MATTER_E_INVAL;
	}
	if ((enc_len - MATTER_TAG_LEN) > sizeof(s_scratch)) {
		return MATTER_E_NOSPACE;
	}

	memcpy(salt, in->ipk, MATTER_CASE_IPK_LEN);
	memcpy(&salt[MATTER_CASE_IPK_LEN], in->transcript_hash, 32u);
	rc = tm_hkdf(salt, sizeof(salt), in->shared, MATTER_CASE_SECRET_LEN, k_info,
			sizeof(k_info), s3k, sizeof(s3k));
	memset(salt, 0, sizeof(salt));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	/* The tag is the last 16 bytes; no AAD, the same as Sigma2. */
	n = enc_len - MATTER_TAG_LEN;
	rc = matter_aead_decrypt(s3k, k_nonce, NULL, 0u, enc, n, enc + n, s_scratch);
	memset(s3k, 0, sizeof(s3k));
	if (rc != MATTER_OK) {
		return rc;
	}

	/* TBEData3: the initiator's chain and its signature over TBSData3. */
	matter_tlv_reader_init(&r, s_scratch, n);
	if (matter_tlv_next(&r) != MATTER_OK ||
	    matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TBE_NOC)) {
			rc = matter_tlv_get_bytes(&r, &noc, &noc_len);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TBE_ICAC)) {
			rc = matter_tlv_get_bytes(&r, &icac, &icac_len);
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TBE_SIGNATURE)) {
			rc = matter_tlv_get_bytes(&r, &sig, &sig_len);
		} else {
			rc = MATTER_OK;
		}
		if (rc != MATTER_OK) {
			return MATTER_E_TYPE;
		}
	}
	if (noc == NULL || sig == NULL || sig_len != MATTER_CASE_SIG_LEN) {
		return MATTER_E_INVAL;
	}

	/*
	 * TBSData3. Same tag numbers as TBSData2 but the roles are swapped: the
	 * SENDER is now the initiator, so its ephemeral key goes in tag 3 and
	 * this node's in tag 4. Encoding them the other way round produces a
	 * structure that is well formed, decodes cleanly, and never verifies.
	 */
	matter_tlv_writer_init(&w, tbs, sizeof(tbs));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_NOC), noc, noc_len);
	if (icac != NULL && icac_len > 0u) {
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_ICAC), icac, icac_len);
	}
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_SENDER_PUBKEY), in->initiator_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(TAG_TBS_RECV_PUBKEY), in->responder_eph_pub,
				   MATTER_CASE_PUBKEY_LEN);
	(void)matter_tlv_end_container(&w);
	rc = matter_tlv_writer_finish(&w, &n);
	if (rc != MATTER_OK) {
		return rc;
	}

	/* The key to check it with comes from the NOC that was sent alongside
	 * it, which is only worth anything because the chain is bound to the
	 * fabric -- see the caller's fabric id check. */
	if (matter_cert_parse(noc, noc_len, &cert) != MATTER_OK || !cert.have_public_key) {
		return MATTER_E_INVAL;
	}
	if (matter_case_verify(cert.public_key, tbs, n, sig) != 0) {
		return MATTER_E_TYPE;
	}

	out->node_id = cert.node_id;
	out->fabric_id = cert.fabric_id;
	memcpy(out->cats, cert.cats, sizeof(out->cats));
	out->n_cats = cert.n_cats;
	memcpy(out->public_key, cert.public_key, MATTER_CASE_PUBKEY_LEN);
	return MATTER_OK;
}

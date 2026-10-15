/* SPDX-License-Identifier: ISC */

/**
 * @file matter_case_client.h — the same proof, from the other end.
 *
 * matter_case.h is this node answering a CASE handshake somebody else started.
 * This file is the node STARTING one: it is what a Matter client needs before
 * it can send a command to another node on the fabric, which is what the
 * binding feature does when the UWB gate fires.
 *
 *   Sigma1  this node -> peer   who I want, and my ephemeral key
 *   Sigma2  peer -> this node   its certificate chain, signed, encrypted
 *   Sigma3  this node -> peer   the same, in the other direction
 *
 * Every primitive is already in matter_case.c -- the ECDH, the signing, the
 * destination identifier, the AEAD, the key schedule. What is new here is the
 * DIRECTION: the tag numbers Sigma2 and Sigma3 put the two ephemeral keys
 * under swap roles between the halves, and getting that backwards produces
 * messages that encode, decode, and never verify. Each function below says
 * which role it is writing.
 *
 * Separate from matter_case.c so an image with the client compiled out is byte
 * for byte the image that existed before it -- see the CMakeLists.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_case.h>
#include <tinymatter/matter_crypto.h>
#include <tinymatter/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Enough for a Sigma1: two 32-byte values, a P-256 point and the framing. */
#define MATTER_CASE_SIGMA1_MAX 160u

/** What building a Sigma1 needs. The destination identifier is derived here. */
struct matter_case_client_sigma1_in {
	/** The fabric's OPERATIONAL IPK -- see matter_case_operational_ipk(). */
	const uint8_t *ipk; /**< 16 bytes. */
	/** The fabric's trusted root, uncompressed and INCLUDING its 0x04. */
	const uint8_t *root_pub; /**< 65 bytes. */
	uint64_t fabric_id;
	/** Who this handshake is for. Named in the destination identifier. */
	uint64_t peer_node_id;

	/** Freshly drawn by the caller: this module has no entropy source. */
	const uint8_t *initiator_random;  /**< 32 bytes. */
	const uint8_t *initiator_eph_pub; /**< 65 bytes. */
	uint16_t initiator_session_id;
};

/**
 * Build a Sigma1 (CASESession.cpp:74-83).
 *
 *   destinationId = HMAC(IPK, initiatorRandom || rootPublicKey ||
 *                             fabricId || nodeId)
 *   Sigma1        = { initiatorRandom, initiatorSessionId, destinationId,
 *                     initiatorEphPubKey }
 *
 * WHAT THIS DELIBERATELY OMITS: the initiator's SessionParameters, tag 5. They
 * are optional, they only tune how fast the PEER retransmits at this node, and
 * omitting them makes the peer use the spec defaults -- which are the values
 * this node's own Sigma2 sends anyway. A wrong tag number here would be
 * refused by nothing and would cost a field nobody reads, so it is not sent.
 *
 * Resumption is not offered. A resumed session would save one round trip on a
 * warm unlock, and the session cache saves the whole handshake instead.
 *
 * @return MATTER_OK, MATTER_E_INVAL for a missing field, MATTER_E_NOSPACE, or
 *         whatever the TLV writer returned.
 */
int matter_case_client_sigma1_encode(const struct matter_case_client_sigma1_in *in, uint8_t *out,
				     size_t cap, size_t *out_len);

/** What a Sigma2 carries. Pointers borrow the caller's buffer; nothing is copied. */
struct matter_case_client_sigma2 {
	const uint8_t *responder_random;  /**< 32 bytes. */
	const uint8_t *responder_eph_pub; /**< 65 bytes. */
	/** TBEData2, still sealed. Its last MATTER_TAG_LEN bytes are the tag. */
	const uint8_t *encrypted;
	size_t encrypted_len;
	uint16_t responder_session_id;
};

/**
 * Decode a Sigma2 (CASESession.cpp:85-92).
 *
 * The two fixed-length fields are checked against their lengths rather than
 * merely read, for the reason matter_case_sigma1_decode() gives: a key that is
 * not a P-256 point cannot lead anywhere.
 *
 * SessionParameters, tag 5, is skipped. This node's MRP timings are not
 * negotiable -- matter_mrp.h owns them -- so reading the peer's would be
 * reading a value nothing acts on.
 *
 * @return MATTER_OK, MATTER_E_INVAL if a mandatory field is missing or
 *         mis-sized, or whatever the TLV decoder returned.
 */
int matter_case_client_sigma2_decode(const uint8_t *tlv, size_t len,
				     struct matter_case_client_sigma2 *out);

/** What opening a Sigma2 needs, all of it in hand by the time one arrives. */
struct matter_case_client_sigma2_in {
	const struct matter_case_client_sigma2 *s2;
	/** The fabric's OPERATIONAL IPK. */
	const uint8_t *ipk; /**< 16 bytes. */
	/** SHA-256 of the Sigma1 payload exactly as it was sent. */
	const uint8_t *transcript_hash; /**< 32 bytes. */
	/** This node's ephemeral pair, kept from the Sigma1. */
	const uint8_t *initiator_eph_priv; /**< 32 bytes. */
	const uint8_t *initiator_eph_pub;  /**< 65 bytes. */
	/** The fabric's trusted root, to check the chain the peer sent. */
	const uint8_t *root_pub; /**< 65 bytes. */
	/** Refused unless the peer's NOC names both of these. */
	uint64_t fabric_id;
	uint64_t peer_node_id;
};

/** Who the Sigma2 proved its sender to be, and what Sigma3 still needs. */
struct matter_case_client_sigma2_out {
	uint64_t node_id;
	uint64_t fabric_id;
	/** The peer's operational public key, out of the NOC it sent. */
	uint8_t public_key[MATTER_CASE_PUBKEY_LEN];
	/** The ECDH secret. Sigma3 and the session keys both still need it. */
	uint8_t shared[MATTER_CASE_SECRET_LEN];
};

/**
 * Open and check a Sigma2, the responder's half of the proof.
 *
 *   shared   = ECDH(initiatorEphPriv, responderEphPubKey)
 *   S2K      = HKDF(shared, salt = IPK || responderRandom ||
 *                                  responderEphPubKey || transcriptHash,
 *                   info = "Sigma2", 16)
 *   TBEData2 = AES-CCM-open(encrypted2, S2K, "NCASE_Sigma2N")
 *            = { responderNOC, responderICAC?, signature, resumptionID }
 *   TBSData2 = { responderNOC, responderICAC?, responderEphPubKey,
 *                initiatorEphPubKey }
 *
 * Note the tag order, which is the mirror of the one matter_case_sigma3_open()
 * warns about: TBSData2 names the SENDER first, and here the sender is the
 * PEER, so its ephemeral key goes in tag 3 and this node's in tag 4.
 *
 * Four things must hold, and each is refused separately so a log line can say
 * which: the AEAD tag (the peer holds the fabric IPK and the right ephemeral
 * key), the signature over TBSData2 (it holds the key its NOC names), the
 * certificate chain up to @ref matter_case_client_sigma2_in::root_pub, and the
 * identity -- the NOC must name the fabric and the node this node asked for,
 * not merely some member of the fabric.
 *
 * @return MATTER_OK, MATTER_E_INVAL for a malformed message, MATTER_E_TYPE if
 *         the AEAD tag or a signature failed, MATTER_E_ACCESS if the chain or
 *         the identity did, MATTER_E_NOSPACE if the message is larger than
 *         this node can hold, or MATTER_E_STATE for a failed primitive.
 */
int matter_case_client_sigma2_open(const struct matter_case_client_sigma2_in *in,
				   struct matter_case_client_sigma2_out *out);

/** What building a Sigma3 needs, and nothing it can derive for itself. */
struct matter_case_client_sigma3_in {
	const uint8_t *shared;          /**< 32, the ECDH secret from Sigma2. */
	const uint8_t *ipk;             /**< 16, operational. */
	const uint8_t *transcript_hash; /**< 32, SHA-256 over Sigma1 || Sigma2. */
	/** Both ephemeral keys, in the roles TBSData3 names them. */
	const uint8_t *initiator_eph_pub; /**< 65, this node's. */
	const uint8_t *responder_eph_pub; /**< 65, the one Sigma2 carried. */

	/** This node's operational certificate chain and key, for this fabric. */
	const uint8_t *noc;
	size_t noc_len;
	const uint8_t *icac; /**< NULL when the NOC was signed by the root. */
	size_t icac_len;
	const uint8_t *op_priv; /**< 32 bytes, the key the NOC certifies. */
	/**
	 * The NOC's own public key, to verify the signature just made. Optional;
	 * NULL skips the check. Never NULL on hardware, for the reason
	 * matter_case_sigma2_encode() gives: a peer that rejects a signature
	 * says nothing about why.
	 */
	const uint8_t *verify_pub;
};

/**
 * Build the Sigma3 that closes the handshake.
 *
 *   S3K      = HKDF(shared, salt = IPK || TranscriptHash(Sigma1 || Sigma2),
 *                   info = "Sigma3", 16)
 *   TBSData3 = { initiatorNOC, initiatorICAC?, initiatorEphPubKey,
 *                responderEphPubKey }
 *   TBEData3 = { initiatorNOC, initiatorICAC?, Sign(opPriv, TBSData3) }
 *   Sigma3   = { AES-CCM(TBEData3, S3K, "NCASE_Sigma3N") }
 *
 * TBEData3 carries NO resumption identifier: that field is Sigma2's, and the
 * responder is the side that picks one.
 *
 * @return MATTER_OK, MATTER_E_NOSPACE, MATTER_E_INVAL, or MATTER_E_STATE when a
 *         crypto primitive failed.
 */
int matter_case_client_sigma3_encode(const struct matter_case_client_sigma3_in *in, uint8_t *out,
				     size_t cap, size_t *out_len);

/**
 * Derive the session keys for a handshake this node STARTED.
 *
 *   keys = HKDF(shared, salt = IPK || TranscriptHash(Sigma1 || Sigma2 || Sigma3),
 *               info = "SessionKeys")  ->  i2r | r2i | challenge
 *
 * and then i2r and r2i are SWAPPED before they are handed back.
 *
 * WHY NOT JUST return them in spec order: because matter_exchange.c seals with
 * @ref matter_session_keys::r2i and opens with @ref matter_session_keys::i2r,
 * hard-coded, because until now every session this node held was one it
 * responded to. As the INITIATOR the directions are the other way round.
 * Swapping the two fields here makes that one existing rule true for both
 * roles, and costs nothing in the message path -- where a role flag would cost
 * a branch on every message this node sends or receives, for a session type
 * most images do not compile in at all.
 *
 * The swap is invisible to the peer: these are the same two keys, and only the
 * question of which one this node reaches for differs.
 *
 * @return MATTER_OK, or whatever matter_derive_session_keys() returned.
 */
int matter_case_client_keys(const uint8_t shared[MATTER_CASE_SECRET_LEN],
			    const uint8_t ipk[MATTER_CASE_IPK_LEN],
			    const uint8_t transcript_hash[32], struct matter_session_keys *out);

#ifdef __cplusplus
}
#endif

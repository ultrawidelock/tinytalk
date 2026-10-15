/* SPDX-License-Identifier: ISC */

/**
 * @file matter_crypto.h — Matter message crypto: nonce, AES-CCM, session keys.
 *
 * Matter secures every message with AES-128-CCM: a 13-byte nonce built from
 * fields the peer can see, a 16-byte tag, and the plaintext message header as
 * additional authenticated data so the routing fields cannot be edited in
 * flight.
 *
 *   nonce  security_flags:u8  message_counter:u32  node_id:u64   (little-endian)
 *   aad    the message header exactly as it appears on the wire
 *   keys   HKDF-SHA256(secret, salt, "SessionKeys") -> i2r | r2i | challenge
 *
 * The replay window lives in matter_mrp.c with the duplicate suppression it
 * belongs to.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_msg.h>
#include <tinytalk/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** AES-128: one key size, one tag size, one nonce size. Matter fixes all three. */
#define MATTER_KEY_LEN   16u
#define MATTER_NONCE_LEN 13u
#define MATTER_TAG_LEN   16u

/** i2r | r2i | attestation challenge, one HKDF output. */
#define MATTER_SESSION_KEYS_LEN 48u

/**
 * Largest AAD this CCM accepts.
 *
 * CCM encodes an AAD length below 0xFF00 in two bytes and anything larger in a
 * longer form. A Matter AAD is a message header, so it never exceeds
 * MATTER_MSG_HEADER_MAX (24) and the long form would be dead code; the limit is
 * enforced rather than assumed so an oversized AAD fails loudly instead of
 * being encoded wrongly.
 */
#define MATTER_AAD_MAX 0xFEFFu

/**
 * The legacy AES block signature, kept as the project this was extracted from
 * declared it.
 *
 * Defined by backends/psa/ on PSA Crypto. Host tests link
 * tests/host/aes_ref.c, a real FIPS-197 implementation. Declared here so this
 * module depends on no backend's headers.
 */
int crypto_aes_ecb_encrypt(const uint8_t *key, size_t key_bits, const uint8_t in[16],
			   uint8_t out[16]);

/** Session keys, in the order the one HKDF output supplies them. */
struct matter_session_keys {
	/** Initiator to responder. */
	uint8_t i2r[MATTER_KEY_LEN];
	/** Responder to initiator. */
	uint8_t r2i[MATTER_KEY_LEN];
	/** Bound into attestation signatures; not an encryption key. */
	uint8_t attestation_challenge[MATTER_KEY_LEN];
};

/**
 * Derive the session key schedule from an established shared secret.
 *
 * @param secret   PASE's Ke or CASE's ECDH-derived secret.
 * @param salt     may be NULL with salt_len 0, which is what PASE uses.
 * @param resume   true selects the "SessionResumptionKeys" info string.
 * @return MATTER_OK or MATTER_E_INVAL.
 */
int matter_derive_session_keys(const uint8_t *secret, size_t secret_len, const uint8_t *salt,
			       size_t salt_len, bool resume, struct matter_session_keys *out);

/**
 * Build the 13-byte AEAD nonce.
 *
 * @param node_id the SENDER's node ID, which comes from the session rather than
 *        from the header being sent: the source node ID field is absent from
 *        most messages, so reading it off the wire would produce a nonce that
 *        only sometimes matched the peer's.
 */
int matter_build_nonce(uint8_t security_flags, uint32_t message_counter, uint64_t node_id,
		       uint8_t out[MATTER_NONCE_LEN]);

/**
 * AES-128-CCM. @p ct_out may alias @p pt.
 * @return MATTER_OK, or MATTER_E_INVAL for a bad argument or an oversized
 *         input, or MATTER_E_STATE if the AES backend failed.
 */
int matter_aead_encrypt(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
			const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
			uint8_t *ct_out, uint8_t tag_out[MATTER_TAG_LEN]);

/**
 * @return MATTER_OK, or MATTER_E_TYPE if the tag does not verify -- in which
 *         case @p pt_out has been zeroed, because a caller that ignores the
 *         return value must not be handed attacker-chosen plaintext.
 */
int matter_aead_decrypt(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
			const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
			const uint8_t tag[MATTER_TAG_LEN], uint8_t *pt_out);

/**
 * Encode @p h and seal @p payload under it, producing header | ciphertext | tag.
 *
 * The header is written into @p out first and those exact bytes are then used
 * as the AAD, so the authenticated header and the transmitted header cannot
 * disagree. That is the reason this lives beside the cipher instead of in
 * matter_msg.c.
 *
 * @param sender_node_id the local node ID, for the nonce. See matter_build_nonce().
 * @return MATTER_OK, MATTER_E_NOSPACE, or MATTER_E_INVAL.
 */
int matter_crypto_seal(const struct matter_msg_header *h, const uint8_t key[MATTER_KEY_LEN],
		       uint64_t sender_node_id, const uint8_t *payload, size_t payload_len,
		       uint8_t *out, size_t cap, size_t *out_len);

/**
 * Decode the header of @p buf and open the rest in place of it.
 *
 * @param sender_node_id the PEER's node ID, held by the session.
 * @param pt_out receives the plaintext; needs len - header - tag bytes.
 * @return MATTER_OK, MATTER_E_TRUNC if there is no room for a header and a tag,
 *         MATTER_E_TYPE if the tag does not verify, else as matter_msg_header_decode().
 */
int matter_crypto_open(const uint8_t *buf, size_t len, const uint8_t key[MATTER_KEY_LEN],
		       uint64_t sender_node_id, struct matter_msg_header *h, uint8_t *pt_out,
		       size_t pt_cap, size_t *pt_len);

#ifdef __cplusplus
}
#endif

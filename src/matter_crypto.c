/* SPDX-License-Identifier: ISC */

/**
 * @file matter_crypto.c — AES-128-CCM, the Matter nonce, and the key schedule.
 */
/*
 * Written out rather than reusing the CCC ladder's AES-CCM*, which is welded to
 * SP0 (8-byte tag, internal nonce, 128-byte scratch cap); Matter needs a
 * 16-byte tag, a caller-supplied nonce and no length cap. No scratch buffer at
 * all: the CBC-MAC streams and the CTR keystream is generated a block at a
 * time, so stack cost is a few 16-byte blocks regardless of message length.
 * One primitive underneath, crypto_aes_ecb_encrypt() -- CCM never needs AES
 * decryption.
 */
#include <string.h>

#include <tinymatter/matter_crypto.h>

#include <tinymatter/tm_hash.h>

/** L, the octet count of the length field: 15 - 13 = 2 for a Matter nonce. */
#define CCM_L           2u
/** Largest payload L can express. */
#define CCM_MAX_PAYLOAD 0xFFFFu
#define AES_BLOCK       16u

/* HKDF info strings. CHIP CryptoContext.cpp:44,47; CircuitMatter pase.py:178. */
static const uint8_t k_session_keys_info[] = {'S', 'e', 's', 's', 'i', 'o',
					      'n', 'K', 'e', 'y', 's'};
static const uint8_t k_resume_keys_info[] = {'S', 'e', 's', 's', 'i', 'o', 'n', 'R', 'e', 's', 'u',
					     'm', 'p', 't', 'i', 'o', 'n', 'K', 'e', 'y', 's'};

/** Streaming CBC-MAC state: no buffer proportional to the message. */
struct cbc_mac {
	const uint8_t *key;
	uint8_t x[AES_BLOCK];
	uint8_t part[AES_BLOCK];
	size_t part_len;
};

/**
 * XOR one 128-bit block into the CBC-MAC state and encrypt it with AES-ECB.
 */
static int mac_block(struct cbc_mac *m, const uint8_t b[AES_BLOCK])
{
	for (size_t i = 0; i < AES_BLOCK; i++) {
		m->x[i] ^= b[i];
	}
	return crypto_aes_ecb_encrypt(m->key, 128u, m->x, m->x);
}

/**
 * Update CBC-MAC state with input bytes: accumulate into partial blocks and process full 128-bit
 * blocks through the cipher. Returns 0 on success or cipher error.
 */
static int mac_update(struct cbc_mac *m, const uint8_t *p, size_t len)
{
	while (len > 0u) {
		size_t take = AES_BLOCK - m->part_len;

		if (take > len) {
			take = len;
		}
		memcpy(&m->part[m->part_len], p, take);
		m->part_len += take;
		p += take;
		len -= take;

		if (m->part_len == AES_BLOCK) {
			int rc = mac_block(m, m->part);

			if (rc != 0) {
				return rc;
			}
			m->part_len = 0u;
		}
	}
	return 0;
}

/** Flush a partial block, zero-padded, as CCM requires at each section end. */
static int mac_flush(struct cbc_mac *m)
{
	int rc;

	if (m->part_len == 0u) {
		return 0;
	}
	memset(&m->part[m->part_len], 0, AES_BLOCK - m->part_len);
	rc = mac_block(m, m->part);
	m->part_len = 0u;
	return rc;
}

/**
 * Counter block A_i, per RFC 3610: flags | nonce | i, with only L-1 in the
 * flags because A blocks carry no Adata or tag-length fields.
 */
static void ctr_block(const uint8_t nonce[MATTER_NONCE_LEN], uint16_t i, uint8_t out[AES_BLOCK])
{
	out[0] = (uint8_t)(CCM_L - 1u);
	memcpy(&out[1], nonce, MATTER_NONCE_LEN);
	out[14] = (uint8_t)(i >> 8);
	out[15] = (uint8_t)i;
}

/** Run the CBC-MAC over B0, the length-prefixed AAD, and the payload. */
static int ccm_mac(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
		   uint8_t t_out[AES_BLOCK])
{
	struct cbc_mac m;
	uint8_t b0[AES_BLOCK];
	int rc;

	memset(&m, 0, sizeof(m));
	m.key = key;

	/* B0 flags: Adata | ((M-2)/2)<<3 | (L-1), M = 16 so the middle term is 7. */
	b0[0] = (uint8_t)((aad_len > 0u ? 0x40u : 0x00u) | (((MATTER_TAG_LEN - 2u) / 2u) << 3) |
			  (CCM_L - 1u));
	memcpy(&b0[1], nonce, MATTER_NONCE_LEN);
	b0[14] = (uint8_t)(pt_len >> 8);
	b0[15] = (uint8_t)pt_len;

	rc = mac_block(&m, b0);
	if (rc != 0) {
		return rc;
	}

	if (aad_len > 0u) {
		uint8_t hdr[2];

		hdr[0] = (uint8_t)(aad_len >> 8);
		hdr[1] = (uint8_t)aad_len;
		rc = mac_update(&m, hdr, sizeof(hdr));
		if (rc == 0) {
			rc = mac_update(&m, aad, aad_len);
		}
		if (rc == 0) {
			rc = mac_flush(&m);
		}
		if (rc != 0) {
			return rc;
		}
	}

	if (pt_len > 0u) {
		rc = mac_update(&m, pt, pt_len);
		if (rc == 0) {
			rc = mac_flush(&m);
		}
		if (rc != 0) {
			return rc;
		}
	}

	memcpy(t_out, m.x, AES_BLOCK);
	return 0;
}

/** XOR the CTR keystream over @p len bytes, starting at counter block 1. */
static int ccm_ctr(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
		   const uint8_t *in, size_t len, uint8_t *out)
{
	uint8_t a[AES_BLOCK];
	uint8_t s[AES_BLOCK];
	uint16_t counter = 1u;
	size_t off = 0u;

	while (off < len) {
		size_t take = len - off;
		int rc;

		if (take > AES_BLOCK) {
			take = AES_BLOCK;
		}
		ctr_block(nonce, counter, a);
		rc = crypto_aes_ecb_encrypt(key, 128u, a, s);
		if (rc != 0) {
			return rc;
		}
		for (size_t i = 0; i < take; i++) {
			out[off + i] = (uint8_t)(in[off + i] ^ s[i]);
		}
		off += take;
		counter++;
	}
	return 0;
}

/** Mask the raw CBC-MAC with S0 to produce the transmitted tag. */
static int ccm_tag(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
		   const uint8_t t[AES_BLOCK], uint8_t tag_out[MATTER_TAG_LEN])
{
	uint8_t a0[AES_BLOCK];
	uint8_t s0[AES_BLOCK];
	int rc;

	ctr_block(nonce, 0u, a0);
	rc = crypto_aes_ecb_encrypt(key, 128u, a0, s0);
	if (rc != 0) {
		return rc;
	}
	for (size_t i = 0; i < MATTER_TAG_LEN; i++) {
		tag_out[i] = (uint8_t)(t[i] ^ s0[i]);
	}
	return 0;
}

/** Constant time: a tag comparison must not leak how far it matched. */
static bool tag_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0u;

	for (size_t i = 0; i < len; i++) {
		diff |= (uint8_t)(a[i] ^ b[i]);
	}
	return diff == 0u;
}

/**
 * Build an AES-CCM nonce from security flags, message counter, and node ID in little-endian form;
 * returns MATTER_OK on success.
 */
int matter_build_nonce(uint8_t security_flags, uint32_t message_counter, uint64_t node_id,
		       uint8_t out[MATTER_NONCE_LEN])
{
	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	out[0] = security_flags;
	for (size_t i = 0; i < 4u; i++) {
		out[1u + i] = (uint8_t)(message_counter >> (8u * i));
	}
	for (size_t i = 0; i < 8u; i++) {
		out[5u + i] = (uint8_t)(node_id >> (8u * i));
	}
	return MATTER_OK;
}

/**
 * Derive session keys from a shared secret using HKDF for Matter secure channel setup.
 * Expands secret into i2r, r2i, and attestation_challenge keys using either normal or resume
 * derivation context.
 * Returns MATTER_E_INVAL if secret, out are NULL or secret_len is zero; returns MATTER_E_INVAL if
 * salt_len is nonzero but salt is NULL; returns MATTER_E_STATE if HKDF fails.
 */
int matter_derive_session_keys(const uint8_t *secret, size_t secret_len, const uint8_t *salt,
			       size_t salt_len, bool resume, struct matter_session_keys *out)
{
	uint8_t keys[MATTER_SESSION_KEYS_LEN];
	const uint8_t *info = resume ? k_resume_keys_info : k_session_keys_info;
	size_t info_len = resume ? sizeof(k_resume_keys_info) : sizeof(k_session_keys_info);
	int rc;

	if (secret == NULL || secret_len == 0u || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (salt == NULL && salt_len != 0u) {
		return MATTER_E_INVAL;
	}

	rc = tm_hkdf(salt, salt_len, secret, secret_len, info, info_len, keys, sizeof(keys));
	if (rc != 0) {
		return MATTER_E_STATE;
	}

	memcpy(out->i2r, &keys[0], MATTER_KEY_LEN);
	memcpy(out->r2i, &keys[MATTER_KEY_LEN], MATTER_KEY_LEN);
	memcpy(out->attestation_challenge, &keys[2 * (size_t)MATTER_KEY_LEN], MATTER_KEY_LEN);
	memset(keys, 0, sizeof(keys));
	return MATTER_OK;
}

/**
 * Encrypt a plaintext with AES-CCM, optionally authenticated with AAD, by computing the CBC-MAC,
 * generating the authentication tag, and encrypting the plaintext with CTR; returns MATTER_OK on
 * success.
 */
int matter_aead_encrypt(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
			const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
			uint8_t *ct_out, uint8_t tag_out[MATTER_TAG_LEN])
{
	uint8_t t[AES_BLOCK];
	int rc;

	if (key == NULL || nonce == NULL || tag_out == NULL) {
		return MATTER_E_INVAL;
	}
	if ((aad == NULL) != (aad_len == 0u)) {
		return MATTER_E_INVAL;
	}
	if ((pt == NULL || ct_out == NULL) && pt_len != 0u) {
		return MATTER_E_INVAL;
	}
	if (aad_len > MATTER_AAD_MAX || pt_len > CCM_MAX_PAYLOAD) {
		return MATTER_E_INVAL;
	}

	/* MAC the PLAINTEXT, then encrypt it: CCM authenticates before it
	 * encrypts, so this order is not interchangeable. */
	rc = ccm_mac(key, nonce, aad, aad_len, pt, pt_len, t);
	if (rc == 0) {
		rc = ccm_tag(key, nonce, t, tag_out);
	}
	if (rc == 0 && pt_len > 0u) {
		rc = ccm_ctr(key, nonce, pt, pt_len, ct_out);
	}
	memset(t, 0, sizeof(t));
	return (rc == 0) ? MATTER_OK : MATTER_E_STATE;
}

/**
 * Decrypt an AES-CCM ciphertext with an authentication tag and optional AAD, verifying the tag in
 * constant time before returning plaintext; returns MATTER_OK on success or MATTER_E_TYPE if the
 * tag does not verify.
 */
int matter_aead_decrypt(const uint8_t key[MATTER_KEY_LEN], const uint8_t nonce[MATTER_NONCE_LEN],
			const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
			const uint8_t tag[MATTER_TAG_LEN], uint8_t *pt_out)
{
	uint8_t t[AES_BLOCK];
	uint8_t want[MATTER_TAG_LEN];
	int rc;

	if (key == NULL || nonce == NULL || tag == NULL) {
		return MATTER_E_INVAL;
	}
	if ((aad == NULL) != (aad_len == 0u)) {
		return MATTER_E_INVAL;
	}
	if ((ct == NULL || pt_out == NULL) && ct_len != 0u) {
		return MATTER_E_INVAL;
	}
	if (aad_len > MATTER_AAD_MAX || ct_len > CCM_MAX_PAYLOAD) {
		return MATTER_E_INVAL;
	}

	/* Decrypt first, because the MAC covers the plaintext. Nothing is handed
	 * back until the tag verifies. */
	if (ct_len > 0u) {
		rc = ccm_ctr(key, nonce, ct, ct_len, pt_out);
		if (rc != 0) {
			goto fail;
		}
	}
	rc = ccm_mac(key, nonce, aad, aad_len, pt_out, ct_len, t);
	if (rc != 0) {
		goto fail;
	}
	rc = ccm_tag(key, nonce, t, want);
	if (rc != 0) {
		goto fail;
	}

	if (!tag_equal(want, tag, MATTER_TAG_LEN)) {
		/* Guarded like the fail: path below: the check above admits
		 * pt_out == NULL when ct_len is 0, and memset(NULL, 0, 0) is UB. */
		if (ct_len > 0u) {
			memset(pt_out, 0, ct_len);
		}
		memset(t, 0, sizeof(t));
		memset(want, 0, sizeof(want));
		return MATTER_E_TYPE;
	}

	memset(t, 0, sizeof(t));
	memset(want, 0, sizeof(want));
	return MATTER_OK;

fail:
	if (ct_len > 0u) {
		memset(pt_out, 0, ct_len);
	}
	memset(t, 0, sizeof(t));
	memset(want, 0, sizeof(want));
	return MATTER_E_STATE;
}

/**
 * Encrypt and authenticate a Matter message: encode header into output buffer, build nonce from
 * security flags and counter, and encrypt payload with AAD set to the encoded header bytes. Caller
 * must ensure output capacity >= header length + payload length + MATTER_TAG_LEN. Returns MATTER_OK
 * on success or encoding error.
 */
int matter_crypto_seal(const struct matter_msg_header *h, const uint8_t key[MATTER_KEY_LEN],
		       uint64_t sender_node_id, const uint8_t *payload, size_t payload_len,
		       uint8_t *out, size_t cap, size_t *out_len)
{
	uint8_t nonce[MATTER_NONCE_LEN];
	size_t hdr_len = 0u;
	int rc;

	if (h == NULL || key == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	/* Encode into the output buffer first, so the bytes fed to the AEAD as AAD
	 * are literally the bytes that will be transmitted. Building the AAD
	 * separately would let the two drift. */
	rc = matter_msg_header_encode(h, out, cap, &hdr_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	if (cap - hdr_len < payload_len + MATTER_TAG_LEN) {
		return MATTER_E_NOSPACE;
	}

	rc = matter_build_nonce(h->security_flags, h->message_counter, sender_node_id, nonce);
	if (rc != MATTER_OK) {
		return rc;
	}

	rc = matter_aead_encrypt(key, nonce, out, hdr_len, payload, payload_len, out + hdr_len,
				 out + hdr_len + payload_len);
	memset(nonce, 0, sizeof(nonce));
	if (rc != MATTER_OK) {
		return rc;
	}

	if (out_len != NULL) {
		*out_len = hdr_len + payload_len + MATTER_TAG_LEN;
	}
	return MATTER_OK;
}

/**
 * Decrypt and verify a Matter message: decode header, extract ciphertext and authentication tag,
 * build nonce from security flags and counter, and decrypt with AAD set to the message header.
 * Returns MATTER_OK on successful decryption, MATTER_E_INVAL on bad parameters, MATTER_E_TRUNC if
 * ciphertext too short for tag, MATTER_E_NOSPACE if plaintext exceeds output capacity.
 */
int matter_crypto_open(const uint8_t *buf, size_t len, const uint8_t key[MATTER_KEY_LEN],
		       uint64_t sender_node_id, struct matter_msg_header *h, uint8_t *pt_out,
		       size_t pt_cap, size_t *pt_len)
{
	uint8_t nonce[MATTER_NONCE_LEN];
	size_t hdr_len = 0u;
	size_t ct_len;
	int rc;

	if (buf == NULL || key == NULL || h == NULL) {
		return MATTER_E_INVAL;
	}

	rc = matter_msg_header_decode(buf, len, h, &hdr_len);
	if (rc != MATTER_OK) {
		return rc;
	}
	/* A message with no room for a tag cannot be authenticated, so it is
	 * truncated rather than merely empty. */
	if (len - hdr_len < MATTER_TAG_LEN) {
		return MATTER_E_TRUNC;
	}
	ct_len = len - hdr_len - MATTER_TAG_LEN;
	if (ct_len > pt_cap) {
		return MATTER_E_NOSPACE;
	}

	rc = matter_build_nonce(h->security_flags, h->message_counter, sender_node_id, nonce);
	if (rc != MATTER_OK) {
		return rc;
	}

	/* AAD is the received header bytes, the same structural guarantee as seal. */
	rc = matter_aead_decrypt(key, nonce, buf, hdr_len, buf + hdr_len, ct_len,
				 buf + hdr_len + ct_len, pt_out);
	memset(nonce, 0, sizeof(nonce));
	if (rc != MATTER_OK) {
		return rc;
	}

	if (pt_len != NULL) {
		*pt_len = ct_len;
	}
	return MATTER_OK;
}

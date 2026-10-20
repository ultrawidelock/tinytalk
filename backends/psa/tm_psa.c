/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The P-256, AES and randomness seams the core declares, on Arm PSA Crypto.
 *
 * The public functions at the bottom are the wrappers the source project's
 * Zephyr app kept beside its Matter glue; the static helpers above them are its
 * PSA primitive provider, cut down to what those wrappers call.
 * psa_crypto_init() must have run before any of them is used.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "psa/crypto.h"

#include <tinytalk/matter_attest.h>
#include <tinytalk/matter_case.h>
#include <tinytalk/matter_crypto.h>
#include <tinytalk/tm_platform.h>

#define TM_P256_SCALAR 32u
#define TM_P256_POINT  65u
#define TM_P256_SIG    64u

// Encrypt one AES-128/256-ECB block via PSA Crypto. Returns 0 on success, -1
// for an invalid argument, unsupported key size, or backend failure.
static int aes_ecb_encrypt(const uint8_t *key, size_t key_bits, const uint8_t in[16],
			   uint8_t out[16])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t olen = 0;
	int rc = -1;

	if (key == NULL || in == NULL || out == NULL ||
	    (key_bits != 128u && key_bits != 256u)) {
		return -1;
	}
	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
	psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attr, key_bits);
	if (psa_import_key(&attr, key, key_bits / 8u, &k) != PSA_SUCCESS) {
		return -1;
	}
	/* ECB has no IV, so the one-shot output is exactly the 16-byte block. */
	if (psa_cipher_encrypt(k, PSA_ALG_ECB_NO_PADDING, in, 16, out, 16, &olen) == PSA_SUCCESS &&
	    olen == 16) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Generate a new NIST P-256 key pair via PSA Crypto.
// Writes the private scalar to priv and the uncompressed public point to pub. Returns 0 on success,
// -1 if key generation or export fails.
static int ec_p256_keygen(uint8_t priv[TM_P256_SCALAR], uint8_t pub[TM_P256_POINT])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t plen = 0, publen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_generate_key(&attr, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_export_key(k, priv, TM_P256_SCALAR, &plen) == PSA_SUCCESS &&
	    plen == TM_P256_SCALAR &&
	    psa_export_public_key(k, pub, TM_P256_POINT, &publen) == PSA_SUCCESS &&
	    publen == TM_P256_POINT) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Compute the P-256 ECDH shared secret x-coordinate for priv and a peer's public point via PSA
// Crypto. Writes the shared x-coordinate to shared_x. Returns 0 on success, -1 if key import or key
// agreement fails.
static int ecdh_p256(const uint8_t priv[TM_P256_SCALAR], const uint8_t peer_pub[TM_P256_POINT],
		     uint8_t shared_x[TM_P256_SCALAR])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t olen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, priv, TM_P256_SCALAR, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_raw_key_agreement(PSA_ALG_ECDH, k, peer_pub, TM_P256_POINT, shared_x,
				  TM_P256_SCALAR, &olen) == PSA_SUCCESS &&
	    olen == TM_P256_SCALAR) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Sign a message with ECDSA over P-256 using SHA-256, via PSA Crypto.
// Writes the signature to sig. Returns 0 on success, -1 if private key import or signing fails.
static int ecdsa_p256_sign(const uint8_t priv[TM_P256_SCALAR], const uint8_t *msg,
			   size_t msg_len, uint8_t sig[TM_P256_SIG])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	size_t slen = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attr, 256);
	if (psa_import_key(&attr, priv, TM_P256_SCALAR, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_sign_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), msg, msg_len, sig, TM_P256_SIG,
			     &slen) == PSA_SUCCESS &&
	    slen == TM_P256_SIG) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Verify an ECDSA-P256 signature against an already computed SHA-256 digest and public key, via
// PSA Crypto. Returns 0 if the signature verifies, -1 if public key import fails or verification
// fails.
static int ecdsa_p256_verify_hash(const uint8_t pub[TM_P256_POINT], const uint8_t hash[32],
				  const uint8_t sig[TM_P256_SIG])
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t k = 0;
	int rc = -1;

	psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	if (psa_import_key(&attr, pub, TM_P256_POINT, &k) != PSA_SUCCESS) {
		return -1;
	}
	if (psa_verify_hash(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash, 32u, sig,
			    TM_P256_SIG) == PSA_SUCCESS) {
		rc = 0;
	}
	psa_destroy_key(k);
	return rc;
}

// Verify an ECDSA-P256/SHA-256 signature against a message and public key, via PSA Crypto.
// Returns 0 if the signature verifies, -1 if hashing, public key import or verification fails.
//
// Hashes here and takes the digest path below, so an image carries one PSA verify entry. With
// psa_verify_message kept next to psa_verify_hash the source project's nRF52833 lock images grew
// by about 230 bytes.
static int ecdsa_p256_verify(const uint8_t pub[TM_P256_POINT], const uint8_t *msg,
			     size_t msg_len, const uint8_t sig[TM_P256_SIG])
{
	uint8_t hash[32];
	size_t hlen = 0;

	if (psa_hash_compute(PSA_ALG_SHA_256, msg, msg_len, hash, sizeof(hash), &hlen) !=
		    PSA_SUCCESS ||
	    hlen != sizeof(hash)) {
		return -1;
	}
	return ecdsa_p256_verify_hash(pub, hash, sig);
}

/*
 * The two seams matter_attest.h declares. Kept here rather than in the module
 * so the core stays free of any particular crypto backend.
 */
int matter_attest_ecdsa_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
			     uint8_t sig[MATTER_ATTEST_SIG_LEN])
{
	return ecdsa_p256_sign(priv, msg, msg_len, sig);
}

/**
 * Generate a P-256 keypair for Matter attestation. Fills priv with the 32-byte private key and pub
 * with the 65-byte uncompressed public key. Returns 0 on success.
 */
int matter_attest_ec_keygen(uint8_t priv[32], uint8_t pub[65])
{
	return ec_p256_keygen(priv, pub);
}

/*
 * The two matter_case.h declares. ECDH yields the X coordinate only, which is
 * what the spec means by the shared secret -- the Y coordinate carries no
 * additional entropy and including it would give a secret neither peer agrees
 * on.
 */
int matter_case_ecdh(const uint8_t priv[32], const uint8_t peer_pub[MATTER_CASE_PUBKEY_LEN],
		     uint8_t secret_out[MATTER_CASE_SECRET_LEN])
{
	return ecdh_p256(priv, peer_pub, secret_out);
}

/**
 * Sign a message with a P-256 private key. Fills sig with the MATTER_CASE_SIG_LEN-byte signature.
 * Returns 0 on success.
 */
int matter_case_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
		     uint8_t sig[MATTER_CASE_SIG_LEN])
{
	return ecdsa_p256_sign(priv, msg, msg_len, sig);
}

/**
 * Verify a message signature with a P-256 public key. The public key is MATTER_CASE_PUBKEY_LEN
 * bytes, the signature is MATTER_CASE_SIG_LEN bytes. Returns 0 if the signature is valid.
 */
int matter_case_verify(const uint8_t pub[MATTER_CASE_PUBKEY_LEN], const uint8_t *msg,
		       size_t msg_len, const uint8_t sig[MATTER_CASE_SIG_LEN])
{
	return ecdsa_p256_verify(pub, msg, msg_len, sig);
}

/* The AES-ECB adapter matter_crypto.h declares: argument check, then errno. */
int crypto_aes_ecb_encrypt(const uint8_t *key, size_t key_bits, const uint8_t in[16],
			   uint8_t out[16])
{
	if (key == NULL || in == NULL || out == NULL ||
	    (key_bits != 128u && key_bits != 256u)) {
		return -EINVAL;
	}

	return aes_ecb_encrypt(key, key_bits, in, out) == 0 ? 0 : -EIO;
}

/* The CSPRNG tm_platform.h declares: PSA's, which psa_crypto_init() seeded. */
int tm_random(void *out, size_t len)
{
	return psa_generate_random(out, len) == PSA_SUCCESS ? 0 : -EIO;
}

#ifdef TM_SHA256_PSA
/* tm_hash.h's SHA-256 on PSA, which an image with OpenThread on PSA links
 * anyway. The API cannot fail, so a PSA failure zeroes the digest. */
#include <string.h>
#include <tinytalk/tm_hash.h>

void tm_sha256_init(struct tm_sha256 *s)
{
	s->op = psa_hash_operation_init();
	(void)psa_hash_setup(&s->op, PSA_ALG_SHA_256);
}

void tm_sha256_update(struct tm_sha256 *s, const void *data, size_t len)
{
	(void)psa_hash_update(&s->op, data, len);
}

void tm_sha256_final(struct tm_sha256 *s, uint8_t out[TM_SHA256_LEN])
{
	size_t n = 0;

	if (psa_hash_finish(&s->op, out, TM_SHA256_LEN, &n) != PSA_SUCCESS || n != TM_SHA256_LEN) {
		memset(out, 0, TM_SHA256_LEN);
		(void)psa_hash_abort(&s->op);
	}
}

void tm_sha256(const void *data, size_t len, uint8_t out[TM_SHA256_LEN])
{
	size_t n = 0;

	if (psa_hash_compute(PSA_ALG_SHA_256, data, len, out, TM_SHA256_LEN, &n) != PSA_SUCCESS ||
	    n != TM_SHA256_LEN) {
		memset(out, 0, TM_SHA256_LEN);
	}
}
#endif /* TM_SHA256_PSA */

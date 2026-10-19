/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_attest.h — proving to a commissioner that this is a real device.
 *
 * After the fail-safe is armed, the commissioner stops asking what this node is
 * and starts asking it to prove it. Three questions, in this order:
 *
 *   CertificateChainRequest  give me your DAC, then your PAI
 *   AttestationRequest       sign this nonce with the DAC's private key
 *   CSRRequest               make me a key I can certify, and sign for it
 *
 * The certificates are static blobs. The signatures are not: each covers the
 * message AND the session's attestation challenge, which is why a recorded
 * exchange cannot be replayed into a different session.
 *
 * WHAT THESE CREDENTIALS ARE. The DAC, PAI and CD here are the SDK's published
 * development credentials for vendor 0xFFF1 / product 0x8001, and the DAC's
 * private key is published alongside them. They prove nothing about who built
 * this device -- anyone can extract the same key from a public repository, and
 * a commissioner that enforces attestation will reject them. They are here so
 * commissioning can be developed against a real phone; shipping a product means
 * a DAC issued under a real PAI, and its private key must not live in flash
 * next to the certificate.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** CertificateChainTypeEnum (OperationalCredentials/Enums.h). */
#define MATTER_CERT_TYPE_DAC 1u
#define MATTER_CERT_TYPE_PAI 2u

/** A commissioner's nonce, and the session challenge signatures are bound to. */
#define MATTER_ATTEST_NONCE_LEN     32u
#define MATTER_ATTEST_CHALLENGE_LEN 16u

/** Raw ECDSA P-256 signature, r||s. */
#define MATTER_ATTEST_SIG_LEN 64u

/**
 * Enough for a P-256 CSR.
 *
 * The structure is fixed -- one public key, a three-letter subject and an empty
 * attribute set -- so the only variable part is the two DER integers in the
 * signature, which can each carry a leading zero byte. Measured at 221 bytes,
 * and this leaves room for both.
 */
#define MATTER_CSR_MAX 256u

/**
 * Enough for attestationElements: the CD is 539 bytes, plus a 32-byte nonce, a
 * timestamp and the TLV framing. The 32 bytes of headroom
 * matter_attest_sign_with_challenge() needs are NOT included -- see there.
 */
#define MATTER_ATTEST_ELEMENTS_MAX 640u

/**
 * Borrow one of the built-in certificates.
 *
 * @param type MATTER_CERT_TYPE_DAC or MATTER_CERT_TYPE_PAI.
 * @return MATTER_OK, or MATTER_E_INVAL for any other type. Static storage; the
 *         caller must not free or modify it.
 */
int matter_attest_cert(uint8_t type, const uint8_t **out, size_t *len);

/**
 * Encode attestationElements (DeviceAttestationConstructor.cpp:166-182).
 *
 *   [1] the certification declaration   [2] the commissioner's nonce
 *   [3] a timestamp                     [4] firmware info, omitted
 *
 * Tags must ASCEND, and the deconstructor enforces it (lines 104-116), so this
 * is not merely conventional ordering.
 *
 * @param timestamp seconds. This node has no clock, and 0 is what a device
 *        without one sends; it is not a placeholder for something better.
 */
int matter_attest_elements_encode(const uint8_t *nonce, size_t nonce_len, uint32_t timestamp,
				  uint8_t *out, size_t cap, size_t *out_len);

/**
 * Encode NOCSRElements (DeviceAttestationConstructor.cpp:203-219).
 *
 *   [1] the CSR   [2] the commissioner's nonce
 */
int matter_attest_nocsr_encode(const uint8_t *csr, size_t csr_len, const uint8_t *nonce,
			       size_t nonce_len, uint8_t *out, size_t cap, size_t *out_len);

/**
 * Sign @p payload_len bytes of @p buf, with the challenge appended, using the
 * DAC private key.
 *
 * Both attestation and CSR signatures cover (payload || attestationChallenge)
 * -- operational-credentials-cluster.cpp:1013-1021 and 368-376. The challenge
 * is never sent; only a peer that shares the session can recompute it, which is
 * what stops a recorded response being replayed into another session.
 *
 * Appended IN PLACE rather than into a second buffer: attestationElements is
 * over 600 bytes and this runs on a work queue whose depth is still an
 * argument. @p buf must therefore have MATTER_ATTEST_CHALLENGE_LEN bytes spare
 * beyond @p payload_len; the appended bytes are wiped before returning, so
 * @p buf holds exactly what it did on entry.
 *
 * @return MATTER_OK, MATTER_E_NOSPACE if the headroom is missing, or
 *         MATTER_E_STATE if the signature could not be produced.
 */
int matter_attest_sign_with_challenge(uint8_t *buf, size_t payload_len, size_t cap,
				      const uint8_t *challenge, size_t challenge_len,
				      uint8_t sig[MATTER_ATTEST_SIG_LEN]);

/**
 * Build a PKCS#10 CSR for @p pub, self-signed with @p priv.
 *
 * RFC 2986, shaped exactly as CHIP's own
 * (crypto/CHIPCryptoPAL.cpp:1060-1215): version 0, a subject of OU="CSA"
 * because the commissioner replaces it anyway, the P-256 public key, and an
 * empty extensionRequest attribute set. Self-signed, so it proves this node
 * holds the private key for the public key it is asking to have certified.
 *
 * @return MATTER_OK, MATTER_E_NOSPACE, MATTER_E_INVAL, or MATTER_E_STATE when
 *         signing failed.
 */
int matter_attest_csr(const uint8_t priv[32], const uint8_t pub[65], uint8_t *out, size_t cap,
		      size_t *out_len);

/**
 * ECDSA-P256-SHA256 over a raw message, provided by the platform.
 *
 * Declared rather than included so this module stays free of any particular
 * crypto backend, the same seam matter_crypto.c uses for AES. backends/psa/
 * provides it on PSA Crypto; the host suite substitutes one
 * whose output is checked against OpenSSL.
 *
 * @param sig r||s, 32 bytes each. @return 0 on success.
 */
int matter_attest_ecdsa_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
			     uint8_t sig[MATTER_ATTEST_SIG_LEN]);

/**
 * A fresh P-256 key pair, provided by the platform. Same seam as above;
 * backends/psa/ provides it on PSA Crypto.
 *
 * @param pub uncompressed, 0x04 || X || Y. @return 0 on success.
 */
int matter_attest_ec_keygen(uint8_t priv[32], uint8_t pub[65]);

#ifdef __cplusplus
}
#endif

/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_matter_attest.c — attestation framing, with a fake signer.
 *
 * The signature itself cannot be checked here: the C suite has no P-256, so
 * anything this file asserted about it would only prove it agrees with itself.
 * tests/host/test_matter_attest.py verifies the real signature and the CSR
 * against OpenSSL.
 *
 * What IS checkable here is everything around it, and it is the part that has
 * gone wrong before: which bytes are presented for signature, whether the
 * challenge is appended and then removed again, and whether the TLV tags ascend
 * the way the peer's deconstructor demands.
 */
#include <string.h>

#include <tinytalk/matter_attest.h>
#include <tinytalk/matter_tlv.h>

#include "test.h"
#include "test_matter_attest_stub.h"

void test_matter_attest(void)
{
	uint8_t nonce[MATTER_ATTEST_NONCE_LEN];
	uint8_t challenge[MATTER_ATTEST_CHALLENGE_LEN];
	uint8_t buf[MATTER_ATTEST_ELEMENTS_MAX + MATTER_ATTEST_CHALLENGE_LEN];
	uint8_t sig[MATTER_ATTEST_SIG_LEN];
	size_t len = 0u;

	for (size_t i = 0; i < sizeof(nonce); i++) {
		nonce[i] = (uint8_t)(0xA0u + i);
	}
	for (size_t i = 0; i < sizeof(challenge); i++) {
		challenge[i] = (uint8_t)(0x50u + i);
	}

	t_group("the certificates that ship");
	{
		const uint8_t *c = NULL;
		size_t n = 0u;

		T_EQ("DAC", matter_attest_cert(MATTER_CERT_TYPE_DAC, &c, &n), MATTER_OK);
		T_EQ("DAC length", (long)n, 491L);
		/* Every one is an X.509 SEQUENCE whose own length header agrees
		 * with the array size -- the check that a copy-paste out of the
		 * SDK dropped nothing. */
		T_OK("DAC is a DER SEQUENCE", c[0] == 0x30u && c[1] == 0x82u);
		T_EQ("DAC self-declared length", (long)((c[2] << 8) | c[3]) + 4L, (long)n);

		T_EQ("PAI", matter_attest_cert(MATTER_CERT_TYPE_PAI, &c, &n), MATTER_OK);
		T_EQ("PAI length", (long)n, 463L);
		T_EQ("PAI self-declared length", (long)((c[2] << 8) | c[3]) + 4L, (long)n);

		T_EQ("no such certificate type", matter_attest_cert(0u, &c, &n), MATTER_E_INVAL);
		T_EQ("nor type 3", matter_attest_cert(3u, &c, &n), MATTER_E_INVAL);
		T_EQ("null refused", matter_attest_cert(MATTER_CERT_TYPE_DAC, NULL, &n),
		     MATTER_E_INVAL);
	}

	t_group("attestationElements");
	{
		struct matter_tlv_reader r;
		const uint8_t *cd = NULL;
		size_t cd_len = 0u;
		const uint8_t *got = NULL;
		size_t got_len = 0u;
		uint64_t ts = 99u;

		T_EQ("encodes",
		     matter_attest_elements_encode(nonce, sizeof(nonce), 0u, buf,
						   MATTER_ATTEST_ELEMENTS_MAX, &len),
		     MATTER_OK);
		T_OK("plausible size", len > 560u && len < MATTER_ATTEST_ELEMENTS_MAX);

		matter_tlv_reader_init(&r, buf, len);
		T_EQ("outer element", matter_tlv_next(&r), MATTER_OK);
		T_EQ("a structure", matter_tlv_element_type(&r), MATTER_TLV_STRUCTURE);
		T_EQ("enter", matter_tlv_enter(&r), MATTER_OK);

		/* Tags must ASCEND: DeviceAttestationConstructor.cpp:104-116
		 * refuses the message otherwise, and out-of-order tags encode
		 * perfectly well. */
		T_EQ("first field", matter_tlv_next(&r), MATTER_OK);
		T_OK("is the certification declaration", matter_tlv_tag(&r) == MATTER_TLV_CTX(1));
		T_EQ("as octets", matter_tlv_get_bytes(&r, &cd, &cd_len), MATTER_OK);
		T_EQ("CD length", (long)cd_len, 539L);
		T_OK("CD is a DER SEQUENCE", cd[0] == 0x30u && cd[1] == 0x82u);

		T_EQ("second field", matter_tlv_next(&r), MATTER_OK);
		T_OK("is the nonce", matter_tlv_tag(&r) == MATTER_TLV_CTX(2));
		T_EQ("as octets", matter_tlv_get_bytes(&r, &got, &got_len), MATTER_OK);
		T_EQ("nonce length", (long)got_len, (long)sizeof(nonce));
		T_OK("nonce bytes", memcmp(got, nonce, sizeof(nonce)) == 0);

		T_EQ("third field", matter_tlv_next(&r), MATTER_OK);
		T_OK("is the timestamp", matter_tlv_tag(&r) == MATTER_TLV_CTX(3));
		T_EQ("as an integer", matter_tlv_get_u64(&r, &ts), MATTER_OK);
		/* Zero because this node has no clock, not as a placeholder. */
		T_EQ("timestamp", (long)ts, 0L);

		T_EQ("nothing more", matter_tlv_next(&r), MATTER_END);

		T_EQ("no room refused",
		     matter_attest_elements_encode(nonce, sizeof(nonce), 0u, buf, 16u, &len),
		     MATTER_E_NOSPACE);
		T_EQ("null refused",
		     matter_attest_elements_encode(NULL, 32u, 0u, buf, sizeof(buf), &len),
		     MATTER_E_INVAL);
	}

	t_group("what actually gets signed");
	{
		size_t elements_len = 0u;
		uint8_t before[MATTER_ATTEST_ELEMENTS_MAX];

		T_EQ("encode",
		     matter_attest_elements_encode(nonce, sizeof(nonce), 0u, buf,
						   MATTER_ATTEST_ELEMENTS_MAX, &elements_len),
		     MATTER_OK);
		memcpy(before, buf, elements_len);

		g_attest_sign_calls = 0u;
		g_attest_sign_fail = 0;
		T_EQ("sign",
		     matter_attest_sign_with_challenge(buf, elements_len, sizeof(buf), challenge,
						       sizeof(challenge), sig),
		     MATTER_OK);
		T_EQ("signed once", (long)g_attest_sign_calls, 1L);

		/* The signature covers the elements AND the challenge. Without
		 * that, a response recorded from one session would verify in
		 * another. */
		T_EQ("message length", (long)g_attest_last_len,
		     (long)(elements_len + sizeof(challenge)));
		T_OK("elements first", memcmp(g_attest_last_msg, before, elements_len) == 0);
		T_OK("challenge appended",
		     memcmp(g_attest_last_msg + elements_len, challenge, sizeof(challenge)) == 0);

		/* And the caller's buffer is left holding only the elements: the
		 * challenge is session key material. */
		T_OK("buffer unchanged", memcmp(buf, before, elements_len) == 0);
		{
			bool wiped = true;

			for (size_t i = 0; i < sizeof(challenge); i++) {
				if (buf[elements_len + i] != 0u) {
					wiped = false;
				}
			}
			T_OK("challenge wiped afterwards", wiped);
		}

		/* Signed with the DAC key, not something else. */
		T_OK("used a real-looking key", g_attest_last_priv[0] == 0xaau);

		T_EQ("no headroom refused",
		     matter_attest_sign_with_challenge(buf, elements_len, elements_len + 4u,
						       challenge, sizeof(challenge), sig),
		     MATTER_E_NOSPACE);

		g_attest_sign_fail = 1;
		T_EQ("a failing signer is reported",
		     matter_attest_sign_with_challenge(buf, elements_len, sizeof(buf), challenge,
						       sizeof(challenge), sig),
		     MATTER_E_STATE);
		g_attest_sign_fail = 0;
	}

	t_group("NOCSRElements");
	{
		static const uint8_t fake_csr[8] = {1, 2, 3, 4, 5, 6, 7, 8};
		struct matter_tlv_reader r;
		const uint8_t *got = NULL;
		size_t got_len = 0u;

		T_EQ("encodes",
		     matter_attest_nocsr_encode(fake_csr, sizeof(fake_csr), nonce, sizeof(nonce),
						buf, sizeof(buf), &len),
		     MATTER_OK);
		matter_tlv_reader_init(&r, buf, len);
		T_EQ("outer", matter_tlv_next(&r), MATTER_OK);
		T_EQ("enter", matter_tlv_enter(&r), MATTER_OK);
		T_EQ("first", matter_tlv_next(&r), MATTER_OK);
		T_OK("is the csr", matter_tlv_tag(&r) == MATTER_TLV_CTX(1));
		T_EQ("octets", matter_tlv_get_bytes(&r, &got, &got_len), MATTER_OK);
		T_OK("csr bytes",
		     got_len == sizeof(fake_csr) && memcmp(got, fake_csr, sizeof(fake_csr)) == 0);
		T_EQ("second", matter_tlv_next(&r), MATTER_OK);
		T_OK("is the nonce", matter_tlv_tag(&r) == MATTER_TLV_CTX(2));
		T_EQ("nothing more", matter_tlv_next(&r), MATTER_END);
	}

	t_group("the CSR, as far as C can check it");
	{
		uint8_t priv[32];
		uint8_t pub[65];
		uint8_t csr[MATTER_CSR_MAX];
		size_t csr_len = 0u;

		T_EQ("keygen", matter_attest_ec_keygen(priv, pub), 0);

		g_attest_sign_calls = 0u;
		T_EQ("builds", matter_attest_csr(priv, pub, csr, sizeof(csr), &csr_len), MATTER_OK);
		/* Signed ONCE, over the CertificationRequestInfo -- the two-pass
		 * build must not sign twice or sign the wrong pass. */
		T_EQ("signed once", (long)g_attest_sign_calls, 1L);
		/* Self-signed: the key being certified is the one that signs. */
		T_OK("signed with the operational key", memcmp(g_attest_last_priv, priv, 32) == 0);

		T_OK("is a DER SEQUENCE", csr[0] == 0x30u && csr[1] == 0x81u);
		T_EQ("self-declared length", (long)csr[2] + 3L, (long)csr_len);
		/* The signed CertificationRequestInfo is a prefix of the CSR
		 * body, and it is what was presented for signature. */
		T_OK("signed the request info",
		     g_attest_last_len > 0u &&
			     memcmp(csr + 3, g_attest_last_msg, g_attest_last_len) == 0);
		/* The public key must appear verbatim. */
		{
			bool found = false;

			for (size_t i = 0; i + 65u <= csr_len; i++) {
				if (memcmp(csr + i, pub, 65u) == 0) {
					found = true;
				}
			}
			T_OK("carries the public key", found);
		}

		T_EQ("no room refused", matter_attest_csr(priv, pub, csr, 32u, &csr_len),
		     MATTER_E_NOSPACE);
		T_EQ("null refused", matter_attest_csr(NULL, pub, csr, sizeof(csr), &csr_len),
		     MATTER_E_INVAL);

		g_attest_sign_fail = 1;
		T_EQ("a failing signer is reported",
		     matter_attest_csr(priv, pub, csr, sizeof(csr), &csr_len), MATTER_E_STATE);
		g_attest_sign_fail = 0;
	}
}

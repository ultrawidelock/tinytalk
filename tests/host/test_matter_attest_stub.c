/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_matter_attest_stub.c — the crypto seams, for the C suite only.
 *
 * These are DELIBERATELY NOT REAL. The C suite has no P-256, so a signature
 * checked here would only prove that this file agrees with itself. What the C
 * tests can check is the plumbing: that the right bytes are presented for
 * signature, in the right order, with the challenge appended.
 *
 * The signature itself is verified against OpenSSL in
 * tests/host/test_matter_attest.py, which is the only place it can be.
 */
#include <string.h>

#include <tinytalk/matter_attest.h>

#include "test_matter_attest_stub.h"

uint8_t g_attest_last_msg[1024];
size_t g_attest_last_len;
uint8_t g_attest_last_priv[32];
unsigned int g_attest_sign_calls;
int g_attest_sign_fail;
int g_attest_keygen_fail;

int matter_attest_ecdsa_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
			     uint8_t sig[MATTER_ATTEST_SIG_LEN])
{
	g_attest_sign_calls++;
	if (msg_len <= sizeof(g_attest_last_msg)) {
		memcpy(g_attest_last_msg, msg, msg_len);
		g_attest_last_len = msg_len;
	} else {
		g_attest_last_len = 0u;
	}
	memcpy(g_attest_last_priv, priv, 32u);
	if (g_attest_sign_fail) {
		return -1;
	}
	/* Deterministic and dependent on the message, so a test can tell two
	 * different signatures apart without pretending this is ECDSA. */
	for (size_t i = 0; i < MATTER_ATTEST_SIG_LEN; i++) {
		sig[i] = (uint8_t)(0x40u + i + (msg_len & 0xFFu));
	}
	/* Keep the top bit of each integer clear so the DER encoder's padding
	 * path is exercised by the python test rather than by luck here. */
	sig[0] &= 0x7Fu;
	sig[32] &= 0x7Fu;
	return 0;
}

int matter_attest_ec_keygen(uint8_t priv[32], uint8_t pub[65])
{
	if (g_attest_keygen_fail) {
		return -1;
	}
	for (size_t i = 0; i < 32u; i++) {
		priv[i] = (uint8_t)(0x11u + i);
	}
	pub[0] = 0x04u;
	for (size_t i = 1; i < 65u; i++) {
		pub[i] = (uint8_t)(0x80u + i);
	}
	return 0;
}

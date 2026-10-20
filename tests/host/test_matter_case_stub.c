/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file test_matter_case_stub.c — ECDH and signing the suite can steer.
 *
 * The host suite has no P-256, so these record what they were asked to do and
 * return something deterministic. That is enough for what IS checkable here:
 * which bytes get signed, which key signs them, and that the shared secret
 * reaches the salt. The signature itself is verified against the only judge
 * that matters, a real commissioner.
 *
 * PAIRED MODE, g_case_stub_paired, is the exception, and it exists because one
 * question cannot be asked of a stub that only records: does this node's CASE
 * INITIATOR agree with this node's CASE RESPONDER? Answering it needs the two
 * halves run against each other in one process, and that needs primitives that
 * are consistent rather than merely deterministic -- the recording ECDH below
 * is NOT symmetric, so the two sides derive different secrets and every later
 * step fails for a reason that says nothing.
 *
 * So paired mode is a toy public-key system with the one property the round
 * trip turns on: a keypair is a private half and a public half that names it,
 * ECDH(a, Pub(b)) == ECDH(b, Pub(a)), and a signature verifies under the public
 * half of the key that made it. It proves the two halves of THIS node agree.
 * It proves nothing about P-256, and is not meant to.
 */
#include "test_matter_case_stub.h"

#include <string.h>

#include <tinytalk/tm_hash.h>
#include <tinytalk/matter_case.h>

uint8_t g_case_signed[1024];
size_t g_case_signed_len;
uint8_t g_case_sign_priv[32];
int g_case_sign_calls;
int g_case_ecdh_calls;
uint8_t g_case_ecdh_peer[MATTER_CASE_PUBKEY_LEN];
int g_case_ecdh_fail;
int g_case_sign_fail;
int g_case_verify_calls;
int g_case_verify_fail;
int g_case_stub_paired;

void test_matter_case_stub_pubkey(const uint8_t priv[32], uint8_t out[MATTER_CASE_PUBKEY_LEN])
{
	/* 0x04 because everything in this node's Matter code expects an
	 * uncompressed point and checks that byte. The private half is carried
	 * in the clear so the stub can recover it; a real point does not work
	 * this way, which is the whole reason paired mode is only a stub. */
	out[0] = 0x04u;
	memcpy(&out[1], priv, 32u);
	for (size_t i = 0; i < 32u; i++) {
		out[33u + i] = (uint8_t)~priv[i];
	}
}

/** Hash the two private halves in a fixed order, so both sides agree. */
static void paired_secret(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
	struct tm_sha256 h;
	const uint8_t *lo = (memcmp(a, b, 32u) <= 0) ? a : b;
	const uint8_t *hi = (lo == a) ? b : a;

	tm_sha256_init(&h);
	tm_sha256_update(&h, lo, 32u);
	tm_sha256_update(&h, hi, 32u);
	tm_sha256_final(&h, out);
}

/** The signature paired mode makes: two hashes, so the whole 64 bytes matter. */
static void paired_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
			uint8_t sig[MATTER_CASE_SIG_LEN])
{
	struct tm_sha256 h;

	tm_sha256_init(&h);
	tm_sha256_update(&h, priv, 32u);
	tm_sha256_update(&h, msg, msg_len);
	tm_sha256_final(&h, &sig[0]);

	tm_sha256_init(&h);
	tm_sha256_update(&h, msg, msg_len);
	tm_sha256_update(&h, priv, 32u);
	tm_sha256_final(&h, &sig[32]);
}

void test_matter_case_stub_reset(void)
{
	g_case_stub_paired = 0;
	memset(g_case_signed, 0, sizeof(g_case_signed));
	g_case_signed_len = 0u;
	memset(g_case_sign_priv, 0, sizeof(g_case_sign_priv));
	g_case_sign_calls = 0;
	g_case_ecdh_calls = 0;
	memset(g_case_ecdh_peer, 0, sizeof(g_case_ecdh_peer));
	g_case_ecdh_fail = 0;
	g_case_sign_fail = 0;
	g_case_verify_calls = 0;
	g_case_verify_fail = 0;
}

int matter_case_ecdh(const uint8_t priv[32], const uint8_t peer_pub[MATTER_CASE_PUBKEY_LEN],
		     uint8_t secret_out[MATTER_CASE_SECRET_LEN])
{
	g_case_ecdh_calls++;
	if (g_case_ecdh_fail) {
		return -1;
	}
	memcpy(g_case_ecdh_peer, peer_pub, MATTER_CASE_PUBKEY_LEN);
	if (g_case_stub_paired) {
		paired_secret(priv, &peer_pub[1], secret_out);
		return 0;
	}
	/* Deterministic and dependent on both inputs, so a test can tell a
	 * secret that was derived from a secret that was not. */
	for (size_t i = 0; i < MATTER_CASE_SECRET_LEN; i++) {
		secret_out[i] = (uint8_t)(priv[i] ^ peer_pub[i + 1u] ^ 0x5Au);
	}
	return 0;
}

int matter_case_sign(const uint8_t priv[32], const uint8_t *msg, size_t msg_len,
		     uint8_t sig[MATTER_CASE_SIG_LEN])
{
	g_case_sign_calls++;
	if (g_case_sign_fail) {
		return -1;
	}
	if (msg_len > sizeof(g_case_signed)) {
		return -1;
	}
	memcpy(g_case_signed, msg, msg_len);
	g_case_signed_len = msg_len;
	memcpy(g_case_sign_priv, priv, sizeof(g_case_sign_priv));

	if (g_case_stub_paired) {
		paired_sign(priv, msg, msg_len, sig);
		return 0;
	}
	for (size_t i = 0; i < MATTER_CASE_SIG_LEN; i++) {
		sig[i] = (uint8_t)(0xA0u + i);
	}
	return 0;
}

int matter_case_verify(const uint8_t pub[MATTER_CASE_PUBKEY_LEN], const uint8_t *msg,
		       size_t msg_len, uint8_t const sig[MATTER_CASE_SIG_LEN])
{
	g_case_verify_calls++;
	if (g_case_verify_fail) {
		return -1;
	}
	if (g_case_stub_paired) {
		uint8_t want[MATTER_CASE_SIG_LEN];

		paired_sign(&pub[1], msg, msg_len, want);
		return (memcmp(want, sig, sizeof(want)) == 0) ? 0 : -1;
	}
	(void)msg;
	(void)msg_len;
	(void)sig;
	return 0;
}

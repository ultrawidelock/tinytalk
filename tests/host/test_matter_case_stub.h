/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/** @file test_matter_case_stub.h — see test_matter_case_stub.c. */
#ifndef TINYTALK_TEST_MATTER_CASE_STUB_H
#define TINYTALK_TEST_MATTER_CASE_STUB_H

#include <stddef.h>
#include <stdint.h>

/** Exactly the bytes the last matter_case_sign() was given. */
extern uint8_t g_case_signed[1024];
extern size_t g_case_signed_len;
extern uint8_t g_case_sign_priv[32];
extern int g_case_sign_calls;

extern int g_case_ecdh_calls;
extern uint8_t g_case_ecdh_peer[65];

extern int g_case_ecdh_fail;
extern int g_case_sign_fail;
extern int g_case_verify_calls;
extern int g_case_verify_fail;

/**
 * Make ECDH symmetric and signatures checkable, so the initiator and the
 * responder can be run against each other. See the .c file. Cleared by reset().
 */
extern int g_case_stub_paired;

/** The public half paired mode pairs with @p priv. Meaningless outside it. */
void test_matter_case_stub_pubkey(const uint8_t priv[32], uint8_t out[65]);

void test_matter_case_stub_reset(void);

#endif /* TINYTALK_TEST_MATTER_CASE_STUB_H */

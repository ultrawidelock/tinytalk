/*
 * What the fake signer in test_matter_attest_stub.c recorded. See that file for
 * why it is a fake.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

extern uint8_t g_attest_last_msg[1024];
extern size_t g_attest_last_len;
extern uint8_t g_attest_last_priv[32];
extern unsigned int g_attest_sign_calls;
extern int g_attest_sign_fail;
extern int g_attest_keygen_fail;

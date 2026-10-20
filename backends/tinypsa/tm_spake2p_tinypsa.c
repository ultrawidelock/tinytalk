/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The four SPAKE2+ P-256 primitives matter_spake2p.h declares, on tinypsa.
 * tinypsa's spake2p_p256.h follows nrf_oberon's contract
 * (ocrypto_spake2p_p256.h) under its own names, so each function here only
 * forwards. No arithmetic: tinypsa's suite proves the math, PASE on hardware
 * proves the wiring.
 */
#include <stddef.h>
#include <stdint.h>

#include <tinypsa/spake2p_p256.h>

#include <tinytalk/matter_spake2p.h>

void ocrypto_spake2p_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len)
{
	tinypsa_spake2p_p256_reduce(x, xs, xs_len);
}

int ocrypto_spake2p_p256_check_key(const uint8_t K[65])
{
	return tinypsa_spake2p_p256_check_key(K);
}

int ocrypto_spake2p_p256_get_key_share(uint8_t XY[65], const uint8_t w0[32], const uint8_t xy[32],
				       const uint8_t MN[65])
{
	return tinypsa_spake2p_p256_get_key_share(XY, w0, xy, MN);
}

int ocrypto_spake2p_p256_get_ZV(uint8_t Z[65], uint8_t V[65], const uint8_t w0[32],
				const uint8_t w1[32], const uint8_t xy[32], const uint8_t YX[65],
				const uint8_t NM[65], const uint8_t L[65])
{
	return tinypsa_spake2p_p256_get_ZV(Z, V, w0, w1, xy, YX, NM, L);
}

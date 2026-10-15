/**
 * @file spakefake.c — host stand-in for oberon's SPAKE2+ primitives.
 *
 * reduce() is REAL (shift-and-subtract mod the P-256 group order, pinned
 * against python-computed values). get_key_share()/get_ZV() are NOT a curve:
 * they REPLAY one exchange gen_pase_vector.py computed with a real P-256 and
 * refuse any other input loudly -- which is the point: swapping M and N, or
 * passing w1 where L belongs, fails here rather than on a phone. Everything
 * downstream (transcript, SHA-256, HKDF, confirmations, session keys) runs for
 * real over the recorded points. What this does NOT prove is that oberon
 * computes what the script computed; only the on-target selftest answers that.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The order of the P-256 base point, big-endian (SEC 2, secp256r1 n). */
static const uint8_t k_order[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
	0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

/** @return true when the 32-byte big-endian @p a is >= the group order. */
static int ge_order(const uint8_t a[32])
{
	for (size_t i = 0; i < 32u; i++) {
		if (a[i] != k_order[i]) {
			return a[i] > k_order[i];
		}
	}
	return 1; /* equal counts as >= */
}

/** a -= order, big-endian, assuming a >= order. */
static void sub_order(uint8_t a[32])
{
	int borrow = 0;

	for (size_t i = 32u; i-- > 0;) {
		int d = (int)a[i] - (int)k_order[i] - borrow;

		if (d < 0) {
			d += 256;
			borrow = 1;
		} else {
			borrow = 0;
		}
		a[i] = (uint8_t)d;
	}
}

void ocrypto_spake2p_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len)
{
	uint8_t r[32];

	memset(r, 0, sizeof(r));

	/* Shift the input in one bit at a time, reducing whenever it fits. Slow
	 * and obviously correct, which is what a reference wants to be. */
	for (size_t byte = 0; byte < xs_len; byte++) {
		for (int bit = 7; bit >= 0; bit--) {
			int carry = (xs[byte] >> bit) & 1;

			for (size_t i = 32u; i-- > 0;) {
				int v = (r[i] << 1) | carry;

				carry = (v >> 8) & 1;
				r[i] = (uint8_t)v;
			}
			if (carry != 0 || ge_order(r)) {
				sub_order(r);
			}
		}
	}

	memcpy(x, r, 32u);
}

/* ------------------------------------------------------------- the replay ---
 *
 * Not a curve. See the note at the top of this file for why that is the right
 * answer here and what it does and does not establish.
 */

#include "spakefake/spakefake.h"

#include <tinymatter/matter_spake2p.h>

static struct {
	uint8_t w0[32];
	uint8_t l[65];
	uint8_t y[32];
	uint8_t pa[65];
	uint8_t pb[65];
	uint8_t z[65];
	uint8_t v[65];
	int armed;
	unsigned key_share_calls;
	unsigned zv_calls;
	const char *fault;
} g_replay;

/** Record the first refusal only: the later ones are consequences of it. */
static int refuse(const char *why)
{
	if (g_replay.fault == NULL) {
		g_replay.fault = why;
	}
	return -1;
}

void spakefake_replay_arm(const uint8_t w0[32], const uint8_t l[65], const uint8_t y_ws[40],
			  const uint8_t pa[65], const uint8_t pb[65], const uint8_t z[65],
			  const uint8_t v[65])
{
	memset(&g_replay, 0, sizeof(g_replay));
	memcpy(g_replay.w0, w0, sizeof(g_replay.w0));
	memcpy(g_replay.l, l, sizeof(g_replay.l));
	ocrypto_spake2p_p256_reduce(g_replay.y, y_ws, 40u);
	memcpy(g_replay.pa, pa, sizeof(g_replay.pa));
	memcpy(g_replay.pb, pb, sizeof(g_replay.pb));
	memcpy(g_replay.z, z, sizeof(g_replay.z));
	memcpy(g_replay.v, v, sizeof(g_replay.v));
	g_replay.armed = 1;
}

void spakefake_replay_clear(void)
{
	memset(&g_replay, 0, sizeof(g_replay));
}

const char *spakefake_replay_fault(void)
{
	return g_replay.fault;
}

unsigned spakefake_replay_key_share_calls(void)
{
	return g_replay.key_share_calls;
}

unsigned spakefake_replay_zv_calls(void)
{
	return g_replay.zv_calls;
}

/**
 * Structural validation only: uncompressed marker present and the coordinates
 * not all zero.
 *
 * That is enough to exercise the state machine's reject path with a point every
 * real implementation also rejects, and it is honestly all a host build without
 * a curve can say. A point that is well-formed but off-curve passes here and
 * would not pass oberon.
 */
int ocrypto_spake2p_p256_check_key(const uint8_t K[65])
{
	int nonzero = 0;

	if (K[0] != 0x04u) {
		return -1;
	}
	for (size_t i = 1u; i < 65u; i++) {
		nonzero |= K[i];
	}
	return nonzero ? 0 : -1;
}

int ocrypto_spake2p_p256_get_key_share(uint8_t XY[65], const uint8_t w0[32], const uint8_t xy[32],
				       const uint8_t MN[65])
{
	g_replay.key_share_calls++;

	if (!g_replay.armed) {
		return refuse("get_key_share with no recording armed");
	}
	if (memcmp(w0, g_replay.w0, 32u) != 0) {
		return refuse("get_key_share got a w0 that is not the verifier's");
	}
	if (memcmp(xy, g_replay.y, 32u) != 0) {
		return refuse("get_key_share got a scalar that is not reduce(y_ws)");
	}
	/* The responder's own element is N. Passing M here is the mistake this
	 * whole replay exists to catch. */
	if (memcmp(MN, matter_spake2p_N, 65u) != 0) {
		return refuse("get_key_share got M where the responder must pass N");
	}

	memcpy(XY, g_replay.pb, 65u);
	return 0;
}

int ocrypto_spake2p_p256_get_ZV(uint8_t Z[65], uint8_t V[65], const uint8_t w0[32],
				const uint8_t w1[32], const uint8_t xy[32], const uint8_t YX[65],
				const uint8_t NM[65], const uint8_t L[65])
{
	g_replay.zv_calls++;

	if (!g_replay.armed) {
		return refuse("get_ZV with no recording armed");
	}
	/* ocrypto_spake2p_p256.h:83,87 -- w1 is NULL on the server side and L is
	 * NULL on the client side. Supplying the wrong one computes the wrong
	 * half of the protocol and nothing downstream would notice. */
	if (w1 != NULL) {
		return refuse("get_ZV got a w1; the responder side must pass NULL");
	}
	if (L == NULL) {
		return refuse("get_ZV got no L; the responder side must supply it");
	}
	if (memcmp(w0, g_replay.w0, 32u) != 0) {
		return refuse("get_ZV got a w0 that is not the verifier's");
	}
	if (memcmp(L, g_replay.l, 65u) != 0) {
		return refuse("get_ZV got an L that is not the verifier's");
	}
	if (memcmp(xy, g_replay.y, 32u) != 0) {
		return refuse("get_ZV got a scalar that is not reduce(y_ws)");
	}
	if (memcmp(YX, g_replay.pa, 65u) != 0) {
		return refuse("get_ZV got a peer share that is not the recorded pA");
	}
	/* The PEER's element is M, the mirror of the key share above. */
	if (memcmp(NM, matter_spake2p_M, 65u) != 0) {
		return refuse("get_ZV got N where the responder must pass M");
	}

	memcpy(Z, g_replay.z, 65u);
	memcpy(V, g_replay.v, 65u);
	return 0;
}

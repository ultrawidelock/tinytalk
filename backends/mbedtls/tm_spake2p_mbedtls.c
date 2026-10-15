/* SPDX-License-Identifier: ISC */

/*
 * The four SPAKE2+ P-256 primitives matter_spake2p.h declares, on Mbed TLS 3.6
 * ECP. The contracts are nrf_oberon's (ocrypto_spake2p_p256.h), so the core
 * cannot tell which of the two it is linked against.
 *
 *   reduce         x = xs mod n
 *   check_key      K is an uncompressed P-256 point, on the curve, not the
 *                  identity
 *   get_key_share  XY = xy*G + w0*MN
 *   get_ZV         T = YX - w0*NM, then Z = xy*T and
 *                    prover   (w1 set, L NULL):  V = w1*T
 *                    verifier (w1 NULL, L set):  V = xy*L
 *
 * P-256 has cofactor 1, so the h of the SPAKE2+ drafts drops out. Every
 * function returns -1 rather than an identity point.
 *
 * Needs MBEDTLS_ECP_C, MBEDTLS_ECP_DP_SECP256R1_ENABLED and
 * MBEDTLS_PSA_CRYPTO_C. mbedtls_ecp_mul() requires an RNG for its blinding, and
 * the PSA one is the RNG a 3.6 build with PSA already seeds; psa_crypto_init()
 * is called before each use and costs nothing after the first.
 *
 * SECRET-DEPENDENT BRANCHES AND TABLE LOOKUPS, all of them, by place:
 *
 *  - reduce() and neg_scalar(): none. Fixed iteration counts, and the
 *    conditional subtraction is a mask, not a branch.
 *  - mul(): mbedtls_mpi_read_binary() trims leading zero limbs, so the limb
 *    count of a secret scalar leaks when its top 64 bits are zero
 *    (probability 2^-64 for a uniform scalar). mbedtls_ecp_mul() then checks
 *    the scalar against n with an early-exit compare before its documented
 *    constant-flow, blinded comb multiplication.
 *  - add(): mbedtls_ecp_muladd() is documented as NOT constant time. With
 *    both scalars 1 it reduces to one point addition, and that addition
 *    branches when its inputs are equal, opposite or the identity. In get_ZV
 *    the inputs are the peer's share and -w0*NM, so those cases need the
 *    peer to already know w0.
 *  - store_point(): branches on the result being the identity, which only
 *    decides between success and failure.
 *  - Field arithmetic inside Mbed TLS is the library's own, with the timing
 *    properties its documentation gives for mbedtls_ecp_mul().
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/psa_util.h>
#include <psa/crypto.h>

#include <tinytalk/matter_spake2p.h>

/* The order of the P-256 base point, big-endian (SEC 2, secp256r1 n). */
static const uint8_t k_order[32] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17,
	0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n-- > 0u) {
		*v++ = 0u;
	}
}

void ocrypto_spake2p_p256_reduce(uint8_t x[32], const uint8_t *xs, size_t xs_len)
{
	uint8_t r[32];
	uint8_t t[32];

	memset(r, 0, sizeof(r));
	/* One bit at a time: r = 2r + bit, then subtract n if that reached it.
	 * r < n before each step, so one subtraction is always enough. */
	for (size_t byte = 0; byte < xs_len; byte++) {
		for (int bit = 7; bit >= 0; bit--) {
			unsigned carry = (xs[byte] >> bit) & 1u;
			unsigned borrow = 0u;
			uint8_t keep_t;

			for (size_t i = 32u; i-- > 0u;) {
				unsigned v = ((unsigned)r[i] << 1) | carry;

				carry = v >> 8;
				r[i] = (uint8_t)v;
			}
			for (size_t i = 32u; i-- > 0u;) {
				unsigned v = (unsigned)r[i] - k_order[i] - borrow;

				borrow = (v >> 8) & 1u;
				t[i] = (uint8_t)v;
			}
			/* 2r + bit >= n exactly when bit 256 is set or r - n did
			 * not borrow. */
			keep_t = (uint8_t)(0u - (carry | (borrow ^ 1u)));
			for (size_t i = 0; i < 32u; i++) {
				r[i] = (uint8_t)((t[i] & keep_t) | (r[i] & (uint8_t)~keep_t));
			}
		}
	}
	memcpy(x, r, sizeof(r));
	wipe(r, sizeof(r));
	wipe(t, sizeof(t));
}

/* out = n - k mod 2^256. For a reduced nonzero k that is -k mod n. */
static void neg_scalar(uint8_t out[32], const uint8_t k[32])
{
	unsigned borrow = 0u;

	for (size_t i = 32u; i-- > 0u;) {
		unsigned v = (unsigned)k_order[i] - k[i] - borrow;

		borrow = (v >> 8) & 1u;
		out[i] = (uint8_t)v;
	}
}

static int load_group(mbedtls_ecp_group *grp)
{
	if (psa_crypto_init() != PSA_SUCCESS) {
		return -1;
	}
	return mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1) == 0 ? 0 : -1;
}

/* Uncompressed only, on the curve and not the identity. */
static int load_point(const mbedtls_ecp_group *grp, mbedtls_ecp_point *p, const uint8_t buf[65])
{
	if (buf[0] != 0x04u || mbedtls_ecp_point_read_binary(grp, p, buf, 65u) != 0) {
		return -1;
	}
	return mbedtls_ecp_check_pubkey(grp, p) == 0 ? 0 : -1;
}

static int store_point(const mbedtls_ecp_group *grp, mbedtls_ecp_point *p, uint8_t out[65])
{
	size_t olen = 0u;

	if (mbedtls_ecp_is_zero(p)) {
		return -1;
	}
	if (mbedtls_ecp_point_write_binary(grp, p, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out,
					   65u) != 0 ||
	    olen != 65u) {
		return -1;
	}
	return 0;
}

/* r = k*p. Refuses k = 0 and k >= n, as mbedtls_ecp_mul() does. */
static int mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *r, const uint8_t k[32],
	       const mbedtls_ecp_point *p)
{
	mbedtls_mpi m;
	int rc;

	mbedtls_mpi_init(&m);
	rc = mbedtls_mpi_read_binary(&m, k, 32u);
	if (rc == 0) {
		rc = mbedtls_ecp_mul(grp, r, &m, p, mbedtls_psa_get_random,
				     MBEDTLS_PSA_RANDOM_STATE);
	}
	mbedtls_mpi_free(&m);
	return rc == 0 ? 0 : -1;
}

/* r = a + b, both affine. */
static int add(mbedtls_ecp_group *grp, mbedtls_ecp_point *r, const mbedtls_ecp_point *a,
	       const mbedtls_ecp_point *b)
{
	mbedtls_mpi one;
	int rc;

	mbedtls_mpi_init(&one);
	rc = mbedtls_mpi_lset(&one, 1);
	if (rc == 0) {
		rc = mbedtls_ecp_muladd(grp, r, &one, a, &one, b);
	}
	mbedtls_mpi_free(&one);
	return rc == 0 ? 0 : -1;
}

int ocrypto_spake2p_p256_check_key(const uint8_t K[65])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point p;
	int rc = -1;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&p);
	if (load_group(&grp) == 0 && load_point(&grp, &p, K) == 0) {
		rc = 0;
	}
	mbedtls_ecp_point_free(&p);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int ocrypto_spake2p_p256_get_key_share(uint8_t XY[65], const uint8_t w0[32], const uint8_t xy[32],
				       const uint8_t MN[65])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point mn, a, b, r;
	int rc = -1;

	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&mn);
	mbedtls_ecp_point_init(&a);
	mbedtls_ecp_point_init(&b);
	mbedtls_ecp_point_init(&r);
	if (load_group(&grp) == 0 && load_point(&grp, &mn, MN) == 0 &&
	    mul(&grp, &a, xy, &grp.G) == 0 && mul(&grp, &b, w0, &mn) == 0 &&
	    add(&grp, &r, &a, &b) == 0) {
		rc = store_point(&grp, &r, XY);
	}
	mbedtls_ecp_point_free(&r);
	mbedtls_ecp_point_free(&b);
	mbedtls_ecp_point_free(&a);
	mbedtls_ecp_point_free(&mn);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int ocrypto_spake2p_p256_get_ZV(uint8_t Z[65], uint8_t V[65], const uint8_t w0[32],
				const uint8_t w1[32], const uint8_t xy[32], const uint8_t YX[65],
				const uint8_t NM[65], const uint8_t L[65])
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point yx, nm, l, a, t, z, v;
	uint8_t neg_w0[32];
	uint8_t zb[65];
	uint8_t vb[65];
	int rc = -1;

	/* Exactly one of w1 (the prover) and L (the verifier). Both or neither
	 * would compute half of the wrong side. */
	if ((w1 == NULL) == (L == NULL)) {
		return -1;
	}
	neg_scalar(neg_w0, w0);
	mbedtls_ecp_group_init(&grp);
	mbedtls_ecp_point_init(&yx);
	mbedtls_ecp_point_init(&nm);
	mbedtls_ecp_point_init(&l);
	mbedtls_ecp_point_init(&a);
	mbedtls_ecp_point_init(&t);
	mbedtls_ecp_point_init(&z);
	mbedtls_ecp_point_init(&v);
	if (load_group(&grp) == 0 && load_point(&grp, &yx, YX) == 0 &&
	    load_point(&grp, &nm, NM) == 0 && (L == NULL || load_point(&grp, &l, L) == 0) &&
	    mul(&grp, &a, neg_w0, &nm) == 0 && add(&grp, &t, &yx, &a) == 0 &&
	    mul(&grp, &z, xy, &t) == 0 &&
	    (w1 != NULL ? mul(&grp, &v, w1, &t) : mul(&grp, &v, xy, &l)) == 0 &&
	    store_point(&grp, &z, zb) == 0 && store_point(&grp, &v, vb) == 0) {
		memcpy(Z, zb, sizeof(zb));
		memcpy(V, vb, sizeof(vb));
		rc = 0;
	}
	mbedtls_ecp_point_free(&v);
	mbedtls_ecp_point_free(&z);
	mbedtls_ecp_point_free(&t);
	mbedtls_ecp_point_free(&a);
	mbedtls_ecp_point_free(&l);
	mbedtls_ecp_point_free(&nm);
	mbedtls_ecp_point_free(&yx);
	mbedtls_ecp_group_free(&grp);
	wipe(neg_w0, sizeof(neg_w0));
	wipe(zb, sizeof(zb));
	wipe(vb, sizeof(vb));
	return rc;
}

/**
 * @file test_spake2p_mbedtls.c — the Mbed TLS SPAKE2+ backend against outside answers.
 *
 * Three sources, none of them this C:
 *
 *  1. connectedhomeip's SPAKE2+ vectors. They are for draft-bar-cfrg-spake2plus-01,
 *     which is the draft Matter follows (CHIPCryptoPAL.h cites it) and which
 *     differs from RFC 9383 in its key schedule, not in its curve arithmetic.
 *     All four, both sides, then through matter_spake2p_p2() to the
 *     confirmation MACs and Ke.
 *  2. The exchange gen_pase_vector.py computes in plain Python integers, both
 *     sides.
 *  3. A fresh exchange: a prover built here from the four primitives, against
 *     the real responder state machine. Both must agree on cA, cB and every
 *     session key.
 *
 * Built only with the real curve, which is the default; SPAKE=fake leaves it out.
 */
#include <string.h>

#include <tinytalk/matter_crypto.h>
#include <tinytalk/matter_pase.h>
#include <tinytalk/matter_pase_sm.h>
#include <tinytalk/matter_spake2p.h>

#include "test.h"

struct chip_tv {
	const char *context;
	const char *prover_identity;
	const char *verifier_identity;
	const char *w0, *w1, *L, *x, *X, *y, *Y, *Z, *V;
	const char *ka, *ke, *kca, *kcb, *mac_kca, *mac_kcb;
};

/* connectedhomeip src/crypto/tests/SPAKE2P_RFC_test_vectors.h, draft-bar-cfrg-spake2plus-01 */
static const struct chip_tv k_chip_tv[] = {
	{
		.context = "SPAKE2+-P256-SHA256-HKDF draft-01",
		.prover_identity = "client",
		.verifier_identity = "server",
		.w0 = "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c",
		.w1 = "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512",
		.L = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9",
		.x = "8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6",
		.X = "04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e",
		.y = "2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91",
		.Y = "04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4",
		.Z = "0471a35282d2026f36bf3ceb38fcf87e3112a4452f46e9f7b47fd769cfb570145b62589c76b7aa1eb6080a832e5332c36898426912e29c40ef9e9c742eee82bf30",
		.V = "046718981bf15bc4db538fc1f1c1d058cb0eececf1dbe1b1ea08a4e25275d382e82b348c8131d8ed669d169c2e03a858db7cf6ca2853a4071251a39fbe8cfc39bc",
		.ka = "f9cab9adcc0ed8e5a4db11a8505914b2",
		.ke = "801db297654816eb4f02868129b9dc89",
		.kca = "0d248d7d19234f1486b2efba5179c52d",
		.kcb = "556291df26d705a2caedd6474dd0079b",
		.mac_kca = "d4376f2da9c72226dd151b77c2919071155fc22a2068d90b5faa6c78c11e77dd",
		.mac_kcb = "0660a680663e8c5695956fb22dff298b1d07a526cf3cc591adfecd1f6ef6e02e",
	},
	{
		.context = "SPAKE2+-P256-SHA256-HKDF draft-01",
		.prover_identity = "client",
		.verifier_identity = "",
		.w0 = "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c",
		.w1 = "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512",
		.L = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9",
		.x = "ec82d9258337f61239c9cd68e8e532a3a6b83d12d2b1ca5d543f44def17dfb8d",
		.X = "04230779960824076d3666a7418e4d433e2fa15b06176eabdd572f43a32ecc79a192b243d2624310a7356273b86e5fd9bd627d3ade762baeff1a320d4ad7a4e47f",
		.y = "eac3f7de4b198d5fe25c443c0cd4963807add767815dd02a6f0133b4bc2c9eb0",
		.Y = "044558642e71b616b248c9583bd6d7aa1b3952c6df6a9f7492a06035ca5d92522d84443de7aa20a59380fa4de6b7438d925dbfb7f1cfe60d79acf961ee33988c7d",
		.Z = "04b4e8770f19f58ddf83f9220c3a9305792665e0c60989e6ee9d7fa449c775d6395f6f25f307e3903ac045a013fbb5a676e872a6abfcf4d7bb5aac69efd6140eed",
		.V = "04141db83bc7d96f41b636622e7a5c552ad83211ff55319ac25ed0a09f0818bd942e8150319bfbfa686183806dc61911183f6a0f5956156023d96e0f93d275bf50",
		.ka = "e2cbee3ae19a4dbe9f146be6bee9bfa1",
		.ke = "6989d8f9177ef7df67da437987f07255",
		.kca = "2f9e0bb669d2c22645bce34da04ac16a",
		.kcb = "eb7a35168759dd8e9ce44e4dc51277ce",
		.mac_kca = "e1b9258807ba4750dae1d7f3c3c294f13dc4fa60cde346d5de7d200e2f8fd3fc",
		.mac_kcb = "b9c39dfa49c47757de778d9bedeaca2448b905be19a43b94ee24b770208135e3",
	},
	{
		.context = "SPAKE2+-P256-SHA256-HKDF draft-01",
		.prover_identity = "",
		.verifier_identity = "server",
		.w0 = "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c",
		.w1 = "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512",
		.L = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9",
		.x = "ba0f0f5b78ef23fd07868e46aeca63b51fda519a3420501acbe23d53c2918748",
		.X = "04c14d28f4370fea20745106cea58bcfb60f2949fa4e131b9aff5ea13fd5aa79d507ae1d229e447e000f15eb78a9a32c2b88652e3411642043c1b2b7992cf2d4de",
		.y = "39397fbe6db47e9fbd1a263d79f5d0aaa44df26ce755f78e092644b434533a42",
		.Y = "04d1bee3120fd87e86fe189cb952dc688823080e62524dd2c08dffe3d22a0a8986aa64c9fe0191033cafbc9bcaefc8e2ba8ba860cd127af9efdd7f1c3a41920fe8",
		.Z = "04aac71cf4c8df8181b867c9ecbee9d0963caf51f1534a823429c26fe5248313ffc5c5e44ea8162161ab6b3d73b87704a45889bf6343d96fa96cd1641efa71607c",
		.V = "04c7c9505365f7ce57293c92a37f1bbdc68e0322901e61edef59fee7876b17b063e0fa4a126eae0a671b37f1464cf1ccad591c33ae944e3b1f318d76e36fea9966",
		.ka = "ec8d19b807ffb1d1eea81a93ba35cdfe",
		.ke = "2ea40e4badfa5452b5744dc5983e99ba",
		.kca = "66de534d9bf1e44e96a53a4b48d6b353",
		.kcb = "4945c38bb476cb0f347f3222be9b64a2",
		.mac_kca = "e564c93b3015efb946dc16d642bbe7d1c8da5be164ed9fc3bae4e0ff86e1bd3c",
		.mac_kcb = "072a94d9a54edc201d8891534c2317cadf3ea3792827f479e873f93e90f21552",
	},
	{
		.context = "SPAKE2+-P256-SHA256-HKDF draft-01",
		.prover_identity = "",
		.verifier_identity = "",
		.w0 = "e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c",
		.w1 = "24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512",
		.L = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9",
		.x = "5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786",
		.X = "04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd",
		.y = "766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e",
		.Y = "04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947",
		.Z = "040a150d9a62f514c9a1fedd782a0240a342721046cefb1111c3adb3be893ce9fcd2ffa137922fcf8a588d0f76ba9c55c85da2af3f1c789ca17976810387fb1d7e",
		.V = "04f8e247cc263a1846272f5a3b61b68aa60a5a2665d10cd22c89cd6bad05dc0e5e650f21ff017186cc92651a4cd7e66ce88f529299f340ea80fb90a9bad094e1a6",
		.ka = "5929a3ce9822c81401bf0f764f69af08",
		.ke = "ea3276d68334576097e04b19ee5a3a8b",
		.kca = "7f84b939d600117256b0c8a6d40cf181",
		.kcb = "f7d7547ced93f681e8df4c258c4516fd",
		.mac_kca = "71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea",
		.mac_kcb = "095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3",
	},
};

/* generated by tests/host/gen_pase_vector.py -- copied from test_matter_pase_sm.c */
static const char *const K_SALT =
	"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
static const char *const K_Y_WS =
	"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7";
static const char *const K_W0 =
	"c77189dcfabe03801f58373948a6a884db72fdaa93d5262c6828c57a7d766028";
static const char *const K_L =
	"04bbbd9d1e8eb982d8733b84e54dbf6adf943719a1c58bcb55d09dcfb17720709407ead7480fcaea51f9c6a8"
	"0a1e7c62a2c9223a5686445cee6da59a7eb6c06759";
static const char *const K_PA =
	"048961ff3ad9ffcc1589abc7798c54d904b842d733b1ee721a49e8faf8ed9b9424caf59cf9842eb0404e23b8"
	"e6d822e35848c42cf437841fdc176cc0f1d9f9d4f0";
static const char *const K_EXPECT_PB =
	"04252597b0cd7f885023b5678f9f710e4ec81ecff6e533b8b5861a7e49d4d03e868d1c539a58de731bce0453"
	"8a36ed21b4009dd8f0cc9a84100c357feb67a2108b";
static const char *const K_Z =
	"04da5b024cfeb107a72f2e378cf44c5ff2fd1034b26c3589091d52ca55f652f2f6ac59e866c9fa3df33beea7"
	"2165ba647e4469ad1f141dc2238e5b8ad4f705dfe9";
static const char *const K_V =
	"049167108bcc98f5ba4601f7eac3922f38929b0b9d63cc5b7d47aeed7f5eb1f694d5df961de3e484aaf4e3a9"
	"9b378beef0ba891f6f9cba71e142a6e3cc1144a82d";
/* The generator's other inputs: PASSCODE, ITERATIONS and X_WS (0x01..0x28). */
#define VEC_PASSCODE   20202021u
#define VEC_ITERATIONS 1000u

/* The iPhone PBKDFParamRequest test_matter_pase_sm.c drives the responder with. */
static const char *const K_APPLE_REQ =
	"15300120a882bce8bfdeab50e04ac596bfc05024db5902b7512ed9b278cfaacc125230122502b6e424030028"
	"0435052501f40125022c012503a00f24041224050b2606000004012407011818";

/** Append one transcript element: its length as a little-endian uint64, then it. */
static size_t tt_put(uint8_t *tt, size_t off, const uint8_t *e, size_t len)
{
	for (size_t i = 0u; i < 8u; i++) {
		tt[off + i] = (uint8_t)((uint64_t)len >> (8u * i));
	}
	if (len != 0u) {
		memcpy(&tt[off + 8u], e, len);
	}
	return off + 8u + len;
}

static void chip_vector(const struct chip_tv *tv)
{
	uint8_t w0[32], w1[32], x[32], y[32];
	uint8_t l[65], px[65], py[65], z[65], v[65];
	uint8_t tt[640];
	size_t n = 0u;
	struct matter_spake2p_result res;

	(void)t_unhex(w0, tv->w0, sizeof(w0));
	(void)t_unhex(w1, tv->w1, sizeof(w1));
	(void)t_unhex(x, tv->x, sizeof(x));
	(void)t_unhex(y, tv->y, sizeof(y));
	(void)t_unhex(l, tv->L, sizeof(l));
	(void)t_unhex(px, tv->X, sizeof(px));
	(void)t_unhex(py, tv->Y, sizeof(py));

	T_EQ("L is a valid point", ocrypto_spake2p_p256_check_key(l), 0);
	T_EQ("prover share", ocrypto_spake2p_p256_get_key_share(z, w0, x, matter_spake2p_M), 0);
	t_vec("X = x*G + w0*M", z, 65u, tv->X);
	T_EQ("verifier share", ocrypto_spake2p_p256_get_key_share(z, w0, y, matter_spake2p_N), 0);
	t_vec("Y = y*G + w0*N", z, 65u, tv->Y);

	T_EQ("prover ZV", ocrypto_spake2p_p256_get_ZV(z, v, w0, w1, x, py, matter_spake2p_N, NULL),
	     0);
	t_vec("prover Z", z, 65u, tv->Z);
	t_vec("prover V", v, 65u, tv->V);
	T_EQ("verifier ZV",
	     ocrypto_spake2p_p256_get_ZV(z, v, w0, NULL, y, px, matter_spake2p_M, l), 0);
	t_vec("verifier Z", z, 65u, tv->Z);
	t_vec("verifier V", v, 65u, tv->V);

	n = tt_put(tt, n, (const uint8_t *)tv->context, strlen(tv->context));
	n = tt_put(tt, n, (const uint8_t *)tv->prover_identity, strlen(tv->prover_identity));
	n = tt_put(tt, n, (const uint8_t *)tv->verifier_identity, strlen(tv->verifier_identity));
	n = tt_put(tt, n, matter_spake2p_M, 65u);
	n = tt_put(tt, n, matter_spake2p_N, 65u);
	n = tt_put(tt, n, px, 65u);
	n = tt_put(tt, n, py, 65u);
	n = tt_put(tt, n, z, 65u);
	n = tt_put(tt, n, v, 65u);
	n = tt_put(tt, n, w0, 32u);
	T_EQ("p2", matter_spake2p_p2(tt, n, px, py, &res), MATTER_OK);
	t_vec("cA = MAC(KcA, Y)", res.ca, sizeof(res.ca), tv->mac_kca);
	t_vec("cB = MAC(KcB, X)", res.cb, sizeof(res.cb), tv->mac_kcb);
	t_vec("Ke", res.ke, sizeof(res.ke), tv->ke);
}

void test_spake2p_mbedtls(void)
{
	uint8_t w0[32], w1[32], x[32], y[32];
	uint8_t ws[40];
	uint8_t salt[32];
	uint8_t l[65], pa[65], pb[65], z[65], v[65], k[65];

	t_group("connectedhomeip draft-01 vectors");
	for (size_t i = 0u; i < sizeof(k_chip_tv) / sizeof(k_chip_tv[0]); i++) {
		chip_vector(&k_chip_tv[i]);
	}

	t_group("the gen_pase_vector.py exchange, both sides");
	(void)t_unhex(salt, K_SALT, sizeof(salt));
	T_EQ("w0w1", matter_spake2p_w0w1(VEC_PASSCODE, salt, sizeof(salt), VEC_ITERATIONS, w0, w1),
	     MATTER_OK);
	t_vec("w0 from the passcode", w0, sizeof(w0), K_W0);
	(void)t_unhex(l, K_L, sizeof(l));
	for (size_t i = 0u; i < sizeof(ws); i++) {
		ws[i] = (uint8_t)(0x01u + i);
	}
	ocrypto_spake2p_p256_reduce(x, ws, sizeof(ws));
	(void)t_unhex(ws, K_Y_WS, sizeof(ws));
	ocrypto_spake2p_p256_reduce(y, ws, sizeof(ws));
	T_EQ("pA", ocrypto_spake2p_p256_get_key_share(pa, w0, x, matter_spake2p_M), 0);
	t_vec("pA", pa, 65u, K_PA);
	T_EQ("pB", ocrypto_spake2p_p256_get_key_share(pb, w0, y, matter_spake2p_N), 0);
	t_vec("pB", pb, 65u, K_EXPECT_PB);
	T_EQ("prover ZV", ocrypto_spake2p_p256_get_ZV(z, v, w0, w1, x, pb, matter_spake2p_N, NULL),
	     0);
	t_vec("prover Z", z, 65u, K_Z);
	t_vec("prover V", v, 65u, K_V);
	T_EQ("verifier ZV", ocrypto_spake2p_p256_get_ZV(z, v, w0, NULL, y, pa, matter_spake2p_M, l),
	     0);
	t_vec("verifier Z", z, 65u, K_Z);
	t_vec("verifier V", v, 65u, K_V);

	t_group("check_key refuses what is not a point");
	memcpy(k, pa, sizeof(k));
	k[0] = 0x02u;
	T_EQ("compressed marker", ocrypto_spake2p_p256_check_key(k), -1);
	memcpy(k, pa, sizeof(k));
	k[64] ^= 0x01u;
	T_EQ("off the curve", ocrypto_spake2p_p256_check_key(k), -1);
	memset(k, 0, sizeof(k));
	k[0] = 0x04u;
	T_EQ("all zero", ocrypto_spake2p_p256_check_key(k), -1);
	memset(k, 0xFF, sizeof(k));
	k[0] = 0x04u;
	T_EQ("coordinates past p", ocrypto_spake2p_p256_check_key(k), -1);
	T_EQ("key share refuses an off-curve element",
	     ocrypto_spake2p_p256_get_key_share(z, w0, x, k), -1);
	T_EQ("ZV refuses an off-curve share",
	     ocrypto_spake2p_p256_get_ZV(z, v, w0, NULL, y, k, matter_spake2p_M, l), -1);
	T_EQ("ZV refuses both w1 and L",
	     ocrypto_spake2p_p256_get_ZV(z, v, w0, w1, y, pa, matter_spake2p_M, l), -1);
	T_EQ("ZV refuses neither w1 nor L",
	     ocrypto_spake2p_p256_get_ZV(z, v, w0, NULL, y, pa, matter_spake2p_M, NULL), -1);
	memset(k, 0, 32u);
	T_EQ("a zero scalar", ocrypto_spake2p_p256_get_key_share(z, w0, k, matter_spake2p_M), -1);

	t_group("a fresh prover against the real responder");
	{
		struct matter_pase_responder r;
		struct matter_pase_verifier ver;
		struct matter_pase_pake1 p1;
		struct matter_pase_pake2 p2;
		struct matter_pase_pake3 p3;
		struct matter_spake2p_result res;
		struct matter_session_keys keys;
		uint8_t rr[MATTER_PASE_RANDOM_LEN];
		uint8_t req[128];
		uint8_t resp[MATTER_PASE_REPLY_MAX];
		uint8_t out[MATTER_PASE_REPLY_MAX];
		uint8_t msg[MATTER_PASE_REPLY_MAX];
		uint8_t context[MATTER_SPAKE_HASH_LEN];
		uint8_t tt[MATTER_SPAKE_TT_LEN];
		size_t req_len, resp_len = 0u, out_len = 0u, n = 0u, tt_len = sizeof(tt);
		uint8_t opcode = 0u;

		/* Entropy no recording has seen, on both sides. */
		for (size_t i = 0u; i < sizeof(ws); i++) {
			ws[i] = (uint8_t)(0x51u + 3u * i);
		}
		ocrypto_spake2p_p256_reduce(x, ws, sizeof(ws));
		for (size_t i = 0u; i < sizeof(ws); i++) {
			ws[i] = (uint8_t)(0xA7u ^ (5u * i));
		}
		for (size_t i = 0u; i < sizeof(rr); i++) {
			rr[i] = (uint8_t)(0x30u + i);
		}

		memset(&ver, 0, sizeof(ver));
		memcpy(ver.w0, w0, sizeof(ver.w0));
		memcpy(ver.l, l, sizeof(ver.l));
		memcpy(ver.salt, salt, sizeof(salt));
		ver.salt_len = (uint8_t)sizeof(salt);
		ver.iterations = VEC_ITERATIONS;
		T_EQ("responder init", matter_pase_responder_init(&r, &ver, 0x4321u, rr, ws),
		     MATTER_OK);

		req_len = (size_t)t_unhex(req, K_APPLE_REQ, sizeof(req));
		T_EQ("request", matter_pase_responder_recv(&r, MATTER_PASE_OP_PBKDF_REQ, req, req_len,
							   resp, sizeof(resp), &resp_len, &opcode),
		     MATTER_OK);
		T_EQ("PBKDFParamResponse", opcode, MATTER_PASE_OP_PBKDF_RESP);
		T_EQ("prover context",
		     matter_spake2p_context(req, req_len, resp, resp_len, context), MATTER_OK);

		T_EQ("prover pA", ocrypto_spake2p_p256_get_key_share(pa, w0, x, matter_spake2p_M), 0);
		memcpy(p1.pa, pa, sizeof(p1.pa));
		(void)matter_pase_pake1_encode(&p1, msg, sizeof(msg), &n);
		T_EQ("Pake1", matter_pase_responder_recv(&r, MATTER_PASE_OP_PAKE1, msg, n, out,
							 sizeof(out), &out_len, &opcode),
		     MATTER_OK);
		T_EQ("Pake2", opcode, MATTER_PASE_OP_PAKE2);
		T_EQ("Pake2 decodes", matter_pase_pake2_decode(out, out_len, &p2), MATTER_OK);

		T_EQ("prover ZV",
		     ocrypto_spake2p_p256_get_ZV(z, v, w0, w1, x, p2.pb, matter_spake2p_N, NULL), 0);
		T_EQ("prover transcript",
		     matter_spake2p_transcript(context, pa, p2.pb, z, v, w0, tt, &tt_len), MATTER_OK);
		T_EQ("prover p2", matter_spake2p_p2(tt, tt_len, pa, p2.pb, &res), MATTER_OK);
		T_OK("the responder's cB is the one the prover expects",
		     matter_spake2p_verify(res.cb, p2.cb));

		memcpy(p3.ca, res.ca, sizeof(p3.ca));
		(void)matter_pase_pake3_encode(&p3, msg, sizeof(msg), &n);
		T_EQ("Pake3", matter_pase_responder_recv(&r, MATTER_PASE_OP_PAKE3, msg, n, out,
							 sizeof(out), &out_len, &opcode),
		     MATTER_OK);
		T_EQ("done", matter_pase_responder_state(&r), MATTER_PASE_ST_DONE);

		T_EQ("prover session keys",
		     matter_derive_session_keys(res.ke, MATTER_SPAKE_HALF_LEN, NULL, 0u, false, &keys),
		     MATTER_OK);
		T_OK("same i2r", memcmp(keys.i2r, r.keys.i2r, sizeof(keys.i2r)) == 0);
		T_OK("same r2i", memcmp(keys.r2i, r.keys.r2i, sizeof(keys.r2i)) == 0);
		T_OK("same attestation challenge",
		     memcmp(keys.attestation_challenge, r.keys.attestation_challenge,
			    sizeof(keys.attestation_challenge)) == 0);
	}
}

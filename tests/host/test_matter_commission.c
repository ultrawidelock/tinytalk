/* SPDX-License-Identifier: ISC */

/*
 * The node's boot path, on the host port: the real matter_commission_init()
 * and fabric store over tests/host/host_port.c's RAM key-value store, so a
 * "reboot" is a second init over what the first one left stored.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_commission.h>
#include <tinytalk/matter_exchange.h>
#include <tinytalk/matter_fab_store.h>
#include <tinytalk/matter_msg.h>
#include <tinytalk/matter_pase.h>
#include <tinytalk/matter_thread.h>
#include <tinytalk/tm_door_lock.h>
#include <tinytalk/tm_kv.h>

#include "host_port.h"
#include "test.h"

/* The sample's Kconfig defaults (passcode 58490394). */
static const struct matter_commission_config k_cfg = {
	.vendor_id = 0xFFF1u,
	.product_id = 0x8001u,
	.verifier_hex = "ca92f10ad437760cc8948aefe2d09f142bc1a363824a0079a63e6df097575bb5"
			"043609715ad65a53cd3c18a0f80011bf09dbbfbd9453c2b00eed286f5275ecaae6"
			"0a2e896837995232334c319994d790ee2d09fe5cb4a229503234f8479eb3d308",
	.salt_hex = "04f7398d5b49b5b5db8a5e61c8aece1d1a230e3b9085199d854ef034fd30a89b",
	.iterations = 20000u,
	.product_name = "tinytalk door lock",
	.hardware_version = 1u,
	.software_version = 1u,
	.endpoints = &tm_door_lock_endpoint,
	.n_endpoints = 1u,
};

/* LockState as the Door Lock stores it, which is what a reboot reads back. */
static int store_lock_state(uint8_t lock_state)
{
	return tm_kv_set(TM_KV_KEY_MATTER_DL_LOCK_STATE, &lock_state, sizeof(lock_state));
}

/* An iPhone's PBKDFParamRequest payload; see test_matter_pase_sm.c. */
static const char *const K_APPLE_REQ =
	"15300120a882bce8bfdeab50e04ac596bfc05024db5902b7512ed9b278cfaacc125230122502b6e424030028"
	"0435052501f40125022c012503a00f24041224050b2606000004012407011818";

/* The PBKDFParamRequest as it arrives over UDP: unsecured, initiator, reliable. */
static size_t pbkdf_datagram(uint8_t *buf, size_t cap, uint32_t counter)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	uint8_t payload[128];
	size_t mh_len = 0u;
	size_t ph_len = 0u;
	int n = t_unhex(payload, K_APPLE_REQ, sizeof(payload));

	memset(&mh, 0, sizeof(mh));
	mh.flags = MATTER_MSG_DSIZ_NONE | MATTER_MSG_FLAG_S;
	mh.source_node_id = 0x6557F7497EA9A507ULL;
	mh.session_id = MATTER_SESSION_ID_UNSECURED;
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = counter;
	memset(&ph, 0, sizeof(ph));
	ph.exchange_flags = (uint8_t)(MATTER_EX_FLAG_I | MATTER_EX_FLAG_R);
	ph.opcode = MATTER_PASE_OP_PBKDF_REQ;
	ph.exchange_id = 0x1234u;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;
	(void)matter_msg_header_encode(&mh, buf, cap, &mh_len);
	(void)matter_proto_header_encode(&ph, buf + mh_len, cap - mh_len, &ph_len);
	memcpy(buf + mh_len + ph_len, payload, (size_t)n);
	return mh_len + ph_len + (size_t)n;
}

static int s_sent;

static int count_send(void *ctx, const uint8_t *msg, size_t len)
{
	(void)ctx;
	(void)msg;
	(void)len;
	s_sent++;
	return MATTER_OK;
}

/* A committed fabric and its Thread network, as commissioning leaves them. */
static int store_one_fabric(void)
{
	static struct matter_device_info info;

	memset(&info, 0, sizeof(info));
	info.fabrics[0].index = 1u;
	info.fabrics[0].have_root = true;
	info.fabrics[0].fabric_id = 0x93148f13u;
	info.fabrics[0].node_id = 0xd2451b37u;
	info.fabrics[0].root_public_key[0] = 0x04u;
	info.thread_dataset_len = 16u;
	info.have_thread_xpanid = true;
	return matter_fab_commit(&info, MATTER_FABRIC_STORE_COMMIT_ATTEMPT, 0u, NULL, 0u);
}

static void boot(void)
{
	g_host_lock_state = 0u;
	g_host_lock_state_calls = 0;
	T_EQ("the node starts", matter_commission_init(&k_cfg), 0);
}

void test_matter_commission(void)
{
	t_group("init refuses a missing configuration");
	T_OK("no config", matter_commission_init(NULL) < 0);

	t_group("a first boot puts the bolt at Locked");
	(void)tm_kv_erase_all();
	boot();
	T_EQ("the bolt is told once", g_host_lock_state_calls, 1);
	T_EQ("and told Locked", g_host_lock_state, MATTER_DL_LOCK_STATE_LOCKED);
	T_OK("with no fabric, the node is commissionable", !matter_commission_has_fabric());

	t_group("LockState comes back after a reboot");
	T_EQ("Unlocked is stored", store_lock_state(MATTER_DL_LOCK_STATE_UNLOCKED), 0);
	boot();
	T_EQ("the bolt is told Unlocked", g_host_lock_state, MATTER_DL_LOCK_STATE_UNLOCKED);
	T_EQ("Locked is stored", store_lock_state(MATTER_DL_LOCK_STATE_LOCKED), 0);
	boot();
	T_EQ("the bolt is told Locked", g_host_lock_state, MATTER_DL_LOCK_STATE_LOCKED);

	t_group("a fabric erase leaves the bolt where it is");
	T_EQ("Unlocked is stored", store_lock_state(MATTER_DL_LOCK_STATE_UNLOCKED), 0);
	T_EQ("the fabrics are erased", matter_fab_erase(), 0);
	boot();
	T_EQ("the bolt is still told Unlocked", g_host_lock_state, MATTER_DL_LOCK_STATE_UNLOCKED);

	t_group("erasing the Door Lock attributes forgets it");
	T_EQ("the attributes are erased", tm_door_lock_erase(), 0);
	boot();
	T_EQ("the bolt is back at Locked", g_host_lock_state, MATTER_DL_LOCK_STATE_LOCKED);

	t_group("PASE over IP needs a commissioning window once a fabric exists");
	{
		uint8_t msg[256];
		uint8_t reply[MATTER_THREAD_REPLY_MAX];
		size_t n;

		T_EQ("the fabrics are erased", matter_fab_erase(), 0);
		T_EQ("a fabric is stored", store_one_fabric(), 0);
		boot();
		T_OK("the node comes back commissioned", matter_commission_has_fabric());
		T_OK("with no window open", !matter_commission_window_open());

		s_sent = 0;
		n = pbkdf_datagram(msg, sizeof(msg), 1u);
		T_EQ("a PBKDFParamRequest gets no reply",
		     matter_thread_on_datagram(msg, n, reply, sizeof(reply), count_send, NULL), 0);
		T_EQ("and nothing is sent", s_sent, 0);

		T_EQ("a window opens", matter_commission_open_window(60u), 0);
		n = pbkdf_datagram(msg, sizeof(msg), 2u);
		T_OK("now it is answered",
		     matter_thread_on_datagram(msg, n, reply, sizeof(reply), count_send, NULL) > 0u);
		T_EQ("once", s_sent, 1);

		matter_commission_work(TM_WORK_ADMIN_EXPIRE);
		T_OK("the window closes", !matter_commission_window_open());
		n = pbkdf_datagram(msg, sizeof(msg), 3u);
		T_EQ("and the next request is refused again",
		     matter_thread_on_datagram(msg, n, reply, sizeof(reply), count_send, NULL), 0);
	}
}

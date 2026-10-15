/* SPDX-License-Identifier: ISC */

/*
 * The node's boot path, on the host port: the real matter_commission_init()
 * and fabric store over tests/host/host_port.c's RAM key-value store, so a
 * "reboot" is a second init over what the first one left stored.
 */
#include <tinymatter/matter_clusters.h>
#include <tinymatter/matter_commission.h>
#include <tinymatter/matter_fab_store.h>
#include <tinymatter/tm_kv.h>

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
};

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
	T_EQ("Unlocked is stored", matter_dl_lock_state_store(MATTER_DL_LOCK_STATE_UNLOCKED), 0);
	boot();
	T_EQ("the bolt is told Unlocked", g_host_lock_state, MATTER_DL_LOCK_STATE_UNLOCKED);
	T_EQ("Locked is stored", matter_dl_lock_state_store(MATTER_DL_LOCK_STATE_LOCKED), 0);
	boot();
	T_EQ("the bolt is told Locked", g_host_lock_state, MATTER_DL_LOCK_STATE_LOCKED);

	t_group("a fabric erase leaves the bolt where it is");
	T_EQ("Unlocked is stored", matter_dl_lock_state_store(MATTER_DL_LOCK_STATE_UNLOCKED), 0);
	T_EQ("the fabrics are erased", matter_fab_erase(), 0);
	boot();
	T_EQ("the bolt is still told Unlocked", g_host_lock_state, MATTER_DL_LOCK_STATE_UNLOCKED);

	t_group("erasing the Door Lock attributes forgets it");
	T_EQ("the attributes are erased", matter_dl_attr_erase(), 0);
	boot();
	T_EQ("the bolt is back at Locked", g_host_lock_state, MATTER_DL_LOCK_STATE_LOCKED);
}

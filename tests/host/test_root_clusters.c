/* SPDX-License-Identifier: ISC */

/*
 * The root clusters the Root Node device type requires and the node serves
 * from a table: General Diagnostics. Driven through the same matter_im_server
 * the Interaction Model calls.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_tlv.h>
#include <tinytalk/tm_kv.h>
#include <tinytalk/tm_platform.h>

#include "test.h"
#include "test_matter_thread_stub.h"

/* An operational administrator on fabric 1, through the CASE admin subject. */
static void admin_info(struct matter_device_info *info)
{
	memset(info, 0, sizeof(*info));
	info->fabrics[0].index = 1u;
	info->fabrics[0].fabric_id = 1u;
	info->fabrics[0].node_id = 1u;
	info->fabrics[0].case_admin_subject = 0x77u;
	info->committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
	info->accessing_fabric_index = 1u;
	info->accessing_node_id = 0x77u;
}

/* Encode one root attribute into @p out; its length. */
static size_t read_root(struct matter_im_server *srv, uint32_t cl, uint32_t attr, uint8_t *out,
			size_t cap)
{
	struct matter_tlv_writer w;

	matter_tlv_writer_init(&w, out, cap);
	srv->value(srv->ctx, MATTER_ENDPOINT_ROOT, cl, attr, false, &w, MATTER_TLV_ANON);
	return w.len;
}

static uint64_t read_root_u64(struct matter_im_server *srv, uint32_t cl, uint32_t attr)
{
	struct matter_tlv_reader r;
	uint8_t out[32];
	uint64_t v = 0xFFFFFFFFu;
	size_t n = read_root(srv, cl, attr, out, sizeof(out));

	matter_tlv_reader_init(&r, out, n);
	if (matter_tlv_next(&r) == MATTER_OK) {
		(void)matter_tlv_get_u64(&r, &v);
	}
	return v;
}

/* A list of unsigned ids; how many were read. */
static size_t read_root_ids(struct matter_im_server *srv, uint32_t cl, uint32_t attr,
			    uint64_t *ids, size_t cap)
{
	struct matter_tlv_reader r;
	uint8_t out[128];
	size_t n = read_root(srv, cl, attr, out, sizeof(out));
	size_t k = 0u;

	matter_tlv_reader_init(&r, out, n);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return 0u;
	}
	while (k < cap && matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_get_u64(&r, &ids[k]) == MATTER_OK) {
			k++;
		}
	}
	return k;
}

static bool listed(const uint64_t *ids, size_t n, uint64_t id)
{
	for (size_t i = 0u; i < n; i++) {
		if (ids[i] == id) {
			return true;
		}
	}
	return false;
}

static uint8_t root_invoke(struct matter_im_server *srv, uint32_t cl, uint32_t cmd,
			   const uint8_t *fields, size_t len, uint32_t *response)
{
	struct matter_im_invoke inv;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_ROOT;
	inv.cluster = cl;
	inv.command = cmd;
	inv.fields = fields;
	inv.fields_len = len;
	inv.has_fields = fields != NULL;
	*response = MATTER_IM_NO_RESPONSE;
	return srv->command(srv->ctx, &inv, response);
}

static void t_general_diagnostics(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint64_t ids[16];
	uint8_t out[256];
	size_t n;

	admin_info(&info);
	matter_clusters_init(&srv, &info);

	t_group("General Diagnostics is on the root");
	{
		n = read_root_ids(&srv, MATTER_CLUSTER_DESCRIPTOR, MATTER_ATTR_DESC_SERVER_LIST,
				  ids, 16u);
		T_OK("in ServerList", listed(ids, n, MATTER_CLUSTER_GENERAL_DIAGNOSTICS));
		T_OK("has_cluster agrees",
		     srv.has_cluster(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_GENERAL_DIAGNOSTICS));
		T_EQ("ClusterRevision 2",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
					 MATTER_ATTR_CLUSTER_REVISION),
		     2L);
		T_EQ("FeatureMap 0",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
					 MATTER_ATTR_FEATURE_MAP),
		     0L);
		n = read_root_ids(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				  MATTER_ATTR_ATTRIBUTE_LIST, ids, 16u);
		T_OK("AttributeList has the four and the globals",
		     n == 9u && listed(ids, n, MATTER_ATTR_GD_NETWORK_INTERFACES) &&
			     listed(ids, n, MATTER_ATTR_GD_REBOOT_COUNT) &&
			     listed(ids, n, MATTER_ATTR_GD_UP_TIME) &&
			     listed(ids, n, MATTER_ATTR_GD_TEST_EVENT_TRIGGERS) &&
			     listed(ids, n, MATTER_ATTR_ATTRIBUTE_LIST));
		n = read_root_ids(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				  MATTER_ATTR_ACCEPTED_CMD_LIST, ids, 16u);
		T_OK("accepts TestEventTrigger and TimeSnapshot",
		     n == 2u && ids[0] == MATTER_CMD_GD_TEST_EVENT_TRIGGER &&
			     ids[1] == MATTER_CMD_GD_TIME_SNAPSHOT);
		n = read_root_ids(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				  MATTER_ATTR_GENERATED_CMD_LIST, ids, 16u);
		T_OK("generates TimeSnapshotResponse",
		     n == 1u && ids[0] == MATTER_CMD_GD_TIME_SNAPSHOT_RESPONSE);
		T_EQ("an attribute it does not have",
		     srv.status(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				0x0005u),
		     MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE);
	}

	t_group("RebootCount counts boots and persists");
	{
		uint16_t stored = 0u;
		size_t len = sizeof(stored);

		(void)tm_kv_erase_all();
		matter_general_diagnostics_boot();
		T_EQ("first boot", (long)read_root_u64(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
						       MATTER_ATTR_GD_REBOOT_COUNT),
		     1L);
		matter_general_diagnostics_boot();
		T_EQ("second boot", (long)read_root_u64(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
							MATTER_ATTR_GD_REBOOT_COUNT),
		     2L);
		T_OK("stored",
		     tm_kv_get(TM_KV_KEY_MATTER_REBOOT_COUNT, &stored, &len) == TM_KV_OK &&
			     stored == 2u);
		{
			uint64_t before = (uint64_t)tm_uptime_ms() / 1000u;
			uint64_t up = read_root_u64(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
						    MATTER_ATTR_GD_UP_TIME);
			uint64_t after = (uint64_t)tm_uptime_ms() / 1000u;

			T_OK("UpTime is seconds since boot", up >= before && up <= after);
		}
		n = read_root(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
			      MATTER_ATTR_GD_TEST_EVENT_TRIGGERS, out, sizeof(out));
		T_OK("TestEventTriggersEnabled is false", n == 1u && out[0] == 0x08u);
	}

	t_group("NetworkInterfaces is the one Thread interface");
	{
		struct matter_tlv_reader r;
		const uint8_t *bytes = NULL;
		size_t blen = 0u;
		uint64_t v = 0u;
		bool b = false;
		int entries = 0;
		int v6 = 0;
		static const uint8_t k_ext[8] = {1, 2, 3, 4, 5, 6, 7, 8};

		test_matter_thread_stub_reset();
		g_thread_iface.attached = true;
		memcpy(g_thread_iface.ext_addr, k_ext, sizeof(k_ext));
		g_thread_iface.n_addrs = 2u;
		g_thread_iface.addrs[0][0] = 0xFDu;
		g_thread_iface.addrs[1][0] = 0xFEu;
		n = read_root(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
			      MATTER_ATTR_GD_NETWORK_INTERFACES, out, sizeof(out));
		matter_tlv_reader_init(&r, out, n);
		T_OK("a list", matter_tlv_next(&r) == MATTER_OK && matter_tlv_enter(&r) == MATTER_OK);
		while (matter_tlv_next(&r) == MATTER_OK) {
			entries++;
			T_OK("of structs", matter_tlv_enter(&r) == MATTER_OK);
			while (matter_tlv_next(&r) == MATTER_OK) {
				matter_tlv_tag_t tag = matter_tlv_tag(&r);

				if (tag == MATTER_TLV_CTX(1u)) {
					T_OK("IsOperational follows the attach",
					     matter_tlv_get_bool(&r, &b) == MATTER_OK && b);
				} else if (tag == MATTER_TLV_CTX(4u)) {
					T_OK("HardwareAddress is the extended address",
					     matter_tlv_get_bytes(&r, &bytes, &blen) == MATTER_OK &&
						     blen == 8u && memcmp(bytes, k_ext, 8u) == 0);
				} else if (tag == MATTER_TLV_CTX(6u)) {
					T_OK("IPv6Addresses a list",
					     matter_tlv_enter(&r) == MATTER_OK);
					while (matter_tlv_next(&r) == MATTER_OK) {
						if (matter_tlv_get_bytes(&r, &bytes, &blen) ==
							    MATTER_OK &&
						    blen == 16u) {
							v6++;
						}
					}
					(void)matter_tlv_exit(&r);
				} else if (tag == MATTER_TLV_CTX(7u)) {
					T_OK("Type Thread",
					     matter_tlv_get_u64(&r, &v) == MATTER_OK && v == 4u);
				}
			}
			(void)matter_tlv_exit(&r);
		}
		T_EQ("one entry", entries, 1);
		T_EQ("with both addresses", v6, 2);
	}

	t_group("TestEventTrigger is refused, TimeSnapshot answered");
	{
		/* EnableKey 16 zero bytes, EventTrigger 1. */
		static const uint8_t k_trigger[] = {
			0x15u, 0x30u, 0x00u, 0x10u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0x24u, 0x01u, 0x01u, 0x18u,
		};
		static const uint8_t k_empty[] = {0x15u, 0x18u};
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		uint32_t response;
		uint64_t ms = 0u;

		T_EQ("no key configured: CONSTRAINT_ERROR",
		     root_invoke(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				 MATTER_CMD_GD_TEST_EVENT_TRIGGER, k_trigger, sizeof(k_trigger),
				 &response),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("missing fields: INVALID_COMMAND",
		     root_invoke(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				 MATTER_CMD_GD_TEST_EVENT_TRIGGER, k_empty, sizeof(k_empty),
				 &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("TimeSnapshot succeeds",
		     root_invoke(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				 MATTER_CMD_GD_TIME_SNAPSHOT, NULL, 0u, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("with TimeSnapshotResponse", (long)response,
		     (long)MATTER_CMD_GD_TIME_SNAPSHOT_RESPONSE);
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.command_fields(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				   response, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("a struct", matter_tlv_next(&r) == MATTER_OK && matter_tlv_enter(&r) == MATTER_OK);
		T_OK("SystemTimeMs first", matter_tlv_next(&r) == MATTER_OK &&
						   matter_tlv_tag(&r) == MATTER_TLV_CTX(0u) &&
						   matter_tlv_get_u64(&r, &ms) == MATTER_OK);
		T_OK("PosixTimeMs null", matter_tlv_next(&r) == MATTER_OK &&
						 matter_tlv_tag(&r) == MATTER_TLV_CTX(1u) &&
						 matter_tlv_element_type(&r) == 0x14u);

		info.accessing_node_id = 0u;
		T_EQ("not over PASE",
		     root_invoke(&srv, MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
				 MATTER_CMD_GD_TIME_SNAPSHOT, NULL, 0u, &response),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		info.accessing_node_id = 0x77u;
	}
}

void test_root_clusters(void)
{
	t_general_diagnostics();
}

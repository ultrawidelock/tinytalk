/* SPDX-License-Identifier: ISC */

/*
 * The root clusters the Root Node device type requires and the node serves
 * from a table: General Diagnostics and Group Key Management. Driven through the same matter_im_server
 * the Interaction Model calls.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_tlv.h>
#include <tinytalk/tm_door_lock.h>
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

static uint8_t root_write(struct matter_im_server *srv, uint32_t cl, uint32_t attr,
			  const uint8_t *data, size_t len)
{
	struct matter_im_path path;

	memset(&path, 0, sizeof(path));
	path.endpoint = MATTER_ENDPOINT_ROOT;
	path.have_endpoint = true;
	path.cluster = cl;
	path.have_cluster = true;
	path.attribute = attr;
	path.have_attribute = true;
	return srv->write(srv->ctx, &path, data, len);
}

static void t_group_keys(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint64_t ids[16];
	uint8_t out[256];
	size_t n;

	admin_info(&info);
	matter_clusters_init(&srv, &info);

	t_group("Group Key Management is on the root");
	{
		n = read_root_ids(&srv, MATTER_CLUSTER_DESCRIPTOR, MATTER_ATTR_DESC_SERVER_LIST,
				  ids, 16u);
		T_OK("in ServerList", listed(ids, n, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT));
		T_EQ("ClusterRevision 2",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
					 MATTER_ATTR_CLUSTER_REVISION),
		     2L);
		T_EQ("FeatureMap 0, no CacheAndSync",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
					 MATTER_ATTR_FEATURE_MAP),
		     0L);
		T_EQ("MaxGroupsPerFabric 0",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
					 MATTER_ATTR_GKM_MAX_GROUPS),
		     0L);
		T_EQ("MaxGroupKeysPerFabric 1, the IPK",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
					 MATTER_ATTR_GKM_MAX_KEYS),
		     1L);
		n = read_root(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
			      MATTER_ATTR_GKM_GROUP_KEY_MAP, out, sizeof(out));
		T_OK("GroupKeyMap empty", n == 2u && out[0] == 0x16u && out[1] == 0x18u);
		n = read_root(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
			      MATTER_ATTR_GKM_GROUP_TABLE, out, sizeof(out));
		T_OK("GroupTable empty", n == 2u && out[0] == 0x16u && out[1] == 0x18u);
		n = read_root_ids(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				  MATTER_ATTR_ACCEPTED_CMD_LIST, ids, 16u);
		T_OK("accepts the four KeySet commands", n == 4u && ids[0] == 0u && ids[3] == 4u);
		n = read_root_ids(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				  MATTER_ATTR_GENERATED_CMD_LIST, ids, 16u);
		T_OK("generates the two responses", n == 2u && ids[0] == 2u && ids[1] == 5u);
	}

	t_group("GroupKeyMap takes an empty list and nothing else");
	{
		static const uint8_t k_empty[] = {0x16u, 0x18u};
		/* One GroupKeyMapStruct: GroupId 1, GroupKeySetID 1. */
		static const uint8_t k_entry[] = {0x16u, 0x15u, 0x24u, 0x01u, 0x01u,
						  0x24u, 0x02u, 0x01u, 0x18u, 0x18u};

		T_EQ("empty", root_write(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
					  MATTER_ATTR_GKM_GROUP_KEY_MAP, k_empty, sizeof(k_empty)),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("an entry", root_write(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
					     MATTER_ATTR_GKM_GROUP_KEY_MAP, k_entry, sizeof(k_entry)),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("an appended entry", root_write(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
						      MATTER_ATTR_GKM_GROUP_KEY_MAP, k_entry + 1,
						      sizeof(k_entry) - 2u),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("GroupTable is read-only",
		     root_write(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				MATTER_ATTR_GKM_GROUP_TABLE, k_empty, sizeof(k_empty)),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);
	}

	t_group("the KeySet commands answer for the IPK alone");
	{
		static const uint8_t k_id0[] = {0x15u, 0x24u, 0x00u, 0x00u, 0x18u};
		static const uint8_t k_id1[] = {0x15u, 0x24u, 0x00u, 0x01u, 0x18u};
		/* KeySetWrite with GroupKeySet { GroupKeySetID }. */
		static const uint8_t k_write0[] = {0x15u, 0x35u, 0x00u, 0x24u, 0x00u, 0x00u,
						   0x18u, 0x18u};
		static const uint8_t k_write1[] = {0x15u, 0x35u, 0x00u, 0x24u, 0x00u, 0x01u,
						   0x18u, 0x18u};
		static const uint8_t k_none[] = {0x15u, 0x18u};
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		uint32_t response;
		uint64_t v = 0xFFu;

		T_EQ("KeySetWrite of the IPK", root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
							    MATTER_CMD_GKM_KEY_SET_WRITE, k_write0,
							    sizeof(k_write0), &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("KeySetWrite of another set: no room",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_WRITE, k_write1, sizeof(k_write1),
				 &response),
		     MATTER_IM_STATUS_RESOURCE_EXHAUSTED);
		T_EQ("KeySetWrite without a set", root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
							       MATTER_CMD_GKM_KEY_SET_WRITE, k_none,
							       sizeof(k_none), &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("KeySetRead of an unknown set",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_READ, k_id1, sizeof(k_id1), &response),
		     MATTER_IM_STATUS_NOT_FOUND);
		T_EQ("KeySetRemove of the IPK",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_REMOVE, k_id0, sizeof(k_id0), &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("KeySetRemove of an unknown set",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_REMOVE, k_id1, sizeof(k_id1), &response),
		     MATTER_IM_STATUS_NOT_FOUND);

		T_EQ("KeySetRead of the IPK",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_READ, k_id0, sizeof(k_id0), &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("answers KeySetReadResponse", (long)response,
		     (long)MATTER_CMD_GKM_KEY_SET_READ_RESPONSE);
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.command_fields(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				   response, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("GroupKeySet", matter_tlv_next(&r) == MATTER_OK &&
					    matter_tlv_enter(&r) == MATTER_OK &&
					    matter_tlv_next(&r) == MATTER_OK &&
					    matter_tlv_enter(&r) == MATTER_OK);
		T_OK("id 0", matter_tlv_next(&r) == MATTER_OK &&
				     matter_tlv_get_u64(&r, &v) == MATTER_OK && v == 0u);
		T_OK("TrustFirst", matter_tlv_next(&r) == MATTER_OK &&
					   matter_tlv_get_u64(&r, &v) == MATTER_OK && v == 0u);
		T_OK("no key material", matter_tlv_next(&r) == MATTER_OK &&
						matter_tlv_element_type(&r) == 0x14u);

		T_EQ("KeySetReadAllIndices",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_READ_ALL, k_none, sizeof(k_none), &response),
		     MATTER_IM_STATUS_SUCCESS);
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.command_fields(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				   response, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		v = 0xFFu;
		T_OK("lists the IPK alone",
		     matter_tlv_next(&r) == MATTER_OK && matter_tlv_enter(&r) == MATTER_OK &&
			     matter_tlv_next(&r) == MATTER_OK && matter_tlv_enter(&r) == MATTER_OK &&
			     matter_tlv_next(&r) == MATTER_OK &&
			     matter_tlv_get_u64(&r, &v) == MATTER_OK && v == 0u &&
			     matter_tlv_next(&r) == MATTER_END);

		info.accessing_node_id = 0u;
		T_EQ("not over PASE",
		     root_invoke(&srv, MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
				 MATTER_CMD_GKM_KEY_SET_READ_ALL, k_none, sizeof(k_none), &response),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		info.accessing_node_id = 0x77u;
	}
}

/* What each cluster on endpoint 0 must say about itself. */
struct want_globals {
	uint32_t cluster;
	uint64_t revision;
	uint64_t features;
	size_t accepted;
	size_t generated;
};

static const struct want_globals k_want[] = {
	{ MATTER_CLUSTER_DESCRIPTOR, 3u, 0u, 0u, 0u },
	{ MATTER_CLUSTER_ACCESS_CONTROL, 2u, 0u, 0u, 0u },
	{ MATTER_CLUSTER_BASIC_INFORMATION, 5u, 0u, 0u, 0u },
	{ MATTER_CLUSTER_GENERAL_COMMISSIONING, 2u, 0u, 3u, 3u },
	{ MATTER_CLUSTER_NETWORK_COMMISSIONING, 2u, MATTER_NC_FEATURE_THREAD, 5u, 3u },
	{ MATTER_CLUSTER_GENERAL_DIAGNOSTICS, 2u, 0u, 2u, 1u },
	{ MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, 2u, 0u, 8u, 4u },
	{ MATTER_CLUSTER_ADMIN_COMMISSIONING, 1u, 1u, 3u, 0u },
	{ MATTER_CLUSTER_GROUP_KEY_MANAGEMENT, 2u, 0u, 4u, 2u },
};

static const uint32_t k_globals[] = {
	MATTER_ATTR_FEATURE_MAP,       MATTER_ATTR_CLUSTER_REVISION, MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST, MATTER_ATTR_GENERATED_CMD_LIST,
};

/* Encode one attribute anywhere; how many top-level elements it was. */
static size_t value_len(struct matter_im_server *srv, uint16_t ep, uint32_t cl, uint32_t attr)
{
	struct matter_tlv_writer w;
	uint8_t out[512];

	matter_tlv_writer_init(&w, out, sizeof(out));
	srv->value(srv->ctx, ep, cl, attr, false, &w, MATTER_TLV_ANON);
	return w.len;
}

static void t_globals(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint64_t servers[16];
	uint64_t ids[32];
	size_t n_servers;

	T_EQ("the Door Lock endpoint is taken",
	     matter_clusters_set_endpoints(&tm_door_lock_endpoint, 1u), MATTER_OK);
	admin_info(&info);
	matter_clusters_init(&srv, &info);

	t_group("every cluster on endpoint 0 serves the five globals");
	{
		const uint32_t *attrs = NULL;
		size_t n_attrs;
		int complete = 0;

		n_servers = read_root_ids(&srv, MATTER_CLUSTER_DESCRIPTOR,
					  MATTER_ATTR_DESC_SERVER_LIST, servers, 16u);
		T_EQ("ServerList has the nine root clusters", (long)n_servers, 9L);
		for (size_t c = 0u; c < n_servers; c++) {
			int ok = 1;

			/* The wildcard's list, which is also AttributeList. */
			n_attrs = srv.list_attrs(srv.ctx, MATTER_ENDPOINT_ROOT,
						 (uint32_t)servers[c], &attrs);
			for (size_t g = 0u; g < 5u; g++) {
				bool in_list = false;

				for (size_t i = 0u; i < n_attrs; i++) {
					in_list = in_list || attrs[i] == k_globals[g];
				}
				if (!in_list ||
				    srv.status(srv.ctx, MATTER_ENDPOINT_ROOT, (uint32_t)servers[c],
					       k_globals[g]) != MATTER_IM_STATUS_SUCCESS ||
				    value_len(&srv, MATTER_ENDPOINT_ROOT, (uint32_t)servers[c],
					      k_globals[g]) == 0u) {
					ok = 0;
				}
			}
			complete += ok;
		}
		T_EQ("in its wildcard list, served and non-empty, on all nine", complete, 9);
	}

	t_group("each root cluster's globals have its own values");
	{
		for (size_t i = 0u; i < sizeof(k_want) / sizeof(k_want[0]); i++) {
			const struct want_globals *wg = &k_want[i];
			size_t n_attrs;
			const uint32_t *attrs = NULL;

			T_EQ("ClusterRevision",
			     (long)read_root_u64(&srv, wg->cluster, MATTER_ATTR_CLUSTER_REVISION),
			     (long)wg->revision);
			T_EQ("FeatureMap",
			     (long)read_root_u64(&srv, wg->cluster, MATTER_ATTR_FEATURE_MAP),
			     (long)wg->features);
			T_EQ("AcceptedCommandList",
			     (long)read_root_ids(&srv, wg->cluster, MATTER_ATTR_ACCEPTED_CMD_LIST,
						 ids, 32u),
			     (long)wg->accepted);
			T_EQ("GeneratedCommandList",
			     (long)read_root_ids(&srv, wg->cluster, MATTER_ATTR_GENERATED_CMD_LIST,
						 ids, 32u),
			     (long)wg->generated);
			n_attrs = srv.list_attrs(srv.ctx, MATTER_ENDPOINT_ROOT, wg->cluster, &attrs);
			T_EQ("AttributeList is the wildcard's list",
			     (long)read_root_ids(&srv, wg->cluster, MATTER_ATTR_ATTRIBUTE_LIST, ids,
						 32u),
			     (long)n_attrs);
		}
	}

	t_group("a wildcard over endpoint 0 reports every global");
	{
		static struct matter_im_read one;
		static uint8_t big[8192];
		uint16_t sent = 0u;
		uint16_t emitted = 0u;
		bool more = true;
		int chunks = 0;
		int globals = 0;
		size_t len = 0u;

		memset(&one, 0, sizeof(one));
		one.n_paths = 1u;
		one.paths[0].endpoint = MATTER_ENDPOINT_ROOT;
		one.paths[0].have_endpoint = true;
		while (more && chunks < 16) {
			T_EQ("a chunk encodes",
			     matter_im_report_data_chunk(&srv, &one, sent, big, 1180u, &len, &more,
							 &emitted, NULL),
			     MATTER_OK);
			sent = (uint16_t)(sent + emitted);
			chunks++;
			/* Count AttributePathIBs naming a global: the Attribute
			 * field, context tag 4, as a 2-byte unsigned. */
			for (size_t i = 0u; i + 4u < len; i++) {
				if (big[i] == 0x25u && big[i + 1u] == 0x04u && big[i + 3u] == 0xFFu &&
				    (big[i + 2u] == 0xF8u || big[i + 2u] == 0xF9u ||
				     big[i + 2u] == 0xFBu || big[i + 2u] == 0xFCu ||
				     big[i + 2u] == 0xFDu)) {
					globals++;
				}
			}
		}
		T_OK("in more than one chunk", chunks > 1 && !more);
		T_EQ("five globals for each of the nine clusters", globals, 45);
	}

	t_group("every endpoint's Descriptor serves the five globals");
	{
		{
			struct matter_tlv_writer w;
			uint8_t out[8];

			matter_tlv_writer_init(&w, out, sizeof(out));
			srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DESCRIPTOR,
				  MATTER_ATTR_CLUSTER_REVISION, false, &w, MATTER_TLV_ANON);
			T_OK("revision 3 on the lock endpoint too",
			     w.len == 2u && out[0] == 0x04u && out[1] == 0x03u);
		}
		T_EQ("ClusterRevision served", srv.status(srv.ctx, MATTER_ENDPOINT_LOCK,
							   MATTER_CLUSTER_DESCRIPTOR,
							   MATTER_ATTR_CLUSTER_REVISION),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("GeneratedCommandList served",
		     srv.status(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DESCRIPTOR,
				MATTER_ATTR_GENERATED_CMD_LIST),
		     MATTER_IM_STATUS_SUCCESS);
	}
}

/* Basic Information UniqueID as a string, into @p out. */
static size_t read_unique_id(struct matter_im_server *srv, char *out, size_t cap)
{
	struct matter_tlv_reader r;
	uint8_t buf[64];
	const char *str = NULL;
	size_t len = 0u;
	size_t n = read_root(srv, MATTER_CLUSTER_BASIC_INFORMATION, MATTER_ATTR_BASIC_UNIQUE_ID,
			     buf, sizeof(buf));

	matter_tlv_reader_init(&r, buf, n);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_get_utf8(&r, &str, &len) != MATTER_OK ||
	    len >= cap) {
		return 0u;
	}
	memcpy(out, str, len);
	out[len] = '\0';
	return len;
}

static bool upper_hex(const char *s, size_t len)
{
	for (size_t i = 0u; i < len; i++) {
		if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F'))) {
			return false;
		}
	}
	return true;
}

static void t_unique_id(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	char first[40];
	char again[40];
	char fresh[40];
	char serial[40];

	t_group("UniqueID is random per identity and survives a reboot");
	admin_info(&info);
	matter_clusters_init(&srv, &info);
	(void)tm_kv_erase_all();

	matter_clusters_unique_id_boot(&info);
	T_EQ("16 characters", (long)read_unique_id(&srv, first, sizeof(first)), 16L);
	T_OK("uppercase hex", upper_hex(first, 16u));

	memset(info.unique_id, 0, sizeof(info.unique_id));
	matter_clusters_unique_id_boot(&info);
	T_EQ("read back after a reboot", (long)read_unique_id(&srv, again, sizeof(again)), 16L);
	T_OK("the same id", strcmp(first, again) == 0);

	(void)tm_kv_erase_all();
	memset(info.unique_id, 0, sizeof(info.unique_id));
	matter_clusters_unique_id_boot(&info);
	T_EQ("drawn again after a wipe", (long)read_unique_id(&srv, fresh, sizeof(fresh)), 16L);
	T_OK("a new id", strcmp(first, fresh) != 0);

	memcpy(info.serial_number, "TT-0123456789ABCDEF", 20u);
	{
		struct matter_tlv_reader r;
		uint8_t buf[64];
		const char *str = NULL;
		size_t len = 0u;
		size_t n = read_root(&srv, MATTER_CLUSTER_BASIC_INFORMATION,
				     MATTER_ATTR_BASIC_SERIAL_NUMBER, buf, sizeof(buf));

		matter_tlv_reader_init(&r, buf, n);
		T_OK("SerialNumber stays the serial",
		     matter_tlv_next(&r) == MATTER_OK &&
			     matter_tlv_get_utf8(&r, &str, &len) == MATTER_OK && len < sizeof(serial) &&
			     memcmp(str, "TT-0123456789ABCDEF", len) == 0 && len == 19u);
	}
}

static void t_network_commissioning(void)
{
	static const uint8_t k_xpanid[8] = {0xDEu, 0xADu, 0x00u, 0xBEu, 0xEFu, 0x00u, 0xCAu, 0xFEu};
	struct matter_device_info info;
	struct matter_im_server srv;
	uint8_t out[512];
	uint32_t response;
	size_t n;

	admin_info(&info);
	matter_clusters_init(&srv, &info);
	test_matter_thread_stub_reset();

	t_group("NetworkCommissioning's last-attempt and Thread attributes");
	{
		n = read_root(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
			      MATTER_ATTR_NC_LAST_NETWORK_ID, out, sizeof(out));
		T_OK("LastNetworkID null before any attempt", n == 1u && out[0] == 0x14u);
		n = read_root(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
			      MATTER_ATTR_NC_LAST_CONNECT_ERROR, out, sizeof(out));
		T_OK("LastConnectErrorValue null", n == 1u && out[0] == 0x14u);
		T_EQ("SupportedThreadFeatures none",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
					 MATTER_ATTR_NC_SUPPORTED_THREAD_FEAT),
		     0L);
		g_thread_iface.thread_version = 5u;
		T_EQ("ThreadVersion from the stack",
		     (long)read_root_u64(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
					 MATTER_ATTR_NC_THREAD_VERSION),
		     5L);
	}

	t_group("ScanNetworks reports what the stack heard, without a fail-safe");
	{
		static const uint8_t k_empty[] = {0x15u, 0x18u};
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		uint64_t v = 0xFFu;
		int results = 0;

		info.attempt.active = false;
		g_thread_scan_n = 2u;
		g_thread_scan[0].pan_id = 0x1234u;
		memcpy(g_thread_scan[0].xpanid, k_xpanid, 8u);
		memcpy(g_thread_scan[0].name, "MyHome", 7u);
		g_thread_scan[0].channel = 25u;
		g_thread_scan[0].rssi = -48;
		g_thread_scan[1].pan_id = 0x5678u;
		T_EQ("ScanNetworks succeeds",
		     root_invoke(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				 MATTER_CMD_NC_SCAN_NETWORKS, k_empty, sizeof(k_empty), &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("with ScanNetworksResponse", (long)response,
		     (long)MATTER_CMD_NC_SCAN_NETWORKS_RESPONSE);
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.command_fields(srv.ctx, MATTER_ENDPOINT_ROOT,
				   MATTER_CLUSTER_NETWORK_COMMISSIONING, response, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("NetworkingStatus Success", matter_tlv_next(&r) == MATTER_OK &&
						 matter_tlv_enter(&r) == MATTER_OK &&
						 matter_tlv_next(&r) == MATTER_OK &&
						 matter_tlv_get_u64(&r, &v) == MATTER_OK && v == 0u);
		T_OK("ThreadScanResults", matter_tlv_next(&r) == MATTER_OK &&
						  matter_tlv_tag(&r) == MATTER_TLV_CTX(3u) &&
						  matter_tlv_enter(&r) == MATTER_OK);
		while (matter_tlv_next(&r) == MATTER_OK) {
			results++;
			if (results == 1) {
				T_OK("first is a struct", matter_tlv_enter(&r) == MATTER_OK);
				T_OK("PanId", matter_tlv_next(&r) == MATTER_OK &&
						      matter_tlv_get_u64(&r, &v) == MATTER_OK &&
						      v == 0x1234u);
				T_OK("ExtendedPanId big-endian",
				     matter_tlv_next(&r) == MATTER_OK &&
					     matter_tlv_get_u64(&r, &v) == MATTER_OK &&
					     v == 0xDEAD00BEEF00CAFEull);
				(void)matter_tlv_exit(&r);
			}
		}
		T_EQ("both networks", results, 2);

		g_thread_scan_rc = MATTER_E_STATE;
		T_EQ("a scan that cannot run still answers",
		     root_invoke(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				 MATTER_CMD_NC_SCAN_NETWORKS, k_empty, sizeof(k_empty), &response),
		     MATTER_IM_STATUS_SUCCESS);
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.command_fields(srv.ctx, MATTER_ENDPOINT_ROOT,
				   MATTER_CLUSTER_NETWORK_COMMISSIONING, response, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("with UnknownError and no results",
		     matter_tlv_next(&r) == MATTER_OK && matter_tlv_enter(&r) == MATTER_OK &&
			     matter_tlv_next(&r) == MATTER_OK &&
			     matter_tlv_get_u64(&r, &v) == MATTER_OK && v == 0x0Cu &&
			     matter_tlv_next(&r) == MATTER_END);
		g_thread_scan_rc = MATTER_OK;
	}

	t_group("ReorderNetwork with the one network there is");
	{
		uint8_t req[32];
		size_t len;
		struct matter_tlv_writer w;

		info.attempt.active = true;
		info.attempt.have_thread_candidate = true;
		memcpy(info.attempt.thread_xpanid, k_xpanid, 8u);
		for (int idx = 0; idx < 2; idx++) {
			matter_tlv_writer_init(&w, req, sizeof(req));
			(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), k_xpanid, 8u);
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), (uint64_t)idx);
			(void)matter_tlv_end_container(&w);
			len = w.len;
			T_EQ("answered with NetworkConfigResponse",
			     root_invoke(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
					 MATTER_CMD_NC_REORDER_NETWORK, req, len, &response),
			     MATTER_IM_STATUS_SUCCESS);
			T_EQ(idx == 0 ? "index 0: Success" : "index 1: OutOfRange",
			     (long)info.last_network_status, idx == 0 ? 0L : 1L);
		}
		info.attempt.thread_xpanid[0] ^= 1u;
		T_EQ("another network id",
		     root_invoke(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				 MATTER_CMD_NC_REORDER_NETWORK, req, len, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("is NetworkIDNotFound", (long)info.last_network_status, 3L);
		info.attempt.active = false;
		T_EQ("and needs the fail-safe",
		     root_invoke(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				 MATTER_CMD_NC_REORDER_NETWORK, req, len, &response),
		     MATTER_IM_STATUS_FAILSAFE_REQUIRED);
	}

	t_group("ConnectNetwork records LastNetworkID even when it fails");
	{
		uint8_t req[32];
		struct matter_tlv_writer w;
		static const uint8_t k_other[8] = {1, 2, 3, 4, 5, 6, 7, 8};

		info.attempt.active = true;
		matter_tlv_writer_init(&w, req, sizeof(req));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), k_other, 8u);
		(void)matter_tlv_end_container(&w);
		T_EQ("ConnectNetwork for an unknown network",
		     root_invoke(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				 MATTER_CMD_NC_CONNECT_NETWORK, req, w.len, &response),
		     MATTER_IM_STATUS_SUCCESS);
		n = read_root(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
			      MATTER_ATTR_NC_LAST_NETWORK_ID, out, sizeof(out));
		T_OK("LastNetworkID is that network",
		     n == 10u && out[0] == 0x10u && out[1] == 8u && memcmp(&out[2], k_other, 8u) == 0);
		info.attempt.active = false;
		info.attempt.have_thread_candidate = false;
	}
}

static void t_update_noc(void)
{
	/* NOCValue only: the answer never gets as far as reading it. */
	static const uint8_t k_req[] = {0x15u, 0x30u, 0x00u, 0x01u, 0x00u, 0x18u};
	struct matter_device_info info;
	struct matter_im_server srv;
	struct matter_tlv_writer w;
	struct matter_tlv_reader r;
	uint8_t out[64];
	uint32_t response;
	uint64_t v = 0xFFu;

	t_group("UpdateNOC answers MissingCsr, in the cluster's order");
	admin_info(&info);
	matter_clusters_init(&srv, &info);
	T_OK("listed as accepted",
	     srv.status(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
			MATTER_ATTR_ACCEPTED_CMD_LIST) == MATTER_IM_STATUS_SUCCESS);
	T_EQ("without a fail-safe: FAILSAFE_REQUIRED",
	     root_invoke(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, MATTER_CMD_OC_UPDATE_NOC,
			 k_req, sizeof(k_req), &response),
	     MATTER_IM_STATUS_FAILSAFE_REQUIRED);
	info.attempt.active = true;
	info.accessing_fabric_index = 0u;
	T_EQ("over PASE: INVALID_COMMAND",
	     root_invoke(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, MATTER_CMD_OC_UPDATE_NOC,
			 k_req, sizeof(k_req), &response),
	     MATTER_IM_STATUS_INVALID_COMMAND);
	info.accessing_fabric_index = 1u;
	T_EQ("over CASE: a NOCResponse",
	     root_invoke(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, MATTER_CMD_OC_UPDATE_NOC,
			 k_req, sizeof(k_req), &response),
	     MATTER_IM_STATUS_SUCCESS);
	T_EQ("NOCResponse", (long)response, (long)MATTER_CMD_OC_NOC_RESPONSE);
	matter_tlv_writer_init(&w, out, sizeof(out));
	srv.command_fields(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
			   response, &w, MATTER_TLV_ANON);
	matter_tlv_reader_init(&r, out, w.len);
	T_OK("StatusCode MissingCsr and no FabricIndex",
	     matter_tlv_next(&r) == MATTER_OK && matter_tlv_enter(&r) == MATTER_OK &&
		     matter_tlv_next(&r) == MATTER_OK && matter_tlv_get_u64(&r, &v) == MATTER_OK &&
		     v == MATTER_NOC_STATUS_MISSING_CSR && matter_tlv_next(&r) == MATTER_END);
	info.attempt.active = false;
}

void test_root_clusters(void)
{
	t_general_diagnostics();
	t_group_keys();
	t_globals();
	t_unique_id();
	t_network_commissioning();
	t_update_noc();
}

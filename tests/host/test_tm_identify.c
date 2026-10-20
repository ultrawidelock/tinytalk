/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The Identify module (clusters/identify) on the Door Lock endpoint, through the
 * same matter_im_server the Interaction Model calls.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_tlv.h>
#include <tinytalk/tm_door_lock.h>
#include <tinytalk/tm_identify.h>

#include "test.h"

static uint16_t s_seconds;
static int s_identify_calls;
static uint8_t s_effect;
static int s_effect_calls;

static void on_identify(uint16_t endpoint, uint16_t seconds)
{
	(void)endpoint;
	s_seconds = seconds;
	s_identify_calls++;
}

static void on_effect(uint16_t endpoint, uint8_t effect, uint8_t variant)
{
	(void)endpoint;
	(void)variant;
	s_effect = effect;
	s_effect_calls++;
}

static const struct tm_identify_hooks k_hooks = {
	.identify = on_identify,
	.effect = on_effect,
};

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

static size_t read_ids(struct matter_im_server *srv, uint16_t ep, uint32_t cl, uint32_t attr,
		       uint64_t *ids, size_t cap)
{
	struct matter_tlv_writer w;
	struct matter_tlv_reader r;
	uint8_t out[128];
	size_t n = 0u;

	matter_tlv_writer_init(&w, out, sizeof(out));
	srv->value(srv->ctx, ep, cl, attr, false, &w, MATTER_TLV_ANON);
	matter_tlv_reader_init(&r, out, w.len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return 0u;
	}
	while (n < cap && matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_get_u64(&r, &ids[n]) == MATTER_OK) {
			n++;
		}
	}
	return n;
}

static uint64_t read_u64(struct matter_im_server *srv, uint32_t attr)
{
	struct matter_tlv_writer w;
	struct matter_tlv_reader r;
	uint8_t out[16];
	uint64_t v = 0xFFFFFu;

	matter_tlv_writer_init(&w, out, sizeof(out));
	srv->value(srv->ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_IDENTIFY, attr, false, &w,
		   MATTER_TLV_ANON);
	matter_tlv_reader_init(&r, out, w.len);
	if (matter_tlv_next(&r) == MATTER_OK) {
		(void)matter_tlv_get_u64(&r, &v);
	}
	return v;
}

static uint8_t invoke(struct matter_im_server *srv, uint32_t cmd, const uint8_t *fields,
		      size_t len)
{
	struct matter_im_invoke inv;
	uint32_t response = MATTER_IM_NO_RESPONSE;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_LOCK;
	inv.cluster = MATTER_CLUSTER_IDENTIFY;
	inv.command = cmd;
	inv.fields = fields;
	inv.fields_len = len;
	inv.has_fields = fields != NULL;
	return srv->command(srv->ctx, &inv, &response);
}

void test_tm_identify(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint64_t ids[16];
	size_t n;

	T_EQ("the Door Lock endpoint is taken",
	     matter_clusters_set_endpoints(&tm_door_lock_endpoint, 1u), MATTER_OK);
	admin_info(&info);
	matter_clusters_init(&srv, &info);

	t_group("Identify sits beside the Door Lock");
	{
		n = read_ids(&srv, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DESCRIPTOR,
			     MATTER_ATTR_DESC_SERVER_LIST, ids, 16u);
		T_OK("ServerList is Descriptor, Door Lock, Identify",
		     n == 3u && ids[0] == MATTER_CLUSTER_DESCRIPTOR &&
			     ids[1] == MATTER_CLUSTER_DOOR_LOCK && ids[2] == MATTER_CLUSTER_IDENTIFY);
		T_EQ("ClusterRevision 6", (long)read_u64(&srv, MATTER_ATTR_CLUSTER_REVISION), 6L);
		T_EQ("FeatureMap 0", (long)read_u64(&srv, MATTER_ATTR_FEATURE_MAP), 0L);
		n = read_ids(&srv, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_IDENTIFY,
			     MATTER_ATTR_ACCEPTED_CMD_LIST, ids, 16u);
		T_OK("accepts Identify and TriggerEffect",
		     n == 2u && ids[0] == MATTER_CMD_IDENTIFY && ids[1] == MATTER_CMD_TRIGGER_EFFECT);
		n = read_ids(&srv, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_IDENTIFY,
			     MATTER_ATTR_GENERATED_CMD_LIST, ids, 16u);
		T_EQ("generates nothing", (long)n, 0L);
		T_EQ("IdentifyType None until configured",
		     (long)read_u64(&srv, MATTER_ATTR_IDENTIFY_TYPE), 0L);
		T_EQ("IdentifyTime 0", (long)read_u64(&srv, MATTER_ATTR_IDENTIFY_TIME), 0L);
	}

	t_group("LockState is still the heartbeat's attribute");
	{
		struct matter_im_path p;
		const struct tm_cluster *cl;
		bool found = false;

		for (size_t bit = 0u; !found && matter_clusters_change_path(bit, &p, &cl); bit++) {
			if (p.attribute < 0xF000u) {
				found = true;
			}
		}
		T_OK("the first application attribute is Door Lock LockState",
		     found && p.cluster == MATTER_CLUSTER_DOOR_LOCK &&
			     p.attribute == MATTER_ATTR_DL_LOCK_STATE);
	}

	t_group("Identify and TriggerEffect reach the application");
	{
		static const uint8_t k_ten[] = {0x15u, 0x24u, 0x00u, 0x0Au, 0x18u};
		static const uint8_t k_zero[] = {0x15u, 0x24u, 0x00u, 0x00u, 0x18u};
		static const uint8_t k_none[] = {0x15u, 0x18u};
		static const uint8_t k_blink[] = {0x15u, 0x24u, 0x00u, 0x00u, 0x24u, 0x01u, 0x00u, 0x18u};
		static const uint8_t k_bad_effect[] = {0x15u, 0x24u, 0x00u, 0x07u,
						       0x24u, 0x01u, 0x00u, 0x18u};
		static const uint8_t k_bad_variant[] = {0x15u, 0x24u, 0x00u, 0x00u,
							0x24u, 0x01u, 0x01u, 0x18u};
		static const uint8_t k_stop[] = {0x15u, 0x24u, 0x00u, 0xFFu, 0x24u, 0x01u, 0x00u, 0x18u};
		static const uint8_t k_write5[] = {0x04u, 0x05u};
		struct matter_im_path path;
		uint64_t left;

		tm_identify_configure(MATTER_IDENTIFY_TYPE_VISIBLE_INDICATOR, &k_hooks);
		T_EQ("IdentifyType as configured",
		     (long)read_u64(&srv, MATTER_ATTR_IDENTIFY_TYPE), 2L);
		s_identify_calls = 0;
		T_EQ("Identify 10 s", invoke(&srv, MATTER_CMD_IDENTIFY, k_ten, sizeof(k_ten)),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("the hook is told", s_identify_calls == 1 && s_seconds == 10u);
		left = read_u64(&srv, MATTER_ATTR_IDENTIFY_TIME);
		T_OK("IdentifyTime counts from 10", left >= 9u && left <= 10u);
		T_EQ("Identify 0 stops", invoke(&srv, MATTER_CMD_IDENTIFY, k_zero, sizeof(k_zero)),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("and says so", s_identify_calls == 2 && s_seconds == 0u);
		T_EQ("IdentifyTime back to 0", (long)read_u64(&srv, MATTER_ATTR_IDENTIFY_TIME), 0L);
		T_EQ("Identify without its field",
		     invoke(&srv, MATTER_CMD_IDENTIFY, k_none, sizeof(k_none)),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		s_effect_calls = 0;
		T_EQ("TriggerEffect Blink",
		     invoke(&srv, MATTER_CMD_TRIGGER_EFFECT, k_blink, sizeof(k_blink)),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("reaches the effect hook", s_effect_calls == 1 && s_effect == 0u);
		T_EQ("an unknown effect",
		     invoke(&srv, MATTER_CMD_TRIGGER_EFFECT, k_bad_effect, sizeof(k_bad_effect)),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("a variant other than Default",
		     invoke(&srv, MATTER_CMD_TRIGGER_EFFECT, k_bad_variant, sizeof(k_bad_variant)),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("TriggerEffect without fields",
		     invoke(&srv, MATTER_CMD_TRIGGER_EFFECT, k_none, sizeof(k_none)),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		memset(&path, 0, sizeof(path));
		path.endpoint = MATTER_ENDPOINT_LOCK;
		path.have_endpoint = true;
		path.cluster = MATTER_CLUSTER_IDENTIFY;
		path.have_cluster = true;
		path.attribute = MATTER_ATTR_IDENTIFY_TIME;
		path.have_attribute = true;
		T_EQ("writing IdentifyTime starts it",
		     srv.write(srv.ctx, &path, k_write5, sizeof(k_write5)), MATTER_IM_STATUS_SUCCESS);
		T_OK("for 5 s", s_seconds == 5u && read_u64(&srv, MATTER_ATTR_IDENTIFY_TIME) >= 4u);
		T_EQ("StopEffect", invoke(&srv, MATTER_CMD_TRIGGER_EFFECT, k_stop, sizeof(k_stop)),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("ends it", (long)read_u64(&srv, MATTER_ATTR_IDENTIFY_TIME), 0L);
		path.attribute = MATTER_ATTR_IDENTIFY_TYPE;
		T_EQ("IdentifyType is read-only", srv.write(srv.ctx, &path, k_write5, sizeof(k_write5)),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		info.accessing_node_id = 0u;
		T_EQ("not over PASE", invoke(&srv, MATTER_CMD_IDENTIFY, k_ten, sizeof(k_ten)),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		info.accessing_node_id = 0x77u;
		tm_identify_configure(MATTER_IDENTIFY_TYPE_NONE, NULL);
		(void)matter_clusters_take_changes((uint32_t[MATTER_CHANGE_WORDS]){0});
	}
}

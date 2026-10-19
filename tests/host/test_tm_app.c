/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The application data model (tm_app.h): a table of endpoints and clusters the
 * node serves beside the root, driven through the same matter_im_server the
 * Interaction Model calls. Two made-up endpoints rather than the Door Lock, so
 * nothing here passes because the lock happens to answer.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_tlv.h>
#include <tinytalk/tm_app.h>
#include <tinytalk/tm_door_lock.h>

#include "test.h"

#define EP_LIGHT      2u
#define EP_SENSOR     3u
#define CL_ONOFF      0x0006u
#define CL_VENDOR     0xFFF1FC01u
#define ATTR_ON       0x0000u
#define ATTR_LEVEL    0x0001u
#define CMD_OFF       0x00u
#define CMD_ON        0x01u
#define CMD_ASK       0x00u
#define CMD_ANSWER    0x01u
#define EVENT_SEEN    0x0007u

static struct tm_req s_last_req;
static uint32_t s_last_cmd;
static uint64_t s_written;
static bool s_on;

static void onoff_read(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
		       matter_tlv_tag_t tag)
{
	s_last_req = *req;
	if (attr == ATTR_ON) {
		(void)matter_tlv_put_bool(w, tag, s_on);
	}
}

static uint8_t onoff_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			    size_t len, uint32_t *response)
{
	(void)fields;
	(void)len;
	(void)response;
	s_last_req = *req;
	s_last_cmd = cmd;
	s_on = cmd == CMD_ON;
	tm_attr_changed(req->endpoint, CL_ONOFF, ATTR_ON);
	return MATTER_IM_STATUS_SUCCESS;
}

static const uint32_t k_onoff_attrs[] = {
	ATTR_ON,
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};
static const uint32_t k_onoff_cmds[] = { CMD_OFF, CMD_ON };

static const struct tm_cluster k_onoff = {
	.id = CL_ONOFF,
	.attrs = k_onoff_attrs,
	.n_attrs = sizeof(k_onoff_attrs) / sizeof(k_onoff_attrs[0]),
	.accepted = k_onoff_cmds,
	.n_accepted = 2u,
	.revision = 6u,
	.features = 0x1u,
	.read = onoff_read,
	.invoke = onoff_invoke,
};

static void vendor_read(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
			matter_tlv_tag_t tag)
{
	(void)req;
	if (attr == ATTR_LEVEL) {
		(void)matter_tlv_put_u64(w, tag, s_written);
	}
}

static uint8_t vendor_write(const struct tm_req *req, uint32_t attr, const uint8_t *tlv,
			    size_t len)
{
	struct matter_tlv_reader r;

	(void)req;
	(void)attr;
	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != 0 || matter_tlv_get_u64(&r, &s_written) != 0) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	return MATTER_IM_STATUS_SUCCESS;
}

static uint8_t vendor_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			     size_t len, uint32_t *response)
{
	(void)req;
	(void)fields;
	(void)len;
	s_last_cmd = cmd;
	*response = CMD_ANSWER;
	return MATTER_IM_STATUS_SUCCESS;
}

static void vendor_response(const struct tm_req *req, uint32_t response,
			    struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)req;
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(0u), 0x42u + response);
	(void)matter_tlv_end_container(w);
}

static void vendor_event(const struct tm_req *req, uint32_t event, const uint8_t *blob,
			 struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)req;
	(void)event;
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(0u), blob[0]);
	(void)matter_tlv_end_container(w);
}

static const uint32_t k_vendor_attrs[] = { ATTR_LEVEL, MATTER_ATTR_CLUSTER_REVISION };
static const uint32_t k_vendor_cmds[] = { CMD_ASK };
static const uint32_t k_vendor_resps[] = { CMD_ANSWER };

static const struct tm_cluster k_vendor = {
	.id = CL_VENDOR,
	.attrs = k_vendor_attrs,
	.n_attrs = 2u,
	.accepted = k_vendor_cmds,
	.n_accepted = 1u,
	.generated = k_vendor_resps,
	.n_generated = 1u,
	.invoke_privilege = MATTER_AC_PRIVILEGE_MANAGE,
	.revision = 1u,
	.read = vendor_read,
	.write = vendor_write,
	.invoke = vendor_invoke,
	.response = vendor_response,
	.event = vendor_event,
};

static const struct tm_cluster *const k_light_clusters[] = { &k_onoff };
static const struct tm_cluster *const k_sensor_clusters[] = { &k_vendor };

static const struct tm_endpoint k_eps[] = {
	{ .id = EP_LIGHT, .device_type = 0x0100u, .device_revision = 3u,
	  .clusters = k_light_clusters, .n_clusters = 1u },
	{ .id = EP_SENSOR, .device_type = 0xFFF10001u, .device_revision = 1u,
	  .clusters = k_sensor_clusters, .n_clusters = 1u },
};

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

/* Encode one attribute value and decode its ids, if it is a list of them. */
static size_t read_ids(struct matter_im_server *srv, uint16_t ep, uint32_t cl, uint32_t attr,
		       uint64_t *ids, size_t cap)
{
	struct matter_tlv_writer w;
	struct matter_tlv_reader r;
	uint8_t out[256];
	size_t n = 0u;

	matter_tlv_writer_init(&w, out, sizeof(out));
	srv->value(srv->ctx, ep, cl, attr, false, &w, MATTER_TLV_ANON);
	matter_tlv_reader_init(&r, out, w.len);
	if (matter_tlv_next(&r) != 0 || matter_tlv_enter(&r) != 0) {
		return 0u;
	}
	while (n < cap && matter_tlv_next(&r) == 0) {
		if (matter_tlv_get_u64(&r, &ids[n]) == 0) {
			n++;
		}
	}
	return n;
}

static uint64_t read_u64(struct matter_im_server *srv, uint16_t ep, uint32_t cl, uint32_t attr)
{
	struct matter_tlv_writer w;
	struct matter_tlv_reader r;
	uint8_t out[32];
	uint64_t v = 0xFFFFu;

	matter_tlv_writer_init(&w, out, sizeof(out));
	srv->value(srv->ctx, ep, cl, attr, false, &w, MATTER_TLV_ANON);
	matter_tlv_reader_init(&r, out, w.len);
	if (matter_tlv_next(&r) == 0) {
		(void)matter_tlv_get_u64(&r, &v);
	}
	return v;
}

static uint8_t invoke(struct matter_im_server *srv, uint16_t ep, uint32_t cl, uint32_t cmd,
		      uint32_t *response)
{
	struct matter_im_invoke inv;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = ep;
	inv.cluster = cl;
	inv.command = cmd;
	*response = MATTER_IM_NO_RESPONSE;
	return srv->command(srv->ctx, &inv, response);
}

void test_tm_app(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint64_t ids[8];

	t_group("the endpoint table is checked before it is served");
	{
		struct tm_endpoint bad[TM_ENDPOINTS_MAX + 1u];
		static const struct tm_cluster *const k_twice[] = { &k_onoff, &k_onoff };
		static const struct tm_cluster k_desc = { .id = MATTER_CLUSTER_DESCRIPTOR };
		static const struct tm_cluster *const k_desc_list[] = { &k_desc };

		memcpy(bad, k_eps, sizeof(k_eps));
		bad[0].id = MATTER_ENDPOINT_ROOT;
		T_EQ("endpoint 0 is the node's", matter_clusters_set_endpoints(bad, 1u),
		     MATTER_E_INVAL);
		memcpy(bad, k_eps, sizeof(k_eps));
		bad[1].id = bad[0].id;
		T_EQ("an id used twice", matter_clusters_set_endpoints(bad, 2u), MATTER_E_INVAL);
		T_EQ("more endpoints than the build holds",
		     matter_clusters_set_endpoints(bad, TM_ENDPOINTS_MAX + 1u), MATTER_E_INVAL);
		memcpy(bad, k_eps, sizeof(k_eps));
		bad[0].clusters = k_twice;
		bad[0].n_clusters = 2u;
		T_EQ("a cluster twice on one endpoint", matter_clusters_set_endpoints(bad, 1u),
		     MATTER_E_INVAL);
		bad[0].clusters = k_desc_list;
		bad[0].n_clusters = 1u;
		T_EQ("Descriptor is the node's", matter_clusters_set_endpoints(bad, 1u),
		     MATTER_E_INVAL);
		T_EQ("the real table is taken", matter_clusters_set_endpoints(k_eps, 2u), MATTER_OK);
	}

	admin_info(&info);
	matter_clusters_init(&srv, &info);

	t_group("Descriptor is built from the table");
	{
		const uint16_t *eps = NULL;
		const uint32_t *cls = NULL;
		size_t n;

		n = read_ids(&srv, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_DESCRIPTOR,
			     MATTER_ATTR_DESC_PARTS_LIST, ids, 8u);
		T_EQ("the root lists both endpoints", n, 2u);
		T_OK("in table order", ids[0] == EP_LIGHT && ids[1] == EP_SENSOR);
		n = srv.list_endpoints(srv.ctx, &eps);
		T_EQ("a wildcard walks three", n, 3u);
		T_OK("the root first", eps[0] == MATTER_ENDPOINT_ROOT && eps[2] == EP_SENSOR);
		n = read_ids(&srv, EP_LIGHT, MATTER_CLUSTER_DESCRIPTOR,
			     MATTER_ATTR_DESC_SERVER_LIST, ids, 8u);
		T_OK("ServerList is Descriptor then OnOff",
		     n == 2u && ids[0] == MATTER_CLUSTER_DESCRIPTOR && ids[1] == CL_ONOFF);
		n = srv.list_clusters(srv.ctx, EP_SENSOR, &cls);
		T_OK("and the wildcard list agrees", n == 2u && cls[1] == CL_VENDOR);
		T_OK("has_cluster agrees", srv.has_cluster(srv.ctx, EP_LIGHT, CL_ONOFF) &&
						   !srv.has_cluster(srv.ctx, EP_LIGHT, CL_VENDOR));
	}

	t_group("the globals come from the table");
	{
		T_EQ("FeatureMap", read_u64(&srv, EP_LIGHT, CL_ONOFF, MATTER_ATTR_FEATURE_MAP), 1u);
		T_EQ("ClusterRevision",
		     read_u64(&srv, EP_LIGHT, CL_ONOFF, MATTER_ATTR_CLUSTER_REVISION), 6u);
		T_EQ("AttributeList is attrs",
		     read_ids(&srv, EP_LIGHT, CL_ONOFF, MATTER_ATTR_ATTRIBUTE_LIST, ids, 8u),
		     sizeof(k_onoff_attrs) / sizeof(k_onoff_attrs[0]));
		T_EQ("AcceptedCommandList",
		     read_ids(&srv, EP_LIGHT, CL_ONOFF, MATTER_ATTR_ACCEPTED_CMD_LIST, ids, 8u), 2u);
		T_EQ("a global not listed is not served",
		     srv.status(srv.ctx, EP_SENSOR, CL_VENDOR, MATTER_ATTR_FEATURE_MAP),
		     MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE);
	}

	t_group("a read reaches the cluster with who is asking");
	{
		struct matter_tlv_writer w;
		uint8_t out[16];

		s_on = true;
		memset(&s_last_req, 0, sizeof(s_last_req));
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, EP_LIGHT, CL_ONOFF, ATTR_ON, true, &w, MATTER_TLV_ANON);
		T_OK("the value is the cluster's", w.len == 1u && out[0] == 0x09u);
		T_EQ("on its endpoint", s_last_req.endpoint, EP_LIGHT);
		T_EQ("for the accessing fabric", s_last_req.fabric_index, 1u);
		T_OK("fabric-filtered", s_last_req.fabric_filtered);
		T_EQ("by the accessing node", s_last_req.node_id, 0x77u);
		T_EQ("an unknown attribute",
		     srv.status(srv.ctx, EP_LIGHT, CL_ONOFF, 0x0042u),
		     MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE);
		T_EQ("an unknown cluster", srv.status(srv.ctx, EP_LIGHT, CL_VENDOR, ATTR_LEVEL),
		     MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);
		T_EQ("an unknown endpoint", srv.status(srv.ctx, 9u, CL_ONOFF, ATTR_ON),
		     MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT);
	}

	t_group("invoke runs the cluster's command for a fabric, never for PASE");
	{
		uint32_t response;
		uint8_t out[128];
		size_t len = 0u;
		struct matter_im_invoke inv;

		T_EQ("On runs", invoke(&srv, EP_LIGHT, CL_ONOFF, CMD_ON, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("and the cluster saw it", s_on && s_last_cmd == CMD_ON);
		T_EQ("with a bare status", response, MATTER_IM_NO_RESPONSE);
		T_EQ("a command it does not accept",
		     invoke(&srv, EP_LIGHT, CL_ONOFF, 0x40u, &response),
		     MATTER_IM_STATUS_UNSUPPORTED_COMMAND);
		T_EQ("Descriptor takes no commands",
		     invoke(&srv, EP_LIGHT, MATTER_CLUSTER_DESCRIPTOR, CMD_ON, &response),
		     MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);

		memset(&inv, 0, sizeof(inv));
		inv.endpoint = EP_SENSOR;
		inv.cluster = CL_VENDOR;
		inv.command = CMD_ASK;
		T_EQ("a command with a response encodes",
		     matter_im_invoke_response_encode(&srv, &inv, out, sizeof(out), &len),
		     MATTER_OK);
		{
			/* The answer's field, 0x42 + its command id, is in there. */
			bool found = false;

			for (size_t i = 0u; i + 1u < len; i++) {
				found = found || (out[i] == 0x24u && out[i + 1u] == 0x00u &&
						  i + 2u < len && out[i + 2u] == 0x43u);
			}
			T_OK("and carries the cluster's response fields", found);
		}

		info.accessing_node_id = 0x88u; /* no admin subject, no ACL */
		T_EQ("a fabric without the privilege is refused",
		     invoke(&srv, EP_SENSOR, CL_VENDOR, CMD_ASK, &response),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		info.accessing_fabric_index = 0u;
		info.accessing_node_id = 0u;
		s_last_cmd = 0xFFu;
		T_EQ("PASE cannot invoke", invoke(&srv, EP_LIGHT, CL_ONOFF, CMD_OFF, &response),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		T_EQ("and nothing ran", s_last_cmd, 0xFFu);
		admin_info(&info);
	}

	t_group("a write reaches only a writable cluster");
	{
		struct matter_im_path path;
		struct matter_tlv_writer w;
		uint8_t tlv[16];

		memset(&path, 0, sizeof(path));
		path.endpoint = EP_SENSOR;
		path.cluster = CL_VENDOR;
		path.attribute = ATTR_LEVEL;
		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 1234u);
		T_EQ("accepted", srv.write(srv.ctx, &path, tlv, w.len), MATTER_IM_STATUS_SUCCESS);
		T_EQ("and read back", read_u64(&srv, EP_SENSOR, CL_VENDOR, ATTR_LEVEL), 1234u);
		path.attribute = 0x0099u;
		T_EQ("an attribute it lacks", srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE);
		path.endpoint = EP_LIGHT;
		path.cluster = CL_ONOFF;
		path.attribute = ATTR_ON;
		T_EQ("a cluster with no write()", srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);
	}

	t_group("a change is one bit, and the bit names its path");
	{
		uint32_t changes[MATTER_CHANGE_WORDS];
		struct matter_im_path p;
		const struct tm_cluster *cl = NULL;
		size_t set = 0u;
		size_t at = 0u;

		matter_clusters_take_changes(changes);
		tm_attr_changed(EP_SENSOR, CL_VENDOR, ATTR_LEVEL);
		tm_attr_changed(EP_SENSOR, CL_VENDOR, ATTR_LEVEL);
		tm_attr_changed(EP_LIGHT, CL_VENDOR, ATTR_LEVEL); /* not a path we serve */
		matter_clusters_take_changes(changes);
		for (size_t bit = 0u; bit < TM_ATTRS_MAX; bit++) {
			if ((changes[bit / 32u] & (1u << (bit % 32u))) != 0u) {
				set++;
				at = bit;
			}
		}
		T_EQ("twice the same change is one bit", set, 1u);
		T_OK("and it maps back", matter_clusters_change_path(at, &p, &cl));
		T_OK("to the path", p.endpoint == EP_SENSOR && p.cluster == CL_VENDOR &&
					    p.attribute == ATTR_LEVEL && cl == &k_vendor);
		matter_clusters_take_changes(changes);
		T_EQ("taking them clears them", changes[0], 0u);
		T_OK("a bit past the table maps to nothing",
		     !matter_clusters_change_path(TM_ATTRS_MAX, &p, &cl));
	}

	t_group("an event is encoded by the cluster that emitted it");
	{
		struct matter_im_event ev;
		struct matter_tlv_writer w;
		uint8_t out[32];
		uint8_t blob[TM_EVENT_BLOB_MAX + 1u] = { 0x5Au };

		T_EQ("a blob past the bound is refused",
		     tm_event_emit(EP_SENSOR, CL_VENDOR, EVENT_SEEN, MATTER_EVENT_PRIORITY_INFO, blob,
				   sizeof(blob)),
		     0u);
		T_EQ("one that fits is numbered",
		     tm_event_emit(EP_SENSOR, CL_VENDOR, EVENT_SEEN, MATTER_EVENT_PRIORITY_INFO, blob,
				   1u),
		     1u);
		T_OK("held", srv.event_at(srv.ctx, 0u, &ev));
		T_OK("with its path and priority",
		     ev.endpoint == EP_SENSOR && ev.cluster == CL_VENDOR && ev.event == EVENT_SEEN &&
			     ev.priority == MATTER_EVENT_PRIORITY_INFO);
		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.event_data(srv.ctx, 0u, &w, MATTER_TLV_ANON);
		T_OK("its data is the cluster's encoding of the blob",
		     w.len == 5u && out[0] == 0x15u && out[3] == 0x5Au);
	}

	/* Every later suite runs against the sample's table. */
	(void)matter_clusters_set_endpoints(&tm_door_lock_endpoint, 1u);
}

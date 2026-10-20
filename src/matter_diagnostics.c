/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * General Diagnostics on endpoint 0, which the Root Node device type requires
 * (matter-devices.xml, MA-rootdevice). The mandatory set of revision 2
 * (general-diagnostics-cluster.xml) and nothing more: no fault lists, no
 * events, no PayloadTestRequest.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_thread.h>
#include <tinytalk/tm_kv.h>
#include <tinytalk/tm_platform.h>

/* NetworkInterface struct fields (general-diagnostics-cluster.xml). */
#define TAG_NI_NAME           0u
#define TAG_NI_OPERATIONAL    1u
#define TAG_NI_OFF_PREMISE_V4 2u
#define TAG_NI_OFF_PREMISE_V6 3u
#define TAG_NI_HW_ADDRESS     4u
#define TAG_NI_IPV4           5u
#define TAG_NI_IPV6           6u
#define TAG_NI_TYPE           7u

/* TestEventTrigger and TimeSnapshotResponse fields. */
#define TAG_TET_ENABLE_KEY    0u
#define TAG_TET_EVENT_TRIGGER 1u
#define TAG_TSR_SYSTEM_MS     0u
#define TAG_TSR_POSIX_MS      1u

#define ENABLE_KEY_LEN 16u

static const uint32_t k_gd_attrs[] = {
	MATTER_ATTR_GD_NETWORK_INTERFACES,
	MATTER_ATTR_GD_REBOOT_COUNT,
	MATTER_ATTR_GD_UP_TIME,
	MATTER_ATTR_GD_TEST_EVENT_TRIGGERS,
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};

static const uint32_t k_gd_accepted[] = {
	MATTER_CMD_GD_TEST_EVENT_TRIGGER,
	MATTER_CMD_GD_TIME_SNAPSHOT,
};

static const uint32_t k_gd_generated[] = {
	MATTER_CMD_GD_TIME_SNAPSHOT_RESPONSE,
};

/* This boot's RebootCount; matter_general_diagnostics_boot() sets it. */
static uint16_t s_reboot_count;

void matter_general_diagnostics_boot(void)
{
	uint16_t count = 0u;
	size_t len = sizeof(count);

	if (tm_kv_get(TM_KV_KEY_MATTER_REBOOT_COUNT, &count, &len) != TM_KV_OK ||
	    len != sizeof(count)) {
		count = 0u;
	}
	/* Saturates rather than wrapping: the attribute is a uint16. */
	if (count < UINT16_MAX) {
		count++;
	}
	(void)tm_kv_set(TM_KV_KEY_MATTER_REBOOT_COUNT, &count, sizeof(count));
	s_reboot_count = count;
}

static uint64_t uptime_ms(void)
{
	int64_t ms = tm_uptime_ms();

	return ms > 0 ? (uint64_t)ms : 0u;
}

/*
 * One entry, the Thread interface. The off-premise fields are null: the node
 * has no way to know. IPv4Addresses is empty, as Thread has none.
 */
static void put_network_interfaces(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	struct matter_thread_iface iface;

	if (matter_thread_interface(&iface) != MATTER_OK) {
		memset(&iface, 0, sizeof(iface));
	}
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_utf8(w, MATTER_TLV_CTX(TAG_NI_NAME), "thread", 6u);
	(void)matter_tlv_put_bool(w, MATTER_TLV_CTX(TAG_NI_OPERATIONAL), iface.attached);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_NI_OFF_PREMISE_V4));
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_NI_OFF_PREMISE_V6));
	(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NI_HW_ADDRESS), iface.ext_addr,
				   sizeof(iface.ext_addr));
	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_NI_IPV4), MATTER_TLV_ARRAY);
	(void)matter_tlv_end_container(w);
	(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_NI_IPV6), MATTER_TLV_ARRAY);
	for (uint8_t i = 0u; i < iface.n_addrs && i < MATTER_THREAD_IFACE_ADDRS_MAX; i++) {
		(void)matter_tlv_put_bytes(w, MATTER_TLV_ANON, iface.addrs[i], 16u);
	}
	(void)matter_tlv_end_container(w);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NI_TYPE), MATTER_GD_INTERFACE_THREAD);
	(void)matter_tlv_end_container(w);
	(void)matter_tlv_end_container(w);
}

static void gd_read(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
		    matter_tlv_tag_t tag)
{
	(void)req;
	switch (attr) {
	case MATTER_ATTR_GD_NETWORK_INTERFACES:
		put_network_interfaces(w, tag);
		return;
	case MATTER_ATTR_GD_REBOOT_COUNT:
		(void)matter_tlv_put_u64(w, tag, s_reboot_count);
		return;
	case MATTER_ATTR_GD_UP_TIME:
		(void)matter_tlv_put_u64(w, tag, uptime_ms() / 1000u);
		return;
	case MATTER_ATTR_GD_TEST_EVENT_TRIGGERS:
		/* No enable key is configured, so no trigger can be enabled. */
		(void)matter_tlv_put_bool(w, tag, false);
		return;
	default:
		return;
	}
}

/*
 * TestEventTrigger: its two fields are checked, and then it is refused with
 * CONSTRAINT_ERROR, which is what the cluster answers when the EnableKey does
 * not match or TestEventTriggersEnabled is false (connectedhomeip's
 * general-diagnostics-server does the same).
 */
static uint8_t test_event_trigger(const uint8_t *fields, size_t len)
{
	struct matter_tlv_reader r;
	bool have_key = false;
	bool have_trigger = false;

	if (fields == NULL || len == 0u) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	matter_tlv_reader_init(&r, fields, len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TET_ENABLE_KEY)) {
			const uint8_t *key = NULL;
			size_t key_len = 0u;

			have_key = matter_tlv_get_bytes(&r, &key, &key_len) == MATTER_OK &&
				   key_len == ENABLE_KEY_LEN;
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_TET_EVENT_TRIGGER)) {
			uint64_t v;

			have_trigger = matter_tlv_get_u64(&r, &v) == MATTER_OK;
		}
	}
	if (!have_key || !have_trigger) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	return MATTER_IM_STATUS_CONSTRAINT_ERROR;
}

static uint8_t gd_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			 size_t len, uint32_t *response)
{
	(void)req;
	if (cmd == MATTER_CMD_GD_TEST_EVENT_TRIGGER) {
		return test_event_trigger(fields, len);
	}
	if (cmd == MATTER_CMD_GD_TIME_SNAPSHOT) {
		*response = MATTER_CMD_GD_TIME_SNAPSHOT_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}
	return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
}

/* SystemTimeMs is the uptime; PosixTimeMs is null, as this node keeps no
 * calendar time. */
static void gd_response(const struct tm_req *req, uint32_t cmd, struct matter_tlv_writer *w,
			matter_tlv_tag_t tag)
{
	(void)req;
	if (cmd != MATTER_CMD_GD_TIME_SNAPSHOT_RESPONSE) {
		return;
	}
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_TSR_SYSTEM_MS), uptime_ms());
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_TSR_POSIX_MS));
	(void)matter_tlv_end_container(w);
}

const struct tm_cluster matter_general_diagnostics = {
	.id = MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
	.attrs = k_gd_attrs,
	.n_attrs = sizeof(k_gd_attrs) / sizeof(k_gd_attrs[0]),
	.accepted = k_gd_accepted,
	.n_accepted = sizeof(k_gd_accepted) / sizeof(k_gd_accepted[0]),
	.generated = k_gd_generated,
	.n_generated = sizeof(k_gd_generated) / sizeof(k_gd_generated[0]),
	/* TestEventTrigger asks Manage; TimeSnapshot asks nothing beyond
	 * Operate, which is the table's default and covers both here because
	 * TestEventTrigger never acts. */
	.revision = MATTER_GD_CLUSTER_REVISION,
	.features = 0u,
	.read = gd_read,
	.invoke = gd_invoke,
	.response = gd_response,
};

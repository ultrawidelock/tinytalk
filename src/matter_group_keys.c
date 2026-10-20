/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Group Key Management on endpoint 0, which the Root Node device type requires
 * (matter-devices.xml, MA-rootdevice). Revision 2 (group-key-mgmt-cluster.xml),
 * with no group messaging behind it: each fabric holds one key set, the IPK,
 * keyset 0, which AddNOC installs. So no group is ever mapped, and the
 * commands answer what connectedhomeip answers for a node with no room for a
 * second key set.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>

/* Command fields (group-key-mgmt-cluster.xml). */
#define TAG_KS_GROUP_KEY_SET    0u
#define TAG_KS_ID               0u
#define TAG_KS_POLICY           1u
#define TAG_KS_EPOCH_KEY0       2u
#define TAG_KS_EPOCH_START0     3u
#define TAG_KS_EPOCH_KEY1       4u
#define TAG_KS_EPOCH_START1     5u
#define TAG_KS_EPOCH_KEY2       6u
#define TAG_KS_EPOCH_START2     7u
#define TAG_KSR_ID              0u
#define TAG_KSRAI_IDS           0u

/* The IPK's key set id; GroupKeySecurityPolicyEnum TrustFirst. */
#define KEYSET_IPK          0u
#define POLICY_TRUST_FIRST  0u

static const uint32_t k_gkm_attrs[] = {
	MATTER_ATTR_GKM_GROUP_KEY_MAP,
	MATTER_ATTR_GKM_GROUP_TABLE,
	MATTER_ATTR_GKM_MAX_GROUPS,
	MATTER_ATTR_GKM_MAX_KEYS,
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};

static const uint32_t k_gkm_accepted[] = {
	MATTER_CMD_GKM_KEY_SET_WRITE,
	MATTER_CMD_GKM_KEY_SET_READ,
	MATTER_CMD_GKM_KEY_SET_REMOVE,
	MATTER_CMD_GKM_KEY_SET_READ_ALL,
};

static const uint32_t k_gkm_generated[] = {
	MATTER_CMD_GKM_KEY_SET_READ_RESPONSE,
	MATTER_CMD_GKM_KEY_SET_READ_ALL_RESPONSE,
};

static void put_empty_list(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	(void)matter_tlv_end_container(w);
}

static void gkm_read(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
		     matter_tlv_tag_t tag)
{
	(void)req;
	switch (attr) {
	case MATTER_ATTR_GKM_GROUP_KEY_MAP:
	case MATTER_ATTR_GKM_GROUP_TABLE:
		/* Fabric-scoped, and empty for every fabric: no group exists. */
		put_empty_list(w, tag);
		return;
	case MATTER_ATTR_GKM_MAX_GROUPS:
		(void)matter_tlv_put_u64(w, tag, MATTER_GKM_MAX_GROUPS_PER_FABRIC);
		return;
	case MATTER_ATTR_GKM_MAX_KEYS:
		(void)matter_tlv_put_u64(w, tag, MATTER_GKM_MAX_KEYS_PER_FABRIC);
		return;
	default:
		return;
	}
}

/*
 * GroupKeyMap: replacing it with an empty list is accepted, which is what a
 * controller clearing a fabric's groups sends. Any entry needs a key set other
 * than the IPK, which this node has no room for, so it is a constraint error.
 */
static uint8_t gkm_write(const struct tm_req *req, uint32_t attr, const uint8_t *tlv, size_t len)
{
	struct matter_tlv_reader r;

	(void)req;
	if (attr != MATTER_ATTR_GKM_GROUP_KEY_MAP) {
		return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
	}
	if (tlv == NULL || len == 0u) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	matter_tlv_reader_init(&r, tlv, len);
	if (matter_tlv_next(&r) != MATTER_OK) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (matter_tlv_element_type(&r) != MATTER_TLV_ARRAY) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	return matter_tlv_next(&r) == MATTER_END ? MATTER_IM_STATUS_SUCCESS
						 : MATTER_IM_STATUS_CONSTRAINT_ERROR;
}

/* The key set id a command names: directly (tag 0) for Read and Remove, inside
 * the GroupKeySet struct (tag 0, then tag 0) for Write. */
static bool keyset_id(const uint8_t *fields, size_t len, bool in_struct, uint64_t *id)
{
	struct matter_tlv_reader r;

	if (fields == NULL || len == 0u) {
		return false;
	}
	matter_tlv_reader_init(&r, fields, len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(0u)) {
			continue;
		}
		if (!in_struct) {
			return matter_tlv_get_u64(&r, id) == MATTER_OK;
		}
		if (matter_tlv_enter(&r) != MATTER_OK) {
			return false;
		}
		while (matter_tlv_next(&r) == MATTER_OK) {
			if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_KS_ID)) {
				return matter_tlv_get_u64(&r, id) == MATTER_OK;
			}
		}
		return false;
	}
	return false;
}

static uint8_t gkm_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			  size_t len, uint32_t *response)
{
	uint64_t id = 0u;

	(void)req;
	switch (cmd) {
	case MATTER_CMD_GKM_KEY_SET_WRITE:
		if (!keyset_id(fields, len, true, &id)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/* The IPK is written by AddNOC, never by this command; any
		 * other key set needs a slot this node does not have. */
		return id == KEYSET_IPK ? MATTER_IM_STATUS_INVALID_COMMAND
					: MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
	case MATTER_CMD_GKM_KEY_SET_READ:
		if (!keyset_id(fields, len, false, &id)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (id != KEYSET_IPK) {
			return MATTER_IM_STATUS_NOT_FOUND;
		}
		*response = MATTER_CMD_GKM_KEY_SET_READ_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	case MATTER_CMD_GKM_KEY_SET_REMOVE:
		if (!keyset_id(fields, len, false, &id)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		return id == KEYSET_IPK ? MATTER_IM_STATUS_INVALID_COMMAND
					: MATTER_IM_STATUS_NOT_FOUND;
	case MATTER_CMD_GKM_KEY_SET_READ_ALL:
		*response = MATTER_CMD_GKM_KEY_SET_READ_ALL_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

static void gkm_response(const struct tm_req *req, uint32_t cmd, struct matter_tlv_writer *w,
			 matter_tlv_tag_t tag)
{
	(void)req;
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	if (cmd == MATTER_CMD_GKM_KEY_SET_READ_RESPONSE) {
		/* The IPK as connectedhomeip reports it: one epoch key that
		 * started at 0, and no key material, which a read never
		 * returns. */
		(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_KS_GROUP_KEY_SET),
						 MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_KS_ID), KEYSET_IPK);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_KS_POLICY), POLICY_TRUST_FIRST);
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_KS_EPOCH_KEY0));
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_KS_EPOCH_START0), 0u);
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_KS_EPOCH_KEY1));
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_KS_EPOCH_START1));
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_KS_EPOCH_KEY2));
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_KS_EPOCH_START2));
		(void)matter_tlv_end_container(w);
	} else if (cmd == MATTER_CMD_GKM_KEY_SET_READ_ALL_RESPONSE) {
		/* The accessing fabric's key sets: its IPK. */
		(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_KSRAI_IDS),
						 MATTER_TLV_ARRAY);
		(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, KEYSET_IPK);
		(void)matter_tlv_end_container(w);
	}
	(void)matter_tlv_end_container(w);
}

const struct tm_cluster matter_group_key_management = {
	.id = MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
	.attrs = k_gkm_attrs,
	.n_attrs = sizeof(k_gkm_attrs) / sizeof(k_gkm_attrs[0]),
	.accepted = k_gkm_accepted,
	.n_accepted = sizeof(k_gkm_accepted) / sizeof(k_gkm_accepted[0]),
	.generated = k_gkm_generated,
	.n_generated = sizeof(k_gkm_generated) / sizeof(k_gkm_generated[0]),
	/* Every command asks Administer; GroupKeyMap asks Manage to write. */
	.invoke_privilege = MATTER_AC_PRIVILEGE_ADMINISTER,
	.write_privilege = MATTER_AC_PRIVILEGE_MANAGE,
	.revision = MATTER_GKM_CLUSTER_REVISION,
	.features = 0u,
	.read = gkm_read,
	.write = gkm_write,
	.invoke = gkm_invoke,
	.response = gkm_response,
};

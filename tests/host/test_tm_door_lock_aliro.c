/* SPDX-License-Identifier: Apache-2.0 */

/*
 * The Aliro half of the Door Lock cluster (clusters/door_lock/
 * tm_door_lock_aliro.c), driven through the same matter_im_server the node
 * serves it with: the reader attributes, SetAliroReaderConfig and its clear,
 * the user table and its persistence, and the credential commands against a
 * recording store.
 */
#include <string.h>

#include <tinytalk/matter_clusters.h>
#include <tinytalk/matter_im.h>
#include <tinytalk/matter_tlv.h>
#include <tinytalk/tm_door_lock.h>

#include "test.h"

#define CL MATTER_CLUSTER_DOOR_LOCK
#define EP MATTER_ENDPOINT_LOCK

/* ---- the recording reader ------------------------------------------------- */

static uint8_t s_signing[32], s_verifying[65], s_group[16], s_sub[16], s_grk[16];
static int s_config_calls, s_clear_calls, s_user_clear_calls, s_config_rc;
static uint16_t s_user_cleared;
static uint8_t s_clear_type;
static uint16_t s_clear_index;

struct slot {
	bool used;
	uint8_t type;
	uint16_t index, user;
	uint8_t key[65];
};
static struct slot s_store[8];

static int on_reader_config(const uint8_t signing[32], const uint8_t verifying[65],
			    const uint8_t group[16], const uint8_t sub[16], const uint8_t grk[16])
{
	memcpy(s_signing, signing, 32u);
	memcpy(s_verifying, verifying, 65u);
	memcpy(s_group, group, 16u);
	memcpy(s_sub, sub, 16u);
	memcpy(s_grk, grk, 16u);
	s_config_calls++;
	return s_config_rc;
}

static int on_reader_clear(void)
{
	s_clear_calls++;
	return 0;
}

static struct slot *find(uint8_t type, uint16_t index)
{
	for (size_t i = 0u; i < 8u; i++) {
		if (s_store[i].used && s_store[i].type == type && s_store[i].index == index) {
			return &s_store[i];
		}
	}
	return NULL;
}

static int on_credential_set(uint8_t type, const uint8_t key[65], uint16_t index, uint16_t user)
{
	for (size_t i = 0u; i < 8u; i++) {
		if (!s_store[i].used) {
			s_store[i].used = true;
			s_store[i].type = type;
			s_store[i].index = index;
			s_store[i].user = user;
			memcpy(s_store[i].key, key, 65u);
			return 0;
		}
	}
	return -28; /* -ENOSPC */
}

static int on_credential_clear(uint8_t type, uint16_t index)
{
	s_clear_type = type;
	s_clear_index = index;
	for (size_t i = 0u; i < 8u; i++) {
		if (s_store[i].used && (type == 0u || s_store[i].type == type) &&
		    (index == MATTER_DL_INDEX_ALL || s_store[i].index == index)) {
			s_store[i].used = false;
		}
	}
	return 0;
}

static int on_credential_lookup(uint8_t type, uint16_t index, uint8_t key[65])
{
	struct slot *s = find(type, index);

	if (s == NULL) {
		return -1;
	}
	memcpy(key, s->key, 65u);
	return s->user;
}

static int on_user_clear(uint16_t user)
{
	s_user_clear_calls++;
	s_user_cleared = user;
	return 0;
}

static const struct tm_door_lock_aliro_hooks k_hooks = {
	.reader_config = on_reader_config,
	.reader_clear = on_reader_clear,
	.credential_set = on_credential_set,
	.credential_clear = on_credential_clear,
	.credential_lookup = on_credential_lookup,
	.user_clear = on_user_clear,
};

/* ---- the harness -------------------------------------------------------------- */

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

/* One attribute, encoded; the element type and payload are inspected by the
 * callers. */
static size_t read_attr(struct matter_im_server *srv, uint32_t attr, uint8_t *out, size_t cap)
{
	struct matter_tlv_writer w;

	matter_tlv_writer_init(&w, out, cap);
	srv->value(srv->ctx, EP, CL, attr, false, &w, MATTER_TLV_ANON);
	return w.len;
}

/* 1 when the attribute is an octet string of n bytes (copied to b), 0 when it
 * is null, -1 otherwise. */
static int read_bytes(struct matter_im_server *srv, uint32_t attr, uint8_t *b, size_t n)
{
	struct matter_tlv_reader r;
	uint8_t out[96];
	const uint8_t *p;
	size_t len = read_attr(srv, attr, out, sizeof(out)), got;

	matter_tlv_reader_init(&r, out, len);
	if (matter_tlv_next(&r) != MATTER_OK) {
		return -1;
	}
	if (matter_tlv_get_bytes(&r, &p, &got) == MATTER_OK) {
		if (got != n) {
			return -1;
		}
		memcpy(b, p, n);
		return 1;
	}
	return out[0] == 0x14u ? 0 : -1; /* a null element is control 0x14 */
}

struct fields {
	struct matter_tlv_writer w;
	uint8_t buf[256];
};

static void fields_begin(struct fields *f)
{
	matter_tlv_writer_init(&f->w, f->buf, sizeof(f->buf));
	(void)matter_tlv_start_container(&f->w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
}

static void fields_credential(struct fields *f, uint8_t tag, uint64_t type, uint64_t index)
{
	(void)matter_tlv_start_container(&f->w, MATTER_TLV_CTX(tag), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&f->w, MATTER_TLV_CTX(0u), type);
	(void)matter_tlv_put_u64(&f->w, MATTER_TLV_CTX(1u), index);
	(void)matter_tlv_end_container(&f->w);
}

static uint8_t invoke(struct matter_im_server *srv, uint32_t cmd, struct fields *f,
		      uint32_t *response)
{
	struct matter_im_invoke inv;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = EP;
	inv.cluster = CL;
	inv.command = cmd;
	if (f != NULL) {
		(void)matter_tlv_end_container(&f->w);
		inv.fields = f->buf;
		inv.fields_len = f->w.len;
		inv.has_fields = true;
	}
	*response = MATTER_IM_NO_RESPONSE;
	return srv->command(srv->ctx, &inv, response);
}

/* The response's fields, encoded by the cluster. */
static size_t response_fields(struct matter_im_server *srv, uint32_t response, uint8_t *out,
			      size_t cap)
{
	struct matter_tlv_writer w;

	matter_tlv_writer_init(&w, out, cap);
	srv->command_fields(srv->ctx, EP, CL, response, &w, MATTER_TLV_ANON);
	return w.len;
}

/* Field @p tag of an encoded structure: 1 with its unsigned value, 0 when it
 * is null, 2 when it is a container, -1 when absent. */
static int rsp_field(const uint8_t *buf, size_t len, uint8_t tag, uint64_t *v)
{
	struct matter_tlv_reader r;

	matter_tlv_reader_init(&r, buf, len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return -1;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(tag)) {
			continue;
		}
		if (matter_tlv_is_container(&r)) {
			return 2;
		}
		if (matter_tlv_get_u64(&r, v) == MATTER_OK) {
			return 1;
		}
		return 0;
	}
	return -1;
}

static int rsp_bool(const uint8_t *buf, size_t len, uint8_t tag, bool *v)
{
	struct matter_tlv_reader r;

	matter_tlv_reader_init(&r, buf, len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return -1;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_bool(&r, v) == MATTER_OK ? 1 : 0;
		}
	}
	return -1;
}

static size_t rsp_bytes_len(const uint8_t *buf, size_t len, uint8_t tag)
{
	struct matter_tlv_reader r;
	const uint8_t *p;
	size_t n;

	matter_tlv_reader_init(&r, buf, len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return 0u;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_bytes(&r, &p, &n) == MATTER_OK ? n : 0u;
		}
	}
	return 0u;
}

/* The CredentialStructs in GetUserResponse's Credentials list, as type*256+index. */
static size_t rsp_credentials(const uint8_t *buf, size_t len, uint32_t *out, size_t cap)
{
	struct matter_tlv_reader r;
	size_t n = 0u;

	matter_tlv_reader_init(&r, buf, len);
	if (matter_tlv_next(&r) != MATTER_OK || matter_tlv_enter(&r) != MATTER_OK) {
		return 0u;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(6u) || !matter_tlv_is_container(&r)) {
			continue;
		}
		if (matter_tlv_enter(&r) != MATTER_OK) {
			return 0u;
		}
		while (n < cap && matter_tlv_next(&r) == MATTER_OK) {
			uint64_t type = 0u, index = 0u;

			if (matter_tlv_enter(&r) != MATTER_OK) {
				return n;
			}
			while (matter_tlv_next(&r) == MATTER_OK) {
				if (matter_tlv_tag(&r) == MATTER_TLV_CTX(0u)) {
					(void)matter_tlv_get_u64(&r, &type);
				} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(1u)) {
					(void)matter_tlv_get_u64(&r, &index);
				}
			}
			(void)matter_tlv_exit(&r);
			out[n++] = (uint32_t)(type * 256u + index);
		}
		return n;
	}
	return 0u;
}

void test_tm_door_lock_aliro(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;
	uint8_t key[65], b[65], sub[16], sub2[16], rsp[256];
	uint32_t response;
	uint64_t v;
	size_t n;

	for (size_t i = 0u; i < sizeof(key); i++) {
		key[i] = (uint8_t)(0x40u + i);
	}
	memset(s_store, 0, sizeof(s_store));
	(void)matter_clusters_set_endpoints(&tm_door_lock_endpoint, 1u);
	admin_info(&info);
	tm_door_lock_aliro_configure(&k_hooks);
	matter_clusters_init(&srv, &info);
	tm_door_lock.init(EP);

	t_group("the reader attributes before any provisioning");
	{
		uint8_t out[64];

		T_EQ("verification key null", read_bytes(&srv, MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY,
							  b, 65u), 0);
		T_EQ("group id null", read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_ID, b, 16u), 0);
		T_EQ("group resolving key null",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY, b, 16u), 0);
		T_EQ("group sub id is 16 bytes",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID, sub, 16u), 1);
		tm_door_lock.init(EP);
		T_EQ("and the same after a reboot",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID, sub2, 16u), 1);
		T_OK("byte for byte", memcmp(sub, sub2, 16u) == 0);
		/* An array of one octet string, 01 00. */
		n = read_attr(&srv, MATTER_ATTR_DL_ALIRO_BLE_UWB_VERSIONS, out, sizeof(out));
		T_OK("BLE-UWB versions is [0x0100]",
		     n == 6u && out[0] == 0x16u && out[1] == 0x10u && out[2] == 2u &&
			     out[3] == 0x01u && out[4] == 0x00u && out[5] == 0x18u);
		n = read_attr(&srv, MATTER_ATTR_DL_ALIRO_ISSUER_KEYS_MAX, out, sizeof(out));
		T_OK("issuer keys max 5", n == 2u && out[1] == 5u);
		n = read_attr(&srv, MATTER_ATTR_DL_ALIRO_ENDPOINT_KEYS_MAX, out, sizeof(out));
		T_OK("endpoint keys max 6", n == 2u && out[1] == 6u);
		n = read_attr(&srv, MATTER_ATTR_DL_USERS_MAX, out, sizeof(out));
		T_OK("users max 10", n == 2u && out[1] == 10u);
	}

	t_group("SetAliroReaderConfig hands the identity to the reader");
	{
		struct fields f;
		uint8_t signing[32], group[16], grk[16];

		memset(signing, 0x11, sizeof(signing));
		memset(group, 0x22, sizeof(group));
		memset(grk, 0x33, sizeof(grk));

		fields_begin(&f);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(0u), signing, 31u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(1u), key, 65u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), group, 16u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(3u), grk, 16u);
		T_EQ("a short signing key", invoke(&srv, MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, &f,
						    &response), MATTER_IM_STATUS_CONSTRAINT_ERROR);
		fields_begin(&f);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(0u), signing, 32u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), group, 16u);
		T_EQ("a missing verification key",
		     invoke(&srv, MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, &f, &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		fields_begin(&f);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(0u), signing, 32u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(1u), key, 65u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), group, 16u);
		T_EQ("no GRK", invoke(&srv, MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, &f, &response),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("none of those reached the reader", s_config_calls, 0);

		fields_begin(&f);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(0u), signing, 32u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(1u), key, 65u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), group, 16u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(3u), grk, 16u);
		s_config_rc = -1;
		T_EQ("the reader refusing it is FAILURE",
		     invoke(&srv, MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, &f, &response),
		     MATTER_IM_STATUS_FAILURE);
		T_EQ("still null", read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_ID, b, 16u), 0);
		s_config_rc = 0;
		fields_begin(&f);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(0u), signing, 32u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(1u), key, 65u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), group, 16u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(3u), grk, 16u);
		T_EQ("the whole config", invoke(&srv, MATTER_CMD_DL_SET_ALIRO_READER_CONFIG, &f,
						 &response), MATTER_IM_STATUS_SUCCESS);
		T_EQ("a bare status", response, MATTER_IM_NO_RESPONSE);
		T_EQ("reached the reader once", s_config_calls, 2);
		T_OK("with the signing key", memcmp(s_signing, signing, 32u) == 0);
		T_OK("the group id", memcmp(s_group, group, 16u) == 0);
		T_OK("this lock's sub id", memcmp(s_sub, sub, 16u) == 0);
		T_OK("and the GRK", memcmp(s_grk, grk, 16u) == 0);
		T_OK("verification key reads back",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY, b, 65u) == 1 &&
			     memcmp(b, key, 65u) == 0);
		T_OK("group id reads back",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_ID, b, 16u) == 1 &&
			     memcmp(b, group, 16u) == 0);
		T_OK("GRK reads back",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY, b, 16u) == 1 &&
			     memcmp(b, grk, 16u) == 0);

		T_EQ("ClearAliroReaderConfig",
		     invoke(&srv, MATTER_CMD_DL_CLEAR_ALIRO_READER_CONFIG, NULL, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("told the reader", s_clear_calls, 1);
		T_EQ("verification key null again",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY, b, 65u), 0);
		T_EQ("GRK null again",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY, b, 16u), 0);

		tm_door_lock_aliro_set_identity(key, group, grk);
		T_OK("the reader's own identity after a reboot reads back",
		     read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_ID, b, 16u) == 1 &&
			     memcmp(b, group, 16u) == 0);
		tm_door_lock_aliro_set_identity(NULL, NULL, NULL);
		T_EQ("and none is null", read_bytes(&srv, MATTER_ATTR_DL_ALIRO_GROUP_ID, b, 16u), 0);
	}

	t_group("the user table");
	{
		struct fields f;

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 0u);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(1u), 0u);
		T_EQ("user index 0", invoke(&srv, MATTER_CMD_DL_SET_USER, &f, &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(1u), 11u);
		T_EQ("user index past the table", invoke(&srv, MATTER_CMD_DL_SET_USER, &f, &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 0u); /* Add */
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(1u), 1u);
		(void)matter_tlv_put_null(&f.w, MATTER_TLV_CTX(2u));   /* name */
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(3u), 0x1234u);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(4u), 1u);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(5u), 0u);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(6u), 0u);
		T_EQ("SetUser 1", invoke(&srv, MATTER_CMD_DL_SET_USER, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 1u);
		T_EQ("GetUser 1", invoke(&srv, MATTER_CMD_DL_GET_USER, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("answers with GetUserResponse", response, MATTER_CMD_DL_GET_USER_RESPONSE);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("index 1", rsp_field(rsp, n, 0u, &v) == 1 && v == 1u);
		T_EQ("name null", rsp_field(rsp, n, 1u, &v), 0);
		T_OK("unique id", rsp_field(rsp, n, 2u, &v) == 1 && v == 0x1234u);
		T_OK("status", rsp_field(rsp, n, 3u, &v) == 1 && v == 1u);
		T_OK("creator fabric", rsp_field(rsp, n, 7u, &v) == 1 && v == 1u);
		T_EQ("credentials is a list", rsp_field(rsp, n, 6u, &v), 2);
		T_EQ("next null", rsp_field(rsp, n, 9u, &v), 0);

		tm_door_lock.init(EP);
		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 1u);
		(void)invoke(&srv, MATTER_CMD_DL_GET_USER, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("the user survives a reboot", rsp_field(rsp, n, 2u, &v) == 1 && v == 0x1234u);

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 2u);
		(void)invoke(&srv, MATTER_CMD_DL_GET_USER, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("an empty slot: index", rsp_field(rsp, n, 0u, &v) == 1 && v == 2u);
		T_EQ("unique id null", rsp_field(rsp, n, 2u, &v), 0);
		T_EQ("credentials null", rsp_field(rsp, n, 6u, &v), 0);
	}

	t_group("credentials go to the reader's store");
	{
		struct fields f;
		uint32_t creds[4];
		bool exists = false;

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 0u);
		fields_credential(&f, 1u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 1u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), key, 65u);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(3u), 1u);
		T_EQ("SetCredential", invoke(&srv, MATTER_CMD_DL_SET_CREDENTIAL, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("answers with SetCredentialResponse", response,
		     MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("status Success", rsp_field(rsp, n, 0u, &v) == 1 && v == 0u);
		T_OK("user index 1", rsp_field(rsp, n, 1u, &v) == 1 && v == 1u);
		T_EQ("next null", rsp_field(rsp, n, 2u, &v), 0);
		T_OK("stored at (7, 1) under user 1",
		     find(7u, 1u) != NULL && find(7u, 1u)->user == 1u &&
			     memcmp(find(7u, 1u)->key, key, 65u) == 0);

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 0u);
		fields_credential(&f, 1u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 1u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), key, 65u);
		(void)invoke(&srv, MATTER_CMD_DL_SET_CREDENTIAL, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("Add on a taken index: Occupied", rsp_field(rsp, n, 0u, &v) == 1 && v == 3u);

		key[5] ^= 0xFFu;
		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 2u); /* Modify */
		fields_credential(&f, 1u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 1u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), key, 65u);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(3u), 1u);
		(void)invoke(&srv, MATTER_CMD_DL_SET_CREDENTIAL, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("Modify replaces it", rsp_field(rsp, n, 0u, &v) == 1 && v == 0u &&
					    find(7u, 1u) != NULL &&
					    memcmp(find(7u, 1u)->key, key, 65u) == 0);

		fields_begin(&f);
		fields_credential(&f, 1u, 2u, 1u); /* RFID */
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), key, 65u);
		(void)invoke(&srv, MATTER_CMD_DL_SET_CREDENTIAL, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("a credential type this lock has not: InvalidField",
		     rsp_field(rsp, n, 0u, &v) == 1 && v == 0x85u);
		fields_begin(&f);
		fields_credential(&f, 1u, MATTER_DL_CRED_ALIRO_ISSUER_KEY, 1u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), key, 64u);
		(void)invoke(&srv, MATTER_CMD_DL_SET_CREDENTIAL, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("a 64-byte key: InvalidField", rsp_field(rsp, n, 0u, &v) == 1 && v == 0x85u);

		fields_begin(&f);
		fields_credential(&f, 0u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 1u);
		T_EQ("GetCredentialStatus", invoke(&srv, MATTER_CMD_DL_GET_CREDENTIAL_STATUS, &f,
						    &response), MATTER_IM_STATUS_SUCCESS);
		T_EQ("answers with its response", response,
		     MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("exists", rsp_bool(rsp, n, 0u, &exists) == 1 && exists);
		T_OK("under user 1", rsp_field(rsp, n, 1u, &v) == 1 && v == 1u);
		T_EQ("with the key", rsp_bytes_len(rsp, n, 5u), 65u);
		fields_begin(&f);
		fields_credential(&f, 0u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 2u);
		(void)invoke(&srv, MATTER_CMD_DL_GET_CREDENTIAL_STATUS, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("an empty index does not exist", rsp_bool(rsp, n, 0u, &exists) == 1 && !exists);
		T_EQ("and carries no key", rsp_bytes_len(rsp, n, 5u), 0u);

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 1u);
		(void)invoke(&srv, MATTER_CMD_DL_GET_USER, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("GetUser lists the credential", rsp_credentials(rsp, n, creds, 4u) == 1u &&
						     creds[0] == 7u * 256u + 1u);

		fields_begin(&f);
		fields_credential(&f, 0u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 1u);
		T_EQ("ClearCredential", invoke(&srv, MATTER_CMD_DL_CLEAR_CREDENTIAL, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("gone from the store", find(7u, 1u) == NULL);
		fields_begin(&f);
		(void)matter_tlv_put_null(&f.w, MATTER_TLV_CTX(0u));
		T_EQ("ClearCredential with a null credential",
		     invoke(&srv, MATTER_CMD_DL_CLEAR_CREDENTIAL, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("asks for every type and index",
		     s_clear_type == 0u && s_clear_index == MATTER_DL_INDEX_ALL);
		fields_begin(&f);
		fields_credential(&f, 0u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 0u);
		T_EQ("index 0", invoke(&srv, MATTER_CMD_DL_CLEAR_CREDENTIAL, &f, &response),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 1u);
		T_EQ("ClearUser 1", invoke(&srv, MATTER_CMD_DL_CLEAR_USER, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("told the reader", s_user_clear_calls == 1 && s_user_cleared == 1u);
		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), 1u);
		(void)invoke(&srv, MATTER_CMD_DL_GET_USER, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_EQ("and the slot is empty", rsp_field(rsp, n, 2u, &v), 0);
		fields_begin(&f);
		(void)matter_tlv_put_u64(&f.w, MATTER_TLV_CTX(0u), MATTER_DL_INDEX_ALL);
		T_EQ("ClearUser all", invoke(&srv, MATTER_CMD_DL_CLEAR_USER, &f, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_OK("passed through", s_user_cleared == MATTER_DL_INDEX_ALL);
	}

	t_group("without hooks the provisioning commands fail closed");
	{
		struct fields f;

		tm_door_lock_aliro_configure(NULL);
		T_EQ("ClearAliroReaderConfig",
		     invoke(&srv, MATTER_CMD_DL_CLEAR_ALIRO_READER_CONFIG, NULL, &response),
		     MATTER_IM_STATUS_FAILURE);
		fields_begin(&f);
		fields_credential(&f, 1u, MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT, 1u);
		(void)matter_tlv_put_bytes(&f.w, MATTER_TLV_CTX(2u), key, 65u);
		(void)invoke(&srv, MATTER_CMD_DL_SET_CREDENTIAL, &f, &response);
		n = response_fields(&srv, response, rsp, sizeof(rsp));
		T_OK("SetCredential: Failure", rsp_field(rsp, n, 0u, &v) == 1 && v == 1u);
		T_EQ("LockDoor still works", invoke(&srv, MATTER_CMD_DL_LOCK_DOOR, NULL, &response),
		     MATTER_IM_STATUS_SUCCESS);
		(void)tm_door_lock_erase();
	}
}

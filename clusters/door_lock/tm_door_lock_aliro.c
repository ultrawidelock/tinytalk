/* SPDX-License-Identifier: ISC */

/*
 * See tm_door_lock.h, the Aliro block. The user table and what a controller
 * may read back of the reader identity live here; the keys themselves go to
 * the application's reader through the hooks and are never kept.
 *
 * Responses are encoded after the command ran, by a pure encoder, so what a
 * response needs (the user index GetUser asked for, the status SetCredential
 * decided) is held in statics between the two.
 */
#include "tm_door_lock_aliro.h"

#include <errno.h>
#include <string.h>

#include <tinytalk/matter_im.h>
#include <tinytalk/tm_hash.h>
#include <tinytalk/tm_kv.h>
#include <tinytalk/tm_platform.h>

/* DlStatus (DoorLock/Enums.h), what SetCredentialResponse carries. */
#define DL_STATUS_SUCCESS            0x00u
#define DL_STATUS_FAILURE            0x01u
#define DL_STATUS_OCCUPIED           0x03u
#define DL_STATUS_INVALID_FIELD      0x85u
#define DL_STATUS_RESOURCE_EXHAUSTED 0x89u

/* DataOperationTypeEnum. */
#define DL_DATA_OP_ADD    0u
#define DL_DATA_OP_CLEAR  1u
#define DL_DATA_OP_MODIFY 2u

/* Command fields (DoorLock/Commands.h). */
#define TAG_SETUSER_OPERATION     0u
#define TAG_SETUSER_INDEX         1u
#define TAG_SETUSER_UNIQUE_ID     3u
#define TAG_SETUSER_STATUS        4u
#define TAG_SETUSER_TYPE          5u
#define TAG_SETUSER_RULE          6u
#define TAG_GETUSER_INDEX         0u
#define TAG_CLEARUSER_INDEX       0u
#define TAG_SETCRED_OPERATION     0u
#define TAG_SETCRED_CREDENTIAL    1u
#define TAG_SETCRED_DATA          2u
#define TAG_SETCRED_USER_INDEX    3u
#define TAG_GETCRED_CREDENTIAL    0u
#define TAG_CLEARCRED_CREDENTIAL  0u
#define TAG_CREDSTRUCT_TYPE       0u
#define TAG_CREDSTRUCT_INDEX      1u
#define TAG_READERCFG_SIGNING     0u
#define TAG_READERCFG_VERIFYING   1u
#define TAG_READERCFG_GROUP_ID    2u
#define TAG_READERCFG_GRK         3u

/* Response fields. */
#define TAG_GETUSERRSP_INDEX      0u
#define TAG_GETUSERRSP_NAME       1u
#define TAG_GETUSERRSP_UNIQUE_ID  2u
#define TAG_GETUSERRSP_STATUS     3u
#define TAG_GETUSERRSP_TYPE       4u
#define TAG_GETUSERRSP_RULE       5u
#define TAG_GETUSERRSP_CREDS      6u
#define TAG_GETUSERRSP_CREATOR    7u
#define TAG_GETUSERRSP_MODIFIER   8u
#define TAG_GETUSERRSP_NEXT       9u
#define TAG_SETCREDRSP_STATUS     0u
#define TAG_SETCREDRSP_USER_INDEX 1u
#define TAG_SETCREDRSP_NEXT       2u
#define TAG_CREDSTATUS_EXISTS     0u
#define TAG_CREDSTATUS_USER_INDEX 1u
#define TAG_CREDSTATUS_CREATOR    2u
#define TAG_CREDSTATUS_MODIFIER   3u
#define TAG_CREDSTATUS_NEXT       4u
#define TAG_CREDSTATUS_DATA       5u

/* Credential indices a lookup walks: the reader holds at most
 * MATTER_ALIRO_ENDPOINT_KEYS_MAX of a type. */
#define CRED_INDEX_MAX MATTER_ALIRO_ENDPOINT_KEYS_MAX

struct user {
	uint32_t unique_id;
	uint8_t status;
	uint8_t type;
	uint8_t rule;
	uint8_t creator;
	uint8_t modifier;
	uint8_t in_use;
};
#define USER_BLOB 10u

static const struct tm_door_lock_aliro_hooks *s_hooks;
static struct user s_users[MATTER_DL_USERS_MAX];

/* The reader identity a controller may read back. */
static uint8_t s_verification_key[MATTER_ALIRO_VERIFICATION_KEY_LEN];
static uint8_t s_group_id[MATTER_ALIRO_GROUP_ID_LEN];
static uint8_t s_group_sub_id[MATTER_ALIRO_GROUP_ID_LEN];
static uint8_t s_grk[MATTER_ALIRO_GROUP_ID_LEN];
static bool s_have_config, s_have_grk;

/* Held for the response encoders. */
static uint16_t s_last_user;
static uint8_t s_cred_status, s_cred_type;
static uint16_t s_cred_user, s_cred_index;

/* ---- fields ------------------------------------------------------------------ */

/* Position r on field @p tag of the structure @p fields. */
static bool field_find(struct matter_tlv_reader *r, const uint8_t *fields, size_t len, uint8_t tag)
{
	if (fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(r, fields, len);
	if (matter_tlv_next(r) != MATTER_OK || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	while (matter_tlv_next(r) == MATTER_OK) {
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(tag)) {
			return true;
		}
	}
	return false;
}

static bool field_u64(const uint8_t *fields, size_t len, uint8_t tag, uint64_t *out)
{
	struct matter_tlv_reader r;

	return field_find(&r, fields, len, tag) && matter_tlv_get_u64(&r, out) == MATTER_OK;
}

static bool field_bytes(const uint8_t *fields, size_t len, uint8_t tag, const uint8_t **out,
			size_t *out_len)
{
	struct matter_tlv_reader r;

	return field_find(&r, fields, len, tag) && matter_tlv_get_bytes(&r, out, out_len) == MATTER_OK;
}

/* A CredentialStruct in field @p tag: type and index. False when the field is
 * absent or null. */
static bool field_credential(const uint8_t *fields, size_t len, uint8_t tag, uint64_t *type,
			     uint64_t *index)
{
	struct matter_tlv_reader r;
	bool have_type = false, have_index = false;

	if (!field_find(&r, fields, len, tag) || !matter_tlv_is_container(&r) ||
	    matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_CREDSTRUCT_TYPE)) {
			have_type = matter_tlv_get_u64(&r, type) == MATTER_OK;
		} else if (matter_tlv_tag(&r) == MATTER_TLV_CTX(TAG_CREDSTRUCT_INDEX)) {
			have_index = matter_tlv_get_u64(&r, index) == MATTER_OK;
		}
	}
	return have_type && have_index;
}

static bool aliro_type(uint64_t type)
{
	return type == MATTER_DL_CRED_ALIRO_ISSUER_KEY ||
	       type == MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT ||
	       type == MATTER_DL_CRED_ALIRO_NONEVICTABLE_ENDPOINT;
}

/* ---- the user table ------------------------------------------------------------ */

static void users_pack(uint8_t out[MATTER_DL_USERS_MAX * USER_BLOB])
{
	for (size_t i = 0u; i < MATTER_DL_USERS_MAX; i++) {
		uint8_t *p = out + i * USER_BLOB;

		for (size_t j = 0u; j < 4u; j++) {
			p[j] = (uint8_t)(s_users[i].unique_id >> (8u * j));
		}
		p[4] = s_users[i].status;
		p[5] = s_users[i].type;
		p[6] = s_users[i].rule;
		p[7] = s_users[i].creator;
		p[8] = s_users[i].modifier;
		p[9] = s_users[i].in_use;
	}
}

static void users_unpack(const uint8_t in[MATTER_DL_USERS_MAX * USER_BLOB])
{
	for (size_t i = 0u; i < MATTER_DL_USERS_MAX; i++) {
		const uint8_t *p = in + i * USER_BLOB;

		s_users[i].unique_id = 0u;
		for (size_t j = 0u; j < 4u; j++) {
			s_users[i].unique_id |= (uint32_t)p[j] << (8u * j);
		}
		s_users[i].status = p[4];
		s_users[i].type = p[5];
		s_users[i].rule = p[6];
		s_users[i].creator = p[7];
		s_users[i].modifier = p[8];
		s_users[i].in_use = p[9] != 0u;
	}
}

/*
 * Stored before the command is acknowledged, in the command path: Apple
 * writes a user and reads it straight back, and after a reboot too, so a
 * table that lives only in RAM tells it two different things. Provisioning is
 * rare, so the flash write under the lock is a price paid a few times.
 */
static int users_store(void)
{
	uint8_t blob[MATTER_DL_USERS_MAX * USER_BLOB];

	users_pack(blob);
	return tm_kv_set(TM_KV_KEY_MATTER_DL_USERS, blob, sizeof(blob)) == TM_KV_OK ? 0 : -EIO;
}

/* ---- attributes ---------------------------------------------------------------- */

static void put_versions(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	static const uint8_t version[2] = { (uint8_t)(MATTER_ALIRO_PROTOCOL_VERSION >> 8),
					    (uint8_t)MATTER_ALIRO_PROTOCOL_VERSION };

	/* A list of octet strings, each one version big-endian, not a list of
	 * integers (DoorLock/Attributes.h, AliroBLEUWBProtocolVersions). */
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	(void)matter_tlv_put_bytes(w, MATTER_TLV_ANON, version, sizeof(version));
	(void)matter_tlv_end_container(w);
}

static void put_nullable_bytes(struct matter_tlv_writer *w, matter_tlv_tag_t tag, bool have,
			       const uint8_t *b, size_t len)
{
	if (have) {
		(void)matter_tlv_put_bytes(w, tag, b, len);
	} else {
		(void)matter_tlv_put_null(w, tag);
	}
}

void tm_dl_aliro_read(uint32_t attr, struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	switch (attr) {
	case MATTER_ATTR_DL_USERS_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_USERS_MAX);
		return;
	case MATTER_ATTR_DL_CREDENTIAL_RULES:
		/* Single (bit 0): one credential opens the door. */
		(void)matter_tlv_put_u64(w, tag, 0x01u);
		return;
	case MATTER_ATTR_DL_CREDS_PER_USER_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_DL_CREDS_PER_USER_MAX);
		return;
	case MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY:
		put_nullable_bytes(w, tag, s_have_config, s_verification_key,
				   sizeof(s_verification_key));
		return;
	case MATTER_ATTR_DL_ALIRO_GROUP_ID:
		put_nullable_bytes(w, tag, s_have_config, s_group_id, sizeof(s_group_id));
		return;
	case MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID:
		/* Never null: it is this lock's own, derived at init. */
		(void)matter_tlv_put_bytes(w, tag, s_group_sub_id, sizeof(s_group_sub_id));
		return;
	case MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY:
		put_nullable_bytes(w, tag, s_have_grk, s_grk, sizeof(s_grk));
		return;
	case MATTER_ATTR_DL_ALIRO_EXPEDITED_VERSIONS:
	case MATTER_ATTR_DL_ALIRO_BLE_UWB_VERSIONS:
		put_versions(w, tag);
		return;
	case MATTER_ATTR_DL_ALIRO_BLE_ADV_VERSION:
		(void)matter_tlv_put_u64(w, tag, MATTER_ALIRO_BLE_ADV_VERSION);
		return;
	case MATTER_ATTR_DL_ALIRO_ISSUER_KEYS_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_ALIRO_ISSUER_KEYS_MAX);
		return;
	case MATTER_ATTR_DL_ALIRO_ENDPOINT_KEYS_MAX:
		(void)matter_tlv_put_u64(w, tag, MATTER_ALIRO_ENDPOINT_KEYS_MAX);
		return;
	default:
		return;
	}
}

static void identity_changed(uint16_t endpoint)
{
	tm_attr_changed(endpoint, MATTER_CLUSTER_DOOR_LOCK, MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY);
	tm_attr_changed(endpoint, MATTER_CLUSTER_DOOR_LOCK, MATTER_ATTR_DL_ALIRO_GROUP_ID);
	tm_attr_changed(endpoint, MATTER_CLUSTER_DOOR_LOCK,
			MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY);
}

/* ---- commands ------------------------------------------------------------------ */

static uint8_t set_reader_config(const struct tm_req *req, const uint8_t *fields, size_t len)
{
	const uint8_t *signing, *verifying, *group, *grk;
	size_t signing_len, verifying_len, group_len, grk_len;

	if (!field_bytes(fields, len, TAG_READERCFG_SIGNING, &signing, &signing_len) ||
	    !field_bytes(fields, len, TAG_READERCFG_VERIFYING, &verifying, &verifying_len) ||
	    !field_bytes(fields, len, TAG_READERCFG_GROUP_ID, &group, &group_len)) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (signing_len != MATTER_ALIRO_SIGNING_KEY_LEN ||
	    verifying_len != MATTER_ALIRO_VERIFICATION_KEY_LEN ||
	    group_len != MATTER_ALIRO_GROUP_ID_LEN) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}
	/* Optional in the schema, required by the BLE_UWB feature this cluster
	 * claims: without a GRK no phone can resolve the advertisement. */
	if (!field_bytes(fields, len, TAG_READERCFG_GRK, &grk, &grk_len) ||
	    grk_len != MATTER_ALIRO_GROUP_ID_LEN) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}
	if (s_hooks == NULL || s_hooks->reader_config == NULL ||
	    s_hooks->reader_config(signing, verifying, group, s_group_sub_id, grk) != 0) {
		return MATTER_IM_STATUS_FAILURE;
	}
	memcpy(s_verification_key, verifying, sizeof(s_verification_key));
	memcpy(s_group_id, group, sizeof(s_group_id));
	memcpy(s_grk, grk, sizeof(s_grk));
	s_have_config = true;
	s_have_grk = true;
	identity_changed(req->endpoint);
	return MATTER_IM_STATUS_SUCCESS;
}

static uint8_t clear_reader_config(const struct tm_req *req)
{
	if (s_hooks == NULL || s_hooks->reader_clear == NULL || s_hooks->reader_clear() != 0) {
		return MATTER_IM_STATUS_FAILURE;
	}
	memset(s_verification_key, 0, sizeof(s_verification_key));
	memset(s_group_id, 0, sizeof(s_group_id));
	memset(s_grk, 0, sizeof(s_grk));
	s_have_config = false;
	s_have_grk = false;
	identity_changed(req->endpoint);
	return MATTER_IM_STATUS_SUCCESS;
}

/*
 * Always answered with SetCredentialResponse: the verdict travels in its
 * Status (DlStatus), and the IM status is SUCCESS even for a refusal.
 */
static uint8_t set_credential(const uint8_t *fields, size_t len, uint32_t *response)
{
	uint64_t op = DL_DATA_OP_ADD, type = 0u, index = 0u, user = 0u;
	const uint8_t *key;
	size_t key_len;
	uint8_t probe[MATTER_ALIRO_VERIFICATION_KEY_LEN];
	int rc;

	*response = MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE;
	s_cred_status = DL_STATUS_FAILURE;
	s_cred_user = 0u;
	(void)field_u64(fields, len, TAG_SETCRED_OPERATION, &op);
	if (!field_credential(fields, len, TAG_SETCRED_CREDENTIAL, &type, &index) ||
	    !field_bytes(fields, len, TAG_SETCRED_DATA, &key, &key_len) || !aliro_type(type) ||
	    index == 0u || index > 0xFFFFu) {
		s_cred_status = DL_STATUS_INVALID_FIELD;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (key_len != MATTER_ALIRO_VERIFICATION_KEY_LEN) {
		s_cred_status = DL_STATUS_INVALID_FIELD;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (field_u64(fields, len, TAG_SETCRED_USER_INDEX, &user) && user > 0xFFFFu) {
		s_cred_status = DL_STATUS_INVALID_FIELD;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (s_hooks == NULL || s_hooks->credential_set == NULL ||
	    s_hooks->credential_lookup == NULL) {
		return MATTER_IM_STATUS_SUCCESS;
	}
	/* An index already holding a key: Add refuses it (Occupied), Modify
	 * replaces it. */
	if (s_hooks->credential_lookup((uint8_t)type, (uint16_t)index, probe) >= 0) {
		if (op != DL_DATA_OP_MODIFY) {
			s_cred_status = DL_STATUS_OCCUPIED;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (s_hooks->credential_clear == NULL ||
		    s_hooks->credential_clear((uint8_t)type, (uint16_t)index) != 0) {
			return MATTER_IM_STATUS_SUCCESS;
		}
	}
	rc = s_hooks->credential_set((uint8_t)type, key, (uint16_t)index, (uint16_t)user);
	if (rc < 0) {
		s_cred_status = rc == -ENOSPC ? DL_STATUS_RESOURCE_EXHAUSTED : DL_STATUS_FAILURE;
		return MATTER_IM_STATUS_SUCCESS;
	}
	s_cred_status = DL_STATUS_SUCCESS;
	s_cred_user = (uint16_t)user;
	return MATTER_IM_STATUS_SUCCESS;
}

static uint8_t clear_credential(const uint8_t *fields, size_t len)
{
	uint64_t type = 0u, index = 0u;
	struct matter_tlv_reader r;

	if (s_hooks == NULL || s_hooks->credential_clear == NULL) {
		return MATTER_IM_STATUS_FAILURE;
	}
	/* A null Credential, or none: every credential of every type. */
	if (!field_find(&r, fields, len, TAG_CLEARCRED_CREDENTIAL) || !matter_tlv_is_container(&r)) {
		return s_hooks->credential_clear(0u, MATTER_DL_INDEX_ALL) == 0
			       ? MATTER_IM_STATUS_SUCCESS
			       : MATTER_IM_STATUS_FAILURE;
	}
	if (!field_credential(fields, len, TAG_CLEARCRED_CREDENTIAL, &type, &index) ||
	    !aliro_type(type) || index == 0u || index > 0xFFFFu) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	return s_hooks->credential_clear((uint8_t)type, (uint16_t)index) == 0
		       ? MATTER_IM_STATUS_SUCCESS
		       : MATTER_IM_STATUS_FAILURE;
}

static uint8_t get_credential_status(const uint8_t *fields, size_t len, uint32_t *response)
{
	uint64_t type = 0u, index = 0u;

	if (!field_credential(fields, len, TAG_GETCRED_CREDENTIAL, &type, &index) ||
	    type > 0xFFu || index > 0xFFFFu) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	s_cred_type = (uint8_t)type;
	s_cred_index = (uint16_t)index;
	*response = MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE;
	return MATTER_IM_STATUS_SUCCESS;
}

static uint8_t set_user(const struct tm_req *req, const uint8_t *fields, size_t len)
{
	uint64_t op = DL_DATA_OP_ADD, index = 0u, unique_id = 0u, status = 1u, type = 0u,
		 rule = 0u;
	struct user prev, *u;

	(void)field_u64(fields, len, TAG_SETUSER_OPERATION, &op);
	if (!field_u64(fields, len, TAG_SETUSER_INDEX, &index) || index == 0u ||
	    index > MATTER_DL_USERS_MAX) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	u = &s_users[index - 1u];
	prev = *u;
	if (op == DL_DATA_OP_CLEAR) {
		memset(u, 0, sizeof(*u));
	} else {
		/* The name (field 2) is nullable, nothing here shows it, and it
		 * is the one field that would cost real RAM: not kept. */
		(void)field_u64(fields, len, TAG_SETUSER_UNIQUE_ID, &unique_id);
		(void)field_u64(fields, len, TAG_SETUSER_STATUS, &status);
		(void)field_u64(fields, len, TAG_SETUSER_TYPE, &type);
		(void)field_u64(fields, len, TAG_SETUSER_RULE, &rule);
		u->unique_id = (uint32_t)unique_id;
		u->status = (uint8_t)status;
		u->type = (uint8_t)type;
		u->rule = (uint8_t)rule;
		if (op != DL_DATA_OP_MODIFY || !prev.in_use) {
			u->creator = req->fabric_index;
		}
		u->modifier = req->fabric_index;
		u->in_use = 1u;
	}
	if (users_store() != 0) {
		*u = prev;
		return MATTER_IM_STATUS_FAILURE;
	}
	return MATTER_IM_STATUS_SUCCESS;
}

static uint8_t get_user(const uint8_t *fields, size_t len, uint32_t *response)
{
	uint64_t index = 0u;

	if (!field_u64(fields, len, TAG_GETUSER_INDEX, &index) || index == 0u ||
	    index > MATTER_DL_USERS_MAX) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	s_last_user = (uint16_t)index;
	*response = MATTER_CMD_DL_GET_USER_RESPONSE;
	return MATTER_IM_STATUS_SUCCESS;
}

/*
 * A controller may remove a person without naming their credentials: the
 * reference server clears a user's credentials with the user, so the reader
 * is told too, or it keeps opening for someone the admin removed.
 */
static uint8_t clear_user(const uint8_t *fields, size_t len)
{
	uint64_t index = 0u;
	struct user prev[MATTER_DL_USERS_MAX];

	if (!field_u64(fields, len, TAG_CLEARUSER_INDEX, &index) || index == 0u ||
	    (index > MATTER_DL_USERS_MAX && index != MATTER_DL_INDEX_ALL)) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (s_hooks == NULL || s_hooks->user_clear == NULL) {
		return MATTER_IM_STATUS_FAILURE;
	}
	memcpy(prev, s_users, sizeof(prev));
	if (index == MATTER_DL_INDEX_ALL) {
		memset(s_users, 0, sizeof(s_users));
	} else {
		memset(&s_users[index - 1u], 0, sizeof(s_users[0]));
	}
	if (s_hooks->user_clear((uint16_t)index) != 0 || users_store() != 0) {
		memcpy(s_users, prev, sizeof(prev));
		return MATTER_IM_STATUS_FAILURE;
	}
	return MATTER_IM_STATUS_SUCCESS;
}

uint8_t tm_dl_aliro_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			   size_t len, uint32_t *response)
{
	switch (cmd) {
	case MATTER_CMD_DL_SET_USER:
		return set_user(req, fields, len);
	case MATTER_CMD_DL_GET_USER:
		return get_user(fields, len, response);
	case MATTER_CMD_DL_CLEAR_USER:
		return clear_user(fields, len);
	case MATTER_CMD_DL_SET_CREDENTIAL:
		return set_credential(fields, len, response);
	case MATTER_CMD_DL_GET_CREDENTIAL_STATUS:
		return get_credential_status(fields, len, response);
	case MATTER_CMD_DL_CLEAR_CREDENTIAL:
		return clear_credential(fields, len);
	case MATTER_CMD_DL_SET_ALIRO_READER_CONFIG:
		return set_reader_config(req, fields, len);
	case MATTER_CMD_DL_CLEAR_ALIRO_READER_CONFIG:
		return clear_reader_config(req);
	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/* ---- responses ----------------------------------------------------------------- */

static void put_u64_or_null(struct matter_tlv_writer *w, matter_tlv_tag_t tag, bool have,
			    uint64_t v)
{
	if (have) {
		(void)matter_tlv_put_u64(w, tag, v);
	} else {
		(void)matter_tlv_put_null(w, tag);
	}
}

/* The credentials filed under @p user, as CredentialStructs. */
static void put_user_credentials(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint16_t user)
{
	static const uint8_t k_types[] = { MATTER_DL_CRED_ALIRO_ISSUER_KEY,
					   MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT,
					   MATTER_DL_CRED_ALIRO_NONEVICTABLE_ENDPOINT };
	uint8_t key[MATTER_ALIRO_VERIFICATION_KEY_LEN];

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	if (s_hooks != NULL && s_hooks->credential_lookup != NULL) {
		for (size_t t = 0u; t < sizeof(k_types); t++) {
			for (uint16_t i = 1u; i <= CRED_INDEX_MAX; i++) {
				if (s_hooks->credential_lookup(k_types[t], i, key) != (int)user) {
					continue;
				}
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CREDSTRUCT_TYPE),
							 k_types[t]);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CREDSTRUCT_INDEX), i);
				(void)matter_tlv_end_container(w);
			}
		}
	}
	(void)matter_tlv_end_container(w);
}

static void get_user_response(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct user *u = &s_users[s_last_user - 1u];
	bool in = u->in_use != 0u;

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_GETUSERRSP_INDEX), s_last_user);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_NAME));
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_UNIQUE_ID), in, u->unique_id);
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_STATUS), in, u->status);
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_TYPE), in, u->type);
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_RULE), in, u->rule);
	if (in) {
		put_user_credentials(w, MATTER_TLV_CTX(TAG_GETUSERRSP_CREDS), s_last_user);
	} else {
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_CREDS));
	}
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_CREATOR), in, u->creator);
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_MODIFIER), in, u->modifier);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_GETUSERRSP_NEXT));
	(void)matter_tlv_end_container(w);
}

static void set_credential_response(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_SETCREDRSP_STATUS), s_cred_status);
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_SETCREDRSP_USER_INDEX), s_cred_user != 0u,
			s_cred_user);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_SETCREDRSP_NEXT));
	(void)matter_tlv_end_container(w);
}

static void credential_status_response(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	uint8_t key[MATTER_ALIRO_VERIFICATION_KEY_LEN];
	int user = -1;

	if (s_hooks != NULL && s_hooks->credential_lookup != NULL) {
		user = s_hooks->credential_lookup(s_cred_type, s_cred_index, key);
	}
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(w, MATTER_TLV_CTX(TAG_CREDSTATUS_EXISTS), user >= 0);
	put_u64_or_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_USER_INDEX), user > 0, (uint64_t)user);
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_CREATOR));
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_MODIFIER));
	(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CREDSTATUS_NEXT));
	if (user >= 0) {
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_CREDSTATUS_DATA), key, sizeof(key));
	}
	(void)matter_tlv_end_container(w);
}

void tm_dl_aliro_response(const struct tm_req *req, uint32_t response,
			  struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)req;
	switch (response) {
	case MATTER_CMD_DL_GET_USER_RESPONSE:
		get_user_response(w, tag);
		return;
	case MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE:
		set_credential_response(w, tag);
		return;
	case MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE:
		credential_status_response(w, tag);
		return;
	default:
		return;
	}
}

/* ---- bring-up ------------------------------------------------------------------ */

void tm_door_lock_aliro_configure(const struct tm_door_lock_aliro_hooks *hooks)
{
	s_hooks = hooks;
}

void tm_door_lock_aliro_set_identity(const uint8_t verification_key[MATTER_ALIRO_VERIFICATION_KEY_LEN],
				     const uint8_t group_id[MATTER_ALIRO_GROUP_ID_LEN],
				     const uint8_t grk[MATTER_ALIRO_GROUP_ID_LEN])
{
	tm_lock();
	s_have_config = verification_key != NULL && group_id != NULL;
	s_have_grk = grk != NULL;
	if (s_have_config) {
		memcpy(s_verification_key, verification_key, sizeof(s_verification_key));
		memcpy(s_group_id, group_id, sizeof(s_group_id));
	}
	if (s_have_grk) {
		memcpy(s_grk, grk, sizeof(s_grk));
	}
	tm_unlock();
}

/*
 * The group sub identifier is this lock's half of the reader identity, and
 * it has to be the same after every reboot: a controller that reads another
 * one is entitled to treat this as a different reader. Derived from the
 * device id rather than drawn and stored, so nothing can lose it.
 */
void tm_dl_aliro_init(void)
{
	static const char k_domain[] = "tinytalk-aliro-group-sub-id";
	uint8_t blob[MATTER_DL_USERS_MAX * USER_BLOB], id[8], digest[TM_SHA256_LEN];
	struct tm_sha256 h;
	size_t len = sizeof(blob);

	tm_device_id(id);
	tm_sha256_init(&h);
	tm_sha256_update(&h, k_domain, sizeof(k_domain) - 1u);
	tm_sha256_update(&h, id, sizeof(id));
	tm_sha256_final(&h, digest);
	memcpy(s_group_sub_id, digest, sizeof(s_group_sub_id));

	memset(s_users, 0, sizeof(s_users));
	if (tm_kv_get(TM_KV_KEY_MATTER_DL_USERS, blob, &len) == TM_KV_OK && len == sizeof(blob)) {
		users_unpack(blob);
	}
}

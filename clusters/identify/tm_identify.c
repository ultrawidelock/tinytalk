/* SPDX-License-Identifier: Apache-2.0 */

/*
 * See tm_identify.h. One Identify per node: the state is this file's.
 *
 * IdentifyTime counts down without a timer: the node keeps the moment
 * identification ends and a read reports the seconds left, rounded up.
 */
#include <tinytalk/tm_identify.h>

#include <tinytalk/matter_im.h>
#include <tinytalk/tm_platform.h>

/* Command fields (identify-cluster.xml). */
#define TAG_IDENTIFY_TIME    0u
#define TAG_EFFECT_ID        0u
#define TAG_EFFECT_VARIANT   1u

static const uint32_t k_identify_attrs[] = {
	MATTER_ATTR_IDENTIFY_TIME,
	MATTER_ATTR_IDENTIFY_TYPE,
	MATTER_ATTR_FEATURE_MAP,
	MATTER_ATTR_CLUSTER_REVISION,
	MATTER_ATTR_ATTRIBUTE_LIST,
	MATTER_ATTR_ACCEPTED_CMD_LIST,
	MATTER_ATTR_GENERATED_CMD_LIST,
};

static const uint32_t k_identify_accepted[] = {
	MATTER_CMD_IDENTIFY,
	MATTER_CMD_TRIGGER_EFFECT,
};

static uint8_t s_type = MATTER_IDENTIFY_TYPE_NONE;
static const struct tm_identify_hooks *s_hooks;
/* When identification ends, in tm_uptime_ms() terms; 0 when not identifying. */
static int64_t s_until_ms;

void tm_identify_configure(uint8_t identify_type, const struct tm_identify_hooks *hooks)
{
	s_type = identify_type;
	s_hooks = hooks;
}

static uint16_t seconds_left(void)
{
	int64_t left = s_until_ms - tm_uptime_ms();

	if (s_until_ms == 0 || left <= 0) {
		return 0u;
	}
	left = (left + 999) / 1000;
	return left > UINT16_MAX ? UINT16_MAX : (uint16_t)left;
}

static void identify_for(uint16_t endpoint, uint16_t seconds)
{
	s_until_ms = seconds == 0u ? 0 : tm_uptime_ms() + (int64_t)seconds * 1000;
	if (s_hooks != NULL && s_hooks->identify != NULL) {
		s_hooks->identify(endpoint, seconds);
	}
	tm_attr_changed(endpoint, MATTER_CLUSTER_IDENTIFY, MATTER_ATTR_IDENTIFY_TIME);
}

static void identify_read(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
			  matter_tlv_tag_t tag)
{
	(void)req;
	if (attr == MATTER_ATTR_IDENTIFY_TIME) {
		(void)matter_tlv_put_u64(w, tag, seconds_left());
	} else if (attr == MATTER_ATTR_IDENTIFY_TYPE) {
		(void)matter_tlv_put_u64(w, tag, s_type);
	}
}

/* One unsigned field of a command, by context tag. */
static bool field(const uint8_t *fields, size_t len, uint8_t tag, uint64_t *out)
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
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_u64(&r, out) == MATTER_OK;
		}
	}
	return false;
}

static uint8_t identify_write(const struct tm_req *req, uint32_t attr, const uint8_t *tlv,
			      size_t len)
{
	struct matter_tlv_reader r;
	uint64_t v;

	if (attr != MATTER_ATTR_IDENTIFY_TIME) {
		return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
	}
	matter_tlv_reader_init(&r, tlv, len);
	if (tlv == NULL || matter_tlv_next(&r) != MATTER_OK || matter_tlv_get_u64(&r, &v) != MATTER_OK) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (v > UINT16_MAX) {
		return MATTER_IM_STATUS_CONSTRAINT_ERROR;
	}
	identify_for(req->endpoint, (uint16_t)v);
	return MATTER_IM_STATUS_SUCCESS;
}

static bool effect_known(uint64_t effect)
{
	return effect == MATTER_IDENTIFY_EFFECT_BLINK || effect == MATTER_IDENTIFY_EFFECT_BREATHE ||
	       effect == MATTER_IDENTIFY_EFFECT_OKAY ||
	       effect == MATTER_IDENTIFY_EFFECT_CHANNEL_CHANGE ||
	       effect == MATTER_IDENTIFY_EFFECT_FINISH || effect == MATTER_IDENTIFY_EFFECT_STOP;
}

static uint8_t identify_invoke(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			       size_t len, uint32_t *response)
{
	uint64_t v = 0u;
	uint64_t variant = 0u;

	(void)response;
	if (cmd == MATTER_CMD_IDENTIFY) {
		if (!field(fields, len, TAG_IDENTIFY_TIME, &v)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (v > UINT16_MAX) {
			return MATTER_IM_STATUS_CONSTRAINT_ERROR;
		}
		identify_for(req->endpoint, (uint16_t)v);
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (cmd == MATTER_CMD_TRIGGER_EFFECT) {
		if (!field(fields, len, TAG_EFFECT_ID, &v) ||
		    !field(fields, len, TAG_EFFECT_VARIANT, &variant)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/* EffectVariant has one value, Default (0). */
		if (!effect_known(v) || variant != 0u) {
			return MATTER_IM_STATUS_CONSTRAINT_ERROR;
		}
		/* Finish and Stop end any identification in progress. */
		if (v == MATTER_IDENTIFY_EFFECT_FINISH || v == MATTER_IDENTIFY_EFFECT_STOP) {
			s_until_ms = 0;
			tm_attr_changed(req->endpoint, MATTER_CLUSTER_IDENTIFY,
					MATTER_ATTR_IDENTIFY_TIME);
		}
		if (s_hooks != NULL && s_hooks->effect != NULL) {
			s_hooks->effect(req->endpoint, (uint8_t)v, (uint8_t)variant);
		}
		return MATTER_IM_STATUS_SUCCESS;
	}
	return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
}

const struct tm_cluster tm_identify = {
	.id = MATTER_CLUSTER_IDENTIFY,
	.attrs = k_identify_attrs,
	.n_attrs = sizeof(k_identify_attrs) / sizeof(k_identify_attrs[0]),
	.accepted = k_identify_accepted,
	.n_accepted = sizeof(k_identify_accepted) / sizeof(k_identify_accepted[0]),
	/* Both commands ask Manage; an IdentifyTime write asks Operate, the
	 * table's default. */
	.invoke_privilege = MATTER_AC_PRIVILEGE_MANAGE,
	.revision = MATTER_IDENTIFY_CLUSTER_REVISION,
	.features = 0u,
	.read = identify_read,
	.write = identify_write,
	.invoke = identify_invoke,
};

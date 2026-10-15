/* SPDX-License-Identifier: ISC */

/* Durable Matter identity storage: fabrics, ACLs and the network, over tm_kv. */
#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>

#include "matter_fab_settings.h"
#include "tm_kv.h"

LOG_MODULE_REGISTER(matter_fab, CONFIG_LOG_DEFAULT_LEVEL);

#define FAB_MAGIC   0x32424146u /* "FAB2", little endian. */
#define FAB_VERSION 1u
#define REC_LIVE    1u
#define REC_DELETED 2u

enum record_kind {
	REC_META = 1,
	REC_NETWORK = 2,
	REC_FABRIC = 3,
	REC_ACL = 4,
	REC_ICAC = 5,
};

struct record_header {
	uint32_t magic;
	uint32_t epoch;
	uint32_t crc;
	uint8_t version;
	uint8_t kind;
	uint8_t state;
	uint8_t slot;
};

struct meta_record {
	struct record_header h;
};

struct network_record {
	struct record_header h;
	uint16_t dataset_len;
	uint8_t xpanid[MATTER_THREAD_XPANID_LEN];
	uint8_t dataset[MATTER_THREAD_DATASET_MAX];
};

struct fabric_record {
	struct record_header h;
	struct matter_fabric fabric;
};

struct acl_record {
	struct record_header h;
	uint64_t fabric_id;
	uint64_t node_id;
	uint16_t len;
	uint8_t fabric_index;
	uint8_t reserved;
	uint8_t data[MATTER_ACL_MAX];
};

struct icac_record {
	struct record_header h;
	uint16_t len;
	uint8_t owner_index;
	uint8_t reserved;
	uint8_t data[MATTER_CERT_MAX];
};

union record_io {
	struct meta_record meta;
	struct network_record network;
	struct fabric_record fabric;
	struct acl_record acl;
	struct icac_record icac;
};

/* One bounded static codec buffer. Earlier tree-shaped settings writes
 * overflowed the OpenThread stack; no record is ever assembled there now. */
static union record_io s_io;
static uint32_t s_epoch = 1u;
static bool s_have_meta;
static uint32_t s_fabric_epoch[MATTER_SUPPORTED_FABRICS];
static uint32_t s_acl_epoch[MATTER_SUPPORTED_FABRICS];
static uint8_t s_fabric_state[MATTER_SUPPORTED_FABRICS];
static uint8_t s_acl_state[MATTER_SUPPORTED_FABRICS];
static uint64_t s_acl_fabric_id[MATTER_SUPPORTED_FABRICS];
static uint64_t s_acl_node_id[MATTER_SUPPORTED_FABRICS];
static uint8_t s_acl_fabric_index[MATTER_SUPPORTED_FABRICS];
static uint32_t s_network_epoch;
static uint8_t s_network_state;
static uint32_t s_icac_epoch;
static uint8_t s_icac_state;

_Static_assert(TM_KV_KEY_MATTER_MF2_FAB0 + MATTER_SUPPORTED_FABRICS <=
		       TM_KV_KEY_MATTER_MF2_FAB_LIMIT,
	       "Matter fabric slots have outgrown their key window");
_Static_assert(TM_KV_KEY_MATTER_MF2_ACL0 + MATTER_SUPPORTED_FABRICS <=
		       TM_KV_KEY_MATTER_MF2_ACL_LIMIT,
	       "Matter ACL slots have outgrown their key window");
_Static_assert(sizeof(union record_io) <= TM_KV_VALUE_MAX,
	       "Matter record exceeds the key-value seam's value ceiling");

static uint32_t crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xffffffffu;

	for (size_t i = 0u; i < len; i++) {
		crc ^= data[i];
		for (uint8_t bit = 0u; bit < 8u; bit++) {
			crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
		}
	}
	return ~crc;
}

static void record_init(struct record_header *h, uint8_t kind, uint8_t state, uint8_t slot)
{
	h->magic = FAB_MAGIC;
	h->epoch = s_epoch;
	h->crc = 0u;
	h->version = FAB_VERSION;
	h->kind = kind;
	h->state = state;
	h->slot = slot;
}

static void record_seal(void *record, size_t len)
{
	struct record_header *h = record;

	h->crc = 0u;
	h->crc = crc32(record, len);
}

/*
 * Every record is assembled at the front of the one codec buffer, so the two
 * steps each store shares are functions of that buffer rather than of a
 * pointer into it. Inlined into every store they cost more flash than the
 * records themselves, in an image that has none to spare.
 */
static void record_begin(uint8_t kind, uint8_t state, uint8_t slot)
{
	memset(&s_io, 0, sizeof(s_io));
	record_init(&s_io.meta.h, kind, state, slot);
}

static int record_put(uint16_t key, size_t len)
{
	record_seal(&s_io, len);
	return tm_kv_set(key, &s_io, len);
}

static bool record_valid(void *record, size_t len, uint8_t kind)
{
	struct record_header *h = record;
	uint32_t stored;
	uint32_t actual;

	if (len < sizeof(*h) || h->magic != FAB_MAGIC || h->version != FAB_VERSION ||
	    h->kind != kind || (h->state != REC_LIVE && h->state != REC_DELETED)) {
		return false;
	}
	stored = h->crc;
	h->crc = 0u;
	actual = crc32(record, len);
	h->crc = stored;
	return stored == actual;
}

/* 0 = exact record, 1 = absent or layout-incompatible, negative = backend
 * failure. A short-buffer INVALID is a stored layout mismatch, not an I/O
 * failure, and is discarded just like the old settings length check. */
static int record_read(uint16_t key, size_t expected)
{
	size_t len = expected;
	int rc;

	if (expected > sizeof(s_io)) {
		return TM_KV_INVALID;
	}
	memset(&s_io, 0, sizeof(s_io));
	rc = tm_kv_get(key, &s_io, &len);
	if (rc == TM_KV_NOT_FOUND || rc == TM_KV_INVALID) {
		return 1;
	}
	if (rc != TM_KV_OK) {
		return rc;
	}
	return len == expected ? 0 : 1;
}

static int load_meta_record(void)
{
	int rc = record_read(TM_KV_KEY_MATTER_MF2_META, sizeof(s_io.meta));

	if (rc != 0) {
		return rc;
	}
	if (!record_valid(&s_io.meta, sizeof(s_io.meta), REC_META) ||
	    s_io.meta.h.state != REC_LIVE || s_io.meta.h.epoch == 0u) {
		return 1;
	}
	s_epoch = s_io.meta.h.epoch;
	s_have_meta = true;
	return 0;
}

static int load_network(struct matter_device_info *info)
{
	int rc = record_read(TM_KV_KEY_MATTER_MF2_NET, sizeof(s_io.network));

	if (rc != 0) {
		return rc < 0 ? rc : 0;
	}
	if (record_valid(&s_io.network, sizeof(s_io.network), REC_NETWORK) &&
	    s_io.network.dataset_len <= MATTER_THREAD_DATASET_MAX) {
		s_network_epoch = s_io.network.h.epoch;
		s_network_state = s_io.network.h.state;
		if (s_network_state == REC_LIVE) {
			memcpy(info->thread_dataset, s_io.network.dataset,
			       s_io.network.dataset_len);
			info->thread_dataset_len = s_io.network.dataset_len;
			memcpy(info->thread_xpanid, s_io.network.xpanid,
			       MATTER_THREAD_XPANID_LEN);
			info->have_thread_xpanid = true;
		}
	}
	return 0;
}

static int load_icac(struct matter_device_info *info)
{
	int rc = record_read(TM_KV_KEY_MATTER_MF2_ICAC, sizeof(s_io.icac));

	if (rc != 0) {
		return rc < 0 ? rc : 0;
	}
	if (record_valid(&s_io.icac, sizeof(s_io.icac), REC_ICAC) &&
	    s_io.icac.len <= MATTER_CERT_MAX) {
		s_icac_epoch = s_io.icac.h.epoch;
		s_icac_state = s_io.icac.h.state;
		if (s_icac_state == REC_LIVE) {
			info->icac.len = s_io.icac.len;
			info->icac.owner_index = s_io.icac.owner_index;
			memcpy(info->icac.buf, s_io.icac.data, s_io.icac.len);
		}
	}
	return 0;
}

static int load_fabric(struct matter_device_info *info, uint8_t slot)
{
	int rc = record_read(TM_KV_KEY_MATTER_MF2_FAB0 + slot,
			     sizeof(s_io.fabric));

	if (rc != 0) {
		return rc < 0 ? rc : 0;
	}
	if (record_valid(&s_io.fabric, sizeof(s_io.fabric), REC_FABRIC) &&
	    s_io.fabric.h.slot == slot) {
		s_fabric_epoch[slot] = s_io.fabric.h.epoch;
		s_fabric_state[slot] = s_io.fabric.h.state;
		if (s_fabric_state[slot] == REC_LIVE) {
			info->fabrics[slot] = s_io.fabric.fabric;
		}
	}
	return 0;
}

static int load_acl(struct matter_device_info *info, uint8_t slot)
{
	int rc = record_read(TM_KV_KEY_MATTER_MF2_ACL0 + slot,
			     sizeof(s_io.acl));

	if (rc != 0) {
		return rc < 0 ? rc : 0;
	}
	if (record_valid(&s_io.acl, sizeof(s_io.acl), REC_ACL) &&
	    s_io.acl.h.slot == slot && s_io.acl.len <= MATTER_ACL_MAX) {
		s_acl_epoch[slot] = s_io.acl.h.epoch;
		s_acl_state[slot] = s_io.acl.h.state;
		s_acl_fabric_id[slot] = s_io.acl.fabric_id;
		s_acl_node_id[slot] = s_io.acl.node_id;
		s_acl_fabric_index[slot] = s_io.acl.fabric_index;
		if (s_acl_state[slot] == REC_LIVE) {
			info->fabric_acls[slot].len = s_io.acl.len;
			memcpy(info->fabric_acls[slot].data, s_io.acl.data, s_io.acl.len);
		}
	}
	return 0;
}

static int ensure_meta(void)
{
	int rc;

	if (s_have_meta) {
		return 0;
	}
	record_begin(REC_META, REC_LIVE, 0xffu);
	rc = record_put(TM_KV_KEY_MATTER_MF2_META, sizeof(s_io.meta));
	if (rc == 0) {
		s_have_meta = true;
	}
	return rc;
}

static int store_network(const struct matter_device_info *info)
{
	const uint8_t *dataset = info->thread_dataset;
	const uint8_t *xpanid = info->thread_xpanid;
	size_t len = info->thread_dataset_len;

	if (info->attempt.have_thread_candidate) {
		dataset = info->attempt.thread_dataset;
		xpanid = info->attempt.thread_xpanid;
		len = info->attempt.thread_dataset_len;
	}
	if (len == 0u || len > MATTER_THREAD_DATASET_MAX) {
		return -EINVAL;
	}
	record_begin(REC_NETWORK, REC_LIVE, 0xffu);
	s_io.network.dataset_len = (uint16_t)len;
	memcpy(s_io.network.xpanid, xpanid, MATTER_THREAD_XPANID_LEN);
	memcpy(s_io.network.dataset, dataset, len);
	return record_put(TM_KV_KEY_MATTER_MF2_NET, sizeof(s_io.network));
}

static int store_acl(const struct matter_device_info *info, uint8_t slot,
		     const uint8_t *value, size_t value_len)
{
	const struct matter_fabric *f = &info->fabrics[slot];

	if (value_len > MATTER_ACL_MAX || (value_len != 0u && value == NULL)) {
		return -EINVAL;
	}
	record_begin(REC_ACL, REC_LIVE, slot);
	s_io.acl.fabric_id = f->fabric_id;
	s_io.acl.node_id = f->node_id;
	s_io.acl.fabric_index = f->index;
	s_io.acl.len = (uint16_t)value_len;
	if (value_len != 0u) {
		memcpy(s_io.acl.data, value, value_len);
	}
	return record_put(TM_KV_KEY_MATTER_MF2_ACL0 + slot, sizeof(s_io.acl));
}

static int store_icac(const struct matter_device_info *info)
{
	uint8_t state = REC_LIVE;

	if (info->icac.len > MATTER_CERT_MAX) {
		return -EINVAL;
	}
	if (info->icac.len == 0u || info->icac.owner_index == 0u) {
		state = REC_DELETED;
	}
	record_begin(REC_ICAC, state, 0xffu);
	s_io.icac.len = (uint16_t)info->icac.len;
	s_io.icac.owner_index = info->icac.owner_index;
	if (state == REC_LIVE) {
		memcpy(s_io.icac.data, info->icac.buf, info->icac.len);
	}
	return record_put(TM_KV_KEY_MATTER_MF2_ICAC, sizeof(s_io.icac));
}

int matter_fab_commit(const struct matter_device_info *info,
		      enum matter_fabric_store_operation operation, uint8_t slot,
		      const uint8_t *value, size_t value_len)
{
	int rc;

	if (info == NULL) {
		return -EINVAL;
	}
	rc = tm_kv_init();
	if (rc != TM_KV_OK) {
		return rc;
	}
	if (slot >= MATTER_SUPPORTED_FABRICS) {
		return -EINVAL;
	}
	rc = ensure_meta();
	if (rc != 0) {
		return rc;
	}
	if (operation == MATTER_FABRIC_STORE_ACL) {
		return store_acl(info, slot, value, value_len);
	}
	if (operation == MATTER_FABRIC_STORE_COMMIT_ATTEMPT) {
		if (info->committed_slots == 0u) {
			rc = store_network(info);
			if (rc != 0) {
				return rc;
			}
		}
		rc = store_icac(info);
		if (rc != 0) {
			return rc;
		}
		rc = store_acl(info, slot, info->fabric_acls[slot].data,
			       info->fabric_acls[slot].len);
		if (rc != 0) {
			return rc;
		}
	}
	record_begin(REC_FABRIC, operation == MATTER_FABRIC_STORE_REMOVE ? REC_DELETED : REC_LIVE,
		     slot);
	if (operation == MATTER_FABRIC_STORE_COMMIT_ATTEMPT ||
	    operation == MATTER_FABRIC_STORE_UPDATE) {
		s_io.fabric.fabric = info->fabrics[slot];
	} else if (operation != MATTER_FABRIC_STORE_REMOVE) {
		return -EINVAL;
	}
	return record_put(TM_KV_KEY_MATTER_MF2_FAB0 + slot, sizeof(s_io.fabric));
}

static void clear_identity(struct matter_device_info *info)
{
	memset(info->fabrics, 0, sizeof(info->fabrics));
	memset(info->fabric_acls, 0, sizeof(info->fabric_acls));
	memset(&info->icac, 0, sizeof(info->icac));
	info->committed_slots = 0u;
	info->thread_dataset_len = 0u;
	info->have_thread_xpanid = false;
}

static void legacy_cleanup(void)
{
	static const uint16_t fixed[] = {
		TM_KV_KEY_MATTER_FAB_OK,
		TM_KV_KEY_MATTER_FAB_VER,
		TM_KV_KEY_MATTER_FAB_TD,
		TM_KV_KEY_MATTER_FAB_XP,
		TM_KV_KEY_MATTER_FAB_ICLEN,
		TM_KV_KEY_MATTER_FAB_ICAC,
	};

	for (size_t i = 0u; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
		(void)tm_kv_delete(fixed[i]);
	}
	for (uint8_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		(void)tm_kv_delete(TM_KV_KEY_MATTER_FAB_SLOT0 + i);
	}
}

int matter_fab_load(struct matter_device_info *info)
{
	bool used_index[MATTER_SUPPORTED_FABRICS + 1u] = { false };
	bool icac_valid;
	int rc;

	if (info == NULL) {
		return -EINVAL;
	}
	rc = tm_kv_init();
	if (rc != TM_KV_OK) {
		clear_identity(info);
		return rc;
	}
	clear_identity(info);
	memset(s_fabric_epoch, 0, sizeof(s_fabric_epoch));
	memset(s_acl_epoch, 0, sizeof(s_acl_epoch));
	memset(s_fabric_state, 0, sizeof(s_fabric_state));
	memset(s_acl_state, 0, sizeof(s_acl_state));
	memset(s_acl_fabric_id, 0, sizeof(s_acl_fabric_id));
	memset(s_acl_node_id, 0, sizeof(s_acl_node_id));
	memset(s_acl_fabric_index, 0, sizeof(s_acl_fabric_index));
	s_network_epoch = 0u;
	s_network_state = 0u;
	s_icac_epoch = 0u;
	s_icac_state = 0u;
	s_have_meta = false;
	rc = load_meta_record();
	legacy_cleanup();
	if (rc != 0 || !s_have_meta) {
		clear_identity(info);
		return rc < 0 ? rc : 1;
	}
	rc = load_network(info);
	if (rc == 0) {
		rc = load_icac(info);
	}
	for (uint8_t i = 0u; rc == 0 && i < MATTER_SUPPORTED_FABRICS; i++) {
		rc = load_fabric(info, i);
		if (rc == 0) {
			rc = load_acl(info, i);
		}
	}
	if (rc != 0) {
		clear_identity(info);
		return rc;
	}
	for (uint8_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		struct matter_fabric *f = &info->fabrics[i];

		if (s_fabric_epoch[i] != s_epoch || s_fabric_state[i] != REC_LIVE ||
		    f->index == 0u || f->index > MATTER_SUPPORTED_FABRICS ||
		    used_index[f->index]) {
			memset(f, 0, sizeof(*f));
			memset(&info->fabric_acls[i], 0, sizeof(info->fabric_acls[i]));
			continue;
		}
		used_index[f->index] = true;
		info->committed_slots |= MATTER_FABRIC_SLOT_BIT(i);
		if (s_acl_epoch[i] != s_epoch || s_acl_state[i] != REC_LIVE ||
		    s_acl_fabric_index[i] != f->index || s_acl_fabric_id[i] != f->fabric_id ||
		    s_acl_node_id[i] != f->node_id) {
			memset(&info->fabric_acls[i], 0, sizeof(info->fabric_acls[i]));
		}
	}
	if (info->committed_slots == 0u || s_network_epoch != s_epoch ||
	    s_network_state != REC_LIVE || info->thread_dataset_len == 0u ||
	    !info->have_thread_xpanid) {
		clear_identity(info);
		return 1;
	}
	icac_valid = s_icac_epoch == s_epoch && s_icac_state == REC_LIVE &&
		     info->icac.len > 0u && info->icac.owner_index > 0u &&
		     info->icac.owner_index <= MATTER_SUPPORTED_FABRICS &&
		     used_index[info->icac.owner_index];
	if (!icac_valid) {
		memset(&info->icac, 0, sizeof(info->icac));
	}
	/*
	 * A fabric record is authoritative only when every certificate it names
	 * is intact.  The ICAC is shared to save RAM, so a corrupt ICAC record
	 * must discard its one owner without taking healthy neighbouring fabrics
	 * with it.  An empty slot remains recoverable through normal commissioning.
	 */
	for (uint8_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		struct matter_fabric *f = &info->fabrics[i];

		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) == 0u ||
		    f->icac_len == 0u) {
			continue;
		}
		if (!icac_valid || info->icac.owner_index != f->index ||
		    info->icac.len != f->icac_len) {
			memset(f, 0, sizeof(*f));
			memset(&info->fabric_acls[i], 0, sizeof(info->fabric_acls[i]));
			info->committed_slots &= (uint8_t)~MATTER_FABRIC_SLOT_BIT(i);
		}
	}
	if (icac_valid) {
		bool owner_present = false;

		for (uint8_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
			const struct matter_fabric *f = &info->fabrics[i];

			if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
			    f->index == info->icac.owner_index && f->icac_len == info->icac.len) {
				owner_present = true;
				break;
			}
		}
		if (!owner_present) {
			memset(&info->icac, 0, sizeof(info->icac));
		}
	}
	if (info->committed_slots == 0u) {
		clear_identity(info);
		return 1;
	}
	return 0;
}

#define EPOCH_SCAN_FIXED 3u
#define EPOCH_SCAN_MAX (EPOCH_SCAN_FIXED + 2u * MATTER_SUPPORTED_FABRICS)

struct epoch_scan {
	uint32_t value[EPOCH_SCAN_MAX];
	size_t count;
};

static void scan_epoch(uint16_t key, size_t expected, struct epoch_scan *out)
{
	const struct record_header *h = &s_io.meta.h;

	if (record_read(key, expected) != 0 ||
	    out->count >= sizeof(out->value) / sizeof(out->value[0]) ||
	    h->magic != FAB_MAGIC || h->version != FAB_VERSION || h->epoch == 0u) {
		return;
	}
	out->value[out->count++] = h->epoch;
}

int matter_fab_erase(void)
{
	struct epoch_scan scan = {0};
	uint32_t next = 1u;
	int rc;

	rc = tm_kv_init();
	if (rc != TM_KV_OK) {
		return rc;
	}

	/* A clean-break erase may run before load and even with a corrupt meta
	 * record. Pick an epoch no current record uses, so publishing the new
	 * meta can never resurrect a stale fabric by collision. */
	scan_epoch(TM_KV_KEY_MATTER_MF2_META, sizeof(s_io.meta), &scan);
	scan_epoch(TM_KV_KEY_MATTER_MF2_NET, sizeof(s_io.network), &scan);
	scan_epoch(TM_KV_KEY_MATTER_MF2_ICAC, sizeof(s_io.icac), &scan);
	for (uint8_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		scan_epoch(TM_KV_KEY_MATTER_MF2_FAB0 + i,
			   sizeof(s_io.fabric), &scan);
		scan_epoch(TM_KV_KEY_MATTER_MF2_ACL0 + i,
			   sizeof(s_io.acl), &scan);
	}
	for (;;) {
		bool collision = false;

		for (size_t i = 0u; i < scan.count; i++) {
			if (scan.value[i] == next) {
				collision = true;
				break;
			}
		}
		if (!collision) {
			break;
		}
		next++;
		if (next == 0u) {
			next = 1u;
		}
	}
	s_epoch = next;
	s_have_meta = false;
	/* The one atomic replacement is the erase authority. Before it lands the
	 * old epoch is live; after it lands every older record is unreachable. */
	rc = ensure_meta();
	if (rc == 0) {
		legacy_cleanup();
		LOG_WRN("Matter operational identity erased at epoch %u",
			(unsigned int)s_epoch);
	}
	return rc;
}

/* ---- the writable Door Lock attributes ------------------------------------ */

/* Separate keys from the operational identity. These values survive selective
 * fabric removal and Matter-only erase. */

int matter_dl_attr_store(const struct matter_device_info *info, uint32_t prev_auto_relock_s)
{
	int first_err = 0;
	int rc;

	if (info == NULL) {
		return -EINVAL;
	}
	rc = tm_kv_init();
	if (rc != TM_KV_OK) {
		return rc;
	}
	if (info->auto_relock_time_s != prev_auto_relock_s) {
		rc = tm_kv_set(TM_KV_KEY_MATTER_DL_AUTO_RELOCK,
					  &info->auto_relock_time_s,
					  sizeof(info->auto_relock_time_s));
		if (rc != 0) {
			first_err = rc;
		}
	}
	return first_err;
}

int matter_dl_attr_load(struct matter_device_info *info)
{
	uint32_t relock;
	size_t len;

	if (info == NULL) {
		return -EINVAL;
	}
	(void)tm_kv_init();
	len = sizeof(relock);
	if (tm_kv_get(TM_KV_KEY_MATTER_DL_AUTO_RELOCK,
				 &relock, &len) == TM_KV_OK &&
	    len == sizeof(relock)) {
		info->auto_relock_time_s = relock;
	}
	return 0;
}

int matter_dl_attr_erase(void)
{
	static const uint16_t keys[] = {
		TM_KV_KEY_MATTER_DL_AUTO_RELOCK,
	};
	int first_err = 0;
	int rc = tm_kv_init();

	if (rc != TM_KV_OK) {
		return rc;
	}

	for (size_t i = 0u; i < sizeof(keys) / sizeof(keys[0]); i++) {
		rc = tm_kv_delete(keys[i]);

		if (rc != TM_KV_OK && rc != TM_KV_NOT_FOUND &&
		    first_err == 0) {
			first_err = rc;
		}
	}
	return first_err;
}

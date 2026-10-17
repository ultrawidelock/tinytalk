/* SPDX-License-Identifier: ISC */

/*
 * See matter_clusters.h.
 *
 * status() answers from the attribute lists a wildcard expands, so the two
 * agree by construction. value() is a switch rather than a table of function
 * pointers: a table would cost a relocation and an indirect call per
 * attribute on a part where flash is the binding constraint.
 */
#include <tinytalk/matter_clusters.h>
#include <tinytalk/tm_kv.h>
#include <tinytalk/tm_platform.h>

#include <stddef.h>
#include <string.h>

/* GeneralCommissioning/Structs.h:41-44 */
#define TAG_BCI_FAILSAFE_EXPIRY 0u
#define TAG_BCI_FAILSAFE_MAX    1u

/* OperationalCredentials Structs.h:43-49, FabricDescriptorStruct. */
#define TAG_FABRIC_ROOT_KEY  1u
#define TAG_FABRIC_VENDOR_ID 2u
#define TAG_FABRIC_FABRIC_ID 3u
#define TAG_FABRIC_NODE_ID   4u
#define TAG_FABRIC_LABEL     5u
/** Every fabric-scoped struct carries this, always at 254. */
#define TAG_FABRIC_INDEX     254u

/* Same header, NOCStruct at :84-87. */
#define TAG_NOC_NOC  1u
#define TAG_NOC_ICAC 2u

/* BasicInformation/Structs.h:43-44, CapabilityMinimaStruct. */
#define TAG_CAPMIN_CASE_SESSIONS 0u
#define TAG_CAPMIN_SUBSCRIPTIONS 1u

/* Strings this node reports about itself. */
#define MATTER_NAME_FALLBACK "tinytalk"
#define MATTER_SERIAL_NUMBER_FALLBACK "TT-UNKNOWN"

/* Descriptor/Structs.h:43-44, DeviceTypeStruct. */
#define TAG_DEVTYPE_TYPE     0u
#define TAG_DEVTYPE_REVISION 1u

/**
 * Every cluster the root endpoint serves, for Descriptor's ServerList.
 *
 * Descriptor is in it: a controller that reads ServerList and does not find the
 * cluster it just read is entitled to conclude the answer is stale.
 */
/*
 * Installed by the port. Declared up here rather than beside the command
 * handler because the WindowStatus ATTRIBUTE is read far earlier in this file
 * than the commands are dispatched, and a controller reads that attribute to
 * decide whether its own OpenCommissioningWindow worked.
 */
static const struct matter_admin_hooks *s_admin_hooks;

static const uint32_t k_root_servers[] = {
	MATTER_CLUSTER_DESCRIPTOR,
	MATTER_CLUSTER_ACCESS_CONTROL,
	MATTER_CLUSTER_BASIC_INFORMATION,
	MATTER_CLUSTER_GENERAL_COMMISSIONING,
	MATTER_CLUSTER_NETWORK_COMMISSIONING,
	MATTER_CLUSTER_GENERAL_DIAGNOSTICS,
	MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
	MATTER_CLUSTER_ADMIN_COMMISSIONING,
	MATTER_CLUSTER_GROUP_KEY_MANAGEMENT,
};

/* NetworkInfoStruct (python clusters/Objects.py, NetworkInfoStruct). */
#define TAG_NETINFO_ID        0u
#define TAG_NETINFO_CONNECTED 1u

/**
 * The slot currently being provisioned, allocating one if needed.
 *
 * A commissioner builds a fabric across several commands -- the root arrives
 * before the NOC -- so the half-built slot must survive between them. A slot
 * with a root but no index yet is that one. NULL when every slot is taken,
 * which is what AddNOC reports as TABLE_FULL.
 */
static size_t fabric_pending_slot(struct matter_device_info *info)
{
	size_t i;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].have_root && info->fabrics[i].index == 0u) {
			return i;
		}
	}
	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) == 0u &&
		    (info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(i)) == 0u &&
		    !info->fabrics[i].have_root && info->fabrics[i].index == 0u) {
			return i;
		}
	}
	return MATTER_SUPPORTED_FABRICS;
}

static struct matter_fabric *fabric_pending(struct matter_device_info *info, size_t *slot)
{
	size_t i = fabric_pending_slot(info);

	if (i >= MATTER_SUPPORTED_FABRICS) {
		return NULL;
	}
	if (slot != NULL) {
		*slot = i;
	}
	return &info->fabrics[i];
}

static size_t fabric_slot_for_index(const struct matter_device_info *info, uint8_t index)
{
	size_t i;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (info->fabrics[i].index == index &&
		    (info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u) {
			return i;
		}
	}
	return MATTER_SUPPORTED_FABRICS;
}

static size_t fabric_slot_for_request(const struct matter_device_info *info, uint8_t index)
{
	size_t i;
	uint8_t visible = info->committed_slots | info->attempt.owned_slots;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((visible & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].index == index) {
			return i;
		}
	}
	return MATTER_SUPPORTED_FABRICS;
}

#define MATTER_AC_AUTH_MODE_CASE        2u
/**
 * The high half of a subject id that names a CASE Authenticated Tag.
 *
 * Operational node ids never reach it, so both subject kinds share one field
 * without ambiguity: below the prefix a subject is a node, at it a tag group.
 */
#define MATTER_ACL_CAT_PREFIX           0xFFFFFFFDu
/*
 * AccessControlEntryStruct numbers its fields from 1 (Privilege=1, AuthMode=2,
 * Subjects=3, Targets=4) -- verified against the entry a real commissioner
 * writes. Numbered from 0 these matched nothing, so every entry silently
 * granted nobody and all access fell through to the case-admin bootstrap.
 */
#define MATTER_AC_ENTRY_PRIVILEGE_TAG   1u
#define MATTER_AC_ENTRY_AUTH_MODE_TAG   2u
#define MATTER_AC_ENTRY_SUBJECTS_TAG    3u
#define MATTER_AC_ENTRY_TARGETS_TAG     4u
#define MATTER_AC_TARGET_CLUSTER_TAG    0u
#define MATTER_AC_TARGET_ENDPOINT_TAG   1u
#define MATTER_AC_TARGET_DEVICE_TAG     2u
#define MATTER_TLV_NULL_TYPE            0x14u

/**
 * Does @p subject, read out of an ACL entry, name this accessor?
 *
 * Two kinds of subject live in the same 64-bit field. Below the CAT range it is
 * an operational node id and the test is equality. Inside the range
 * 0xFFFFFFFD_00000000..0xFFFFFFFD_FFFFFFFF the low 32 bits are a CASE
 * Authenticated Tag: identifier in the high half, version in the low.
 *
 * A CAT matches when the accessor's NOC carries the SAME identifier at a
 * version at least the one the entry asks for -- greater-or-equal, so that
 * re-issuing controllers at a higher version keeps old entries working while
 * bumping the entry's version retires every controller below it. Equality
 * would make the version field pointless; less-than would invert it.
 */
static bool acl_subject_matches(uint64_t subject, uint64_t node_id, const uint32_t *cats,
				uint8_t n_cats)
{
	uint32_t tag;
	uint16_t want_id;
	uint16_t want_ver;
	uint8_t i;

	if ((subject >> 32) != MATTER_ACL_CAT_PREFIX) {
		return subject == node_id;
	}
	tag = (uint32_t)subject;
	want_id = (uint16_t)(tag >> 16);
	want_ver = (uint16_t)tag;
	/* Version 0 is not a valid tag; an entry carrying one matches nothing
	 * rather than everything. */
	if (want_ver == 0u || cats == NULL) {
		return false;
	}
	for (i = 0u; i < n_cats && i < MATTER_MAX_CATS; i++) {
		if ((uint16_t)(cats[i] >> 16) == want_id && (uint16_t)cats[i] >= want_ver) {
			return true;
		}
	}
	return false;
}

static bool acl_subjects_match(struct matter_tlv_reader *r, uint64_t node_id,
			       const uint32_t *cats, uint8_t n_cats)
{
	bool match = false;

	if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
		return true;
	}
	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		uint64_t subject;
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (matter_tlv_get_u64(r, &subject) == MATTER_OK &&
		    acl_subject_matches(subject, node_id, cats, n_cats)) {
			match = true;
		}
	}
	return matter_tlv_exit(r) == MATTER_OK && match;
}

/* ---- application endpoints (tm_app.h) -------------------------------------- */

static const struct tm_endpoint *s_eps;
static uint8_t s_n_eps;

/*
 * Every endpoint.
 *
 * This exists because Apple reads NetworkCommissioning with the endpoint
 * WILDCARDED, so a node that cannot expand an endpoint wildcard looks like a
 * node with no network interface anywhere -- which is where commissioning
 * stopped before this. The Door Lock must appear here as well as in the root's
 * PartsList: a wildcard read walks THIS list, so an endpoint missing from it is
 * invisible no matter what PartsList claims. Root first, then the table.
 */
static uint16_t s_ep_ids[1u + TM_ENDPOINTS_MAX];

/**
 * Every cluster each application endpoint serves, for Descriptor's ServerList.
 *
 * Descriptor again, because every endpoint has one: it is how a controller
 * learns what the endpoint IS without being told where to look. Built once
 * from the table, so ServerList, has_cluster() and a wildcard cannot drift
 * into disagreeing about what an endpoint carries.
 */
static uint32_t s_servers[TM_ENDPOINTS_MAX][1u + TM_CLUSTERS_MAX];

/** One bit per application attribute, in table order: changed, not yet reported. */
static uint32_t s_changed[MATTER_CHANGE_WORDS];

/** The device the IM server was last pointed at, which tm_event_emit() records into. */
static struct matter_device_info *s_dm;

static bool id_listed(const uint32_t *ids, size_t n, uint32_t id)
{
	for (size_t i = 0u; i < n; i++) {
		if (ids[i] == id) {
			return true;
		}
	}
	return false;
}

/** The application endpoint @p endpoint and its table index, or NULL. */
static const struct tm_endpoint *app_endpoint(uint16_t endpoint, size_t *index)
{
	for (size_t i = 0u; i < s_n_eps; i++) {
		if (s_eps[i].id == endpoint) {
			if (index != NULL) {
				*index = i;
			}
			return &s_eps[i];
		}
	}
	return NULL;
}

static const struct tm_cluster *app_cluster(const struct tm_endpoint *ep, uint32_t cluster)
{
	for (size_t i = 0u; i < ep->n_clusters; i++) {
		if (ep->clusters[i]->id == cluster) {
			return ep->clusters[i];
		}
	}
	return NULL;
}

static void app_req(const struct matter_device_info *info, uint16_t endpoint,
		    bool fabric_filtered, struct tm_req *req)
{
	req->endpoint = endpoint;
	req->fabric_index = info->accessing_fabric_index;
	req->fabric_filtered = fabric_filtered;
	req->node_id = info->accessing_node_id;
}

/*
 * Root clusters described by a struct tm_cluster, served through the same
 * table path as an application cluster: the node answers their five globals,
 * checks their privileges and dispatches their callbacks from the table. The
 * older root clusters predate the table: their globals come from the same
 * path (k_legacy_meta), and the rest from their hand-written paths.
 */
static const struct tm_cluster *const k_root_tables[] = {
	&matter_general_diagnostics,
	&matter_group_key_management,
};

/* The hand-written root clusters' and the Descriptor's metadata, for their
 * globals: see k_legacy_meta below. */
static const struct tm_cluster *legacy_meta(uint32_t cluster);

/* The five global attributes the node answers from a cluster's table. */
static bool is_global(uint32_t attribute)
{
	return attribute == MATTER_ATTR_FEATURE_MAP || attribute == MATTER_ATTR_CLUSTER_REVISION ||
	       attribute == MATTER_ATTR_ATTRIBUTE_LIST ||
	       attribute == MATTER_ATTR_ACCEPTED_CMD_LIST ||
	       attribute == MATTER_ATTR_GENERATED_CMD_LIST;
}

static const struct tm_cluster *root_table(uint32_t cluster)
{
	for (size_t i = 0u; i < sizeof(k_root_tables) / sizeof(k_root_tables[0]); i++) {
		if (k_root_tables[i]->id == cluster) {
			return k_root_tables[i];
		}
	}
	return NULL;
}

int matter_clusters_set_endpoints(const struct tm_endpoint *eps, uint8_t n)
{
	size_t attrs = 0u;

	if (n > TM_ENDPOINTS_MAX || (n > 0u && eps == NULL)) {
		return MATTER_E_INVAL;
	}
	for (uint8_t i = 0u; i < n; i++) {
		if (eps[i].id == MATTER_ENDPOINT_ROOT || eps[i].n_clusters > TM_CLUSTERS_MAX ||
		    (eps[i].n_clusters > 0u && eps[i].clusters == NULL)) {
			return MATTER_E_INVAL;
		}
		for (uint8_t j = 0u; j < i; j++) {
			if (eps[j].id == eps[i].id) {
				return MATTER_E_INVAL;
			}
		}
		for (uint8_t c = 0u; c < eps[i].n_clusters; c++) {
			const struct tm_cluster *cl = eps[i].clusters[c];

			if (cl == NULL || cl->id == MATTER_CLUSTER_DESCRIPTOR ||
			    (cl->n_attrs > 0u && cl->attrs == NULL)) {
				return MATTER_E_INVAL;
			}
			for (uint8_t d = 0u; d < c; d++) {
				if (eps[i].clusters[d]->id == cl->id) {
					return MATTER_E_INVAL;
				}
			}
			attrs += cl->n_attrs;
		}
	}
	if (attrs > TM_ATTRS_MAX) {
		return MATTER_E_INVAL;
	}
	s_eps = eps;
	s_n_eps = n;
	s_ep_ids[0] = MATTER_ENDPOINT_ROOT;
	for (uint8_t i = 0u; i < n; i++) {
		s_ep_ids[1u + i] = eps[i].id;
		s_servers[i][0] = MATTER_CLUSTER_DESCRIPTOR;
		for (uint8_t c = 0u; c < eps[i].n_clusters; c++) {
			s_servers[i][1u + c] = eps[i].clusters[c]->id;
		}
	}
	memset(s_changed, 0, sizeof(s_changed));
	return MATTER_OK;
}

const struct tm_endpoint *matter_clusters_endpoint_at(uint8_t i)
{
	return i < s_n_eps ? &s_eps[i] : NULL;
}

void tm_attr_changed(uint16_t endpoint, uint32_t cluster, uint32_t attr)
{
	size_t bit = 0u;

	for (size_t i = 0u; i < s_n_eps; i++) {
		for (size_t c = 0u; c < s_eps[i].n_clusters; c++) {
			const struct tm_cluster *cl = s_eps[i].clusters[c];

			for (size_t a = 0u; a < cl->n_attrs; a++, bit++) {
				if (s_eps[i].id == endpoint && cl->id == cluster &&
				    cl->attrs[a] == attr) {
					s_changed[bit / 32u] |= 1u << (bit % 32u);
					(void)tm_work_schedule(TM_WORK_NOTIFY, 0u);
					return;
				}
			}
		}
	}
}

void matter_clusters_take_changes(uint32_t out[MATTER_CHANGE_WORDS])
{
	memcpy(out, s_changed, sizeof(s_changed));
	memset(s_changed, 0, sizeof(s_changed));
}

bool matter_clusters_change_path(size_t bit, struct matter_im_path *out,
				 const struct tm_cluster **cluster)
{
	for (size_t i = 0u; i < s_n_eps; i++) {
		for (size_t c = 0u; c < s_eps[i].n_clusters; c++) {
			const struct tm_cluster *cl = s_eps[i].clusters[c];

			if (bit < cl->n_attrs) {
				memset(out, 0, sizeof(*out));
				out->endpoint = s_eps[i].id;
				out->cluster = cl->id;
				out->attribute = cl->attrs[bit];
				out->have_endpoint = true;
				out->have_cluster = true;
				out->have_attribute = true;
				*cluster = cl;
				return true;
			}
			bit -= cl->n_attrs;
		}
	}
	return false;
}

static uint32_t endpoint_device_type(uint16_t endpoint)
{
	const struct tm_endpoint *ep;

	if (endpoint == MATTER_ENDPOINT_ROOT) {
		return MATTER_DEVICE_TYPE_ROOT_NODE;
	}
	ep = app_endpoint(endpoint, NULL);
	return ep != NULL ? ep->device_type : 0u;
}

static bool acl_target_match(struct matter_tlv_reader *r, uint16_t endpoint, uint32_t cluster)
{
	bool match = true;

	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		uint64_t value;
		matter_tlv_tag_t tag;
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		tag = matter_tlv_tag(r);
		if (tag != MATTER_TLV_CTX(MATTER_AC_TARGET_CLUSTER_TAG) &&
		    tag != MATTER_TLV_CTX(MATTER_AC_TARGET_ENDPOINT_TAG) &&
		    tag != MATTER_TLV_CTX(MATTER_AC_TARGET_DEVICE_TAG)) {
			continue;
		}
		/* Null means this dimension is unrestricted. */
		if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
			continue;
		}
		if (matter_tlv_get_u64(r, &value) != MATTER_OK) {
			match = false;
			continue;
		}
		if (tag == MATTER_TLV_CTX(MATTER_AC_TARGET_CLUSTER_TAG)) {
			match = match && value == cluster;
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_TARGET_ENDPOINT_TAG)) {
			match = match && value == endpoint;
		} else {
			match = match && endpoint_device_type(endpoint) != 0u &&
				value == endpoint_device_type(endpoint);
		}
	}
	return matter_tlv_exit(r) == MATTER_OK && match;
}

static bool acl_targets_match(struct matter_tlv_reader *r, uint16_t endpoint, uint32_t cluster)
{
	bool match = false;

	if (matter_tlv_element_type(r) == MATTER_TLV_NULL_TYPE) {
		return true;
	}
	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (acl_target_match(r, endpoint, cluster)) {
			match = true;
		}
	}
	return matter_tlv_exit(r) == MATTER_OK && match;
}

static bool acl_entry_grants(struct matter_tlv_reader *r, uint64_t node_id,
			     const uint32_t *cats, uint8_t n_cats, uint8_t required_privilege,
			     uint16_t endpoint, uint32_t cluster)
{
	uint64_t privilege = 0u;
	uint64_t auth_mode = 0u;
	bool have_privilege = false;
	bool have_auth_mode = false;
	bool subjects_match = false;
	bool targets_match = false;

	if (!matter_tlv_is_container(r) || matter_tlv_enter(r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		matter_tlv_tag_t tag;
		int rc = matter_tlv_next(r);

		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		tag = matter_tlv_tag(r);
		if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_PRIVILEGE_TAG)) {
			have_privilege = matter_tlv_get_u64(r, &privilege) == MATTER_OK;
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_AUTH_MODE_TAG)) {
			have_auth_mode = matter_tlv_get_u64(r, &auth_mode) == MATTER_OK;
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_SUBJECTS_TAG)) {
			subjects_match = acl_subjects_match(r, node_id, cats, n_cats);
		} else if (tag == MATTER_TLV_CTX(MATTER_AC_ENTRY_TARGETS_TAG)) {
			targets_match = acl_targets_match(r, endpoint, cluster);
		}
	}
	if (matter_tlv_exit(r) != MATTER_OK) {
		return false;
	}
	return have_privilege && privilege >= required_privilege && have_auth_mode &&
	       auth_mode == MATTER_AC_AUTH_MODE_CASE && subjects_match && targets_match;
}

static bool fabric_slot_has_privilege(const struct matter_device_info *info, size_t slot,
			      uint8_t required_privilege, uint16_t endpoint,
			      uint32_t cluster)
{
	struct matter_tlv_reader r;

	if (slot >= MATTER_SUPPORTED_FABRICS || info->accessing_node_id == 0u) {
		return false;
	}
	/*
	 * Bootstrap authority from AddNOC. It remains a recovery administrator
	 * even if a later malformed ACL would otherwise lock every controller out.
	 *
	 * Matched the same way an ACL subject is, because CaseAdminSubject IS an
	 * ACL subject and Apple sets it to a CAT rather than a node id. Compared
	 * by equality, that hub authenticates as a member of a group whose tag
	 * never equals any node id, so the recovery path it exists to provide
	 * silently was not there. acl_subject_matches() falls through to plain
	 * equality for a node-id subject, so nothing changes for a controller
	 * that sets one.
	 */
	if (info->fabrics[slot].case_admin_subject != 0u &&
	    acl_subject_matches(info->fabrics[slot].case_admin_subject, info->accessing_node_id,
				info->accessing_cats, info->accessing_n_cats)) {
		return true;
	}
	if (info->fabric_acls[slot].len == 0u) {
		return false;
	}
	matter_tlv_reader_init(&r, info->fabric_acls[slot].data,
			       info->fabric_acls[slot].len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r) ||
	    matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&r);

		if (rc == MATTER_END) {
			(void)matter_tlv_exit(&r);
			return false;
		}
		if (rc != MATTER_OK) {
			return false;
		}
		if (acl_entry_grants(&r, info->accessing_node_id, info->accessing_cats,
				     info->accessing_n_cats, required_privilege, endpoint,
				     cluster)) {
			return true;
		}
	}
}

/** How many fabrics hold a complete identity. */
static uint8_t fabric_count(const struct matter_device_info *info)
{
	uint8_t n = 0u;
	size_t i;

	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].index != 0u) {
			n++;
		}
	}
	return n;
}

static int fabric_store(struct matter_device_info *info,
			enum matter_fabric_store_operation operation, size_t slot,
			const uint8_t *value, size_t value_len)
{
	if (info->commissioning_hooks == NULL ||
	    info->commissioning_hooks->fabric_store == NULL) {
		return MATTER_OK;
	}
	return info->commissioning_hooks->fabric_store(
		info->commissioning_hooks->ctx, info, operation, (uint8_t)slot, value,
		value_len);
}

static void fabric_slot_clear(struct matter_device_info *info, size_t slot)
{
	struct matter_fabric *f;

	if (slot >= MATTER_SUPPORTED_FABRICS) {
		return;
	}
	f = &info->fabrics[slot];
	if (f->index != 0u) {
		char iname[MATTER_INSTANCE_NAME_LEN];

		if (matter_fabric_instance_name(f, iname, sizeof(iname)) == MATTER_OK) {
			(void)matter_thread_unadvertise(iname);
		}
	}
	if (info->icac.owner_index == f->index) {
		memset(&info->icac, 0, sizeof(info->icac));
	}
	memset(&info->fabric_acls[slot], 0, sizeof(info->fabric_acls[slot]));
	memset(f, 0, sizeof(*f));
	info->attempt.owned_slots &= (uint8_t)~MATTER_FABRIC_SLOT_BIT(slot);
	info->committed_slots &= (uint8_t)~MATTER_FABRIC_SLOT_BIT(slot);
}

/**
 * The lowest index not already taken. Indices are 1-based on the wire.
 *
 * Kept in one place because an off-by-one here reports one fabric's
 * certificate under another's index, which no peer can detect.
 */
static uint8_t fabric_next_index(const struct matter_device_info *info)
{
	uint8_t want;

	for (want = 1u; want <= MATTER_SUPPORTED_FABRICS; want++) {
		bool taken = false;
		size_t i;

		for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
			if (info->fabrics[i].index == want) {
				taken = true;
			}
		}
		if (!taken) {
			return want;
		}
	}
	return 0u;
}

/**
 * Check whether a given cluster is present on a given endpoint. Returns true if the cluster is
 * supported on that endpoint, false otherwise.
 */
static bool has_cluster(void *ctx, uint16_t endpoint, uint32_t cluster)
{
	const struct tm_endpoint *ep;

	(void)ctx;

	if (endpoint != MATTER_ENDPOINT_ROOT) {
		ep = app_endpoint(endpoint, NULL);
		return ep != NULL &&
		       (cluster == MATTER_CLUSTER_DESCRIPTOR || app_cluster(ep, cluster) != NULL);
	}
	return legacy_meta(cluster) != NULL || root_table(cluster) != NULL;
}

/**
 * Return the list of endpoint IDs this device exposes.
 */
static size_t list_endpoints(void *ctx, const uint16_t **out)
{
	(void)ctx;

	*out = s_ep_ids;
	return 1u + s_n_eps;
}

/**
 * Query whether an attribute on a given endpoint and cluster is supported. Returns
 * MATTER_IM_STATUS_SUCCESS if supported, MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT if the endpoint does
 * not exist, MATTER_IM_STATUS_UNSUPPORTED_CLUSTER if the cluster does not exist on that endpoint,
 * or MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE if the attribute does not exist on that cluster.
 */
static size_t list_attrs(void *ctx, uint16_t endpoint, uint32_t cluster, const uint32_t **out);

static uint8_t attr_status(void *ctx, uint16_t endpoint, uint32_t cluster, uint32_t attribute)
{
	const uint32_t *ids = NULL;
	size_t n;

	/*
	 * Endpoint, then cluster, then attribute. The ORDER is the answer:
	 * MetadataLookup.cpp:68-88 reports the outermost thing that is missing,
	 * so a bad endpoint must not be reported as a bad attribute.
	 */
	if (endpoint != MATTER_ENDPOINT_ROOT && app_endpoint(endpoint, NULL) == NULL) {
		return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
	}
	if (!has_cluster(ctx, endpoint, cluster)) {
		return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}
	/*
	 * The same list a wildcard expands, so the two cannot disagree. For every
	 * cluster it is also AttributeList, the globals included.
	 * IsCommissioningWithoutPower (GeneralCommissioning 0x000C) is not on
	 * its list, and a real iPhone does ask for it: UNSUPPORTED_ATTRIBUTE is
	 * the correct answer for a node that does not implement it, and the
	 * commissioner carries on.
	 */
	n = list_attrs(ctx, endpoint, cluster, &ids);
	return id_listed(ids, n, attribute) ? MATTER_IM_STATUS_SUCCESS
					    : MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
}

/** An array attribute whose members are bare unsigned ids; NULL/0 is legal
 * and encodes the empty list, which is how a cluster says "no commands". */
static void put_id_list(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const uint32_t *ids,
			size_t count)
{
	size_t i;

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
	for (i = 0u; i < count; i++) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, ids[i]);
	}
	(void)matter_tlv_end_container(w);
}

/**
 * An application endpoint: its Descriptor, which the node builds from the
 * table, and its clusters' attributes.
 *
 * Split out rather than folded into attr_value() because every endpoint shares
 * cluster IDs with the root -- Descriptor is on all of them -- and a single
 * flat switch on cluster would answer the root's Descriptor for the lock.
 */
static void table_attr_value(const struct matter_device_info *info, const struct tm_cluster *c,
			     uint16_t endpoint, uint32_t attribute, bool fabric_filtered,
			     struct matter_tlv_writer *w, matter_tlv_tag_t tag);

static void app_attr_value(const struct matter_device_info *info, uint16_t endpoint,
			   uint32_t cluster, uint32_t attribute, bool fabric_filtered,
			   struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	size_t index = 0u;
	const struct tm_endpoint *ep = app_endpoint(endpoint, &index);
	const struct tm_cluster *c;

	if (ep == NULL) {
		return;
	}
	if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
		if (is_global(attribute)) {
			table_attr_value(info, legacy_meta(cluster), endpoint, attribute,
					 fabric_filtered, w, tag);
			return;
		}
		switch (attribute) {
		case MATTER_ATTR_DESC_DEVICE_TYPE_LIST:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_TYPE), ep->device_type);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_REVISION),
						 ep->device_revision);
			(void)matter_tlv_end_container(w);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_SERVER_LIST:
			put_id_list(w, tag, s_servers[index], 1u + ep->n_clusters);
			return;
		case MATTER_ATTR_DESC_CLIENT_LIST:
		case MATTER_ATTR_DESC_PARTS_LIST:
			/* A leaf endpoint: nothing hangs off it and it binds
			 * nothing as a client. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_end_container(w);
			return;
		default:
			return;
		}
	}

	c = app_cluster(ep, cluster);
	if (c == NULL) {
		return;
	}
	table_attr_value(info, c, endpoint, attribute, fabric_filtered, w, tag);
}

/* One attribute of a table-described cluster: the globals from the table,
 * everything else from its read() callback. */
static void table_attr_value(const struct matter_device_info *info, const struct tm_cluster *c,
			     uint16_t endpoint, uint32_t attribute, bool fabric_filtered,
			     struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	struct tm_req req;

	switch (attribute) {
	case MATTER_ATTR_FEATURE_MAP:
		(void)matter_tlv_put_u64(w, tag, c->features);
		return;
	case MATTER_ATTR_CLUSTER_REVISION:
		(void)matter_tlv_put_u64(w, tag, c->revision);
		return;
	case MATTER_ATTR_ATTRIBUTE_LIST:
		put_id_list(w, tag, c->attrs, c->n_attrs);
		return;
	case MATTER_ATTR_ACCEPTED_CMD_LIST:
		put_id_list(w, tag, c->accepted, c->n_accepted);
		return;
	case MATTER_ATTR_GENERATED_CMD_LIST:
		put_id_list(w, tag, c->generated, c->n_generated);
		return;
	default:
		if (c->read != NULL) {
			app_req(info, endpoint, fabric_filtered, &req);
			c->read(&req, attribute, w, tag);
		}
		return;
	}
}
/**
 * Retrieve the value of an attribute on a given endpoint and cluster. Encodes the value into the
 * TLV writer using the supplied tag. Handles root and lock endpoints, multiple cluster types
 * including Door Lock, Descriptor, Basic Information, Network Commissioning, Access Control,
 * Operational Credentials, Admin Commissioning, and General Commissioning.
 */
static bool noc_visible(const struct matter_device_info *info, const struct matter_fabric *f,
			bool fabric_filtered)
{
	return f->index != 0u &&
	       (!fabric_filtered || f->index == info->accessing_fabric_index);
}

static void put_noc_entry(const struct matter_device_info *info, const struct matter_fabric *f,
			  struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NOC_NOC), f->noc, f->noc_len);
	if (f->icac_len > 0u && info->icac.owner_index == f->index &&
	    info->icac.len == f->icac_len) {
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NOC_ICAC), info->icac.buf,
					   f->icac_len);
	} else {
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_NOC_ICAC));
	}
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_INDEX), f->index);
	(void)matter_tlv_end_container(w);
}

static size_t list_fragments(void *ctx, uint16_t endpoint, uint32_t cluster,
			     uint32_t attribute, bool fabric_filtered)
{
	const struct matter_device_info *info = ctx;
	size_t count = 1u; /* The empty replace-all. */

	if (endpoint != MATTER_ENDPOINT_ROOT || cluster != MATTER_CLUSTER_OPERATIONAL_CREDENTIALS ||
	    attribute != MATTER_ATTR_OC_NOCS) {
		return 0u;
	}
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if (noc_visible(info, &info->fabrics[i], fabric_filtered)) {
			count++;
		}
	}
	return count;
}

static void list_fragment_value(void *ctx, uint16_t endpoint, uint32_t cluster,
				uint32_t attribute, bool fabric_filtered, size_t index,
				struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = ctx;
	size_t visible = 0u;

	(void)endpoint;
	(void)cluster;
	(void)attribute;
	if (index == 0u) {
		(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
		(void)matter_tlv_end_container(w);
		return;
	}
	for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		const struct matter_fabric *f = &info->fabrics[i];

		if (!noc_visible(info, f, fabric_filtered)) {
			continue;
		}
		if (++visible == index) {
			put_noc_entry(info, f, w, tag);
			return;
		}
	}
}

static void attr_value(void *ctx, uint16_t endpoint, uint32_t cluster, uint32_t attribute,
		       bool fabric_filtered, struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;

	/*
	 * The application's endpoints are answered first and return, so
	 * everything below can still assume the root. attr_status() has already
	 * refused any endpoint that is neither.
	 */
	if (endpoint != MATTER_ENDPOINT_ROOT) {
		app_attr_value(info, endpoint, cluster, attribute, fabric_filtered, w, tag);
		return;
	}
	if (root_table(cluster) != NULL) {
		table_attr_value(info, root_table(cluster), endpoint, attribute, fabric_filtered, w,
				 tag);
		return;
	}
	if (is_global(attribute) && legacy_meta(cluster) != NULL) {
		table_attr_value(info, legacy_meta(cluster), endpoint, attribute, fabric_filtered, w,
				 tag);
		return;
	}

	if (cluster == MATTER_CLUSTER_ADMIN_COMMISSIONING) {
		/* No hooks installed means no window can ever be open, and saying
		 * so truthfully is better than refusing the read: a controller
		 * that cannot read WindowStatus cannot tell why its own
		 * OpenCommissioningWindow appeared to fail. */
		bool live = s_admin_hooks != NULL;

		switch (attribute) {
		case MATTER_ATTR_ADMIN_WINDOW_STATUS:
			(void)matter_tlv_put_u64(w, tag,
						 (live && s_admin_hooks->status != NULL)
							 ? s_admin_hooks->status()
							 : MATTER_ADMIN_WINDOW_NOT_OPEN);
			return;
		case MATTER_ATTR_ADMIN_FABRIC_INDEX: {
			uint8_t fabric = (live && s_admin_hooks->admin_fabric != NULL)
						 ? s_admin_hooks->admin_fabric()
						 : 0u;
			/* Nullable, and null is the correct answer while shut --
			 * zero is a fabric index nobody has. */
			if (fabric == 0u) {
				(void)matter_tlv_put_null(w, tag);
			} else {
				(void)matter_tlv_put_u64(w, tag, fabric);
			}
			return;
		}
		case MATTER_ATTR_ADMIN_VENDOR_ID: {
			uint16_t vendor = (live && s_admin_hooks->admin_vendor != NULL)
						  ? s_admin_hooks->admin_vendor()
						  : 0u;
			if (vendor == 0u) {
				(void)matter_tlv_put_null(w, tag);
			} else {
				(void)matter_tlv_put_u64(w, tag, vendor);
			}
			return;
		}
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_BASIC_INFORMATION) {
		switch (attribute) {
		case MATTER_ATTR_BASIC_DATA_MODEL_REVISION:
			(void)matter_tlv_put_u64(w, tag, MATTER_DATA_MODEL_REVISION);
			return;
		case MATTER_ATTR_BASIC_VENDOR_NAME:
		case MATTER_ATTR_BASIC_PRODUCT_NAME: {
			const char *name = attribute == MATTER_ATTR_BASIC_VENDOR_NAME
						   ? info->vendor_name
						   : info->product_name;

			if (name == NULL) {
				name = MATTER_NAME_FALLBACK;
			}
			(void)matter_tlv_put_utf8(w, tag, name, strlen(name));
			return;
		}
		case MATTER_ATTR_BASIC_VENDOR_ID:
			(void)matter_tlv_put_u64(w, tag, info->vendor_id);
			return;
		case MATTER_ATTR_BASIC_PRODUCT_ID:
			(void)matter_tlv_put_u64(w, tag, info->product_id);
			return;
		case MATTER_ATTR_BASIC_NODE_LABEL:
			/* Writable, and empty until somebody writes one. A
			 * controller supplies its own name for the accessory. */
			(void)matter_tlv_put_utf8(w, tag, "", 0u);
			return;
		case MATTER_ATTR_BASIC_LOCATION:
			/* "XX" is the spec's value for "not configured", and it
			 * has to be exactly two characters. */
			(void)matter_tlv_put_utf8(w, tag, "XX", 2u);
			return;
		case MATTER_ATTR_BASIC_HARDWARE_VERSION:
			(void)matter_tlv_put_u64(w, tag, info->hardware_version);
			return;
		case MATTER_ATTR_BASIC_SOFTWARE_VERSION:
			(void)matter_tlv_put_u64(w, tag, info->software_version);
			return;
		case MATTER_ATTR_BASIC_HARDWARE_VERSION_STR:
		case MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR: {
			/* The number itself, unless the application named it. */
			char num[11];
			const char *v = attribute == MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR
						? info->software_version_str
						: NULL;
			uint32_t n = attribute == MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR
					     ? info->software_version
					     : info->hardware_version;
			size_t len = 0u;

			if (v == NULL) {
				char rev[10];
				size_t k = 0u;

				do {
					rev[k++] = (char)('0' + n % 10u);
					n /= 10u;
				} while (n != 0u);
				while (k > 0u) {
					num[len++] = rev[--k];
				}
				v = num;
			} else {
				len = strlen(v);
			}
			(void)matter_tlv_put_utf8(w, tag, v, len);
			return;
		}
		case MATTER_ATTR_BASIC_SERIAL_NUMBER:
			{
				const char *serial = info->serial_number[0] != '\0'
							   ? info->serial_number
							   : MATTER_SERIAL_NUMBER_FALLBACK;

				(void)matter_tlv_put_utf8(w, tag, serial, strlen(serial));
			}
			return;
		case MATTER_ATTR_BASIC_UNIQUE_ID:
			/*
			 * Random per identity, not derived from the device id as
			 * the serial is: a controller may tie a newly paired node
			 * to an older accessory with the same UniqueID, so a
			 * factory reset has to yield a new one.
			 */
			(void)matter_tlv_put_utf8(w, tag, info->unique_id, strlen(info->unique_id));
			return;
		case MATTER_ATTR_BASIC_CAPABILITY_MINIMA:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CAPMIN_CASE_SESSIONS),
						 MATTER_CASE_SESSIONS_PER_FABRIC);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CAPMIN_SUBSCRIPTIONS),
						 MATTER_SUBSCRIPTIONS_PER_FABRIC);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_BASIC_SPECIFICATION_VERSION:
			(void)matter_tlv_put_u64(w, tag, MATTER_SPECIFICATION_VERSION);
			return;
		case MATTER_ATTR_BASIC_MAX_PATHS_PER_INVOKE:
			(void)matter_tlv_put_u64(w, tag, MATTER_MAX_PATHS_PER_INVOKE);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		switch (attribute) {
		case MATTER_ATTR_NC_MAX_NETWORKS:
			(void)matter_tlv_put_u64(w, tag, 1u);
			return;
		case MATTER_ATTR_NC_NETWORKS:
			/*
			 * A list of NetworkInfoStruct. Empty until a dataset
			 * arrives, and then exactly one entry whose networkID is
			 * the Extended PAN ID -- which is the id ConnectNetwork
			 * names the network by. `connected` is false and stays
			 * false: nothing here has joined anything.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			if (info->attempt.have_thread_candidate || info->have_thread_xpanid) {
				const uint8_t *xpanid = info->attempt.have_thread_candidate
							? info->attempt.thread_xpanid
							: info->thread_xpanid;
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_NETINFO_ID),
							   xpanid, MATTER_THREAD_XPANID_LEN);
				(void)matter_tlv_put_bool(w, MATTER_TLV_CTX(TAG_NETINFO_CONNECTED),
							  matter_thread_attached_to(xpanid));
				(void)matter_tlv_end_container(w);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_NC_SCAN_MAX_TIME_S:
			/* Never scanned; the value still has to be inside the
			 * spec's 1..255 range to be a legal answer. */
			(void)matter_tlv_put_u64(w, tag, 30u);
			return;
		case MATTER_ATTR_NC_CONNECT_MAX_TIME_S:
			(void)matter_tlv_put_u64(w, tag, 60u);
			return;
		case MATTER_ATTR_NC_INTERFACE_ENABLED:
			(void)matter_tlv_put_bool(w, tag, true);
			return;
		case MATTER_ATTR_NC_LAST_NETWORKING_STATUS:
			(void)matter_tlv_put_u64(w, tag, info->last_network_status);
			return;
		case MATTER_ATTR_NC_LAST_NETWORK_ID:
			/* Null until a ConnectNetwork names a network. */
			if (info->have_last_network_id) {
				(void)matter_tlv_put_bytes(w, tag, info->last_network_id,
							   MATTER_THREAD_XPANID_LEN);
			} else {
				(void)matter_tlv_put_null(w, tag);
			}
			return;
		case MATTER_ATTR_NC_LAST_CONNECT_ERROR:
			/* Null: ConnectNetworkResponse's ErrorValue is null too, as
			 * no failure here carries a stack-specific code. */
			(void)matter_tlv_put_null(w, tag);
			return;
		case MATTER_ATTR_NC_SUPPORTED_THREAD_FEAT:
			/* None of ThreadCapabilitiesBitmap: an always-listening
			 * minimal end device is no border router, router, sleepy
			 * or full device. */
			(void)matter_tlv_put_u64(w, tag, 0u);
			return;
		case MATTER_ATTR_NC_THREAD_VERSION: {
			struct matter_thread_iface iface;

			if (matter_thread_interface(&iface) != MATTER_OK) {
				iface.thread_version = 0u;
			}
			(void)matter_tlv_put_u64(w, tag, iface.thread_version);
			return;
		}
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
		size_t i;

		switch (attribute) {
		case MATTER_ATTR_DESC_DEVICE_TYPE_LIST:
			/*
			 * What this endpoint IS, which is the question a
			 * controller asks once it owns the node. Endpoint 0 is
			 * the Root Node and nothing else.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_start_container(w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_TYPE),
						 MATTER_DEVICE_TYPE_ROOT_NODE);
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_DEVTYPE_REVISION),
						 MATTER_DEVICE_TYPE_ROOT_REV);
			(void)matter_tlv_end_container(w);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_SERVER_LIST:
			/* Built from the same list has_cluster() answers from,
			 * so the two cannot drift into disagreeing about what
			 * this endpoint carries. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (i = 0u; i < sizeof(k_root_servers) / sizeof(k_root_servers[0]); i++) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, k_root_servers[i]);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_CLIENT_LIST:
			/* Empty, and empty is an answer: this node binds nothing
			 * as a client. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_DESC_PARTS_LIST:
			/*
			 * The application's endpoints. This is the attribute that
			 * turns an empty tile into a lock: a controller reads the
			 * root's PartsList to find the endpoints that carry
			 * function, and a Root Node on its own carries none.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (i = 0u; i < s_n_eps; i++) {
				(void)matter_tlv_put_u64(w, MATTER_TLV_ANON, s_eps[i].id);
			}
			(void)matter_tlv_end_container(w);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_ACCESS_CONTROL) {
		size_t slot = fabric_slot_for_request(info, info->accessing_fabric_index);

		switch (attribute) {
		case MATTER_ATTR_AC_ACL:
			/*
			 * Handed straight back as it arrived. Authorization decodes
			 * the stored form in place, but preserving the exact element
			 * avoids rebuilding fields this implementation does not alter.
			 */
			if (slot < MATTER_SUPPORTED_FABRICS &&
			    info->fabric_acls[slot].len > 0u) {
				(void)matter_tlv_put_encoded(w, tag, info->fabric_acls[slot].data,
							     info->fabric_acls[slot].len);
			} else {
				(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
				(void)matter_tlv_end_container(w);
			}
			return;
		case MATTER_ATTR_AC_SUBJECTS_PER_ENTRY:
		case MATTER_ATTR_AC_ENTRIES_PER_FABRIC:
			/* The spec's floor for both, and what one fabric needs. */
			(void)matter_tlv_put_u64(w, tag, 4u);
			return;
		case MATTER_ATTR_AC_TARGETS_PER_ENTRY:
			(void)matter_tlv_put_u64(w, tag, 3u);
			return;
		default:
			return;
		}
	}

	if (cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		size_t fi;

		switch (attribute) {
		case MATTER_ATTR_OC_FABRICS:
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
				const struct matter_fabric *f = &info->fabrics[fi];

				if (f->index == 0u ||
				    (fabric_filtered && f->index != info->accessing_fabric_index)) {
					continue;
				}
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_FABRIC_ROOT_KEY),
							   f->root_public_key,
							   MATTER_FABRIC_PUBKEY_LEN);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_VENDOR_ID),
							 f->admin_vendor_id);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_FABRIC_ID),
							 f->fabric_id);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_NODE_ID),
							 f->node_id);
				(void)matter_tlv_put_utf8(w, MATTER_TLV_CTX(TAG_FABRIC_LABEL),
							  f->label, f->label_len);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_FABRIC_INDEX),
							 f->index);
				(void)matter_tlv_end_container(w);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_OC_NOCS:
			/* The certificates themselves. FabricFiltered limits the
			 * list to the CASE session's fabric. */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
				const struct matter_fabric *f = &info->fabrics[fi];

				if (f->index == 0u ||
				    (fabric_filtered && f->index != info->accessing_fabric_index)) {
					continue;
				}
				put_noc_entry(info, f, w, MATTER_TLV_ANON);
			}
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_OC_TRUSTED_ROOTS:
			/*
			 * A list of the root CERTIFICATES, which this node does
			 * not keep -- matter_fabric holds the root public key
			 * and discards the ~300 bytes around it. An empty list
			 * is the honest consequence of that choice.
			 */
			(void)matter_tlv_start_container(w, tag, MATTER_TLV_ARRAY);
			(void)matter_tlv_end_container(w);
			return;
		case MATTER_ATTR_OC_CURRENT_FABRIC_INDEX:
			/*
			 * The fabric of whoever is ASKING, which the port
			 * records from the session the request arrived on.
			 * Answering with the first live fabric was right while
			 * there was one and a guess once there were two -- and
			 * the guess is what made the home hub remove itself.
			 */
			(void)matter_tlv_put_u64(w, tag, info->accessing_fabric_index);
			return;
		case MATTER_ATTR_OC_SUPPORTED_FABRICS:
			(void)matter_tlv_put_u64(w, tag, MATTER_SUPPORTED_FABRICS);
			return;
		case MATTER_ATTR_OC_COMMISSIONED_FABRICS:
			(void)matter_tlv_put_u64(w, tag, fabric_count(info));
			return;
		default:
			return;
		}
	}

	switch (attribute) {
	case MATTER_ATTR_GC_BREADCRUMB:
		(void)matter_tlv_put_u64(w, tag, info->breadcrumb);
		return;
	case MATTER_ATTR_GC_BASIC_COMMISSIONING_INFO:
		(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_BCI_FAILSAFE_EXPIRY),
					 info->failsafe_expiry_s);
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_BCI_FAILSAFE_MAX),
					 info->failsafe_max_s);
		(void)matter_tlv_end_container(w);
		return;
	case MATTER_ATTR_GC_REGULATORY_CONFIG:
		(void)matter_tlv_put_u64(w, tag, info->regulatory_config);
		return;
	case MATTER_ATTR_GC_LOCATION_CAPABILITY:
		(void)matter_tlv_put_u64(w, tag, info->location_capability);
		return;
	case MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION:
		(void)matter_tlv_put_bool(w, tag, info->supports_concurrent_connection);
		return;
	default:
		return;
	}
}

/*
 * Attribute lists for expanding a wildcard read, and what attr_status() answers
 * SUCCESS for: one list, because an id a wildcard named and attr_status()
 * refused would turn a report into a list of UNSUPPORTED_ATTRIBUTE, which is
 * worse than the silence it replaced. Each is also the cluster's AttributeList.
 *
 * Every list ends with the five global attributes, which every cluster must
 * serve. They were left out here once, on the grounds that commissioning did
 * without them; ClusterRevision is mandatory on every cluster, and both of
 * Apple's controllers stopped driving this node (tinylock round 1,
 * 2026-10-17). The node answers them from k_legacy_meta below.
 */
#define GLOBAL_ATTRS                                                                     \
	MATTER_ATTR_FEATURE_MAP, MATTER_ATTR_CLUSTER_REVISION, MATTER_ATTR_ATTRIBUTE_LIST, \
		MATTER_ATTR_ACCEPTED_CMD_LIST, MATTER_ATTR_GENERATED_CMD_LIST

static const uint32_t k_gc_attrs[] = {
	MATTER_ATTR_GC_BREADCRUMB,
	MATTER_ATTR_GC_BASIC_COMMISSIONING_INFO,
	MATTER_ATTR_GC_REGULATORY_CONFIG,
	MATTER_ATTR_GC_LOCATION_CAPABILITY,
	MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION,
	GLOBAL_ATTRS,
};

static const uint32_t k_basic_attrs[] = {
	MATTER_ATTR_BASIC_DATA_MODEL_REVISION,
	MATTER_ATTR_BASIC_VENDOR_NAME,
	MATTER_ATTR_BASIC_VENDOR_ID,
	MATTER_ATTR_BASIC_PRODUCT_NAME,
	MATTER_ATTR_BASIC_PRODUCT_ID,
	MATTER_ATTR_BASIC_NODE_LABEL,
	MATTER_ATTR_BASIC_LOCATION,
	MATTER_ATTR_BASIC_HARDWARE_VERSION,
	MATTER_ATTR_BASIC_HARDWARE_VERSION_STR,
	MATTER_ATTR_BASIC_SOFTWARE_VERSION,
	MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR,
	MATTER_ATTR_BASIC_SERIAL_NUMBER,
	MATTER_ATTR_BASIC_UNIQUE_ID,
	MATTER_ATTR_BASIC_CAPABILITY_MINIMA,
	MATTER_ATTR_BASIC_SPECIFICATION_VERSION,
	MATTER_ATTR_BASIC_MAX_PATHS_PER_INVOKE,
	GLOBAL_ATTRS,
};

static const uint32_t k_desc_attrs[] = {
	MATTER_ATTR_DESC_DEVICE_TYPE_LIST,
	MATTER_ATTR_DESC_SERVER_LIST,
	MATTER_ATTR_DESC_CLIENT_LIST,
	MATTER_ATTR_DESC_PARTS_LIST,
	GLOBAL_ATTRS,
};

static const uint32_t k_ac_attrs[] = {
	MATTER_ATTR_AC_ACL,
	MATTER_ATTR_AC_SUBJECTS_PER_ENTRY,
	MATTER_ATTR_AC_TARGETS_PER_ENTRY,
	MATTER_ATTR_AC_ENTRIES_PER_FABRIC,
	GLOBAL_ATTRS,
};

/**
 * AdministratorCommissioning's three attributes.
 *
 * A controller reads WindowStatus to decide whether its own
 * OpenCommissioningWindow succeeded, and reads the other two to show WHO opened
 * it. Both of those are nullable and are null whenever the window is shut.
 */
static const uint32_t k_admin_attrs[] = {
	MATTER_ATTR_ADMIN_WINDOW_STATUS,
	MATTER_ATTR_ADMIN_FABRIC_INDEX,
	MATTER_ATTR_ADMIN_VENDOR_ID,
	GLOBAL_ATTRS,
};

static const uint32_t k_oc_attrs[] = {
	MATTER_ATTR_OC_NOCS,
	MATTER_ATTR_OC_FABRICS,
	MATTER_ATTR_OC_SUPPORTED_FABRICS,
	MATTER_ATTR_OC_COMMISSIONED_FABRICS,
	MATTER_ATTR_OC_TRUSTED_ROOTS,
	MATTER_ATTR_OC_CURRENT_FABRIC_INDEX,
	GLOBAL_ATTRS,
};

/*
 * FeatureMap says which network technologies exist: Thread, and only Thread.
 * It is the global a commissioner cannot proceed without, and the one Apple
 * was asking for when it read this cluster with the endpoint wildcarded and got
 * silence.
 */
static const uint32_t k_nc_attrs[] = {
	MATTER_ATTR_NC_MAX_NETWORKS,      MATTER_ATTR_NC_NETWORKS,
	MATTER_ATTR_NC_SCAN_MAX_TIME_S,   MATTER_ATTR_NC_CONNECT_MAX_TIME_S,
	MATTER_ATTR_NC_INTERFACE_ENABLED, MATTER_ATTR_NC_LAST_NETWORKING_STATUS,
	MATTER_ATTR_NC_LAST_NETWORK_ID,   MATTER_ATTR_NC_LAST_CONNECT_ERROR,
	MATTER_ATTR_NC_SUPPORTED_THREAD_FEAT, MATTER_ATTR_NC_THREAD_VERSION,
	GLOBAL_ATTRS,
};

/*
 * AcceptedCommandList and GeneratedCommandList: exactly what command()
 * dispatches for each cluster and what it answers with.
 */
static const uint32_t k_gc_cmds[] = {
	MATTER_CMD_GC_ARM_FAIL_SAFE,
	MATTER_CMD_GC_SET_REGULATORY_CONFIG,
	MATTER_CMD_GC_COMMISSIONING_COMPLETE,
};
static const uint32_t k_gc_resps[] = {
	MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE,
	MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE,
	MATTER_CMD_GC_COMMISSIONING_COMPLETE_RESPONSE,
};
static const uint32_t k_nc_cmds[] = {
	MATTER_CMD_NC_SCAN_NETWORKS,
	MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK,
	MATTER_CMD_NC_REMOVE_NETWORK,
	MATTER_CMD_NC_CONNECT_NETWORK,
	MATTER_CMD_NC_REORDER_NETWORK,
};
static const uint32_t k_nc_resps[] = {
	MATTER_CMD_NC_SCAN_NETWORKS_RESPONSE,
	MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE,
	MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE,
};
static const uint32_t k_oc_cmds[] = {
	MATTER_CMD_OC_ATTESTATION_REQUEST,     MATTER_CMD_OC_CERTIFICATE_CHAIN_REQUEST,
	MATTER_CMD_OC_CSR_REQUEST,             MATTER_CMD_OC_ADD_NOC,
	MATTER_CMD_OC_UPDATE_FABRIC_LABEL,     MATTER_CMD_OC_REMOVE_FABRIC,
	MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE,
};
static const uint32_t k_oc_resps[] = {
	MATTER_CMD_OC_ATTESTATION_RESPONSE,
	MATTER_CMD_OC_CERTIFICATE_CHAIN_RESPONSE,
	MATTER_CMD_OC_CSR_RESPONSE,
	MATTER_CMD_OC_NOC_RESPONSE,
};
#ifndef TM_NO_ADMIN_COMMANDS
static const uint32_t k_admin_cmds[] = {
	MATTER_CMD_ADMIN_OPEN_WINDOW,
	MATTER_CMD_ADMIN_OPEN_BASIC_WINDOW,
	MATTER_CMD_ADMIN_REVOKE,
};
#endif

#define N_OF(a) (uint8_t)(sizeof(a) / sizeof((a)[0]))

/*
 * The hand-written clusters' metadata, and the Descriptor's on every endpoint:
 * the globals answered from these through the table path, everything else by
 * attr_value() as before. Revisions are the SDK's cluster XMLs (the 1.5 data
 * model; data_model/1.5/clusters for the three whose zap XML names none).
 */
static const struct tm_cluster k_legacy_meta[] = {
	{ .id = MATTER_CLUSTER_DESCRIPTOR, .attrs = k_desc_attrs, .n_attrs = N_OF(k_desc_attrs),
	  /* No TagList, so no TAGLIST feature. */
	  .revision = 3u },
	{ .id = MATTER_CLUSTER_ACCESS_CONTROL, .attrs = k_ac_attrs, .n_attrs = N_OF(k_ac_attrs),
	  .revision = 2u },
	{ .id = MATTER_CLUSTER_BASIC_INFORMATION, .attrs = k_basic_attrs,
	  .n_attrs = N_OF(k_basic_attrs), .revision = 5u },
	{ .id = MATTER_CLUSTER_GENERAL_COMMISSIONING, .attrs = k_gc_attrs,
	  .n_attrs = N_OF(k_gc_attrs), .accepted = k_gc_cmds, .n_accepted = N_OF(k_gc_cmds),
	  .generated = k_gc_resps, .n_generated = N_OF(k_gc_resps), .revision = 2u },
	{ .id = MATTER_CLUSTER_NETWORK_COMMISSIONING, .attrs = k_nc_attrs,
	  .n_attrs = N_OF(k_nc_attrs), .accepted = k_nc_cmds, .n_accepted = N_OF(k_nc_cmds),
	  .generated = k_nc_resps, .n_generated = N_OF(k_nc_resps), .revision = 2u,
	  .features = MATTER_NC_FEATURE_THREAD },
	{ .id = MATTER_CLUSTER_OPERATIONAL_CREDENTIALS, .attrs = k_oc_attrs,
	  .n_attrs = N_OF(k_oc_attrs), .accepted = k_oc_cmds, .n_accepted = N_OF(k_oc_cmds),
	  .generated = k_oc_resps, .n_generated = N_OF(k_oc_resps), .revision = 2u },
	{ .id = MATTER_CLUSTER_ADMIN_COMMISSIONING, .attrs = k_admin_attrs,
	  .n_attrs = N_OF(k_admin_attrs),
#ifndef TM_NO_ADMIN_COMMANDS
	  .accepted = k_admin_cmds, .n_accepted = N_OF(k_admin_cmds),
	  /* Basic: OpenBasicCommissioningWindow is served. */
	  .features = 0x1u,
#endif
	  .revision = 1u },
};

void matter_clusters_unique_id_boot(struct matter_device_info *info)
{
	static const char k_hex[] = "0123456789ABCDEF";
	uint8_t raw[MATTER_UNIQUE_ID_BYTES];
	size_t len = MATTER_UNIQUE_ID_LEN;

	if (tm_kv_get(TM_KV_KEY_MATTER_UNIQUE_ID, info->unique_id, &len) == TM_KV_OK &&
	    len == MATTER_UNIQUE_ID_LEN) {
		info->unique_id[MATTER_UNIQUE_ID_LEN] = '\0';
		return;
	}
	if (tm_random(raw, sizeof(raw)) != 0) {
		/* No entropy: report nothing rather than a guessable id, and
		 * try again at the next boot. */
		info->unique_id[0] = '\0';
		return;
	}
	for (size_t i = 0u; i < sizeof(raw); i++) {
		info->unique_id[2u * i] = k_hex[raw[i] >> 4];
		info->unique_id[2u * i + 1u] = k_hex[raw[i] & 0x0Fu];
	}
	info->unique_id[MATTER_UNIQUE_ID_LEN] = '\0';
	(void)tm_kv_set(TM_KV_KEY_MATTER_UNIQUE_ID, info->unique_id, MATTER_UNIQUE_ID_LEN);
}

static const struct tm_cluster *legacy_meta(uint32_t cluster)
{
	for (size_t i = 0u; i < sizeof(k_legacy_meta) / sizeof(k_legacy_meta[0]); i++) {
		if (k_legacy_meta[i].id == cluster) {
			return &k_legacy_meta[i];
		}
	}
	return NULL;
}

/**
 * Every cluster on @p endpoint, which is the same list has_cluster() answers
 * from and the same one Descriptor's ServerList reports. One array, so the
 * three cannot drift into disagreeing about what this endpoint carries.
 */
static size_t list_clusters(void *ctx, uint16_t endpoint, const uint32_t **out)
{
	size_t index = 0u;

	(void)ctx;

	if (endpoint != MATTER_ENDPOINT_ROOT) {
		const struct tm_endpoint *ep = app_endpoint(endpoint, &index);

		if (ep == NULL) {
			return 0u;
		}
		*out = s_servers[index];
		return 1u + ep->n_clusters;
	}
	*out = k_root_servers;
	return sizeof(k_root_servers) / sizeof(k_root_servers[0]);
}

/**
 * Return the attribute IDs for a given endpoint and cluster, or 0 if the endpoint or cluster is not
 * supported.
 */
static size_t list_attrs(void *ctx, uint16_t endpoint, uint32_t cluster, const uint32_t **out)
{
	(void)ctx;

	if (endpoint != MATTER_ENDPOINT_ROOT) {
		const struct tm_endpoint *ep = app_endpoint(endpoint, NULL);
		const struct tm_cluster *c;

		if (ep == NULL) {
			return 0u;
		}
		if (cluster == MATTER_CLUSTER_DESCRIPTOR) {
			*out = k_desc_attrs;
			return sizeof(k_desc_attrs) / sizeof(k_desc_attrs[0]);
		}
		c = app_cluster(ep, cluster);
		if (c == NULL) {
			return 0u;
		}
		*out = c->attrs;
		return c->n_attrs;
	}
	if (root_table(cluster) != NULL) {
		*out = root_table(cluster)->attrs;
		return root_table(cluster)->n_attrs;
	}
	if (legacy_meta(cluster) != NULL) {
		*out = legacy_meta(cluster)->attrs;
		return legacy_meta(cluster)->n_attrs;
	}
	return 0u;
}

/** Read one unsigned field out of a command's TLV arguments. */
static bool field_u64(const struct matter_im_invoke *inv, uint8_t tag, uint64_t *out)
{
	struct matter_tlv_reader r;

	if (!inv->has_fields || inv->fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(&r, inv->fields, inv->fields_len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
		return false;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&r);

		if (rc != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_u64(&r, out) == MATTER_OK;
		}
	}
}

/* -------------------------------------- OperationalCredentials --- */

/*
 * Command field tags. Matter numbers a command's arguments from 0 in
 * declaration order, so these are the positions in
 * controller/python/matter/clusters/Objects.py, which spells the tag out
 * rather than leaving it to be counted.
 */
#define TAG_ATTEST_NONCE 0u
#define TAG_CERT_TYPE    0u
#define TAG_CSR_NONCE    0u

#define TAG_ADDNOC_NOC                0u
#define TAG_ADDNOC_ICAC               1u
#define TAG_ADDNOC_IPK                2u
#define TAG_ADDNOC_CASE_ADMIN_SUBJECT 3u
#define TAG_ADDNOC_ADMIN_VENDOR_ID    4u

#define TAG_ADDROOT_CERT 0u

#define TAG_REMOVE_FABRIC_INDEX 0u

/* Response field tags, same source. */
#define TAG_RESP_ELEMENTS  0u
#define TAG_RESP_SIGNATURE 1u
#define TAG_RESP_CERT      0u

#define TAG_NOCRESP_STATUS       0u
#define TAG_NOCRESP_FABRIC_INDEX 1u

/* UpdateFabricLabel's one argument. */
#define TAG_UPDATE_LABEL 0u

/**
 * Extract a bytes field from the TLV-encoded command fields by tag. Searches the structure for the
 * first matching tag and decodes it. Returns true and fills out and len on success, false if the
 * fields are missing, malformed, or the tag is not found.
 */
static bool field_bytes(const struct matter_im_invoke *inv, uint8_t tag, const uint8_t **out,
			size_t *len)
{
	struct matter_tlv_reader r;

	if (!inv->has_fields || inv->fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(&r, inv->fields, inv->fields_len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
		return false;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		if (matter_tlv_next(&r) != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_bytes(&r, out, len) == MATTER_OK;
		}
	}
}

/** The UTF-8 twin: a Label is a string element, which get_bytes refuses. */
static bool field_utf8(const struct matter_im_invoke *inv, uint8_t tag, const char **out,
		       size_t *len)
{
	struct matter_tlv_reader r;

	if (!inv->has_fields || inv->fields == NULL) {
		return false;
	}
	matter_tlv_reader_init(&r, inv->fields, inv->fields_len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
		return false;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		if (matter_tlv_next(&r) != MATTER_OK) {
			return false;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(tag)) {
			return matter_tlv_get_utf8(&r, out, len) == MATTER_OK;
		}
	}
}

/* --------------------------------------- NetworkCommissioning --- */

/* AddOrUpdateThreadNetwork / ConnectNetwork field tags, and the two responses. */
#define TAG_ADDTHREAD_DATASET  0u
#define TAG_CONNECT_NETWORK_ID 0u
#define TAG_NCRESP_STATUS      0u
#define TAG_NCRESP_INDEX       2u
#define TAG_CONNRESP_STATUS    0u
#define TAG_CONNRESP_ERROR     2u
#define TAG_REORDER_INDEX      1u
#define TAG_SCANRESP_STATUS    0u
#define TAG_SCANRESP_THREAD    3u

/* What the last ScanNetworks heard, kept for its response. */
static struct matter_thread_scan_result s_scan[MATTER_THREAD_SCAN_MAX];
static uint8_t s_scan_n;

/* The network Networks lists, if any: the candidate, else the committed one. */
static const uint8_t *listed_network(const struct matter_device_info *info)
{
	if (info->attempt.have_thread_candidate) {
		return info->attempt.thread_xpanid;
	}
	return info->have_thread_xpanid ? info->thread_xpanid : NULL;
}

/**
 * Thread meshcop TLV type for the Extended PAN ID (Thread 1.3 spec, 8.10.1.5).
 *
 * The operational dataset is a sequence of one-byte type, one-byte length,
 * value -- a different encoding from everything else here, and unrelated to
 * Matter TLV.
 */
#define MESHCOP_TLV_CHANNEL           0x00u
#define MESHCOP_TLV_PANID             0x01u
#define MESHCOP_TLV_EXTENDED_PANID    0x02u
#define MESHCOP_TLV_NETWORK_NAME      0x03u
#define MESHCOP_TLV_PSKC              0x04u
#define MESHCOP_TLV_NETWORK_KEY       0x05u
#define MESHCOP_TLV_MESH_LOCAL_PREFIX 0x07u
#define MESHCOP_TLV_SECURITY_POLICY   0x0cu
#define MESHCOP_TLV_ACTIVE_TIMESTAMP  0x0eu
#define MESHCOP_TLV_CHANNEL_MASK      0x35u

static bool dataset_channel_mask_valid(const uint8_t *value, size_t len)
{
	size_t i = 0u;

	while (i + 2u <= len) {
		size_t mask_len = value[i + 1u];

		if (mask_len == 0u || i + 2u + mask_len > len) {
			return false;
		}
		i += 2u + mask_len;
	}
	return i == len && i != 0u;
}

/**
 * Find the Extended PAN ID in a Thread operational dataset.
 *
 * Walked rather than indexed: the dataset's TLVs may arrive in any order, and a
 * length that runs past the end is a malformed dataset rather than a reason to
 * read past the buffer.
 */
static bool dataset_validate(const uint8_t *ds, size_t len,
			     uint8_t out[MATTER_THREAD_XPANID_LEN])
{
	size_t i = 0u;
	uint8_t seen[32] = { 0 };
	uint16_t required = 0u;
	enum {
		HAVE_ACTIVE_TIMESTAMP = 1u << 0,
		HAVE_CHANNEL = 1u << 1,
		HAVE_CHANNEL_MASK = 1u << 2,
		HAVE_XPANID = 1u << 3,
		HAVE_MESH_LOCAL_PREFIX = 1u << 4,
		HAVE_NETWORK_KEY = 1u << 5,
		HAVE_NETWORK_NAME = 1u << 6,
		HAVE_PANID = 1u << 7,
		HAVE_PSKC = 1u << 8,
		HAVE_SECURITY_POLICY = 1u << 9,
		HAVE_ALL = (1u << 10) - 1u,
	};

	if (ds == NULL || len == 0u || len > MATTER_THREAD_DATASET_MAX) {
		return false;
	}
	while (i + 2u <= len) {
		uint8_t type = ds[i];
		size_t vlen = ds[i + 1u];

		if (vlen == 0u || i + 2u + vlen > len ||
		    (seen[type / 8u] & (uint8_t)(1u << (type % 8u))) != 0u) {
			return false;
		}
		seen[type / 8u] |= (uint8_t)(1u << (type % 8u));
		switch (type) {
		case MESHCOP_TLV_ACTIVE_TIMESTAMP:
			if (vlen != 8u) {
				return false;
			}
			required |= HAVE_ACTIVE_TIMESTAMP;
			break;
		case MESHCOP_TLV_CHANNEL:
			if (vlen != 3u || ds[i + 2u] != 0u ||
			    (((uint16_t)ds[i + 3u] << 8) | ds[i + 4u]) < 11u ||
			    (((uint16_t)ds[i + 3u] << 8) | ds[i + 4u]) > 26u) {
				return false;
			}
			required |= HAVE_CHANNEL;
			break;
		case MESHCOP_TLV_PANID:
			if (vlen != 2u) {
				return false;
			}
			required |= HAVE_PANID;
			break;
		case MESHCOP_TLV_EXTENDED_PANID:
			if (vlen != MATTER_THREAD_XPANID_LEN) {
				return false;
			}
			memcpy(out, &ds[i + 2u], MATTER_THREAD_XPANID_LEN);
			required |= HAVE_XPANID;
			break;
		case MESHCOP_TLV_NETWORK_NAME:
			if (vlen == 0u || vlen > 16u) {
				return false;
			}
			required |= HAVE_NETWORK_NAME;
			break;
		case MESHCOP_TLV_PSKC:
			if (vlen != 16u) {
				return false;
			}
			required |= HAVE_PSKC;
			break;
		case MESHCOP_TLV_NETWORK_KEY:
			if (vlen != 16u) {
				return false;
			}
			required |= HAVE_NETWORK_KEY;
			break;
		case MESHCOP_TLV_MESH_LOCAL_PREFIX:
			if (vlen != 8u) {
				return false;
			}
			required |= HAVE_MESH_LOCAL_PREFIX;
			break;
		case MESHCOP_TLV_SECURITY_POLICY:
			if (vlen != 3u && vlen != 4u) {
				return false;
			}
			required |= HAVE_SECURITY_POLICY;
			break;
		case MESHCOP_TLV_CHANNEL_MASK:
			if (!dataset_channel_mask_valid(&ds[i + 2u], vlen)) {
				return false;
			}
			required |= HAVE_CHANNEL_MASK;
			break;
		default:
			break;
		}
		i += 2u + vlen;
	}
	return i == len && required == HAVE_ALL;
}

/**
 * Publish "<compressed-fabric-id>-<node-id>._matter._tcp" over SRP.
 *
 * Silent when there is no fabric yet: a node with a network but no identity has
 * no name to register under, and that is a legal intermediate state rather than
 * a failure. Failures ARE logged by the port, which is where the SRP server's
 * answer eventually lands.
 */
static void advertise_one(const struct matter_fabric *fabric);

/**
 * Advertise one Thread mDNS instance per provisioned fabric, deriving each instance name from the
 * compressed fabric ID and node ID. Do nothing if no fabrics are provisioned.
 */
static void advertise_operational(const struct matter_device_info *info)
{
	size_t fi;

	/*
	 * One instance PER FABRIC. The name is derived from the compressed
	 * fabric id and this node's id on that fabric, so a second
	 * administrator resolving the first fabric's name finds an address it
	 * cannot open a session to.
	 */
	for (fi = 0u; fi < MATTER_SUPPORTED_FABRICS; fi++) {
		if (info->fabrics[fi].index != 0u) {
			advertise_one(&info->fabrics[fi]);
		}
	}
}

/**
 * Advertise this fabric's instance name over Thread on the operational port if the name can be
 * derived.
 */
static void advertise_one(const struct matter_fabric *fabric)
{
	char name[MATTER_INSTANCE_NAME_LEN];

	if (matter_fabric_instance_name(fabric, name, sizeof(name)) != MATTER_OK) {
		return;
	}
	(void)matter_thread_advertise(name, MATTER_OPERATIONAL_PORT);
}

/**
 * Run one NetworkCommissioning command.
 *
 * @return the IM status. The networking verdict goes in last_network_status and
 *         travels in the response payload, the same split AddNOC uses.
 */
/* ---- AdministratorCommissioning (0x003C) ---------------------------------- */
/*
 * The cluster behind Apple Home's "Turn On Pairing Mode", and behind
 * multi-admin sharing generally. Without it a node is commissioned once, by
 * whoever got there first, and can never be handed to a second ecosystem --
 * which is what this board did until now: the button existed in the app and
 * the node answered UNSUPPORTED_CLUSTER.
 *
 * Everything with a side effect is behind hooks the port installs. This file
 * decodes and validates; opening a window means swapping the SPAKE2+ verifier
 * the PASE responder uses and putting the commissionable payload back on the
 * air, and neither belongs in a module that tests/host compiles without Zephyr.
 */
void matter_clusters_set_admin_hooks(const struct matter_admin_hooks *hooks)
{
	s_admin_hooks = hooks;
}

/**
 * Map a hook's cluster-specific status onto an IM status.
 *
 * Lossy, and knowingly so: Matter can carry a ClusterStatus alongside FAILURE
 * so a controller can tell "already open" from "that verifier is malformed",
 * and this IM does not encode one yet. A controller therefore sees a generic
 * failure. Worth fixing when something depends on the distinction; nothing
 * here does, because the only caller that matters retries either way.
 */
#ifndef TM_NO_ADMIN_COMMANDS
static uint8_t admin_status(uint8_t cluster_status)
{
	return cluster_status == 0u ? MATTER_IM_STATUS_SUCCESS : MATTER_IM_STATUS_FAILURE;
}
#endif

/**
 * Decode and dispatch an admin cluster command: open-enhanced-window, open-basic-window, or revoke.
 * Extract TLV-encoded parameters by tag, validate lengths exactly, delegate to the registered
 * hooks, and return a status code. None of the three commands carry a response payload.
 */
static uint8_t admin_command(const struct matter_im_invoke *inv, uint32_t *response_command)
{
#ifdef TM_NO_ADMIN_COMMANDS
	/* CONFIG_TINYTALK_ADMIN_COMMANDS=n: the cluster and its attributes stay,
	 * and only a local gesture opens a window. */
	(void)inv;
	*response_command = MATTER_IM_NO_RESPONSE;
	return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
#else
	const uint8_t *verifier = NULL;
	const uint8_t *salt = NULL;
	size_t verifier_len = 0;
	size_t salt_len = 0;
	uint64_t timeout = 0;
	uint64_t discriminator = 0;
	uint64_t iterations = 0;

	/* None of the three carries a response payload; the status IS the reply. */
	*response_command = MATTER_IM_NO_RESPONSE;

	if (s_admin_hooks == NULL) {
		return MATTER_IM_STATUS_FAILURE;
	}

	switch (inv->command) {
	case MATTER_CMD_ADMIN_OPEN_WINDOW:
		/*
		 * The commissioner supplies the verifier, so the setup code for
		 * this window is one IT chose and the factory code is never
		 * disclosed to the ecosystem being invited in. Field tags are
		 * positional per the spec: timeout, verifier, discriminator,
		 * iterations, salt.
		 */
		if (!field_u64(inv, 0u, &timeout) ||
		    !field_bytes(inv, 1u, &verifier, &verifier_len) ||
		    !field_u64(inv, 2u, &discriminator) || !field_u64(inv, 3u, &iterations) ||
		    !field_bytes(inv, 4u, &salt, &salt_len)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (s_admin_hooks->open_enhanced == NULL) {
			return MATTER_IM_STATUS_FAILURE;
		}
		return admin_status(s_admin_hooks->open_enhanced(
			(uint16_t)timeout, verifier, (uint32_t)verifier_len,
			(uint16_t)discriminator, (uint32_t)iterations, salt, (uint32_t)salt_len));

	case MATTER_CMD_ADMIN_OPEN_BASIC_WINDOW:
		if (!field_u64(inv, 0u, &timeout)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (s_admin_hooks->open_basic == NULL) {
			return MATTER_IM_STATUS_FAILURE;
		}
		return admin_status(s_admin_hooks->open_basic((uint16_t)timeout));

	case MATTER_CMD_ADMIN_REVOKE:
		if (s_admin_hooks->revoke == NULL) {
			return MATTER_IM_STATUS_FAILURE;
		}
		return admin_status(s_admin_hooks->revoke());

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
#endif
}

static uint8_t network_command(struct matter_device_info *info, const struct matter_im_invoke *inv,
			       uint32_t *response_command)
{
	const uint8_t *v = NULL;
	size_t v_len = 0u;
	uint8_t xpanid[MATTER_THREAD_XPANID_LEN];

	/*
	 * ScanNetworks needs no fail-safe, only Administer, which a PASE
	 * session has implicitly. The scan itself is the port's
	 * (matter_thread_scan()); where it cannot run the answer is
	 * UnknownError, which a commissioner reads as "no results".
	 */
	if (inv->command == MATTER_CMD_NC_SCAN_NETWORKS) {
		if (info->accessing_fabric_index != 0u &&
		    !fabric_slot_has_privilege(info,
					       fabric_slot_for_index(info, info->accessing_fabric_index),
					       MATTER_AC_PRIVILEGE_ADMINISTER, MATTER_ENDPOINT_ROOT,
					       MATTER_CLUSTER_NETWORK_COMMISSIONING)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		*response_command = MATTER_CMD_NC_SCAN_NETWORKS_RESPONSE;
		s_scan_n = 0u;
		info->last_network_status =
			matter_thread_scan(s_scan, MATTER_THREAD_SCAN_MAX, &s_scan_n) == MATTER_OK
				? MATTER_NC_STATUS_SUCCESS
				: MATTER_NC_STATUS_UNKNOWN_ERROR;
		return MATTER_IM_STATUS_SUCCESS;
	}
	if (!info->attempt.active) {
		return MATTER_IM_STATUS_FAILSAFE_REQUIRED;
	}

	switch (inv->command) {
	case MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK:
		*response_command = MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE;
		if (!field_bytes(inv, TAG_ADDTHREAD_DATASET, &v, &v_len) ||
		    !dataset_validate(v, v_len, xpanid)) {
			info->last_network_status = MATTER_NC_STATUS_OUT_OF_RANGE;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/* A second administrator may adopt the existing network, never
		 * silently move a working lock away from its current controllers.
		 * The Extended PAN ID is the network identity. Once it matches,
		 * retain the already-committed credentials instead of accepting a
		 * controller's differing timestamp, policy, or key material. */
		if (info->committed_slots != 0u) {
			if (!info->have_thread_xpanid ||
			    memcmp(xpanid, info->thread_xpanid, MATTER_THREAD_XPANID_LEN) != 0) {
				info->last_network_status = MATTER_NC_STATUS_BOUNDS_EXCEEDED;
				return MATTER_IM_STATUS_SUCCESS;
			}
			memcpy(info->attempt.thread_dataset, info->thread_dataset,
			       info->thread_dataset_len);
			info->attempt.thread_dataset_len = info->thread_dataset_len;
			memcpy(info->attempt.thread_xpanid, info->thread_xpanid,
			       MATTER_THREAD_XPANID_LEN);
		} else {
			memcpy(info->attempt.thread_dataset, v, v_len);
			info->attempt.thread_dataset_len = v_len;
			memcpy(info->attempt.thread_xpanid, xpanid, sizeof(xpanid));
		}
		info->attempt.have_thread_candidate = true;
		info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_NC_CONNECT_NETWORK:
		*response_command = MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE;
		/* LastNetworkID names the network this attempt was for, whether
		 * or not it succeeds. */
		if (field_bytes(inv, TAG_CONNECT_NETWORK_ID, &v, &v_len) &&
		    v_len == MATTER_THREAD_XPANID_LEN) {
			memcpy(info->last_network_id, v, MATTER_THREAD_XPANID_LEN);
			info->have_last_network_id = true;
		}
		if (!field_bytes(inv, TAG_CONNECT_NETWORK_ID, &v, &v_len) ||
		    v_len != MATTER_THREAD_XPANID_LEN || !info->attempt.have_thread_candidate ||
		    memcmp(v, info->attempt.thread_xpanid, MATTER_THREAD_XPANID_LEN) != 0) {
			info->last_network_status = MATTER_NC_STATUS_NETWORK_ID_NOT_FOUND;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (matter_thread_attached_to(info->attempt.thread_xpanid)) {
			info->thread_started = true;
		} else {
			/* start() may install the dataset before a later stack step
			 * fails. Mark it applied before the call so fail-safe rollback
			 * restores the committed network on every failure path. */
			info->attempt.thread_applied = true;
			info->thread_started =
				matter_thread_start(info->attempt.thread_dataset,
						    info->attempt.thread_dataset_len) == MATTER_OK;
		}
		if (!info->thread_started) {
			info->last_network_status = MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/*
		 * Blocks. The commissioner is waiting on this reply and allows
		 * up to the ConnectMaxTimeSeconds this node advertises, so the
		 * bound below has to stay comfortably under it. Reporting
		 * Success before the node is actually on the network would send
		 * the commissioner hunting for it and cost far more than a wait.
		 */
		if (matter_thread_wait_attached(MATTER_THREAD_ATTACH_TIMEOUT_MS) != MATTER_OK) {
			info->last_network_status = MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/*
		 * On the network, and now findable ON it. The commissioner
		 * closes BLE the moment this reply says Success and looks the
		 * node up in DNS-SD; registering after that would be a race
		 * against a search already under way.
		 */
		advertise_operational(info);
		info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_NC_REMOVE_NETWORK:
		*response_command = MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE;
		if (!field_bytes(inv, TAG_CONNECT_NETWORK_ID, &v, &v_len) ||
		    v_len != MATTER_THREAD_XPANID_LEN || !info->attempt.have_thread_candidate ||
		    memcmp(v, info->attempt.thread_xpanid, MATTER_THREAD_XPANID_LEN) != 0) {
			info->last_network_status = MATTER_NC_STATUS_NETWORK_ID_NOT_FOUND;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/* Removing an established network is a migration operation, not
		 * part of adding an administrator. Keep it out of this path. */
		if (info->committed_slots != 0u) {
			info->last_network_status = MATTER_NC_STATUS_BOUNDS_EXCEEDED;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (info->attempt.thread_applied) {
			(void)matter_thread_clear();
		}
		info->attempt.have_thread_candidate = false;
		info->attempt.thread_applied = false;
		info->attempt.thread_dataset_len = 0u;
		info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_NC_REORDER_NETWORK: {
		/* One network at most, so the only legal reorder moves it to
		 * index 0, where it already is. */
		const uint8_t *listed = listed_network(info);
		uint64_t index = 0u;

		*response_command = MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE;
		if (!field_bytes(inv, TAG_CONNECT_NETWORK_ID, &v, &v_len) ||
		    !field_u64(inv, TAG_REORDER_INDEX, &index)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (listed == NULL || v_len != MATTER_THREAD_XPANID_LEN ||
		    memcmp(v, listed, MATTER_THREAD_XPANID_LEN) != 0) {
			info->last_network_status = MATTER_NC_STATUS_NETWORK_ID_NOT_FOUND;
		} else if (index != 0u) {
			info->last_network_status = MATTER_NC_STATUS_OUT_OF_RANGE;
		} else {
			info->last_network_status = MATTER_NC_STATUS_SUCCESS;
		}
		return MATTER_IM_STATUS_SUCCESS;
	}

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/** Serialise what network_command() decided. */
static void network_fields(const struct matter_device_info *info, uint32_t response_command,
			   struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);

	if (response_command == MATTER_CMD_NC_SCAN_NETWORKS_RESPONSE) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_SCANRESP_STATUS),
					 info->last_network_status);
		if (info->last_network_status == MATTER_NC_STATUS_SUCCESS) {
			(void)matter_tlv_start_container(w, MATTER_TLV_CTX(TAG_SCANRESP_THREAD),
							 MATTER_TLV_ARRAY);
			for (uint8_t i = 0u; i < s_scan_n && i < MATTER_THREAD_SCAN_MAX; i++) {
				const struct matter_thread_scan_result *r = &s_scan[i];
				uint64_t xpanid = 0u;
				size_t name_len = 0u;

				while (name_len < sizeof(r->name) - 1u && r->name[name_len] != '\0') {
					name_len++;
				}

				for (size_t k = 0u; k < sizeof(r->xpanid); k++) {
					xpanid = (xpanid << 8) | r->xpanid[k];
				}
				(void)matter_tlv_start_container(w, MATTER_TLV_ANON,
								 MATTER_TLV_STRUCTURE);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(0u), r->pan_id);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(1u), xpanid);
				(void)matter_tlv_put_utf8(w, MATTER_TLV_CTX(2u), r->name, name_len);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(3u), r->channel);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(4u), r->version);
				(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(5u), r->ext_addr,
							   sizeof(r->ext_addr));
				(void)matter_tlv_put_i64(w, MATTER_TLV_CTX(6u), r->rssi);
				(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(7u), r->lqi);
				(void)matter_tlv_end_container(w);
			}
			(void)matter_tlv_end_container(w);
		}
	} else if (response_command == MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CONNRESP_STATUS),
					 info->last_network_status);
		/* ErrorValue is nullable and mandatory: null is what a device
		 * sends when the failure has no driver-specific code behind it. */
		(void)matter_tlv_put_null(w, MATTER_TLV_CTX(TAG_CONNRESP_ERROR));
	} else {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NCRESP_STATUS),
					 info->last_network_status);
		if (info->last_network_status == MATTER_NC_STATUS_SUCCESS) {
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NCRESP_INDEX), 0u);
		}
	}

	(void)matter_tlv_end_container(w);
}

/**
 * Install the root the commissioner wants this node to trust.
 *
 * Only the public key is kept -- see matter_fabric.h. Nothing is verified: this
 * node has no prior opinion about which roots are legitimate, which is exactly
 * what makes it commissionable.
 */
static uint8_t add_trusted_root(struct matter_device_info *info, const struct matter_im_invoke *inv)
{
	const uint8_t *cert = NULL;
	size_t cert_len = 0u;
	struct matter_cert_info ci;

	if (!field_bytes(inv, TAG_ADDROOT_CERT, &cert, &cert_len) || cert_len > MATTER_CERT_MAX) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	if (matter_cert_parse(cert, cert_len, &ci) != MATTER_OK || !ci.have_public_key) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}

	{
		size_t slot = MATTER_SUPPORTED_FABRICS;
		struct matter_fabric *f = fabric_pending(info, &slot);

		/* Every slot already holds a complete fabric. Refused here
		 * rather than at AddNOC, so the commissioner learns before it
		 * mints an operational certificate this node cannot accept. */
		if (f == NULL) {
			return MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
		}
		memcpy(f->root_public_key, ci.public_key, sizeof(ci.public_key));
		f->have_root = true;
		info->attempt.owned_slots |= MATTER_FABRIC_SLOT_BIT(slot);
	}
	return MATTER_IM_STATUS_SUCCESS;
}

/**
 * Accept the operational identity the commissioner minted for this node.
 *
 * @return the NodeOperationalCertStatusEnum for the reply. Every refusal is one
 *         of these rather than an IM status, because each names WHICH input was
 *         wrong and a commissioner can act on that.
 */
static uint8_t add_noc(struct matter_device_info *info, const struct matter_im_invoke *inv)
{
	const uint8_t *noc = NULL;
	const uint8_t *icac = NULL;
	const uint8_t *ipk = NULL;
	size_t noc_len = 0u;
	size_t icac_len = 0u;
	size_t ipk_len = 0u;
	struct matter_cert_info ci;
	struct matter_fabric *fab;
	size_t slot = MATTER_SUPPORTED_FABRICS;
	uint8_t new_index;
	uint64_t admin_subject = 0u;
	uint64_t admin_vendor = 0u;

	if (!info->have_op_key) {
		/* No CSR, so there is no private key behind whatever public key
		 * this NOC certifies. */
		return MATTER_NOC_STATUS_MISSING_CSR;
	}
	fab = fabric_pending(info, &slot);
	if (fab == NULL) {
		/* Every slot holds a complete fabric already. This is what a
		 * second administrator sees on a node built for one, and it is
		 * where Apple stopped: the phone and the home hub each want
		 * their own. */
		return MATTER_NOC_STATUS_TABLE_FULL;
	}
	if (!fab->have_root) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}

	if (!field_bytes(inv, TAG_ADDNOC_NOC, &noc, &noc_len) || noc_len > MATTER_NOC_MAX ||
	    !field_bytes(inv, TAG_ADDNOC_IPK, &ipk, &ipk_len) || ipk_len != MATTER_IPK_LEN ||
	    !field_u64(inv, TAG_ADDNOC_CASE_ADMIN_SUBJECT, &admin_subject) || admin_subject == 0u ||
	    !field_u64(inv, TAG_ADDNOC_ADMIN_VENDOR_ID, &admin_vendor) ||
	    admin_vendor > UINT16_MAX) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}
	if (matter_cert_parse(noc, noc_len, &ci) != MATTER_OK || !ci.have_node_id ||
	    !ci.have_fabric_id || !ci.have_public_key) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}
	/*
	 * The certified key must be the one this node minted for the CSR.
	 * Installing an identity whose private half this node does not hold
	 * would look like success here and surface much later as a CASE that
	 * never completes, with nothing to point at.
	 */
	if (memcmp(ci.public_key, info->op_pub, sizeof(info->op_pub)) != 0) {
		return MATTER_NOC_STATUS_INVALID_PUBLIC_KEY;
	}
	/* Optional: absent when the commissioner signed the NOC with its root
	 * directly, which is what Apple does. */
	(void)field_bytes(inv, TAG_ADDNOC_ICAC, &icac, &icac_len);
	if (icac_len > MATTER_CERT_MAX) {
		return MATTER_NOC_STATUS_INVALID_NOC;
	}
	new_index = fabric_next_index(info);
	if (new_index == 0u) {
		return MATTER_NOC_STATUS_TABLE_FULL;
	}
	/* The constrained target has one ICAC buffer. Refuse a second owner
	 * before mutating either fabric so no certificate is silently replaced. */
	if (icac_len != 0u && info->icac.owner_index != 0u &&
	    info->icac.owner_index != new_index) {
		return MATTER_NOC_STATUS_TABLE_FULL;
	}

	memcpy(fab->noc, noc, noc_len);
	fab->noc_len = noc_len;
	if (icac_len != 0u) {
		memcpy(info->icac.buf, icac, icac_len);
		info->icac.len = icac_len;
		info->icac.owner_index = new_index;
	}
	fab->icac_len = icac_len;
	memcpy(fab->ipk, ipk, ipk_len);
	/*
	 * The key this fabric's NOC certifies, taken from the CSR that preceded
	 * it. Copied INTO the fabric rather than left in info->op_priv: the next
	 * administrator issues its own CSRRequest and overwrites that, and a
	 * node that signed Sigma2 with the wrong fabric's key would verify
	 * against the wrong certificate and be refused with nothing said.
	 */
	memcpy(fab->op_priv, info->op_priv, sizeof(fab->op_priv));
	fab->node_id = ci.node_id;
	fab->fabric_id = ci.fabric_id;
	fab->case_admin_subject = admin_subject;
	fab->admin_vendor_id = (uint16_t)admin_vendor;
	fab->index = new_index;
	/*
	 * Findable on the new fabric, immediately. A second administrator adds
	 * its fabric over an EXISTING CASE session and then has to open a new
	 * one to the identity it has just issued -- which means resolving a
	 * DNS-SD name that only exists once this runs. Registration at
	 * ConnectNetwork covers the first fabric only; that is where the second
	 * administrator stopped, with the fabric accepted and nothing to reach.
	 */
	advertise_one(fab);
	/* Held for the response, which is serialised after this has run. */
	info->last_noc_index = fab->index;
	return MATTER_NOC_STATUS_OK;
}

/**
 * Run one OperationalCredentials command.
 *
 * Everything expensive happens here -- the signature, and for a CSR a fresh
 * P-256 key pair -- because this runs exactly once per request while
 * opcred_fields() may not.
 *
 * Out of line on purpose. Its frame is about 400 bytes of scratch, and the
 * optimiser folding it into command() put that under every other command too:
 * MEASURED 2026-10-05, command()'s frame went from 144 to 456 bytes after an
 * unrelated change tipped the inliner.
 */
static __attribute__((noinline)) uint8_t opcred_command(struct matter_device_info *info,
							const struct matter_im_invoke *inv,
							uint32_t *response_command)
{
	const uint8_t *nonce = NULL;
	size_t nonce_len = 0u;
	uint64_t v = 0u;
	int rc;

	switch (inv->command) {
	case MATTER_CMD_OC_CERTIFICATE_CHAIN_REQUEST: {
		const uint8_t *cert = NULL;
		size_t cert_len = 0u;

		if (!field_u64(inv, TAG_CERT_TYPE, &v) || v > UINT8_MAX) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/* Checked here rather than when writing the reply, because a
		 * reply has no way to say "no such certificate". */
		if (matter_attest_cert((uint8_t)v, &cert, &cert_len) != MATTER_OK) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		info->cert_type = (uint8_t)v;
		*response_command = MATTER_CMD_OC_CERTIFICATE_CHAIN_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}

	case MATTER_CMD_OC_ATTESTATION_REQUEST:
		if (!info->have_challenge) {
			/* Nothing to bind the signature to. Refusing beats
			 * signing something a recorded session could reuse. */
			return MATTER_IM_STATUS_FAILURE;
		}
		if (!field_bytes(inv, TAG_ATTEST_NONCE, &nonce, &nonce_len) ||
		    nonce_len != MATTER_ATTEST_NONCE_LEN) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/* No clock on this node, and 0 is what a device without one
		 * sends -- not a placeholder for something better. */
		rc = matter_attest_elements_encode(nonce, nonce_len, 0u, info->attest_buf,
						   MATTER_ATTEST_ELEMENTS_MAX, &info->attest_len);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		rc = matter_attest_sign_with_challenge(
			info->attest_buf, info->attest_len, sizeof(info->attest_buf),
			info->attestation_challenge, sizeof(info->attestation_challenge),
			info->attest_sig);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		*response_command = MATTER_CMD_OC_ATTESTATION_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_OC_CSR_REQUEST: {
		uint8_t csr[MATTER_CSR_MAX];
		size_t csr_len = 0u;

		if (!info->have_challenge) {
			return MATTER_IM_STATUS_FAILURE;
		}
		if (!field_bytes(inv, TAG_CSR_NONCE, &nonce, &nonce_len) ||
		    nonce_len != MATTER_ATTEST_NONCE_LEN) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		/*
		 * A FRESH key every time. Reusing one across commissioning
		 * attempts would let a fabric that saw an earlier CSR recognise
		 * the node on another.
		 */
		if (matter_attest_ec_keygen(info->op_priv, info->op_pub) != 0) {
			return MATTER_IM_STATUS_FAILURE;
		}
		info->have_op_key = true;
		if (matter_attest_csr(info->op_priv, info->op_pub, csr, sizeof(csr), &csr_len) !=
		    MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		rc = matter_attest_nocsr_encode(csr, csr_len, nonce, nonce_len, info->attest_buf,
						MATTER_ATTEST_ELEMENTS_MAX, &info->attest_len);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		rc = matter_attest_sign_with_challenge(
			info->attest_buf, info->attest_len, sizeof(info->attest_buf),
			info->attestation_challenge, sizeof(info->attestation_challenge),
			info->attest_sig);
		if (rc != MATTER_OK) {
			return MATTER_IM_STATUS_FAILURE;
		}
		*response_command = MATTER_CMD_OC_CSR_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}

	case MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE:
		/*
		 * Both of the commands below change what this node believes
		 * about who owns it, which is precisely what a fail-safe exists
		 * to be able to undo. Doing either outside one would leave a
		 * half-installed identity with nothing scheduled to remove it.
		 */
		if (!info->attempt.active) {
			return MATTER_IM_STATUS_FAILSAFE_REQUIRED;
		}
		/* No response command: the reply is a bare SUCCESS status. */
		*response_command = MATTER_IM_NO_RESPONSE;
		return add_trusted_root(info, inv);

	case MATTER_CMD_OC_ADD_NOC:
		if (!info->attempt.active) {
			return MATTER_IM_STATUS_FAILSAFE_REQUIRED;
		}
		info->last_noc_status = add_noc(info, inv);
		*response_command = MATTER_CMD_OC_NOC_RESPONSE;
		/* SUCCESS means "a NOCResponse follows", not "the NOC was
		 * accepted"; last_noc_status carries the verdict. */
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_OC_REMOVE_FABRIC: {
		size_t i;
		size_t accessing_slot;

		/* Reset the response latch before any validation. A rejected request
		 * must never leave a prior successful removal visible to its caller. */
		info->last_noc_status = MATTER_NOC_STATUS_INVALID_FABRIC_INDEX;
		info->last_noc_index = 0u;

		/*
		 * NOT gated on the fail-safe, unlike the additions above: a
		 * removal is administration, not commissioning, and the
		 * controllers that send it -- chip-tool's remove-fabric, a hub
		 * cleaning up after itself -- arm no fail-safe first. A full
		 * table whose orphaned owners can never be removed leaves a
		 * factory wipe as the only way to commission again.
		 */
		if (!field_u64(inv, TAG_REMOVE_FABRIC_INDEX, &v)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		accessing_slot = fabric_slot_for_index(info, info->accessing_fabric_index);
		if (!fabric_slot_has_privilege(info, accessing_slot,
					 MATTER_AC_PRIVILEGE_ADMINISTER, MATTER_ENDPOINT_ROOT,
					 MATTER_CLUSTER_OPERATIONAL_CREDENTIALS)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		/* An index this table cannot hold and an index it merely does
		 * not hold answer the same way: through the NOCResponse, which
		 * is where a commissioner looks for the verdict. */
		for (i = 0u;
		     v >= 1u && v <= MATTER_SUPPORTED_FABRICS && i < MATTER_SUPPORTED_FABRICS;
		     i++) {
			struct matter_fabric *f = &info->fabrics[i];

			if (f->index != (uint8_t)v) {
				continue;
			}
			/* A successful response must survive reset. Write the targeted
			 * tombstone before dropping keys or withdrawing discovery. */
			if (fabric_store(info, MATTER_FABRIC_STORE_REMOVE, i, NULL, 0u) !=
			    MATTER_OK) {
				*response_command = MATTER_IM_NO_RESPONSE;
				return MATTER_IM_STATUS_FAILURE;
			}
			fabric_slot_clear(info, i);
			info->last_noc_status = MATTER_NOC_STATUS_OK;
			info->last_noc_index = (uint8_t)v;
			break;
		}
		*response_command = MATTER_CMD_OC_NOC_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;
	}

	case MATTER_CMD_OC_UPDATE_FABRIC_LABEL: {
		const char *label = NULL;
		size_t label_len = 0u;
		size_t slot = fabric_slot_for_request(info, info->accessing_fabric_index);
		struct matter_fabric *f;
		char prev[sizeof(info->fabrics[0].label)];
		uint8_t prev_len;

		/* Fabric-scoped: the label belongs to the session's own fabric,
		 * and the answer is a NOCResponse exactly as for AddNOC. */
		*response_command = MATTER_CMD_OC_NOC_RESPONSE;
		info->last_noc_status = MATTER_NOC_STATUS_INVALID_FABRIC_INDEX;
		info->last_noc_index = 0u;

		if (!field_utf8(inv, TAG_UPDATE_LABEL, &label, &label_len)) {
			return MATTER_IM_STATUS_INVALID_COMMAND;
		}
		if (label_len > sizeof(f->label)) {
			return MATTER_IM_STATUS_CONSTRAINT_ERROR;
		}
		if (slot >= MATTER_SUPPORTED_FABRICS) {
			return MATTER_IM_STATUS_SUCCESS;
		}
		/* A non-empty label taken by ANOTHER fabric is refused in the
		 * response body; every fabric starts empty and empty never
		 * conflicts, or the second commissioner could not exist. */
		if (label_len != 0u) {
			for (size_t i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
				if (i != slot && info->fabrics[i].index != 0u &&
				    info->fabrics[i].label_len == label_len &&
				    memcmp(info->fabrics[i].label, label, label_len) == 0) {
					info->last_noc_status = MATTER_NOC_STATUS_LABEL_CONFLICT;
					return MATTER_IM_STATUS_SUCCESS;
				}
			}
		}
		f = &info->fabrics[slot];
		prev_len = f->label_len;
		memcpy(prev, f->label, sizeof(prev));
		memcpy(f->label, label, label_len);
		f->label_len = (uint8_t)label_len;
		/* The store reads the slot's record from RAM, so the mutation
		 * comes first -- and is unwound if durability is refused, per
		 * the hooks contract: no committed RAM change on failure. */
		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u &&
		    fabric_store(info, MATTER_FABRIC_STORE_UPDATE, slot, NULL, 0u) != MATTER_OK) {
			memcpy(f->label, prev, sizeof(prev));
			f->label_len = prev_len;
			*response_command = MATTER_IM_NO_RESPONSE;
			return MATTER_IM_STATUS_FAILURE;
		}
		info->last_noc_status = MATTER_NOC_STATUS_OK;
		info->last_noc_index = info->accessing_fabric_index;
		return MATTER_IM_STATUS_SUCCESS;
	}

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/** Serialise what opcred_command() already computed. */
static void opcred_fields(const struct matter_device_info *info, uint32_t response_command,
			  struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);

	if (response_command == MATTER_CMD_OC_CERTIFICATE_CHAIN_RESPONSE) {
		const uint8_t *cert = NULL;
		size_t cert_len = 0u;

		if (matter_attest_cert(info->cert_type, &cert, &cert_len) == MATTER_OK) {
			(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_RESP_CERT), cert,
						   cert_len);
		}
	} else if (response_command == MATTER_CMD_OC_NOC_RESPONSE) {
		(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NOCRESP_STATUS),
					 info->last_noc_status);
		/*
		 * FabricIndex only on success, and DebugText not at all. Both
		 * are optional and CHIP's own device omits them the same way
		 * (operational-credentials-cluster.cpp, SendNOCResponse) -- an
		 * index for a fabric that was not created would be a number the
		 * commissioner could act on.
		 */
		if (info->last_noc_status == MATTER_NOC_STATUS_OK) {
			(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_NOCRESP_FABRIC_INDEX),
						 info->last_noc_index);
		}
	} else {
		/* AttestationResponse and CSRResponse are the same shape: the
		 * elements, then the signature over them. */
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_RESP_ELEMENTS), info->attest_buf,
					   info->attest_len);
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_RESP_SIGNATURE), info->attest_sig,
					   sizeof(info->attest_sig));
	}

	(void)matter_tlv_end_container(w);
}

/**
 * True when @p index names a fabric this node has COMMITTED (not merely staged
 * inside a live fail-safe). Used to decide whether a repeated
 * CommissioningComplete is a retransmission of one that already succeeded.
 */
static bool fabric_index_committed(const struct matter_device_info *info, uint8_t index)
{
	size_t i;

	if (index == 0u) {
		return false;
	}
	for (i = 0u; i < MATTER_SUPPORTED_FABRICS; i++) {
		if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(i)) != 0u &&
		    info->fabrics[i].index == index) {
			return true;
		}
	}
	return false;
}

/* A command on a table-described cluster, checked against the table. */
static uint8_t table_invoke(struct matter_device_info *info, const struct tm_cluster *c,
			    const struct matter_im_invoke *inv, uint32_t *response_command)
{
	size_t accessing_slot = fabric_slot_for_index(info, info->accessing_fabric_index);
	struct tm_req req;

	/* PASE, a removed fabric, and a provisional identity cannot operate
	 * the lock. */
	if (accessing_slot >= MATTER_SUPPORTED_FABRICS || info->accessing_node_id == 0u) {
		return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
	}
	if (c->invoke == NULL || !id_listed(c->accepted, c->n_accepted, inv->command)) {
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
	if (!fabric_slot_has_privilege(info, accessing_slot,
				       c->invoke_privilege != 0u ? c->invoke_privilege
								 : MATTER_AC_PRIVILEGE_OPERATE,
				       inv->endpoint, inv->cluster)) {
		return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
	}
	app_req(info, inv->endpoint, false, &req);
	return c->invoke(&req, inv->command, inv->has_fields ? inv->fields : NULL,
			 inv->has_fields ? inv->fields_len : 0u, response_command);
}

static uint8_t command(void *ctx, const struct matter_im_invoke *inv, uint32_t *response_command)
{
	struct matter_device_info *info = (struct matter_device_info *)ctx;
	uint64_t v = 0u;

	/*
	 * The lock endpoint answers commands too. Refusing every command here
	 * with UNSUPPORTED_ENDPOINT while Descriptor, PartsList and every
	 * attribute read say endpoint 1 exists is a direct self-contradiction,
	 * and it is what a real controller reported back as "the endpoint
	 * indicated is unsupported on the node" before abandoning the pairing.
	 *
	 * UNSUPPORTED_COMMAND is the honest answer for the Door Lock commands
	 * this node has not implemented: the endpoint and the cluster are both
	 * real, the command is not. A controller can act on that; it cannot act
	 * on an endpoint that claims to exist and not exist at once.
	 */
	if (inv->endpoint != MATTER_ENDPOINT_ROOT) {
		const struct tm_endpoint *ep = app_endpoint(inv->endpoint, NULL);
		const struct tm_cluster *c;

		if (ep == NULL) {
			return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
		}
		c = app_cluster(ep, inv->cluster);
		if (c == NULL) {
			return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
		}
		return table_invoke(info, c, inv, response_command);
	}
	if (root_table(inv->cluster) != NULL) {
		return table_invoke(info, root_table(inv->cluster), inv, response_command);
	}
	if (inv->cluster == MATTER_CLUSTER_ADMIN_COMMISSIONING) {
		size_t accessing_slot =
			fabric_slot_for_index(info, info->accessing_fabric_index);

		if (!fabric_slot_has_privilege(info, accessing_slot,
					 MATTER_AC_PRIVILEGE_ADMINISTER, MATTER_ENDPOINT_ROOT,
					 MATTER_CLUSTER_ADMIN_COMMISSIONING)) {
			return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
		}
		return admin_command(inv, response_command);
	}
	if (inv->cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		return opcred_command(info, inv, response_command);
	}
	if (inv->cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		return network_command(info, inv, response_command);
	}
	if (inv->cluster != MATTER_CLUSTER_GENERAL_COMMISSIONING) {
		return MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}

	switch (inv->command) {
	case MATTER_CMD_GC_ARM_FAIL_SAFE:
		/*
		 * The breadcrumb is the commissioner's own progress marker: it
		 * sets it here and reads it back if it has to resume, so losing
		 * it makes a retry restart from nothing.
		 */
		{
			uint64_t expiry = 0u;
			bool new_attempt = !info->attempt.active;

			if (!field_u64(inv, 0u, &expiry) || expiry > info->failsafe_max_s) {
				info->last_commissioning_error =
					MATTER_COMMISSIONING_VALUE_OUTSIDE_RANGE;
				*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
			if (field_u64(inv, 1u, &v)) {
				info->breadcrumb = v;
			}
			if (expiry == 0u) {
				matter_clusters_failsafe_expire(info);
				info->last_commissioning_error = MATTER_COMMISSIONING_OK;
				*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
			if (!info->attempt.active) {
				memset(&info->attempt, 0, sizeof(info->attempt));
				info->attempt.active = true;
				/* A new transaction: whatever completed before
				 * is no longer what a repeat would be asking
				 * about. */
				info->last_completed_fabric_index = 0u;
			}
			if (info->commissioning_hooks != NULL &&
			    info->commissioning_hooks->failsafe_arm != NULL &&
			    info->commissioning_hooks->failsafe_arm(
				    info->commissioning_hooks->ctx, (uint16_t)expiry) != MATTER_OK) {
				if (new_attempt) {
					memset(&info->attempt, 0, sizeof(info->attempt));
				}
				info->last_commissioning_error =
					MATTER_COMMISSIONING_BUSY_WITH_OTHER;
				*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
		}
		info->last_commissioning_error = MATTER_COMMISSIONING_OK;
		*response_command = MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_GC_SET_REGULATORY_CONFIG:
		if (field_u64(inv, 0u, &v)) {
			/* Accept only what LocationCapability claims to support.
			 * Saying yes to a location this node cannot honour is a
			 * lie the commissioner has no way to detect. */
			if (v != info->location_capability &&
			    info->location_capability != MATTER_REGULATORY_INDOOR_OUTDOOR) {
				info->last_commissioning_error =
					MATTER_COMMISSIONING_VALUE_OUTSIDE_RANGE;
				*response_command = MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE;
				return MATTER_IM_STATUS_SUCCESS;
			}
			info->regulatory_config = (uint8_t)v;
		}
		if (field_u64(inv, 2u, &v)) {
			info->breadcrumb = v;
		}
		info->last_commissioning_error = MATTER_COMMISSIONING_OK;
		*response_command = MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE;
		return MATTER_IM_STATUS_SUCCESS;

	case MATTER_CMD_GC_COMMISSIONING_COMPLETE:
	{
		size_t slot;

		*response_command = MATTER_CMD_GC_COMMISSIONING_COMPLETE_RESPONSE;
		/*
		 * Refused over anything but CASE, and NO_FAIL_SAFE rather than
		 * OK because OK would be a lie: the command asserts that the
		 * commissioner has reached this node operationally, and until a
		 * CASE session exists it has not. Telling the truth makes the
		 * commissioner fail cleanly instead of believing it owns a node
		 * it cannot reach.
		 */
		if (!info->attempt.active || info->accessing_fabric_index == 0u ||
		    info->accessing_node_id == 0u) {
			/*
			 * A retransmission of the command that just succeeded,
			 * not a new one. MRP cannot absorb it: the commissioner
			 * re-sends under a fresh message counter once its retry
			 * timer expires, so the replay window lets it through
			 * and it lands here with the fail-safe already disarmed.
			 * Answering OK repeats the answer that was lost; the
			 * command is idempotent and its whole effect is done.
			 */
			if (info->accessing_fabric_index != 0u &&
			    info->accessing_fabric_index == info->last_completed_fabric_index &&
			    fabric_index_committed(info, info->accessing_fabric_index)) {
				info->last_commissioning_error = MATTER_COMMISSIONING_OK;
				return MATTER_IM_STATUS_SUCCESS;
			}
			info->last_commissioning_error = MATTER_COMMISSIONING_NO_FAIL_SAFE;
			return MATTER_IM_STATUS_SUCCESS;
		}
		for (slot = 0u; slot < MATTER_SUPPORTED_FABRICS; slot++) {
			const struct matter_fabric *f = &info->fabrics[slot];

			if ((info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u &&
			    f->index == info->accessing_fabric_index &&
			    /*
			     * The == 0u escape STAYS. A fabric whose admin
			     * subject was never recorded has nobody to compare
			     * against, and refusing there would fail
			     * CommissioningComplete for a commissioner that
			     * simply did not send one. Only the second half
			     * gains CAT matching.
			     */
			    (f->case_admin_subject == 0u ||
			     acl_subject_matches(f->case_admin_subject, info->accessing_node_id,
						 info->accessing_cats,
						 info->accessing_n_cats))) {
				break;
			}
		}
		if (slot >= MATTER_SUPPORTED_FABRICS ||
		    (info->committed_slots == 0u && !info->attempt.have_thread_candidate)) {
			info->last_commissioning_error = MATTER_COMMISSIONING_INVALID_AUTH;
			return MATTER_IM_STATUS_SUCCESS;
		}
		if (fabric_store(info, MATTER_FABRIC_STORE_COMMIT_ATTEMPT, slot, NULL, 0u) !=
		    MATTER_OK) {
			info->last_commissioning_error = MATTER_COMMISSIONING_BUSY_WITH_OTHER;
			return MATTER_IM_STATUS_SUCCESS;
		}
		/*
		 * Commit. Disarming the fail-safe is the substance of the
		 * command, not bookkeeping: until this point every fabric,
		 * every key and the whole operational identity are provisional
		 * and matter_clusters_failsafe_expire() will erase them.
		 */
		if (info->attempt.have_thread_candidate) {
			memcpy(info->thread_dataset, info->attempt.thread_dataset,
			       info->attempt.thread_dataset_len);
			info->thread_dataset_len = info->attempt.thread_dataset_len;
			memcpy(info->thread_xpanid, info->attempt.thread_xpanid,
			       MATTER_THREAD_XPANID_LEN);
			info->have_thread_xpanid = true;
		}
		info->committed_slots |= info->attempt.owned_slots;
		memset(&info->attempt, 0, sizeof(info->attempt));
		if (info->commissioning_hooks != NULL &&
		    info->commissioning_hooks->failsafe_cancel != NULL) {
			info->commissioning_hooks->failsafe_cancel(info->commissioning_hooks->ctx);
		}
		info->last_completed_fabric_index = info->accessing_fabric_index;
		info->last_commissioning_error = MATTER_COMMISSIONING_OK;
		return MATTER_IM_STATUS_SUCCESS;
	}

	default:
		return MATTER_IM_STATUS_UNSUPPORTED_COMMAND;
	}
}

/**
 * Encode the fields of a command response based on endpoint, cluster, and response command type.
 * Handles OperationalCredentials, NetworkCommissioning, and GeneralCommissioning responses on the
 * root endpoint.
 */
static void command_fields(void *ctx, uint16_t endpoint, uint32_t cluster,
			   uint32_t response_command, struct matter_tlv_writer *w,
			   matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;

	if (endpoint != MATTER_ENDPOINT_ROOT) {
		const struct tm_endpoint *ep = app_endpoint(endpoint, NULL);
		const struct tm_cluster *c = ep != NULL ? app_cluster(ep, cluster) : NULL;
		struct tm_req req;

		if (c != NULL && c->response != NULL) {
			app_req(info, endpoint, false, &req);
			c->response(&req, response_command, w, tag);
		}
		return;
	}
	if (root_table(cluster) != NULL) {
		struct tm_req req;

		if (root_table(cluster)->response != NULL) {
			app_req(info, endpoint, false, &req);
			root_table(cluster)->response(&req, response_command, w, tag);
		}
		return;
	}
	if (cluster == MATTER_CLUSTER_OPERATIONAL_CREDENTIALS) {
		opcred_fields(info, response_command, w, tag);
		return;
	}
	if (cluster == MATTER_CLUSTER_NETWORK_COMMISSIONING) {
		network_fields(info, response_command, w, tag);
		return;
	}
	(void)response_command;

	/*
	 * All three GeneralCommissioning responses carry the same two fields:
	 * ErrorCode then DebugText (Commands.h:133-134, 209-210). DebugText is
	 * mandatory and empty, not omitted -- a missing mandatory field is a
	 * decode failure at the commissioner, which presents as a hang.
	 */
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(0u), info->last_commissioning_error);
	(void)matter_tlv_put_utf8(w, MATTER_TLV_CTX(1u), "", 0u);
	(void)matter_tlv_end_container(w);
}

int matter_clusters_resume(struct matter_device_info *info)
{
	if (info == NULL || info->thread_dataset_len == 0u) {
		return MATTER_E_STATE;
	}

	info->thread_started =
		matter_thread_start(info->thread_dataset, info->thread_dataset_len) == MATTER_OK;
	if (!info->thread_started) {
		return MATTER_E_STATE;
	}

	/*
	 * Advertise every restored fabric, not just the first. The same rule as
	 * AddNOC: an administrator resolving a name this node never registered
	 * finds nothing and gives up, and on a reboot there is no commissioner
	 * coming along afterwards to fix it.
	 */
	advertise_operational(info);
	return MATTER_OK;
}

/**
 * Roll back fabric state created after the fail-safe was armed, wiping every
 * provisional fabric's private key and intermediate certificate.
 */
void matter_clusters_failsafe_expire(struct matter_device_info *info)
{
	size_t slot;

	if (info == NULL || !info->attempt.active) {
		return;
	}

	/*
	 * Only fabric slots created inside this fail-safe. Slots captured when it
	 * was armed belong to completed commissioning transactions and must
	 * survive a later administrator abandoning its own AddNOC. Wipe each new
	 * slot in full because it holds the private key its NOC certifies.
	 */
	for (slot = 0u; slot < MATTER_SUPPORTED_FABRICS; slot++) {
		if ((info->attempt.owned_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u) {
			fabric_slot_clear(info, slot);
		}
	}
	if (info->attempt.thread_applied) {
		if (info->committed_slots != 0u && info->thread_dataset_len != 0u) {
			info->thread_started =
				matter_thread_start(info->thread_dataset, info->thread_dataset_len) ==
				MATTER_OK;
			if (info->thread_started) {
				advertise_operational(info);
			}
		} else {
			(void)matter_thread_clear();
			info->thread_started = false;
		}
	}
	memset(info->op_priv, 0, sizeof(info->op_priv));
	memset(info->op_pub, 0, sizeof(info->op_pub));
	info->have_op_key = false;
	info->last_noc_status = MATTER_NOC_STATUS_OK;

	memset(&info->attempt, 0, sizeof(info->attempt));
	info->breadcrumb = 0u;
	info->last_commissioning_error = MATTER_COMMISSIONING_OK;
}

/**
 * Apply an attribute write.
 *
 * One attribute is writable on this node: the ACL. A commissioner's last act is
 * writing itself an entry granting Administer over CASE, and refusing it leaves
 * a home app that finished commissioning and then cannot record that it owns
 * the node -- which is what "Adding to home" is waiting on.
 *
 * The value is stored byte-for-byte so it can be reported back. The bounded
 * access checker above decodes only the fields needed for CASE authorization.
 */
/* A write to a table-described cluster, or to no cluster (@p c NULL). */
static uint8_t table_write(struct matter_device_info *info, const struct tm_cluster *c,
			   const struct matter_im_path *path, const uint8_t *data, size_t data_len)
{
	size_t accessing_slot = fabric_slot_for_index(info, info->accessing_fabric_index);
	struct tm_req req;

	if (!fabric_slot_has_privilege(info, accessing_slot,
				       (c != NULL && c->write_privilege != 0u)
					       ? c->write_privilege
					       : MATTER_AC_PRIVILEGE_OPERATE,
				       path->endpoint, path->cluster)) {
		return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
	}
	if (c == NULL) {
		return path->cluster == MATTER_CLUSTER_DESCRIPTOR ? MATTER_IM_STATUS_UNSUPPORTED_WRITE
								  : MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}
	if (!id_listed(c->attrs, c->n_attrs, path->attribute)) {
		return MATTER_IM_STATUS_UNSUPPORTED_ATTRIBUTE;
	}
	if (c->write == NULL) {
		return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
	}
	app_req(info, path->endpoint, false, &req);
	return c->write(&req, path->attribute, data, data_len);
}

static uint8_t attr_write(void *ctx, const struct matter_im_path *path, const uint8_t *data,
			  size_t data_len)
{
	struct matter_device_info *info = (struct matter_device_info *)ctx;
	size_t slot;

	if (info == NULL) {
		return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
	}
	if (path->endpoint != MATTER_ENDPOINT_ROOT) {
		const struct tm_endpoint *ep = app_endpoint(path->endpoint, NULL);

		if (ep == NULL) {
			return MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT;
		}
		return table_write(info, app_cluster(ep, path->cluster), path, data, data_len);
	}
	if (root_table(path->cluster) != NULL) {
		return table_write(info, root_table(path->cluster), path, data, data_len);
	}
	if (path->cluster != MATTER_CLUSTER_ACCESS_CONTROL) {
		/* Every other cluster this node has is read-only, so the honest
		 * answer distinguishes "no such cluster" from "not writable". */
		return has_cluster(ctx, path->endpoint, path->cluster)
			       ? MATTER_IM_STATUS_UNSUPPORTED_WRITE
			       : MATTER_IM_STATUS_UNSUPPORTED_CLUSTER;
	}
	if (path->attribute != MATTER_ATTR_AC_ACL) {
		return MATTER_IM_STATUS_UNSUPPORTED_WRITE;
	}
	if (data == NULL || data_len == 0u) {
		return MATTER_IM_STATUS_INVALID_COMMAND;
	}
	slot = fabric_slot_for_request(info, info->accessing_fabric_index);
	if (!fabric_slot_has_privilege(info, slot, MATTER_AC_PRIVILEGE_ADMINISTER,
				       path->endpoint, path->cluster)) {
		return MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
	}
	/*
	 * Refused rather than truncated. A half-stored ACL would be read back as
	 * a shorter list than the commissioner wrote, and it would look like the
	 * node had silently dropped entries it was asked to grant.
	 */
	if (data_len > sizeof(info->fabric_acls[slot].data)) {
		return MATTER_IM_STATUS_RESOURCE_EXHAUSTED;
	}
	if ((info->committed_slots & MATTER_FABRIC_SLOT_BIT(slot)) != 0u &&
	    fabric_store(info, MATTER_FABRIC_STORE_ACL, slot, data, data_len) != MATTER_OK) {
		return MATTER_IM_STATUS_FAILURE;
	}
	memcpy(info->fabric_acls[slot].data, data, data_len);
	info->fabric_acls[slot].len = data_len;
	return MATTER_IM_STATUS_SUCCESS;
}

/* ---- events ---------------------------------------------------------------- */

#ifdef TM_NO_EVENTS
/* CONFIG_TINYTALK_EVENTS=n: nothing is recorded, and no event number exists. */
uint64_t tm_event_emit(uint16_t endpoint, uint32_t cluster, uint32_t event, uint8_t priority,
		       const void *blob, size_t len)
{
	(void)endpoint;
	(void)cluster;
	(void)event;
	(void)priority;
	(void)blob;
	(void)len;
	return 0u;
}

size_t matter_clusters_event_count(const struct matter_device_info *info)
{
	(void)info;
	return 0u;
}
#else
uint64_t tm_event_emit(uint16_t endpoint, uint32_t cluster, uint32_t event, uint8_t priority,
		       const void *blob, size_t len)
{
	struct matter_device_info *info = s_dm;
	struct matter_event_rec *ev;

	if (info == NULL || len > TM_EVENT_BLOB_MAX || (blob == NULL && len != 0u)) {
		return 0u;
	}
	/*
	 * A full ring drops its OLDEST, not the new one. The newest event is the
	 * one describing the state a controller can still see on the tile, so
	 * refusing it to keep history would leave the report agreeing with the
	 * past and disagreeing with the bolt.
	 */
	if (info->event_count == MATTER_EVENTS_MAX) {
		memmove(&info->events[0], &info->events[1],
			sizeof(info->events[0]) * (MATTER_EVENTS_MAX - 1u));
		info->event_count--;
	}
	ev = &info->events[info->event_count];
	memset(ev, 0, sizeof(*ev));
	/* Pre-increment: the first event is number 1, so a filter of 0 can mean
	 * "everything" without also meaning "one I have already seen". */
	ev->number = ++info->next_event_number;
	ev->timestamp_ms = info->uptime_ms_cb != NULL ? info->uptime_ms_cb() : 0u;
	ev->endpoint = endpoint;
	ev->cluster = cluster;
	ev->event = event;
	ev->priority = priority;
	if (len > 0u) {
		memcpy(ev->blob, blob, len);
	}
	info->event_count++;
	(void)tm_work_schedule(TM_WORK_NOTIFY, 0u);
	return ev->number;
}

size_t matter_clusters_event_count(const struct matter_device_info *info)
{
	return info != NULL ? info->event_count : 0u;
}

static size_t event_count(void *ctx)
{
	return matter_clusters_event_count((const struct matter_device_info *)ctx);
}

static bool event_at(void *ctx, size_t index, struct matter_im_event *out)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;

	if (info == NULL || out == NULL || index >= info->event_count) {
		return false;
	}
	out->endpoint = info->events[index].endpoint;
	out->cluster = info->events[index].cluster;
	out->event = info->events[index].event;
	out->number = info->events[index].number;
	out->timestamp_ms = info->events[index].timestamp_ms;
	out->priority = info->events[index].priority;
	return true;
}

/** The event's fields, encoded by the cluster that emitted it. */
static void event_data(void *ctx, size_t index, struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct matter_device_info *info = (const struct matter_device_info *)ctx;
	const struct matter_event_rec *ev = NULL;
	const struct tm_endpoint *ep;
	const struct tm_cluster *c = NULL;
	struct tm_req req;

	if (info != NULL && index < info->event_count) {
		ev = &info->events[index];
		ep = app_endpoint(ev->endpoint, NULL);
		c = ep != NULL ? app_cluster(ep, ev->cluster) : NULL;
	}
	if (c == NULL || c->event == NULL) {
		(void)matter_tlv_put_null(w, tag);
		return;
	}
	app_req(info, ev->endpoint, false, &req);
	c->event(&req, ev->event, ev->blob, w, tag);
}
#endif /* TM_NO_EVENTS */

/**
 * Register this device's attribute, cluster, and command handlers with a Matter IM server.
 */
void matter_clusters_init(struct matter_im_server *srv, struct matter_device_info *info)
{
	if (srv == NULL) {
		return;
	}
	srv->status = attr_status;
	srv->value = attr_value;
	srv->has_cluster = has_cluster;
	srv->list_attrs = list_attrs;
	srv->list_fragments = list_fragments;
	srv->list_fragment_value = list_fragment_value;
	srv->list_endpoints = list_endpoints;
	srv->list_clusters = list_clusters;
	srv->command = command;
	srv->command_fields = command_fields;
	srv->write = attr_write;
#ifndef TM_NO_EVENTS
	srv->event_count = event_count;
	srv->event_at = event_at;
	srv->event_data = event_data;
#endif
	srv->ctx = info;
	s_dm = info;
}

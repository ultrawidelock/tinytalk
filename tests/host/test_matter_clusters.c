/**
 * @file test_matter_clusters.c: the lock commands, the ACL write, and resume.
 *
 * These entry points are what a commissioner uses to turn a blank node into a
 * working lock, and none of them were reachable from the other suites: the lock
 * commands are static command handlers behind matter_im_server::command, the ACL write
 * is behind ::write, and matter_clusters_resume() only runs on a reboot with a stored
 * dataset. All of them are driven here through the server vtable that
 * matter_clusters_init() fills in, which is the same seam the IM layer calls in
 * production -- no test-only entry point exists or is added.
 *
 * What the assertions are worth: every status code is checked against the branch that
 * produces it, and the failure cases matter more than the success ones.
 */

#include "test.h"
#include "test_matter_thread_stub.h"

#include <tinymatter/matter_clusters.h>
#include <tinymatter/matter_im.h>
#include <tinymatter/tm_door_lock.h>
#include <tinymatter/matter_tlv.h>

#include <string.h>

/* ---- fixtures ------------------------------------------------------------ */

static void fill_info(struct matter_device_info *info)
{
	memset(info, 0, sizeof(*info));
	info->vendor_id = 0xFFF1u;
	info->product_id = 0x8001u;
	info->regulatory_config = MATTER_REGULATORY_INDOOR;
	info->location_capability = MATTER_REGULATORY_INDOOR;
	info->failsafe_expiry_s = 60u;
	info->failsafe_max_s = 900u;
	info->supports_concurrent_connection = true;
	/* Most cluster tests exercise an operational administrator. Tests of
	 * commissioning replace this state explicitly in test_matter_fabric. */
	info->fabrics[0].index = 1u;
	info->fabrics[0].fabric_id = 1u;
	info->fabrics[0].node_id = 1u;
	info->fabrics[0].case_admin_subject = 1u;
	info->committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
	info->accessing_fabric_index = 1u;
	info->accessing_node_id = 1u;
}

/* A byte pattern that differs per field, so a handler that mixes two of them up
 * fails rather than passing on two buffers that happen to match. */
/**
 * One ACL entry granting @p privilege to @p subject over every target.
 *
 * Targets are null, which the spec reads as "all", so a test built on this
 * turns entirely on whether the SUBJECT matched -- which is the thing under
 * test and the thing that was wrong.
 */
static size_t acl_one_entry(uint8_t *buf, size_t cap, uint64_t subject, uint8_t privilege)
{
	struct matter_tlv_writer w;
	size_t n = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), privilege);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), 2u); /* auth mode CASE */
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(3u), MATTER_TLV_ARRAY);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, subject);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_null(&w, MATTER_TLV_CTX(4u));
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	T_EQ("acl encoded", matter_tlv_writer_finish(&w, &n), MATTER_OK);
	return n;
}

/** Is the accessor allowed an ADMINISTER-gated Door Lock write right now? */
static bool lock_admin_allowed(struct matter_im_server *srv)
{
	struct matter_im_path path;
	struct matter_tlv_writer w;
	uint8_t tlv[16];

	memset(&path, 0, sizeof(path));
	path.endpoint = MATTER_ENDPOINT_LOCK;
	path.cluster = MATTER_CLUSTER_DOOR_LOCK;
	path.attribute = MATTER_ATTR_DL_AUTO_RELOCK_TIME;
	matter_tlv_writer_init(&w, tlv, sizeof(tlv));
	(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 0u);
	return srv->write(srv->ctx, &path, tlv, w.len) != MATTER_IM_STATUS_UNSUPPORTED_ACCESS;
}

/** Invoke UpdateFabricLabel for the accessing fabric; returns the IM status. */
static uint8_t update_label(struct matter_im_server *srv, const char *label, size_t len,
			    uint32_t *response)
{
	struct matter_im_invoke inv;
	struct matter_tlv_writer w;
	uint8_t fields[64];
	size_t n = 0u;

	matter_tlv_writer_init(&w, fields, sizeof(fields));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_utf8(&w, MATTER_TLV_CTX(0u), label, len);
	(void)matter_tlv_end_container(&w);
	T_EQ("label fields encoded", matter_tlv_writer_finish(&w, &n), MATTER_OK);

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_ROOT;
	inv.cluster = MATTER_CLUSTER_OPERATIONAL_CREDENTIALS;
	inv.command = MATTER_CMD_OC_UPDATE_FABRIC_LABEL;
	inv.has_fields = true;
	inv.fields = fields;
	inv.fields_len = n;
	*response = 0u;
	return srv->command(srv->ctx, &inv, response);
}

/** AutoRelockTime as the lock endpoint reports it. */
static uint64_t relock_s(struct matter_im_server *srv)
{
	struct matter_tlv_writer w;
	struct matter_tlv_reader r;
	uint8_t out[16];
	uint64_t v = 0u;

	matter_tlv_writer_init(&w, out, sizeof(out));
	srv->value(srv->ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
		   MATTER_ATTR_DL_AUTO_RELOCK_TIME, false, &w, MATTER_TLV_ANON);
	matter_tlv_reader_init(&r, out, w.len);
	if (matter_tlv_next(&r) != 0 || matter_tlv_get_u64(&r, &v) != 0) {
		return 0xFFFFFFFFFFull;
	}
	return v;
}

static void pattern(uint8_t *dst, size_t len, uint8_t seed)
{
	size_t i;

	for (i = 0u; i < len; i++) {
		dst[i] = (uint8_t)(seed + (uint8_t)i);
	}
}

static size_t build_acl(uint8_t *buf, size_t cap, uint8_t privilege, uint64_t subject,
			bool scoped, uint16_t endpoint, uint32_t cluster)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(2u), MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), privilege);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), 2u); /* CASE */
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(3u), MATTER_TLV_ARRAY);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, subject);
	(void)matter_tlv_end_container(&w);
	if (scoped) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(4u), MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), cluster);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), endpoint);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
	} else {
		(void)matter_tlv_put_null(&w, MATTER_TLV_CTX(4u));
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_writer_finish(&w, &len);
	return len;
}

static uint8_t run_command(struct matter_im_server *srv, uint32_t cluster, uint32_t cmd,
			   const uint8_t *fields, size_t fields_len, uint32_t *response_command)
{
	struct matter_im_invoke inv;
	uint32_t rc = 0u;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_LOCK;
	inv.cluster = cluster;
	inv.command = cmd;
	inv.fields = fields;
	inv.fields_len = fields_len;
	inv.has_fields = fields != NULL;
	return srv->command(srv->ctx, &inv, response_command != NULL ? response_command : &rc);
}

/* Same, on the root endpoint. NetworkCommissioning lives there, not on the lock,
 * and a mismatch answers UNSUPPORTED_CLUSTER rather than anything about fields. */
static uint8_t run_root_command(struct matter_im_server *srv, uint32_t cluster, uint32_t cmd,
				const uint8_t *fields, size_t fields_len,
				uint32_t *response_command)
{
	struct matter_im_invoke inv;
	uint32_t rc = 0u;

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = MATTER_ENDPOINT_ROOT;
	inv.cluster = cluster;
	inv.command = cmd;
	inv.fields = fields;
	inv.fields_len = fields_len;
	inv.has_fields = fields != NULL;
	return srv->command(srv->ctx, &inv, response_command != NULL ? response_command : &rc);
}

/* ---- suite --------------------------------------------------------------- */

void test_matter_clusters(void)
{
	struct matter_device_info info;
	struct matter_im_server srv;

	t_group("an ACL subject naming a CASE Authenticated Tag");
	{
		/*
		 * Apple grants its controllers as a GROUP: one ACL entry whose
		 * subject is a CAT, shared by the phone and the home hub. Matched
		 * by equality against a node id it names nobody, so the hub was
		 * refused every Door Lock command -- which stopped it installing
		 * the endpoint key, and no phone could ever open the lock.
		 */
		uint8_t acl[128];
		size_t acl_len;
		const uint64_t cat_subject = (UINT64_C(0xFFFFFFFD) << 32) | 0x00AB0002u;

		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.fabrics[0].index = 1u;
		info.fabrics[0].case_admin_subject = 0u; /* no bootstrap shortcut */
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		info.accessing_fabric_index = 1u;
		info.accessing_node_id = 0x1122334455667788u;

		acl_len = acl_one_entry(acl, sizeof(acl), cat_subject, 5u /* ADMINISTER */);
		memcpy(info.fabric_acls[0].data, acl, acl_len);
		info.fabric_acls[0].len = acl_len;

		info.accessing_n_cats = 0u;
		T_OK("no tags at all is refused", !lock_admin_allowed(&srv));

		info.accessing_cats[0] = 0x00AB0002u;
		info.accessing_n_cats = 1u;
		T_OK("the same identifier at the same version is allowed",
		     lock_admin_allowed(&srv));

		/* Greater-or-equal: re-issuing a controller at a higher version
		 * must not orphan the entries already granted to it. */
		info.accessing_cats[0] = 0x00AB0009u;
		T_OK("a higher version still satisfies the entry", lock_admin_allowed(&srv));

		/* And the other way is what makes the version field useful: raising
		 * an entry's version retires every controller below it. */
		info.accessing_cats[0] = 0x00AB0001u;
		T_OK("a lower version does not", !lock_admin_allowed(&srv));

		info.accessing_cats[0] = 0x00CD0002u;
		T_OK("a different identifier does not", !lock_admin_allowed(&srv));

		/* Version 0 is not a valid tag; an entry carrying one must match
		 * nothing rather than everything. */
		acl_len = acl_one_entry(acl, sizeof(acl), (UINT64_C(0xFFFFFFFD) << 32) | 0x00AB0000u,
					5u);
		memcpy(info.fabric_acls[0].data, acl, acl_len);
		info.fabric_acls[0].len = acl_len;
		info.accessing_cats[0] = 0x00AB0000u;
		T_OK("version 0 matches nothing", !lock_admin_allowed(&srv));

		/* A plain node-id subject still works exactly as before. */
		acl_len = acl_one_entry(acl, sizeof(acl), 0x1122334455667788u, 5u);
		memcpy(info.fabric_acls[0].data, acl, acl_len);
		info.fabric_acls[0].len = acl_len;
		info.accessing_n_cats = 0u;
		T_OK("a node-id subject is unaffected", lock_admin_allowed(&srv));

		/*
		 * CaseAdminSubject is an ACL subject too, and Apple sets it to a
		 * CAT. Compared by equality it names nobody, so the bootstrap
		 * authority AddNOC hands out -- the recovery path for a fabric
		 * whose ACL would otherwise lock everyone out -- was not there
		 * for the one controller most likely to need it.
		 *
		 * Proven with NO usable ACL, so the only thing that can grant is
		 * the bootstrap check itself.
		 */
		info.fabric_acls[0].len = 0u;
		info.fabrics[0].case_admin_subject = cat_subject;

		info.accessing_n_cats = 0u;
		T_OK("a CAT admin subject grants nothing without the tag",
		     !lock_admin_allowed(&srv));

		info.accessing_cats[0] = 0x00AB0002u;
		info.accessing_n_cats = 1u;
		T_OK("a CAT admin subject grants the controller holding it",
		     lock_admin_allowed(&srv));

		info.accessing_cats[0] = 0x00CD0002u;
		T_OK("and not one holding a different tag", !lock_admin_allowed(&srv));

		/* The node-id form of the same field is untouched. */
		info.accessing_n_cats = 0u;
		info.fabrics[0].case_admin_subject = 0x1122334455667788u;
		T_OK("a node-id admin subject still grants by equality",
		     lock_admin_allowed(&srv));
		info.fabrics[0].case_admin_subject = 0x2222222222222222u;
		T_OK("and a different node id does not", !lock_admin_allowed(&srv));
	}

	t_group("the ACL entry Apple actually writes");
	{
		/*
		 * Captured on the bench, byte for byte: one entry, ADMINISTER,
		 * CASE, subjects [the admin tag 0x41ED v1, the home hub by node
		 * id], targets null. The encoder-built entries above cannot
		 * catch a parser that disagrees with the spec about the field
		 * ids, because the helper and the parser would share the
		 * mistake -- and they did: privilege is field 1 on the wire,
		 * and a parser reading field 0 granted nothing to anybody.
		 */
		static const uint8_t k_wire_acl[] = {
			0x36, 0x02,			/* list, the write's data tag */
			0x15,				/* entry */
			0x24, 0x01, 0x05,		/* privilege 5 ADMINISTER */
			0x24, 0x02, 0x02,		/* auth mode 2 CASE */
			0x36, 0x03,			/* subjects */
			0x07, 0x01, 0x00, 0xed, 0x41, 0xfd, 0xff, 0xff, 0xff,
			0x06, 0xb0, 0x5a, 0xf0, 0x4e,
			0x18,
			0x34, 0x04,			/* targets: null, all */
			0x18, 0x18,
		};

		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.fabrics[0].index = 1u;
		info.fabrics[0].case_admin_subject = 0u; /* no bootstrap shortcut */
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		info.accessing_fabric_index = 1u;
		memcpy(info.fabric_acls[0].data, k_wire_acl, sizeof(k_wire_acl));
		info.fabric_acls[0].len = sizeof(k_wire_acl);

		/* The home hub, named by plain node id. */
		info.accessing_node_id = 0x4EF05AB0u;
		info.accessing_n_cats = 0u;
		T_OK("the node its subjects name is allowed", lock_admin_allowed(&srv));

		/* The phone's controller, named by the tag. */
		info.accessing_node_id = 0xA8946EF9u;
		info.accessing_cats[0] = 0x41ED0001u;
		info.accessing_n_cats = 1u;
		T_OK("a controller presenting the named tag is allowed",
		     lock_admin_allowed(&srv));

		/* Anyone else. */
		info.accessing_node_id = 0x1234u;
		info.accessing_n_cats = 0u;
		T_OK("a stranger is refused", !lock_admin_allowed(&srv));
	}

	t_group("UpdateFabricLabel names the accessing fabric");
	{
		/*
		 * Apple sends this after every commissioning; refusing it as an
		 * unknown command was tolerated but printed a refusal on every
		 * pairing. The answer is a NOCResponse, like AddNOC's.
		 */
		uint32_t response = 0u;
		static const char k_long[] = "123456789012345678901234567890123"; /* 33 */

		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.fabrics[0].index = 1u;
		info.fabrics[1].index = 2u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u) | MATTER_FABRIC_SLOT_BIT(1u);
		info.accessing_fabric_index = 1u;

		T_EQ("the label is accepted", update_label(&srv, "Home", 4u, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("answered as a NOCResponse", (long)response,
		     (long)MATTER_CMD_OC_NOC_RESPONSE);
		T_EQ("which reports OK", (long)info.last_noc_status, (long)MATTER_NOC_STATUS_OK);
		T_EQ("for the accessing fabric", (long)info.last_noc_index, 1L);
		T_EQ("and the label is stored", (long)info.fabrics[0].label_len, 4L);
		T_OK("verbatim", memcmp(info.fabrics[0].label, "Home", 4u) == 0);

		T_EQ("the same fabric may re-set its own label",
		     update_label(&srv, "Home", 4u, &response), MATTER_IM_STATUS_SUCCESS);
		T_EQ("still OK", (long)info.last_noc_status, (long)MATTER_NOC_STATUS_OK);

		info.accessing_fabric_index = 2u;
		T_EQ("another fabric claiming the same label is answered",
		     update_label(&srv, "Home", 4u, &response), MATTER_IM_STATUS_SUCCESS);
		T_EQ("with LabelConflict in the body", (long)info.last_noc_status,
		     (long)MATTER_NOC_STATUS_LABEL_CONFLICT);
		T_EQ("and nothing was stored", (long)info.fabrics[1].label_len, 0L);

		T_EQ("a 33-character label is a constraint error",
		     update_label(&srv, k_long, sizeof(k_long) - 1u, &response),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
	}

	t_group("the ACL is one of two writable attributes");
	{
		struct matter_im_path path;
		uint8_t acl[64];
		uint8_t oversized[MATTER_ACL_MAX + 1u];

		fill_info(&info);
		matter_clusters_init(&srv, &info);
		pattern(acl, sizeof(acl), 0x20u);
		memset(oversized, 0xAAu, sizeof(oversized));

		memset(&path, 0, sizeof(path));
		path.endpoint = MATTER_ENDPOINT_ROOT;
		path.cluster = MATTER_CLUSTER_ACCESS_CONTROL;
		path.attribute = MATTER_ATTR_AC_ACL;
		info.fabrics[0].index = 1u;
		info.fabrics[0].case_admin_subject = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		info.accessing_fabric_index = 1u;
		info.accessing_node_id = 1u;
		T_EQ("ACL write accepted", srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("length recorded", info.fabric_acls[0].len, sizeof(acl));
		T_OK("bytes stored verbatim",
		     memcmp(info.fabric_acls[0].data, acl, sizeof(acl)) == 0);

		/* Truncating would read back as a shorter list than was written, which
		 * looks like the node silently dropped entries it was asked to grant. */
		T_EQ("an oversized ACL is refused, not truncated",
		     srv.write(srv.ctx, &path, oversized, sizeof(oversized)),
		     MATTER_IM_STATUS_RESOURCE_EXHAUSTED);
		T_EQ("and the stored one is untouched", info.fabric_acls[0].len, sizeof(acl));

		T_EQ("an empty write is an invalid command", srv.write(srv.ctx, &path, acl, 0u),
		     MATTER_IM_STATUS_INVALID_COMMAND);
		T_EQ("a null write is an invalid command",
		     srv.write(srv.ctx, &path, NULL, sizeof(acl)),
		     MATTER_IM_STATUS_INVALID_COMMAND);

		path.attribute = MATTER_ATTR_AC_ACL + 1u;
		T_EQ("another Access Control attribute is not writable",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		/* A cluster this node really has, and a cluster it does not: the two
		 * answers must differ, or a commissioner cannot tell a typo from a
		 * read-only attribute. */
		path.cluster = MATTER_CLUSTER_DESCRIPTOR;
		path.attribute = 0u;
		T_EQ("a real read-only cluster says UNSUPPORTED_WRITE",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		path.cluster = 0x1234u;
		T_EQ("a cluster this node lacks says UNSUPPORTED_CLUSTER",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);

		path.endpoint = 9u;
		path.cluster = MATTER_CLUSTER_ACCESS_CONTROL;
		path.attribute = MATTER_ATTR_AC_ACL;
		T_EQ("an endpoint this node lacks says UNSUPPORTED_ENDPOINT",
		     srv.write(srv.ctx, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT);

		path.endpoint = MATTER_ENDPOINT_ROOT;
		T_EQ("a null device refuses every write", srv.write(NULL, &path, acl, sizeof(acl)),
		     MATTER_IM_STATUS_UNSUPPORTED_ENDPOINT);
	}

	t_group("fabric ACLs delegate access without authorizing PASE");
	{
		struct matter_im_path path = {
			.endpoint = MATTER_ENDPOINT_ROOT,
			.cluster = MATTER_CLUSTER_ACCESS_CONTROL,
			.attribute = MATTER_ATTR_AC_ACL,
		};
		struct matter_im_path relock = {
			.endpoint = MATTER_ENDPOINT_LOCK,
			.cluster = MATTER_CLUSTER_DOOR_LOCK,
			.attribute = MATTER_ATTR_DL_AUTO_RELOCK_TIME,
		};
		struct matter_tlv_writer w;
		uint8_t acl[128];
		uint8_t args[64];
		uint8_t relock_tlv[16];
		size_t acl_len;
		size_t args_len = 0u;
		size_t relock_len;
		uint32_t response = 0u;

		fill_info(&info);
		matter_clusters_init(&srv, &info);

		acl_len = build_acl(acl, sizeof(acl), 5u, 0x77u, false, 0u, 0u);
		T_OK("administrator ACL builds", acl_len > 0u);
		T_EQ("bootstrap administrator stores it",
		     srv.write(srv.ctx, &path, acl, acl_len), MATTER_IM_STATUS_SUCCESS);

		info.accessing_node_id = 0x77u;
		matter_tlv_writer_init(&w, relock_tlv, sizeof(relock_tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 30u);
		relock_len = w.len;
		T_EQ("delegated administrator can manage Door Lock",
		     srv.write(srv.ctx, &relock, relock_tlv, relock_len),
		     MATTER_IM_STATUS_SUCCESS);

		matter_tlv_writer_init(&w, args, sizeof(args));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), MATTER_SUPPORTED_FABRICS);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &args_len);
		T_EQ("delegated administrator reaches RemoveFabric",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, args, args_len, &response),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("invalid target still answers with NOCResponse", response,
		     MATTER_CMD_OC_NOC_RESPONSE);

		/* Replace it with an Operate grant scoped to Door Lock. The delegated
		 * administrator above is allowed to make this ACL change. */
		acl_len = build_acl(acl, sizeof(acl), 3u, 0x88u, true, MATTER_ENDPOINT_LOCK,
				    MATTER_CLUSTER_DOOR_LOCK);
		T_EQ("delegated administrator can replace the ACL",
		     srv.write(srv.ctx, &path, acl, acl_len), MATTER_IM_STATUS_SUCCESS);
		info.accessing_node_id = 0x88u;
		T_EQ("scoped operator can unlock",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_UNLOCK_DOOR,
				 NULL, 0u, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("but cannot manage Door Lock",
		     srv.write(srv.ctx, &relock, relock_tlv, relock_len),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
		T_EQ("and cannot remove a fabric",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, args, args_len, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);

		info.accessing_fabric_index = 0u;
		info.accessing_node_id = 0u;
		T_EQ("PASE cannot operate the lock",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_UNLOCK_DOOR,
				 NULL, 0u, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
	}

	t_group("Basic Information uses the port's per-device serial");
	{
		static const char serial[] = "TM-0123456789ABCDEF";
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		const char *value = NULL;
		size_t value_len = 0u;
		uint8_t out[64];

		fill_info(&info);
		memcpy(info.serial_number, serial, sizeof(serial));
		matter_clusters_init(&srv, &info);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_BASIC_INFORMATION,
			  MATTER_ATTR_BASIC_SERIAL_NUMBER, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("serial decodes", matter_tlv_next(&r) == 0 &&
				       matter_tlv_get_utf8(&r, &value, &value_len) == 0);
		T_EQ("serial length matches", value_len, sizeof(serial) - 1u);
		T_OK("serial value matches", memcmp(value, serial, value_len) == 0);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_BASIC_INFORMATION,
			  MATTER_ATTR_BASIC_UNIQUE_ID, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		value = NULL;
		value_len = 0u;
		T_OK("unique id decodes", matter_tlv_next(&r) == 0 &&
					  matter_tlv_get_utf8(&r, &value, &value_len) == 0);
		T_EQ("unique id length matches", value_len, sizeof(serial) - 1u);
		T_OK("unique id uses the same hardware identity",
		     memcmp(value, serial, value_len) == 0);
	}

	t_group("AutoRelockTime is the lock endpoint's writable attribute");
	{
		struct matter_im_path path;
		struct matter_tlv_writer w;
		uint8_t tlv[16];
		uint8_t out[64];
		size_t n;

		fill_info(&info);
		matter_clusters_init(&srv, &info);

		memset(&path, 0, sizeof(path));
		path.endpoint = MATTER_ENDPOINT_LOCK;
		path.cluster = MATTER_CLUSTER_DOOR_LOCK;
		path.attribute = MATTER_ATTR_DL_AUTO_RELOCK_TIME;

		T_EQ("readable before any write",
		     srv.status(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
				MATTER_ATTR_DL_AUTO_RELOCK_TIME),
		     MATTER_IM_STATUS_SUCCESS);

		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 120u);
		T_EQ("a u32 write is accepted",
		     srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("the seconds are stored", relock_s(&srv), 120u);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_DL_AUTO_RELOCK_TIME, false, &w, MATTER_TLV_ANON);
		n = w.len;
		T_OK("the read emits a value", n > 0u);
		{
			struct matter_tlv_reader r;
			uint64_t v = 0u;

			matter_tlv_reader_init(&r, out, n);
			T_OK("read decodes", matter_tlv_next(&r) == 0 &&
					     matter_tlv_get_u64(&r, &v) == 0);
			T_EQ("read value matches", (uint32_t)v, 120u);
		}

		matter_tlv_writer_init(&w, tlv, sizeof(tlv));
		(void)matter_tlv_put_u64(&w, MATTER_TLV_ANON, 0x100000000ull);
		T_EQ("a value wider than u32 is a constraint error",
		     srv.write(srv.ctx, &path, tlv, w.len),
		     MATTER_IM_STATUS_CONSTRAINT_ERROR);
		T_EQ("and the stored value is untouched", relock_s(&srv), 120u);

		T_EQ("an empty write is an invalid command",
		     srv.write(srv.ctx, &path, tlv, 0u), MATTER_IM_STATUS_INVALID_COMMAND);

		path.attribute = MATTER_ATTR_DL_LOCK_STATE;
		T_EQ("LockState itself is not writable",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		path.cluster = MATTER_CLUSTER_DESCRIPTOR;
		T_EQ("the lock's Descriptor is read-only",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_WRITE);

		path.cluster = 0x1234u;
		T_EQ("a cluster the lock endpoint lacks says UNSUPPORTED_CLUSTER",
		     srv.write(srv.ctx, &path, tlv, 4u), MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);
	}

	t_group("the lock serves the globals Apple builds its settings UI from");
	{
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		uint8_t out[256];
		uint64_t v;
		bool saw_auto_relock = false;
		bool saw_lock = false;
		bool saw_unlock = false;
		int accepted = 0;

		fill_info(&info);
		matter_clusters_init(&srv, &info);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_CLUSTER_REVISION, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		v = 0u;
		T_OK("ClusterRevision decodes",
		     matter_tlv_next(&r) == 0 && matter_tlv_get_u64(&r, &v) == 0);
		T_EQ("and is 8, the Nordic reference build's value", (unsigned)v,
		     MATTER_DL_CLUSTER_REVISION);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_ATTRIBUTE_LIST, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("AttributeList is a container",
		     matter_tlv_next(&r) == 0 && matter_tlv_is_container(&r));
		T_OK("and can be entered", matter_tlv_enter(&r) == 0);
		while (matter_tlv_next(&r) == 0) {
			if (matter_tlv_get_u64(&r, &v) == 0 &&
			    v == MATTER_ATTR_DL_AUTO_RELOCK_TIME) {
				saw_auto_relock = true;
			}
		}
		T_OK("and it names AutoRelockTime, the optional control", saw_auto_relock);

		matter_tlv_writer_init(&w, out, sizeof(out));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_DOOR_LOCK,
			  MATTER_ATTR_ACCEPTED_CMD_LIST, false, &w, MATTER_TLV_ANON);
		matter_tlv_reader_init(&r, out, w.len);
		T_OK("AcceptedCommandList decodes",
		     matter_tlv_next(&r) == 0 && matter_tlv_enter(&r) == 0);
		while (matter_tlv_next(&r) == 0) {
			if (matter_tlv_get_u64(&r, &v) == 0) {
				accepted++;
				saw_lock = saw_lock || v == MATTER_CMD_DL_LOCK_DOOR;
				saw_unlock = saw_unlock || v == MATTER_CMD_DL_UNLOCK_DOOR;
			}
		}
		T_OK("and it is exactly LockDoor and UnlockDoor",
		     saw_lock && saw_unlock && accepted == 2);
	}

	t_group("the lock endpoint answers its own commands");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		/* The tile's two buttons, answered with a bare status: DoorLock
		 * defines no LockDoorResponse, and inventing one leaves the
		 * controller waiting. */
		T_EQ("UnlockDoor accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_UNLOCK_DOOR, NULL,
				 0u, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and the lock reports unlocked", tm_door_lock_state(),
		     MATTER_DL_LOCK_STATE_UNLOCKED);
		T_EQ("LockDoor accepted",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, MATTER_CMD_DL_LOCK_DOOR, NULL, 0u,
				 NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and the lock reports locked", tm_door_lock_state(),
		     MATTER_DL_LOCK_STATE_LOCKED);

		/* A cluster the lock endpoint does not have. Answering
		 * UNSUPPORTED_ENDPOINT here would contradict every attribute read
		 * that says endpoint 1 exists. */
		T_EQ("a cluster this endpoint lacks says UNSUPPORTED_CLUSTER",
		     run_command(&srv, MATTER_CLUSTER_DESCRIPTOR, MATTER_CMD_DL_LOCK_DOOR, NULL, 0u,
				 NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_CLUSTER);

		/* A Door Lock command this node has not implemented: the endpoint and
		 * the cluster are both real, the command is not. */
		T_EQ("an unimplemented command says UNSUPPORTED_COMMAND",
		     run_command(&srv, MATTER_CLUSTER_DOOR_LOCK, 0x00FFu, NULL, 0u, NULL),
		     MATTER_IM_STATUS_UNSUPPORTED_COMMAND);
	}

	t_group("resume brings Thread back without a commissioner");
	{
		fill_info(&info);
		matter_clusters_init(&srv, &info);

		T_EQ("a null device cannot resume", matter_clusters_resume(NULL), MATTER_E_STATE);
		T_EQ("no stored dataset means nothing to resume", matter_clusters_resume(&info),
		     MATTER_E_STATE);
		T_OK("and Thread was never started", !info.thread_started);

		/* A dataset that the stack accepts. */
		test_matter_thread_stub_reset();
		info.thread_dataset_len = 16u;
		memset(info.thread_dataset, 0x5Au, info.thread_dataset_len);
		T_EQ("resume starts Thread", matter_clusters_resume(&info), MATTER_OK);
		T_OK("and records that it did", info.thread_started);
		T_EQ("the stack was started once", g_thread_start_calls, 1);
		T_EQ("with the stored dataset", (long)g_thread_last_len, 16L);
		T_OK("verbatim", memcmp(g_thread_last_dataset, info.thread_dataset, 16u) == 0);

		/* A stack that refuses the dataset must not leave the node believing
		 * it is on the network. */
		test_matter_thread_stub_reset();
		info.thread_started = false;
		g_thread_start_fail = 1;
		T_EQ("a refused dataset fails the resume", matter_clusters_resume(&info),
		     MATTER_E_STATE);
		T_OK("and Thread is not claimed to be up", !info.thread_started);
		g_thread_start_fail = 0;
	}

	t_group("a second admin does not knock this node off Thread");
	{
		/*
		 * The failure this pins, measured on hardware 2026-08-07: a
		 * second administrator sends AddOrUpdateThreadNetwork carrying
		 * the dataset of the network the node is ALREADY on. Restarting
		 * the stack detached it for 20+ s, the BLE commissioning link
		 * timed out during the silence, and commissioning died after
		 * AddNOC had already succeeded.
		 */
		static const uint8_t k_xpanid[MATTER_THREAD_XPANID_LEN] = {
			0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
		};
		uint8_t ds[] = {
			0x0e, 0x08, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x03, 0x00, 0x00, 0x19,
			0x35, 0x06, 0x00, 0x04, 0x00, 0x1f, 0xff, 0xe0,
			0x02, 0x08, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
			0x05, 0x10, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
			0x03, 0x04, 'h',  'o',  'm',  'e',
			0x01, 0x02, 0x12, 0x34,
			0x07, 0x08, 0xfd, 0x00, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x04, 0x10, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
			0x0c, 0x04, 0x02, 0xa0, 0xff, 0xf8,
		};
		uint8_t candidate[sizeof(ds)];
		uint8_t fields[256];
		size_t flen = 0u;
		struct matter_tlv_writer w;

		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), ds, sizeof(ds));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);

		/* Already attached to exactly this network: no restart. */
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.attempt.active = true;
		info.fabrics[0].index = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		memcpy(info.thread_dataset, ds, sizeof(ds));
		info.thread_dataset_len = sizeof(ds);
		memcpy(info.thread_xpanid, k_xpanid, sizeof(k_xpanid));
		info.have_thread_xpanid = true;
		test_matter_thread_stub_reset();
		g_thread_attached_to = 1;
		T_EQ("the dataset is accepted",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("the stack is NOT restarted", g_thread_start_calls, 0);
		T_OK("the dataset is staged", info.attempt.have_thread_candidate);
		T_EQ("attachment is not touched before ConnectNetwork",
		     g_thread_attached_to_calls, 0);

		/* A second controller may carry a newer timestamp or even stale
		 * credentials for the same Extended PAN ID. Accept the network
		 * identity but retain the dataset that already keeps the lock
		 * reachable. */
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.attempt.active = true;
		info.fabrics[0].index = 1u;
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u);
		memcpy(info.thread_dataset, ds, sizeof(ds));
		info.thread_dataset_len = sizeof(ds);
		memcpy(info.thread_xpanid, k_xpanid, sizeof(k_xpanid));
		info.have_thread_xpanid = true;
		test_matter_thread_stub_reset();
		memcpy(candidate, ds, sizeof(candidate));
		for (size_t i = 0u; i + 2u <= sizeof(candidate);) {
			size_t len = candidate[i + 1u];

			if (candidate[i] == 0x05u) {
				candidate[i + 2u] ^= 1u;
				break;
			}
			i += 2u + len;
		}
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), candidate,
					   sizeof(candidate));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("same-network credentials are answered",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and accepted", info.last_network_status, MATTER_NC_STATUS_SUCCESS);
		T_OK("while the committed dataset wins",
		     info.attempt.thread_dataset_len == sizeof(ds) &&
			     memcmp(info.attempt.thread_dataset, ds, sizeof(ds)) == 0);
		T_EQ("the stack is untouched", g_thread_start_calls, 0);

		/* A genuinely different Extended PAN ID is a migration request.
		 * Multi-admin commissioning must reject it without moving the lock. */
		memcpy(candidate, ds, sizeof(candidate));
		for (size_t i = 0u; i + 2u <= sizeof(candidate);) {
			size_t len = candidate[i + 1u];

			if (candidate[i] == 0x02u) {
				candidate[i + 2u] ^= 1u;
				break;
			}
			i += 2u + len;
		}
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), candidate,
					   sizeof(candidate));
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("a different network is answered",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("and rejected without moving the lock", info.last_network_status,
		     MATTER_NC_STATUS_BOUNDS_EXCEEDED);
		T_EQ("the stack is still untouched", g_thread_start_calls, 0);

		/*
		 * A dataset with no Extended PAN ID cannot be compared against
		 * anything, so the guard must not fire on it: unknown falls back
		 * to the restart, which is always correct if slower.
		 */
		fill_info(&info);
		matter_clusters_init(&srv, &info);
		info.attempt.active = true;
		test_matter_thread_stub_reset();
		g_thread_attached_to = 1; /* would skip, if it were ever asked */
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_bytes(&w, MATTER_TLV_CTX(0u), ds, 5u); /* timestamp fragment */
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("a dataset without an ext PAN id is answered",
		     run_root_command(&srv, MATTER_CLUSTER_NETWORK_COMMISSIONING,
				      MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("as malformed", info.last_network_status, MATTER_NC_STATUS_OUT_OF_RANGE);
		T_EQ("and the stack remains untouched", g_thread_start_calls, 0);
	}

	t_group("RemoveFabric frees the slot it names and only that slot");
	{
		/*
		 * The failure this pins, measured on hardware 2026-08-07: two
		 * commissioning attempts died mid-flight and left their fabrics
		 * behind, the table filled, and the next AddTrustedRootCertificate
		 * answered RESOURCE_EXHAUSTED with no way to make room short of a
		 * factory wipe. RemoveFabric is that way.
		 */
		uint8_t fields[16];
		size_t flen = 0u;
		uint32_t resp = 0u;
		struct matter_tlv_writer w;
		char expect_name[MATTER_INSTANCE_NAME_LEN];
		size_t i;

		fill_info(&info);
		matter_clusters_init(&srv, &info);
		test_matter_thread_stub_reset();
		for (i = 0u; i < 3u; i++) {
			info.fabrics[i].index = (uint8_t)(i + 1u);
			info.fabrics[i].have_root = true;
			info.fabrics[i].fabric_id = 0x1000u + i;
			info.fabrics[i].node_id = 0x2000u + i;
			info.fabrics[i].noc_len = 1u;
			/* An uncompressed-point root, or the compressed-fabric
			 * derivation behind the instance name refuses it. */
			pattern(info.fabrics[i].root_public_key,
				sizeof(info.fabrics[i].root_public_key), (uint8_t)(0x40u + i));
			info.fabrics[i].root_public_key[0] = 0x04u;
		}
		info.committed_slots = MATTER_FABRIC_SLOT_BIT(0u) |
				       MATTER_FABRIC_SLOT_BIT(1u) |
				       MATTER_FABRIC_SLOT_BIT(2u);
		info.fabrics[0].case_admin_subject = 0x1234u;
		info.accessing_fabric_index = 1u;
		info.accessing_node_id = 0x1234u;
		/* Slot 2 owns the shared intermediate-certificate area. */
		info.icac.owner_index = 2u;
		info.icac.len = 100u;
		/* Computed BEFORE the removal wipes the inputs it derives from. */
		T_EQ("instance name derivable",
		     matter_fabric_instance_name(&info.fabrics[1], expect_name,
						 sizeof(expect_name)),
		     MATTER_OK);

		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), 2u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);

		/* No fail-safe armed on purpose: removal is administration, not
		 * commissioning, and chip-tool's remove-fabric arms none. */
		T_EQ("the command runs without a fail-safe",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("answered with NOCResponse", (long)resp, (long)MATTER_CMD_OC_NOC_RESPONSE);
		T_EQ("status OK", info.last_noc_status, MATTER_NOC_STATUS_OK);
		T_EQ("naming the removed index", info.last_noc_index, 2u);
		T_EQ("the slot is empty", info.fabrics[1].index, 0u);
		T_OK("and holds nothing else", !info.fabrics[1].have_root &&
		     info.fabrics[1].noc_len == 0u);
		T_EQ("its neighbours are untouched", info.fabrics[0].index, 1u);
		T_EQ("both of them", info.fabrics[2].index, 3u);
		T_EQ("the ICAC area it owned is freed", (long)info.icac.len, 0L);
		T_EQ("and disowned", info.icac.owner_index, 0u);
		T_EQ("its SRP record is withdrawn", g_thread_unadvertise_calls, 1);
		T_OK("by the removed fabric's own instance name",
		     strcmp(g_thread_last_unadvertised, expect_name) == 0);

		/* The index just removed no longer exists: the verdict arrives
		 * in the NOCResponse, not as a bare IM status. */
		resp = 0u;
		T_EQ("removing it again still answers",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, &resp),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("with NOCResponse", (long)resp, (long)MATTER_CMD_OC_NOC_RESPONSE);
		T_EQ("saying the index is invalid", info.last_noc_status,
		     MATTER_NOC_STATUS_INVALID_FABRIC_INDEX);
		T_EQ("and the survivors still stand", info.fabrics[0].index, 1u);

		/* Index 0 is what EMPTY slots hold; asking to remove it must not
		 * match one of them. */
		matter_tlv_writer_init(&w, fields, sizeof(fields));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), 0u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_writer_finish(&w, &flen);
		T_EQ("index 0 answers",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, fields, flen, NULL),
		     MATTER_IM_STATUS_SUCCESS);
		T_EQ("as invalid, not as a match on an empty slot", info.last_noc_status,
		     MATTER_NOC_STATUS_INVALID_FABRIC_INDEX);
		T_EQ("and no removal ever withdrew a record it did not remove",
		     g_thread_unadvertise_calls, 1);

		/* A command with no FabricIndex at all is malformed. */
		T_EQ("a missing index is INVALID_COMMAND",
		     run_root_command(&srv, MATTER_CLUSTER_OPERATIONAL_CREDENTIALS,
				      MATTER_CMD_OC_REMOVE_FABRIC, NULL, 0u, NULL),
		     MATTER_IM_STATUS_INVALID_COMMAND);
	}
}

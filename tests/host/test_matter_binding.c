/**
 * @file test_matter_binding.c — the list, and who is allowed to see it.
 *
 * Most of what can go wrong with a Binding cluster is invisible from the
 * outside. A write that quietly drops an entry, a read that leaks another
 * administrator's targets, a second administrator whose write unbinds the
 * first -- each of those produces a node that answers every question correctly
 * and unlocks the wrong number of doors.
 *
 * So the fabric scoping is checked from both directions here: what a write
 * leaves behind, and what a read hands back.
 */
#include <stdbool.h>
#include <string.h>

#include <tinymatter/matter_binding.h>
#include <tinymatter/matter_clusters.h>
#include <tinymatter/matter_tlv.h>

#include "test.h"

#define FABRIC_A 1u
#define FABRIC_B 2u

/** Encode a Binding list of @p n unicast targets, as an administrator writes one. */
static size_t write_list(uint8_t *buf, size_t cap, const uint64_t *nodes, const uint16_t *endpoints,
			 const uint32_t *clusters, size_t n)
{
	struct matter_tlv_writer w;
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
	for (size_t i = 0; i < n; i++) {
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), nodes[i]);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3u), endpoints[i]);
		if (clusters != NULL) {
			(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(4u), clusters[i]);
		}
		(void)matter_tlv_end_container(&w);
	}
	(void)matter_tlv_end_container(&w);
	T_EQ("the list encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
	return len;
}

/** How many entries an encoded Binding attribute value carries. */
static size_t count_array(const uint8_t *buf, size_t len)
{
	struct matter_tlv_reader r;
	size_t n = 0u;


	matter_tlv_reader_init(&r, buf, len);
	T_EQ("into an array", matter_tlv_next(&r), MATTER_OK);
	T_EQ("of the right type", (int)matter_tlv_element_type(&r), (int)MATTER_TLV_ARRAY);
	T_EQ("that opens", matter_tlv_enter(&r), MATTER_OK);
	while (matter_tlv_next(&r) == MATTER_OK) {
		n++;
	}
	return n;
}

/**
 * OR together the FabricIndex stamp on every entry of an encoded value.
 *
 * A bitmask rather than a list because the question these tests ask is WHICH
 * administrators an unfiltered read exposed, and a count cannot tell two
 * entries of one fabric from one entry each of two.
 */
static unsigned int fabric_mask(const uint8_t *buf, size_t len)
{
	struct matter_tlv_reader r;
	unsigned int mask = 0u;

	matter_tlv_reader_init(&r, buf, len);
	T_EQ("into an array", matter_tlv_next(&r), MATTER_OK);
	T_EQ("that opens", matter_tlv_enter(&r), MATTER_OK);
	while (matter_tlv_next(&r) == MATTER_OK) {
		if (matter_tlv_enter(&r) != MATTER_OK) {
			continue;
		}
		while (matter_tlv_next(&r) == MATTER_OK) {
			uint64_t v = 0u;

			if (matter_tlv_tag(&r) == MATTER_TLV_CTX(254u) &&
			    matter_tlv_get_u64(&r, &v) == MATTER_OK) {
				mask |= 1u << (unsigned int)v;
			}
		}
		(void)matter_tlv_exit(&r);
	}
	return mask;
}

/** How many entries a read for @p fabric hands back. */
static size_t read_count(const struct matter_binding_table *t, uint8_t fabric)
{
	struct matter_tlv_writer w;
	uint8_t buf[512];
	size_t len = 0u;

	matter_tlv_writer_init(&w, buf, sizeof(buf));
	matter_binding_read(t, fabric, &w, MATTER_TLV_ANON);
	T_EQ("the read encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
	return count_array(buf, len);
}

void test_matter_binding(void)
{
	struct matter_binding_table t;
	const struct matter_binding_target *e;
	uint8_t buf[512];
	uint8_t idx;
	size_t len;

	t_group("one administrator binds one lock");

	memset(&t, 0, sizeof(t));
	{
		const uint64_t nodes[] = {0x1122334455667788ULL};
		const uint16_t endpoints[] = {1u};
		const uint32_t clusters[] = {MATTER_CLUSTER_DOOR_LOCK};

		len = write_list(buf, sizeof(buf), nodes, endpoints, clusters, 1u);
		T_EQ("the write lands", matter_binding_write(&t, FABRIC_A, buf, len), MATTER_OK);
	}
	T_EQ("one entry is held", (int)t.count, 1);

	idx = 0u;
	e = matter_binding_next(&t, MATTER_CLUSTER_DOOR_LOCK, &idx);
	T_OK("and it is found by cluster", e != NULL);
	T_OK("naming the right node", e->node_id == 0x1122334455667788ULL);
	T_EQ("on the right endpoint", (int)e->endpoint, 1);
	/*
	 * The fabric index is this node's own answer, taken from the session.
	 * A peer that encodes one is ignored -- see the next group.
	 */
	T_EQ("and stamped with the writing fabric", (int)e->fabric_index, (int)FABRIC_A);
	T_OK("and there is only one", matter_binding_next(&t, MATTER_CLUSTER_DOOR_LOCK, &idx) == NULL);

	t_group("a second administrator does not unbind the first");

	{
		const uint64_t nodes[] = {0xAAAAULL};
		const uint16_t endpoints[] = {2u};

		len = write_list(buf, sizeof(buf), nodes, endpoints, NULL, 1u);
		T_EQ("its write lands", matter_binding_write(&t, FABRIC_B, buf, len), MATTER_OK);
	}
	/*
	 * The failure this catches: a write that replaces the WHOLE list rather
	 * than the writing fabric's part of it. Adding a home hub to a lock
	 * already paired with a phone would silently unbind the phone.
	 */
	T_EQ("both fabrics' entries are held", (int)t.count, 2);
	T_EQ("A still sees exactly its own", (int)read_count(&t, FABRIC_A), 1);
	T_EQ("and B sees exactly its own", (int)read_count(&t, FABRIC_B), 1);

	t_group("an entry naming no cluster binds every cluster on the endpoint");

	idx = 0u;
	e = matter_binding_next(&t, MATTER_CLUSTER_DOOR_LOCK, &idx);
	T_OK("the explicit entry matches", e != NULL && e->has_cluster);
	e = matter_binding_next(&t, MATTER_CLUSTER_DOOR_LOCK, &idx);
	T_OK("and so does the one that named none", e != NULL && !e->has_cluster);

	t_group("an empty write is how an administrator unbinds");

	{
		struct matter_tlv_writer w;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
		(void)matter_tlv_end_container(&w);
		T_EQ("the empty list encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
	}
	T_EQ("and it is accepted", matter_binding_write(&t, FABRIC_A, buf, len), MATTER_OK);
	T_EQ("A is unbound", (int)read_count(&t, FABRIC_A), 0);
	T_EQ("and B is untouched", (int)read_count(&t, FABRIC_B), 1);

	t_group("removing a fabric takes its bindings with it");

	matter_binding_forget_fabric(&t, FABRIC_B);
	T_EQ("nothing is left", (int)t.count, 0);
	T_EQ("and nothing reads back", (int)read_count(&t, FABRIC_B), 0);

	t_group("a write this node refuses, leaving the table as it was");

	memset(&t, 0, sizeof(t));
	{
		const uint64_t nodes[] = {1u};
		const uint16_t endpoints[] = {1u};

		len = write_list(buf, sizeof(buf), nodes, endpoints, NULL, 1u);
		T_EQ("a good write first", matter_binding_write(&t, FABRIC_A, buf, len), MATTER_OK);
	}

	/* More entries than this node can hold. Refused whole rather than
	 * truncated: a shorter list than was written is a lock that does not
	 * open with nothing to say why. */
	{
		const uint64_t nodes[] = {1u, 2u, 3u, 4u, 5u};
		const uint16_t endpoints[] = {1u, 1u, 1u, 1u, 1u};

		len = write_list(buf, sizeof(buf), nodes, endpoints, NULL, 5u);
		T_EQ("too many targets", matter_binding_write(&t, FABRIC_A, buf, len),
		     MATTER_E_NOSPACE);
	}
	T_EQ("and the old list survives", (int)t.count, 1);

	/* An entry that addresses nothing: a node with no endpoint. */
	{
		struct matter_tlv_writer w;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), 42u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		T_EQ("it encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
	}
	T_EQ("a node with no endpoint", matter_binding_write(&t, FABRIC_A, buf, len),
	     MATTER_E_INVAL);
	T_EQ("and the old list still survives", (int)t.count, 1);

	/* Both a node AND a group: the one combination the cluster forbids. */
	{
		struct matter_tlv_writer w;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), 42u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), 7u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3u), 1u);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		T_EQ("it encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
	}
	T_EQ("unicast and group at once", matter_binding_write(&t, FABRIC_A, buf, len),
	     MATTER_E_INVAL);

	T_EQ("a write with no fabric behind it",
	     matter_binding_write(&t, 0u, buf, len), MATTER_E_INVAL);

	t_group("a peer does not get to say which fabric it is");

	memset(&t, 0, sizeof(t));
	{
		struct matter_tlv_writer w;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_ARRAY);
		(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), 99u);
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(3u), 1u);
		/* Claiming to be the OTHER administrator. */
		(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(254u), FABRIC_B);
		(void)matter_tlv_end_container(&w);
		(void)matter_tlv_end_container(&w);
		T_EQ("it encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
	}
	T_EQ("the write is accepted", matter_binding_write(&t, FABRIC_A, buf, len), MATTER_OK);
	/*
	 * The claim is ignored and the SESSION decides. Believing it would let
	 * one administrator write entries into another's list -- and then read
	 * them back as its own would not even show them.
	 */
	T_EQ("but the entry belongs to the writer", (int)t.e[0].fabric_index, (int)FABRIC_A);
	T_EQ("and B has nothing", (int)read_count(&t, FABRIC_B), 0);

	t_group("the PIN, which is written and never read back");

	T_EQ("a PIN is stored", matter_binding_write_pin(&t, (const uint8_t *)"1234", 4u),
	     MATTER_OK);
	T_EQ("of the right length", (int)t.pin_len, 4);
	T_OK("and the right digits", memcmp(t.pin, "1234", 4u) == 0);

	{
		struct matter_tlv_writer w;
		struct matter_tlv_reader r;
		const uint8_t *got = NULL;
		size_t got_len = 1u;

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		matter_binding_read_pin(&t, &w, MATTER_TLV_ANON);
		T_EQ("the read encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);

		matter_tlv_reader_init(&r, buf, len);
		T_EQ("and decodes", matter_tlv_next(&r), MATTER_OK);
		T_EQ("as bytes", matter_tlv_get_bytes(&r, &got, &got_len), MATTER_OK);
		/*
		 * The PIN of the lock next door, readable by every administrator
		 * on this fabric, is not a thing worth reporting. Nothing needs
		 * it back.
		 */
		T_EQ("but carries nothing", (int)got_len, 0);
	}

	T_EQ("a PIN longer than this node holds",
	     matter_binding_write_pin(&t, (const uint8_t *)"123456789", 9u), MATTER_E_INVAL);
	T_EQ("is refused rather than truncated", (int)t.pin_len, 4);

	T_EQ("and an empty write clears it", matter_binding_write_pin(&t, NULL, 0u), MATTER_OK);
	T_EQ("leaving nothing", (int)t.pin_len, 0);

	t_group("nothing here dereferences a NULL");

	T_EQ("a write with no table", matter_binding_write(NULL, FABRIC_A, buf, len),
	     MATTER_E_INVAL);
	T_EQ("a PIN with no table", matter_binding_write_pin(NULL, NULL, 0u), MATTER_E_INVAL);
	matter_binding_read(NULL, FABRIC_A, NULL, MATTER_TLV_ANON);
	matter_binding_read_pin(NULL, NULL, MATTER_TLV_ANON);
	matter_binding_forget_fabric(NULL, FABRIC_A);
	T_OK("and an iteration over nothing ends", matter_binding_next(NULL, 0u, &idx) == NULL);

	/*
	 * From here on the table is reached the way a controller reaches it:
	 * through the cluster surface in matter_clusters.c. The table itself is
	 * proven above, so what these check is the WIRING -- that the cluster is
	 * on the endpoint a controller looks at, that a write is scoped by the
	 * SESSION's fabric, and that the manufacturer PIN attribute cannot
	 * shadow the standard list it shares a number with.
	 */
	t_group("the cluster a controller writes it through");

	{
		struct matter_im_server srv;
		static struct matter_device_info info;
		struct matter_im_path path;
		struct matter_tlv_writer w;
		const uint64_t nodes[] = {0x0102030405060708ULL};
		const uint64_t nodes_b[] = {0x1112131415161718ULL};
		const uint16_t endpoints[] = {1u};
		const uint32_t clusters[] = {MATTER_CLUSTER_DOOR_LOCK};
		const uint32_t *attrs = NULL;
		size_t n;

		memset(&info, 0, sizeof(info));
		matter_clusters_init(&srv, &info);
		info.vendor_id = 0xFFF1u;
		/*
		 * Two administrators, each the CASE admin subject its own AddNOC
		 * named. Writing a binding needs Administer, so without this the
		 * cluster refuses every write below on privilege and the fabric
		 * scoping these cases exist to test is never reached.
		 */
		info.fabrics[0].index = FABRIC_A;
		info.fabrics[0].fabric_id = FABRIC_A;
		info.fabrics[0].node_id = FABRIC_A;
		info.fabrics[0].case_admin_subject = FABRIC_A;
		info.fabrics[1].index = FABRIC_B;
		info.fabrics[1].fabric_id = FABRIC_B;
		info.fabrics[1].node_id = FABRIC_B;
		info.fabrics[1].case_admin_subject = FABRIC_B;
		info.committed_slots =
			MATTER_FABRIC_SLOT_BIT(0u) | MATTER_FABRIC_SLOT_BIT(1u);
		info.accessing_node_id = FABRIC_A;

		T_OK("the lock endpoint carries it",
		     srv.has_cluster(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING));
		T_OK("the root endpoint does not",
		     !srv.has_cluster(srv.ctx, MATTER_ENDPOINT_ROOT, MATTER_CLUSTER_BINDING));

		n = srv.list_attrs(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING, &attrs);
		T_OK("and reports an attribute list", n > 0u && attrs != NULL);
		T_EQ("beginning with the list itself", (int)attrs[0], (int)MATTER_ATTR_BINDING_LIST);

		path.endpoint = MATTER_ENDPOINT_LOCK;
		path.cluster = MATTER_CLUSTER_BINDING;
		path.attribute = MATTER_ATTR_BINDING_LIST;

		len = write_list(buf, sizeof(buf), nodes, endpoints, clusters, 1u);
		/*
		 * No session, so no fabric. Refused rather than stored under
		 * fabric 0, which is not a fabric and which no read could hand
		 * back to anybody.
		 */
		info.accessing_fabric_index = 0u;
		T_EQ("a write with no session behind it", (int)srv.write(srv.ctx, &path, buf, len),
		     (int)MATTER_IM_STATUS_UNSUPPORTED_ACCESS);

		info.accessing_fabric_index = FABRIC_A;
		T_EQ("the same write on a session", (int)srv.write(srv.ctx, &path, buf, len),
		     (int)MATTER_IM_STATUS_SUCCESS);
		T_EQ("stores one target", (int)info.binding.count, 1);
		T_EQ("stamped with the session's fabric", (int)info.binding.e[0].fabric_index,
		     (int)FABRIC_A);

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING,
			  MATTER_ATTR_BINDING_LIST, true, &w, MATTER_TLV_ANON);
		T_EQ("the read encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
		T_EQ("and hands that fabric its one entry", (int)count_array(buf, len), 1);

		/* The other administrator sees an empty list, not this one's. */
		info.accessing_fabric_index = FABRIC_B;
		info.accessing_node_id = FABRIC_B;
		matter_tlv_writer_init(&w, buf, sizeof(buf));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING,
			  MATTER_ATTR_BINDING_LIST, true, &w, MATTER_TLV_ANON);
		T_EQ("a second administrator's read encodes", matter_tlv_writer_finish(&w, &len),
		     MATTER_OK);
		T_EQ("and enumerates nothing of the first's", (int)count_array(buf, len), 0);

		t_group("the PIN attribute, and the number it shares");

		path.attribute = MATTER_ATTR_BINDING_PIN(0xFFF1u);
		T_EQ("is readable",
		     (int)srv.status(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING,
				     path.attribute),
		     (int)MATTER_IM_STATUS_SUCCESS);
		{
			struct matter_tlv_writer pw;
			uint8_t pin_buf[32];
			size_t pin_len = 0u;

			matter_tlv_writer_init(&pw, pin_buf, sizeof(pin_buf));
			(void)matter_tlv_put_bytes(&pw, MATTER_TLV_ANON, (const uint8_t *)"4321",
						   4u);
			T_EQ("a PIN encodes", matter_tlv_writer_finish(&pw, &pin_len), MATTER_OK);
			T_EQ("and the write lands", (int)srv.write(srv.ctx, &path, pin_buf, pin_len),
			     (int)MATTER_IM_STATUS_SUCCESS);
		}
		T_EQ("as four digits", (int)info.binding.pin_len, 4);

		/*
		 * MATTER_ATTR_BINDING_PIN(0) is 0x0000, which IS the standard
		 * list attribute. A node that has not been told its vendor id
		 * must answer that number as the LIST -- otherwise an
		 * administrator writing a binding has the bytes stored as a
		 * PIN, and neither end has anything to notice it by.
		 */
		info.vendor_id = 0u;
		info.accessing_fabric_index = FABRIC_A;
		info.accessing_node_id = FABRIC_A;
		info.binding.pin_len = 0u;
		path.attribute = MATTER_ATTR_BINDING_PIN(0u);
		len = write_list(buf, sizeof(buf), nodes, endpoints, clusters, 1u);
		T_EQ("with no vendor id, attribute 0 is still the list",
		     (int)srv.write(srv.ctx, &path, buf, len), (int)MATTER_IM_STATUS_SUCCESS);
		T_EQ("and nothing was taken for a PIN", (int)info.binding.pin_len, 0);
		T_EQ("the list is what changed", (int)info.binding.count, 1);

		t_group("an unfiltered read crosses fabrics, a filtered one does not");

		/*
		 * The second administrator binds a door of its own, so the two
		 * reads below differ by more than a count.
		 */
		info.accessing_fabric_index = FABRIC_B;
		info.accessing_node_id = FABRIC_B;
		path.attribute = MATTER_ATTR_BINDING_LIST;
		len = write_list(buf, sizeof(buf), nodes_b, endpoints, clusters, 1u);
		T_EQ("the second administrator binds one too",
		     (int)srv.write(srv.ctx, &path, buf, len), (int)MATTER_IM_STATUS_SUCCESS);

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING,
			  MATTER_ATTR_BINDING_LIST, true, &w, MATTER_TLV_ANON);
		T_EQ("a filtered read encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
		T_EQ("and still hands back one entry", (int)count_array(buf, len), 1);
		T_EQ("stamped with the reader's own fabric", (int)fabric_mask(buf, len),
		     1 << FABRIC_B);

		matter_tlv_writer_init(&w, buf, sizeof(buf));
		srv.value(srv.ctx, MATTER_ENDPOINT_LOCK, MATTER_CLUSTER_BINDING,
			  MATTER_ATTR_BINDING_LIST, false, &w, MATTER_TLV_ANON);
		T_EQ("an unfiltered read encodes", matter_tlv_writer_finish(&w, &len), MATTER_OK);
		T_EQ("and enumerates both administrators", (int)count_array(buf, len), 2);
		/*
		 * The FabricIndex on every entry is what makes this legible
		 * rather than a leak: a controller reading unfiltered can tell
		 * whose binding is whose, which is the whole reason the spec
		 * expects the cross-fabric read to work.
		 */
		T_EQ("each stamped with the fabric that wrote it", (int)fabric_mask(buf, len),
		     (1 << FABRIC_A) | (1 << FABRIC_B));
	}
}

/* SPDX-License-Identifier: ISC */

/**
 * @file tm_app.h
 * @brief What the application adds to the node: its endpoints, their
 *        clusters, and word of what changed.
 *
 * The node serves endpoint 0, the Root Node, by itself. Everything else is the
 * application's: a const table of struct tm_endpoint, handed over in
 * matter_commission_config, each listing the struct tm_cluster it serves. The
 * node answers Descriptor on every endpoint and the five global attributes on
 * every cluster from that table; a cluster's callbacks answer the rest.
 *
 * Threading: every callback runs with the node's lock held, on whichever
 * context delivered the request, so it must be quick and must not call into
 * the node except through tm_attr_changed() and tm_event_emit(). Outside a
 * callback, change the state a callback reads, and call those two, between
 * tm_lock() and tm_unlock().
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_tlv.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Build-time limits; raise them with -D. */
#ifndef TM_ENDPOINTS_MAX
/** Application endpoints, endpoint 0 not counted. */
#define TM_ENDPOINTS_MAX 4u
#endif
#ifndef TM_CLUSTERS_MAX
/** Clusters on one application endpoint, Descriptor not counted. */
#define TM_CLUSTERS_MAX 6u
#endif
#ifndef TM_ATTRS_MAX
/** Attributes across every application cluster: one change bit each. */
#define TM_ATTRS_MAX 64u
#endif
#ifndef TM_EVENT_BLOB_MAX
/** Bytes an event keeps for its cluster to encode its fields from. */
#define TM_EVENT_BLOB_MAX 16u
#endif

/* AccessControl privileges (AccessControlEntryPrivilegeEnum). */
#define MATTER_AC_PRIVILEGE_VIEW       1u
#define MATTER_AC_PRIVILEGE_OPERATE    3u
#define MATTER_AC_PRIVILEGE_MANAGE     4u
#define MATTER_AC_PRIVILEGE_ADMINISTER 5u

/*
 * The global attributes (GlobalAttributeIds.h), answered by the node for every
 * application cluster that lists them. The CHIP-based lock builds answer all of
 * these on every cluster, and Apple Home builds its accessory-settings UI from
 * what it can discover -- the missing globals are the working hypothesis for
 * why Home showed this lock none of the optional controls the CHIP builds get.
 * The root endpoint commissions fine without them and stays as it was.
 */
#define MATTER_ATTR_GENERATED_CMD_LIST 0xFFF8u
#define MATTER_ATTR_ACCEPTED_CMD_LIST  0xFFF9u
#define MATTER_ATTR_ATTRIBUTE_LIST     0xFFFBu
#define MATTER_ATTR_FEATURE_MAP        0xFFFCu
#define MATTER_ATTR_CLUSTER_REVISION   0xFFFDu

/* Event priorities (PriorityLevel, EventLoggingTypes.h:51-56). */
#define MATTER_EVENT_PRIORITY_DEBUG    0u
#define MATTER_EVENT_PRIORITY_INFO     1u
#define MATTER_EVENT_PRIORITY_CRITICAL 2u

/** Who is asking. */
struct tm_req {
	uint16_t endpoint;
	/** The accessing fabric; 0 over PASE, and for a change made locally. */
	uint8_t fabric_index;
	/** A fabric-scoped list should hold only fabric_index's entries. */
	bool fabric_filtered;
	/** The accessing controller's operational node id; 0 when unknown. */
	uint64_t node_id;
};

/** One server cluster on one endpoint. Const; the table outlives the node. */
struct tm_cluster {
	uint32_t id;
	/**
	 * Every attribute this cluster answers, in the order a wildcard read
	 * reports them, the globals included. It is also AttributeList, so the
	 * two cannot disagree. The node answers the five globals listed; read()
	 * answers the rest.
	 */
	const uint32_t *attrs;
	uint8_t n_attrs;
	/** AcceptedCommandList: what invoke() runs. */
	uint8_t n_accepted;
	/** GeneratedCommandList: the responses invoke() can name. */
	uint8_t n_generated;
	/** Least privilege to invoke and to write; 0 means Operate. */
	uint8_t invoke_privilege;
	uint8_t write_privilege;
	uint16_t revision;
	uint32_t features;
	const uint32_t *accepted;
	const uint32_t *generated;

	/** Encode @p attr, a non-global attribute from attrs, at @p tag. */
	void (*read)(const struct tm_req *req, uint32_t attr, struct matter_tlv_writer *w,
		     matter_tlv_tag_t tag);
	/**
	 * Apply a write of @p attr; @p tlv is one encoded element. NULL makes
	 * every attribute read-only.
	 * @return MATTER_IM_STATUS_*.
	 */
	uint8_t (*write)(const struct tm_req *req, uint32_t attr, const uint8_t *tlv, size_t len);
	/**
	 * Run command @p cmd, one of accepted. @p fields is the encoded
	 * CommandFields structure, or NULL. Set *@p response to a generated id
	 * to answer with that command; response() then encodes its fields.
	 * Only a controller on a fabric reaches this, never PASE.
	 * @return MATTER_IM_STATUS_*.
	 */
	uint8_t (*invoke)(const struct tm_req *req, uint32_t cmd, const uint8_t *fields,
			  size_t len, uint32_t *response);
	void (*response)(const struct tm_req *req, uint32_t response,
			 struct matter_tlv_writer *w, matter_tlv_tag_t tag);
	/** Encode the Data of an event this cluster emitted, from its blob. */
	void (*event)(const struct tm_req *req, uint32_t event, const uint8_t *blob,
		      struct matter_tlv_writer *w, matter_tlv_tag_t tag);
	/** Once, from matter_commission_init(), after storage is up. */
	void (*init)(uint16_t endpoint);
	/**
	 * After subscribers were told of a change, on the node's work context
	 * and WITHOUT the lock: the place to persist, because a flash write
	 * here holds up nothing.
	 */
	void (*changed)(uint16_t endpoint);
};

/** One application endpoint. */
struct tm_endpoint {
	uint16_t id;
	uint16_t device_revision;
	uint32_t device_type;
	const struct tm_cluster *const *clusters;
	uint8_t n_clusters;
};

/**
 * Tell subscribers that @p attr changed. Lock held (see the file comment);
 * the report goes out from deferred work. An unknown path is ignored.
 */
void tm_attr_changed(uint16_t endpoint, uint32_t cluster, uint32_t attr);

/**
 * Record an event for subscribers. @p blob (up to TM_EVENT_BLOB_MAX bytes)
 * is kept with it and handed to the cluster's event() to encode. A full
 * ring drops its oldest. Lock held.
 *
 * @return the event number, or 0 when @p len is too long.
 */
uint64_t tm_event_emit(uint16_t endpoint, uint32_t cluster, uint32_t event, uint8_t priority,
		       const void *blob, size_t len);

#ifdef __cplusplus
}
#endif

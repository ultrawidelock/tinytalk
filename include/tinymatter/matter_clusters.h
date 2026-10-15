/* SPDX-License-Identifier: ISC */

/**
 * @file matter_clusters.h — what this device answers, as opposed to how.
 *
 * matter_im.c owns the ReportData wire format and knows nothing about door
 * locks or vendor IDs. This is the other half: the endpoints, clusters and
 * attributes that exist, and what they say.
 *
 * Scope is deliberately the commissioner's FIRST question and no further. A
 * real iPhone, immediately after PASE, reads nine attribute paths:
 *
 *   endpoint 0  GeneralCommissioning 0x0030  attributes 0x00..0x04 and 0x0C
 *   endpoint 0  BasicInformation     0x0028  VendorID 0x02, ProductID 0x04
 *   endpoint 0  TimeSynchronization  0x0038  all attributes (wildcard)
 *
 * Everything else answers UNSUPPORTED_*, which is a legal answer and a truthful
 * one. Clusters get added when a commissioner is observed asking for them,
 * rather than because the spec lists them.
 *
 * Device-specific values arrive in @ref matter_device_info instead of being
 * read from Kconfig here, so the host suite can build this without Zephyr and
 * assert on the encoded bytes.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <tinymatter/matter_attest.h>
#include <tinymatter/matter_fabric.h>
#include <tinymatter/matter_im.h>
#include <tinymatter/matter_thread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cluster IDs, each from that cluster's generated ClusterId.h:14. */
#define MATTER_CLUSTER_BASIC_INFORMATION       0x0028u
#define MATTER_CLUSTER_GENERAL_COMMISSIONING   0x0030u
#define MATTER_CLUSTER_NETWORK_COMMISSIONING   0x0031u
#define MATTER_CLUSTER_DESCRIPTOR              0x001Du
#define MATTER_CLUSTER_ACCESS_CONTROL          0x001Fu
#define MATTER_CLUSTER_OPERATIONAL_CREDENTIALS 0x003Eu
#define MATTER_CLUSTER_ADMIN_COMMISSIONING     0x003Cu
#define MATTER_CLUSTER_DOOR_LOCK               0x0101u

/*
 * AdministratorCommissioning. This is what Apple Home's "Turn On Pairing Mode"
 * sends, and what multi-admin sharing runs on: a node that does not serve it
 * can be commissioned exactly once, by whoever got there first, and can never
 * be handed to a second ecosystem.
 *
 * AdministratorCommissioning/AttributeIds.h:19-31 and CommandIds.h:19-27.
 */
#define MATTER_ATTR_ADMIN_WINDOW_STATUS 0x0000u
#define MATTER_ATTR_ADMIN_FABRIC_INDEX  0x0001u
#define MATTER_ATTR_ADMIN_VENDOR_ID     0x0002u

#define MATTER_CMD_ADMIN_OPEN_WINDOW       0x0000u
#define MATTER_CMD_ADMIN_OPEN_BASIC_WINDOW 0x0001u
#define MATTER_CMD_ADMIN_REVOKE            0x0002u

/** CommissioningWindowStatusEnum (AdministratorCommissioning/Enums.h). */
#define MATTER_ADMIN_WINDOW_NOT_OPEN 0u
#define MATTER_ADMIN_WINDOW_ENHANCED 1u
#define MATTER_ADMIN_WINDOW_BASIC    2u

/*
 * Cluster-specific status codes, StatusCodeEnum. A controller distinguishes
 * "you are already open" from "that verifier is malformed" by these, and Apple
 * Home shows a different message for each.
 */
#define MATTER_ADMIN_STATUS_BUSY             1u
#define MATTER_ADMIN_STATUS_PAKE_PARAM_ERROR 2u
#define MATTER_ADMIN_STATUS_WINDOW_NOT_OPEN  3u

/* Descriptor attributes (Descriptor/AttributeIds.h:19-33). */
#define MATTER_ATTR_DESC_DEVICE_TYPE_LIST 0x0000u
#define MATTER_ATTR_DESC_SERVER_LIST      0x0001u
#define MATTER_ATTR_DESC_CLIENT_LIST      0x0002u
#define MATTER_ATTR_DESC_PARTS_LIST       0x0003u

/*
 * Root Node, revision 3 (matter-devices.xml:31-38, MA-rootdevice).
 *
 * A controller reads this to learn what it has just adopted. Endpoint 0 is
 * always the Root Node; the Door Lock will be a second endpoint with its own
 * device type, listed in this endpoint's PartsList.
 */
#define MATTER_DEVICE_TYPE_ROOT_NODE 0x0016u
#define MATTER_DEVICE_TYPE_ROOT_REV  3u

/*
 * Door Lock, on endpoint 1 (matter-devices.xml, MA-doorlock).
 *
 * This is what makes the accessory a LOCK rather than a bare node: endpoint 0
 * is a Root Node, which carries no functionality, so a controller that adopts
 * this node and finds nothing in PartsList correctly shows an empty tile.
 */
#define MATTER_DEVICE_TYPE_DOOR_LOCK 0x000Au
#define MATTER_DEVICE_TYPE_LOCK_REV  3u

/* Door Lock attributes (DoorLock/AttributeIds.h:24-147). */
#define MATTER_ATTR_DL_LOCK_STATE                0x0000u
#define MATTER_ATTR_DL_LOCK_TYPE                 0x0001u
#define MATTER_ATTR_DL_ACTUATOR_ENABLED          0x0002u
#define MATTER_ATTR_DL_AUTO_RELOCK_TIME          0x0023u
#define MATTER_ATTR_DL_OPERATING_MODE            0x0025u
#define MATTER_ATTR_DL_SUPPORTED_OPERATING_MODES 0x0026u

/*
 * LockDoor and UnlockDoor (CommandIds.h:97-98), which are what the tile in a
 * controller's UI actually sends. Answering them is what turns "Matter
 * Accessory / No Response" into a lock a user can press.
 *
 * Both carry an OPTIONAL PINCode field this node ignores: it advertises no
 * PIN_CREDENTIAL feature, so a controller has nothing to send and a PIN that
 * arrived anyway would be a credential class this reader does not implement.
 * Both are Timed Invoke commands, which this node already answers.
 */
#define MATTER_CMD_DL_LOCK_DOOR   0x0000u
#define MATTER_CMD_DL_UNLOCK_DOOR 0x0001u

/* LockState (DoorLock/Enums.h:95-99) and OperatingMode (Enums.h:278-284). */
#define MATTER_DL_LOCK_STATE_LOCKED         1u
#define MATTER_DL_LOCK_STATE_UNLOCKED       2u
#define MATTER_DL_OPERATING_MODE_NORMAL     0u
/**
 * SupportedOperatingModes is INVERTED: a bit CLEARED to 0 means the mode is
 * supported (DoorLock cluster spec, DlSupportedOperatingModes). The previous
 * 0x0001 therefore claimed "everything except Normal", the opposite of the
 * truth. 0xFFF6 is CHIP's default and what the reference builds report:
 * Normal (bit 0) and NoRemoteLockUnlock (bit 3) supported, the rest not.
 */
#define MATTER_DL_SUPPORTED_OPERATING_MODES 0xFFF6u

/*
 * The LockOperation event (door-lock-cluster.xml:723-733).
 *
 * Emitted whenever the bolt's reported state is CHANGED by something, such as
 * a controller command. It is the only event this node has, and it exists
 * because the CHIP-based lock builds serve it and this one served no events at
 * all: Apple Home's "Manage Access" pane is the working hypothesis for what
 * that absence gates.
 *
 * Priority is CRITICAL, not Info. That is what the cluster XML says
 * (priority="critical" on the event element), and it is the field a subscriber
 * uses to decide what it may drop.
 */
#define MATTER_EVENT_DL_LOCK_OPERATION 0x0002u

/** PriorityLevel (EventLoggingTypes.h:51-56). */
#define MATTER_EVENT_PRIORITY_DEBUG    0u
#define MATTER_EVENT_PRIORITY_INFO     1u
#define MATTER_EVENT_PRIORITY_CRITICAL 2u

/** LockOperationTypeEnum (door-lock-cluster.xml:854-861). */
#define MATTER_DL_LOCK_OP_LOCK   0u
#define MATTER_DL_LOCK_OP_UNLOCK 1u

/*
 * OperationSourceEnum (door-lock-cluster.xml:882-895). Only the two this node
 * can honestly report: a controller command is Remote, and Unspecified is what
 * a state change with no known cause gets.
 */
#define MATTER_DL_OP_SOURCE_UNSPECIFIED 0u
#define MATTER_DL_OP_SOURCE_REMOTE      7u

/** LockOperation event fields (door-lock-cluster.xml:725-731). */
#define MATTER_DL_LOCK_OP_FIELD_TYPE         0u
#define MATTER_DL_LOCK_OP_FIELD_SOURCE       1u
#define MATTER_DL_LOCK_OP_FIELD_USER_INDEX   2u
#define MATTER_DL_LOCK_OP_FIELD_FABRIC_INDEX 3u
#define MATTER_DL_LOCK_OP_FIELD_SOURCE_NODE  4u

/**
 * Events held for a subscriber that has not collected them yet.
 *
 * Four covers a burst of lock changes, not an audit log. A subscriber is told about each
 * one as it happens, so the ring only has to survive the gap between an event
 * and the report carrying it; anything that needs durability forwards them
 * upstream and keeps them there.
 */
#define MATTER_EVENTS_MAX 4u

/**
 * One recorded event, as a report needs it.
 *
 * LockOperation's credential list (field 5) is deliberately absent: it is
 * optional, it would carry a credential index this node does not track per
 * operation, and a list invented to fill a field is worse than an absent
 * optional.
 */
struct matter_lock_event {
	uint64_t number;
	uint64_t timestamp_ms;
	uint8_t operation;    /**< MATTER_DL_LOCK_OP_*. */
	uint8_t source;       /**< MATTER_DL_OP_SOURCE_*. */
	uint8_t fabric_index; /**< 0 when no fabric owns it; reported as null. */
	uint64_t source_node; /**< Meaningful only with a fabric index. */
};

/** Access Control attributes (access-control-cluster.cpp, AclAttribute). */
#define MATTER_ATTR_AC_ACL                0x0000u
#define MATTER_ATTR_AC_EXTENSION          0x0001u
#define MATTER_ATTR_AC_SUBJECTS_PER_ENTRY 0x0002u
#define MATTER_ATTR_AC_TARGETS_PER_ENTRY  0x0003u
#define MATTER_ATTR_AC_ENTRIES_PER_FABRIC 0x0004u

/**
 * How much of an ACL this node will hold.
 *
 * One fabric, and the spec's floor is four entries per fabric; a commissioner
 * writes the whole list at once, so this bounds the encoded list rather than
 * any single entry.
 */
#define MATTER_ACL_MAX 256u

/** FeatureMap, on every cluster (GlobalAttributeIds.h). */
#define MATTER_ATTR_FEATURE_MAP 0xFFFCu

/*
 * The remaining global attributes (GlobalAttributeIds.h). Served only where a
 * controller has been seen to care: the CHIP-based lock builds answer all of
 * these on every cluster, and Apple Home builds its accessory-settings UI from
 * what it can discover -- the missing globals are the working hypothesis for
 * why Home showed this lock none of the optional controls the CHIP builds get.
 * Answered on the lock endpoint's clusters; the root endpoint commissions fine
 * without them and stays as it was.
 */
#define MATTER_ATTR_GENERATED_CMD_LIST 0xFFF8u
#define MATTER_ATTR_ACCEPTED_CMD_LIST  0xFFF9u
#define MATTER_ATTR_ATTRIBUTE_LIST     0xFFFBu
#define MATTER_ATTR_CLUSTER_REVISION   0xFFFDu

/**
 * Door Lock ClusterRevision: 8, the value the working Nordic reference build
 * reports (the source project's
 * integrations/nrfconnect-door-lock/patches/approach-direction-cluster.patch
 * shows it in the zap context).
 */
#define MATTER_DL_CLUSTER_REVISION 8u

/* BasicInformation attributes (BasicInformation/AttributeIds.h:19-77). */
#define MATTER_ATTR_BASIC_DATA_MODEL_REVISION   0x0000u
#define MATTER_ATTR_BASIC_VENDOR_NAME           0x0001u
#define MATTER_ATTR_BASIC_VENDOR_ID             0x0002u
#define MATTER_ATTR_BASIC_PRODUCT_NAME          0x0003u
#define MATTER_ATTR_BASIC_PRODUCT_ID            0x0004u
#define MATTER_ATTR_BASIC_NODE_LABEL            0x0005u
#define MATTER_ATTR_BASIC_LOCATION              0x0006u
#define MATTER_ATTR_BASIC_HARDWARE_VERSION      0x0007u
#define MATTER_ATTR_BASIC_HARDWARE_VERSION_STR  0x0008u
#define MATTER_ATTR_BASIC_SOFTWARE_VERSION      0x0009u
#define MATTER_ATTR_BASIC_SOFTWARE_VERSION_STR  0x000Au
#define MATTER_ATTR_BASIC_SERIAL_NUMBER         0x000Fu
#define MATTER_ATTR_BASIC_UNIQUE_ID             0x0012u
#define MATTER_ATTR_BASIC_CAPABILITY_MINIMA     0x0013u
#define MATTER_ATTR_BASIC_SPECIFICATION_VERSION 0x0015u
#define MATTER_ATTR_BASIC_MAX_PATHS_PER_INVOKE  0x0016u

/** Matter Basic Information limits SerialNumber and UniqueID to 32 bytes. */
#define MATTER_SERIAL_NUMBER_MAX 32u

/*
 * What this node reports about itself.
 *
 * DataModelRevision and SpecificationVersion are the 1.2 values, not the SDK's
 * current 19 / 0x01050000 (SpecificationDefinedRevisions.h:44,53). Claiming 1.5
 * would claim features this node does not have; 1.2 is what it was written
 * against and what SPECIFICATION_VERSION in the vendored SDK says.
 */
#define MATTER_DATA_MODEL_REVISION   17u
#define MATTER_SPECIFICATION_VERSION 0x01020000u

/*
 * CapabilityMinima: the spec's floors, which are also what this node can do
 * (InteractionModelEngine.h:110-111). One CASE session and one subscription are
 * what it actually holds -- but the floor is 3 and reporting less than the floor
 * is not a legal answer, so these are the honest minimum it may claim.
 */
#define MATTER_CASE_SESSIONS_PER_FABRIC 3u
#define MATTER_SUBSCRIPTIONS_PER_FABRIC 3u

/** CHIP_CONFIG_MAX_PATHS_PER_INVOKE (CHIPConfig.h:1877), and what this node parses. */
#define MATTER_MAX_PATHS_PER_INVOKE 1u

/* GeneralCommissioning attributes (GeneralCommissioning/AttributeIds.h:19-36). */
#define MATTER_ATTR_GC_BREADCRUMB                     0x0000u
#define MATTER_ATTR_GC_BASIC_COMMISSIONING_INFO       0x0001u
#define MATTER_ATTR_GC_REGULATORY_CONFIG              0x0002u
#define MATTER_ATTR_GC_LOCATION_CAPABILITY            0x0003u
#define MATTER_ATTR_GC_SUPPORTS_CONCURRENT_CONNECTION 0x0004u

/* RegulatoryLocationTypeEnum (GeneralCommissioning/Enums.h:65-67). */
#define MATTER_REGULATORY_INDOOR         0u
#define MATTER_REGULATORY_OUTDOOR        1u
#define MATTER_REGULATORY_INDOOR_OUTDOOR 2u

/* GeneralCommissioning commands (GeneralCommissioning/CommandIds.h:21-46). */
#define MATTER_CMD_GC_ARM_FAIL_SAFE                   0x0000u
#define MATTER_CMD_GC_ARM_FAIL_SAFE_RESPONSE          0x0001u
#define MATTER_CMD_GC_SET_REGULATORY_CONFIG           0x0002u
#define MATTER_CMD_GC_SET_REGULATORY_CONFIG_RESPONSE  0x0003u
#define MATTER_CMD_GC_COMMISSIONING_COMPLETE          0x0004u
#define MATTER_CMD_GC_COMMISSIONING_COMPLETE_RESPONSE 0x0005u

/* CommissioningErrorEnum (GeneralCommissioning/Enums.h:34-41). */
#define MATTER_COMMISSIONING_OK                  0u
#define MATTER_COMMISSIONING_VALUE_OUTSIDE_RANGE 1u
#define MATTER_COMMISSIONING_INVALID_AUTH        2u
#define MATTER_COMMISSIONING_NO_FAIL_SAFE        3u
#define MATTER_COMMISSIONING_BUSY_WITH_OTHER     4u

/* NetworkCommissioning attributes (MTRClusterConstants.h:1165-1169). */
#define MATTER_ATTR_NC_MAX_NETWORKS           0x0000u
#define MATTER_ATTR_NC_NETWORKS               0x0001u
#define MATTER_ATTR_NC_SCAN_MAX_TIME_S        0x0002u
#define MATTER_ATTR_NC_CONNECT_MAX_TIME_S     0x0003u
#define MATTER_ATTR_NC_INTERFACE_ENABLED      0x0004u
#define MATTER_ATTR_NC_LAST_NETWORKING_STATUS 0x0005u

/* NetworkCommissioning commands (MTRClusterConstants.h:6296-6300). */
#define MATTER_CMD_NC_ADD_OR_UPDATE_THREAD_NETWORK 0x0003u
#define MATTER_CMD_NC_REMOVE_NETWORK               0x0004u
#define MATTER_CMD_NC_NETWORK_CONFIG_RESPONSE      0x0005u
#define MATTER_CMD_NC_CONNECT_NETWORK              0x0006u
#define MATTER_CMD_NC_CONNECT_NETWORK_RESPONSE     0x0007u

/** NetworkCommissioning Feature bits (python clusters/Objects.py, Feature). */
#define MATTER_NC_FEATURE_THREAD 0x2u

/* NetworkCommissioningStatusEnum, the values this node returns. */
#define MATTER_NC_STATUS_SUCCESS                 0x00u
#define MATTER_NC_STATUS_OUT_OF_RANGE            0x01u
#define MATTER_NC_STATUS_BOUNDS_EXCEEDED          0x02u
#define MATTER_NC_STATUS_NETWORK_ID_NOT_FOUND    0x03u
#define MATTER_NC_STATUS_OTHER_CONNECTION_FAILUR 0x09u

/**
 * A Thread operational dataset, kSizeOperationalDataset
 * (lib/support/ThreadOperationalDataset.h:36).
 */
#define MATTER_THREAD_DATASET_MAX 254u

/** Extended PAN ID: 8 bytes, and the id a network is referred to by. */
#define MATTER_THREAD_XPANID_LEN 8u

/**
 * How long ConnectNetwork waits for the attach before answering.
 *
 * Well under the 60 s this node reports as ConnectMaxTimeSeconds, because the
 * commissioner is blocked on the reply for the whole of it. A Thread attach to
 * a network whose dataset is already known normally completes in a few seconds;
 * this leaves room for a retry without leaving the phone waiting a minute.
 */
#define MATTER_THREAD_ATTACH_TIMEOUT_MS 20000u

/* OperationalCredentials commands (MTRClusterConstants.h:6435-6446). */
#define MATTER_CMD_OC_ATTESTATION_REQUEST          0x0000u
#define MATTER_CMD_OC_ATTESTATION_RESPONSE         0x0001u
#define MATTER_CMD_OC_CERTIFICATE_CHAIN_REQUEST    0x0002u
#define MATTER_CMD_OC_CERTIFICATE_CHAIN_RESPONSE   0x0003u
#define MATTER_CMD_OC_CSR_REQUEST                  0x0004u
#define MATTER_CMD_OC_CSR_RESPONSE                 0x0005u
#define MATTER_CMD_OC_ADD_NOC                      0x0006u
#define MATTER_CMD_OC_NOC_RESPONSE                 0x0008u
#define MATTER_CMD_OC_UPDATE_FABRIC_LABEL          0x0009u
#define MATTER_CMD_OC_REMOVE_FABRIC                0x000Au
#define MATTER_CMD_OC_ADD_TRUSTED_ROOT_CERTIFICATE 0x000Bu

/* OperationalCredentials attributes (MTRClusterConstants.h:1988-1989). */
#define MATTER_ATTR_OC_NOCS                 0x0000u
#define MATTER_ATTR_OC_FABRICS              0x0001u
#define MATTER_ATTR_OC_SUPPORTED_FABRICS    0x0002u
#define MATTER_ATTR_OC_COMMISSIONED_FABRICS 0x0003u
#define MATTER_ATTR_OC_TRUSTED_ROOTS        0x0004u
#define MATTER_ATTR_OC_CURRENT_FABRIC_INDEX 0x0005u

/**
 * How many fabrics this node can hold at once.
 *
 * Two was what a single Apple Home needs: the phone and the home hub commission
 * the device onto SEPARATE fabrics, each with its own trusted root and its own
 * operational key, and a node that advertises one answers the second AddNOC
 * with TABLE_FULL and is never adopted.
 *
 * Three is what a single Apple Home needs (two identities) plus one spare.
 * Failed attempts do not consume one of these slots: they are attempt-owned
 * until CommissioningComplete durably promotes them.
 *
 * Every array below is sized from it. Each slot costs sizeof(struct
 * matter_fabric) plus one struct matter_fabric_acl, so the count is real RAM
 * rather than a policy knob.
 */
#define MATTER_SUPPORTED_FABRICS 3u

/** One byte is enough for the three physical fabric-slot ownership bits. */
#define MATTER_FABRIC_SLOT_BIT(slot) ((uint8_t)(1u << (slot)))

/** Durable mutations the portable cluster asks the owning port to commit. */
enum matter_fabric_store_operation {
	MATTER_FABRIC_STORE_COMMIT_ATTEMPT = 1,
	MATTER_FABRIC_STORE_REMOVE = 2,
	MATTER_FABRIC_STORE_ACL = 3,
	/*
	 * Re-store one COMMITTED slot's fabric record after a field of it
	 * changed in place -- UpdateFabricLabel. Only the fabric record: the
	 * network, ICAC, and ACL records are untouched by such a change, and
	 * rewriting them would spend flash on bytes that did not move.
	 */
	MATTER_FABRIC_STORE_UPDATE = 5,
};

struct matter_device_info;

/**
 * Port-owned operations that cannot live in the OS-neutral cluster module.
 *
 * The store callback is a durability boundary. It returns only after the
 * requested mutation is on stable storage. The cluster emits no success
 * response and changes no committed RAM state when it fails.
 */
struct matter_commissioning_hooks {
	int (*failsafe_arm)(void *ctx, uint16_t expiry_s);
	void (*failsafe_cancel)(void *ctx);
	int (*fabric_store)(void *ctx, const struct matter_device_info *info,
			    enum matter_fabric_store_operation operation, uint8_t slot,
			    const uint8_t *value, size_t value_len);
	void *ctx;
};

/** State owned by one ArmFailSafe lifetime. Never persisted. */
struct matter_commissioning_attempt {
	bool active;
	/** Physical fabrics[] slots created by this attempt. */
	uint8_t owned_slots;
	/** A validated candidate dataset was supplied during this attempt. */
	bool have_thread_candidate;
	/** The candidate was applied to OpenThread and must be undone on abort. */
	bool thread_applied;
	uint8_t thread_dataset[MATTER_THREAD_DATASET_MAX];
	size_t thread_dataset_len;
	uint8_t thread_xpanid[MATTER_THREAD_XPANID_LEN];
};

/** Access-control data belongs to one fabric, never to the node globally. */
struct matter_fabric_acl {
	uint8_t data[MATTER_ACL_MAX];
	size_t len;
};

/*
 * NodeOperationalCertStatusEnum, the verdicts this node actually returns
 * (OperationalCredentials Enums, python clusters/Objects.py). AddNOC reports
 * failure THROUGH this enum rather than through an IM status: the commissioner
 * has to be told which of its inputs was rejected, and a bare FAILURE cannot
 * say.
 */
#define MATTER_NOC_STATUS_OK                   0u
#define MATTER_NOC_STATUS_INVALID_PUBLIC_KEY   1u
#define MATTER_NOC_STATUS_INVALID_NOC          3u
#define MATTER_NOC_STATUS_MISSING_CSR          4u
#define MATTER_NOC_STATUS_TABLE_FULL           5u
#define MATTER_NOC_STATUS_LABEL_CONFLICT       10u
#define MATTER_NOC_STATUS_INVALID_FABRIC_INDEX 11u

/** Every Matter node's root endpoint is 0. */
#define MATTER_ENDPOINT_ROOT 0u
/** The Door Lock. Listed in the root endpoint's PartsList. */
#define MATTER_ENDPOINT_LOCK 1u

/**
 * Complete device information structure held by the Matter node, including vendor/product IDs,
 * commissioning state, operational network configuration, and session-specific attestation and
 * key data.
 */
struct matter_device_info {
	uint16_t vendor_id;
	uint16_t product_id;
	/** Stable, per-device serial supplied by the hardware port. */
	char serial_number[MATTER_SERIAL_NUMBER_MAX + 1u];
	/**
	 * What LockState reports, and what LockDoor/UnlockDoor change.
	 *
	 * Zero is not a legal LockState, so it means "never set" and is reported
	 * as Locked -- a reader that has been asked nothing is not unlocked.
	 * There is still no actuator behind this: it moves no bolt, and saying
	 * Unlocked is a claim about this node's state rather than about a door.
	 * It matters anyway, because a controller draws the tile from it and
	 * refuses to send UnlockDoor to something already reporting Unlocked.
	 */
	uint8_t lock_state;
	/**
	 * AutoRelockTime, in seconds; 0 means no automatic relock.
	 *
	 * Implemented because its ABSENCE changes controller behaviour: Apple
	 * Home shows an auto-lock timing control for locks that carry this
	 * attribute and improvises without it -- observed on hardware as an
	 * unrequested LockDoor a few seconds after every UnlockDoor. The node
	 * itself enforces nothing here yet: the value is reported and writable
	 * so the controller owns the policy. The application persists it after
	 * a successful write response.
	 */
	uint32_t auto_relock_time_s;
	/**
	 * The LockOperation events waiting to be reported, oldest first.
	 *
	 * A ring rather than a single slot: two lock changes inside one
	 * report interval are ordinary, and a slot would report the second twice and
	 * the first never. @ref event_count says how many are live.
	 */
	struct matter_lock_event events[MATTER_EVENTS_MAX];
	uint8_t event_count;
	/**
	 * The next EventNumber to hand out; the first event is 1.
	 *
	 * Zero is never a valid event number, which is what lets an
	 * EventFilter of 0 mean "everything you have" without also meaning
	 * "including one I already saw".
	 */
	uint64_t next_event_number;
	/**
	 * Milliseconds since boot, for an event's SystemTimestamp. The port
	 * owns the clock; NULL makes every event report a timestamp of zero,
	 * which is legal and useless rather than wrong.
	 */
	uint64_t (*uptime_ms_cb)(void);
	/**
	 * The fabric index of the session being served right now, set by the
	 * port before it dispatches each secure message.
	 *
	 * CurrentFabricIndex is FABRIC-SCOPED: it must answer "which fabric are
	 * you, to me", and the answer depends entirely on who is asking. While
	 * this was hardcoded to the first live fabric, the home hub read it over
	 * its own session, was told it was fabric 1, concluded it was not on the
	 * fabric it had just joined, and sent RemoveFabric. Zero means no secure
	 * session, which is not a legal answer to anyone and is why nothing may
	 * read it outside one.
	 */
	uint8_t accessing_fabric_index;
	/**
	 * Written by the commissioner through GeneralCommissioning so it can
	 * tell how far a previous attempt got. Mutable, and the reason this
	 * struct is not const.
	 */
	uint64_t breadcrumb;
	uint8_t regulatory_config;
	uint8_t location_capability;
	/** BasicCommissioningInfo, seconds (GeneralCommissioning/Structs.h:50-51). */
	uint16_t failsafe_expiry_s;
	uint16_t failsafe_max_s;
	/**
	 * Whether BLE stays up while the node joins its operational network.
	 *
	 * False tells the commissioner to expect this node to vanish from BLE
	 * and reappear on Thread. This node has no operational network at all
	 * yet, so false would promise a reappearance that never comes.
	 */
	bool supports_concurrent_connection;
	/** The one in-flight fail-safe transaction. */
	struct matter_commissioning_attempt attempt;
	/** Port timer and durable-store implementation. */
	const struct matter_commissioning_hooks *commissioning_hooks;
	/**
	 * The CommissioningErrorEnum the last GeneralCommissioning command
	 * produced, held between running it and serialising its response --
	 * matter_im_command_fields_fn is pure and cannot recompute it.
	 */
	uint8_t last_commissioning_error;
	/**
	 * The CASE Authenticated Tags of whoever is asking, from the NOC it
	 * proved in Sigma3. Empty over PASE, which has no operational identity.
	 *
	 * An ACL subject in the CAT range names a GROUP, so a controller is only
	 * matched against these -- never against its node id, which no CAT
	 * subject can ever equal.
	 */
	uint32_t accessing_cats[MATTER_MAX_CATS];
	uint8_t accessing_n_cats;
	/**
	 * The fabric index whose CommissioningComplete last succeeded, or 0.
	 *
	 * Exists so a RETRANSMITTED CommissioningComplete can be answered the
	 * same way as the one it repeats. The command disarms the fail-safe as
	 * its substance, so the second copy arrives to a node that no longer has
	 * one and would otherwise be told NO_FAIL_SAFE -- a controller reads
	 * that as the commissioning having failed and abandons the fabric it
	 * just finished building. Cleared when a new fail-safe is armed, which
	 * is the point a fresh transaction begins and the old answer stops being
	 * the truth.
	 */
	uint8_t last_completed_fabric_index;

	/*
	 * ---- attestation --------------------------------------------------
	 *
	 * A command runs once and its reply is serialised afterwards, so
	 * whatever the reply needs is recorded here in between. All of it is
	 * per-session and none of it survives a new commissioner.
	 */

	/**
	 * The session's attestation challenge, which every attestation
	 * signature covers. Copied from the PASE keys when the secure session
	 * comes up; without it a recorded response could be replayed into a
	 * different session.
	 */
	uint8_t attestation_challenge[MATTER_ATTEST_CHALLENGE_LEN];
	bool have_challenge;

	/**
	 * Scratch for the reply, with the headroom
	 * matter_attest_sign_with_challenge() writes the challenge into.
	 */
	uint8_t attest_buf[MATTER_ATTEST_ELEMENTS_MAX + MATTER_ATTEST_CHALLENGE_LEN];
	size_t attest_len;
	uint8_t attest_sig[MATTER_ATTEST_SIG_LEN];
	/** Which certificate CertificateChainResponse should carry. */
	uint8_t cert_type;

	/**
	 * The operational key pair, minted when the commissioner asks for a
	 * CSR. The private half never leaves this node -- that is the point of
	 * a CSR -- and the commissioner certifies the public half into a NOC.
	 */
	uint8_t op_priv[32];
	uint8_t op_pub[65];
	bool have_op_key;

	/*
	 * ---- operational identity ------------------------------------------
	 */

	/** Fabric identities, including at most one provisional attempt-owned slot. */
	struct matter_fabric fabrics[MATTER_SUPPORTED_FABRICS];
	/** Physical slots whose identities are durable and authoritative. */
	uint8_t committed_slots;
	/** Fabric-scoped ACL data, indexed by the same physical slot. */
	struct matter_fabric_acl fabric_acls[MATTER_SUPPORTED_FABRICS];
	/**
	 * The node's single intermediate-certificate slot, shared by every
	 * fabric because at most one has ever needed it. See the note on
	 * matter_fabric.icac_len for what that costs.
	 */
	struct matter_icac_slot icac;

	/*
	 * ---- the operational network ---------------------------------------
	 *
	 * The commissioner hands over a Thread operational dataset -- network
	 * key, channel, PAN ids, the lot -- and expects the node to join with
	 * it. A candidate is staged until ConnectNetwork succeeds, then becomes
	 * the durable dataset restored after reboot. Later administrators may
	 * name the same Extended PAN ID but cannot replace these credentials.
	 */
	uint8_t thread_dataset[MATTER_THREAD_DATASET_MAX];
	size_t thread_dataset_len;
	/** Extended PAN ID, parsed out of the dataset; the network's identity. */
	uint8_t thread_xpanid[MATTER_THREAD_XPANID_LEN];
	bool have_thread_xpanid;
	/** True once the stack accepted the dataset and began attaching. */
	bool thread_started;
	/** NetworkCommissioningStatusEnum from the last network command. */
	uint8_t last_network_status;
	/** Operational node id of the CASE peer serving the current request. */
	uint64_t accessing_node_id;

	/**
	 * The NodeOperationalCertStatusEnum the last AddNOC produced, held for
	 * the same reason as last_commissioning_error: the reply is serialised
	 * after the command has run and cannot recompute the verdict.
	 */
	uint8_t last_noc_status;
	/**
	 * The index AddNOC assigned, held for the NOCResponse.
	 *
	 * The reply is serialised after the command has run and cannot recompute
	 * it -- and with more than one slot, "the fabric that was just created"
	 * is no longer the same thing as "the only one".
	 */
	uint8_t last_noc_index;

};

/**
 * Point @p srv at this data model.
 *
 * @param info borrowed, not copied, and must outlive @p srv. Breadcrumb is
 *        written through it.
 */
/**
 * What the application must do when a controller opens a commissioning window.
 *
 * The cluster decodes and validates; everything it would then have to TOUCH --
 * the SPAKE2+ verifier the PASE responder uses, the BLE advertising payload,
 * the expiry timer -- belongs to the port. So this module stays free of both
 * Bluetooth and Zephyr, which is what lets tests/host compile it.
 *
 * All three return a MATTER_ADMIN_STATUS_* code, or 0 for success.
 */
struct matter_admin_hooks {
	/**
	 * OpenCommissioningWindow: commission with a verifier the CONTROLLER
	 * chose, not the factory one.
	 *
	 * @param verifier w0 || L, exactly the layout the PASE responder wants
	 * @param salt     the PBKDF salt that verifier was derived with
	 *
	 * The old verifier must come back when the window closes, or the
	 * factory setup code stops working for good.
	 */
	uint8_t (*open_enhanced)(uint16_t timeout_s, const uint8_t *verifier, uint32_t verifier_len,
				 uint16_t discriminator, uint32_t iterations, const uint8_t *salt,
				 uint32_t salt_len);
	/** OpenBasicCommissioningWindow: reuse the factory verifier. */
	uint8_t (*open_basic)(uint16_t timeout_s);
	/** RevokeCommissioning: close early. */
	uint8_t (*revoke)(void);
	/** Current MATTER_AC_WINDOW_* value, for the WindowStatus attribute. */
	uint8_t (*status)(void);
	/** Fabric index that opened it, 0 when closed. */
	uint8_t (*admin_fabric)(void);
	/** Vendor ID that opened it, 0 when closed. */
	uint16_t (*admin_vendor)(void);
};

/**
 * Install the hooks above.
 *
 * Until this is called the cluster still APPEARS -- a controller reading
 * ServerList sees it, which is the point, because a node that hides it can
 * never be shared with a second ecosystem -- but every command answers
 * FAILURE rather than pretending to have opened something.
 */
void matter_clusters_set_admin_hooks(const struct matter_admin_hooks *hooks);

void matter_clusters_init(struct matter_im_server *srv, struct matter_device_info *info);

/**
 * Record a LockOperation event, to be carried by the next report.
 *
 * Call after the state has changed, not before: the event says what happened.
 * LockDoor and UnlockDoor record their own, so the caller only needs this for
 * the changes that do not arrive as commands, such as an automatic relock.
 *
 * @param operation MATTER_DL_LOCK_OP_LOCK or _UNLOCK.
 * @param source MATTER_DL_OP_SOURCE_*.
 * @param fabric_index the fabric that asked, or 0 when none did -- reported as
 *        null, together with @p source_node, because an automatic relock has
 *        no fabric and claiming one would name the wrong controller.
 * @param source_node the node that asked; ignored when @p fabric_index is 0.
 */
void matter_clusters_record_lock_operation(struct matter_device_info *info, uint8_t operation,
					   uint8_t source, uint8_t fabric_index,
					   uint64_t source_node);

/** How many events are waiting. Zero after @ref matter_clusters_init. */
size_t matter_clusters_event_count(const struct matter_device_info *info);

/**
 * Undo a commissioning that never finished.
 *
 * This is what the fail-safe MEANS, and until AddNOC there was nothing for it
 * to undo -- so the flag recorded the state without enforcing it. Now a
 * commissioner that gives up half way leaves a fabric behind, and the next
 * attempt is answered TableFull for a reason that has nothing to do with what
 * went wrong. The caller decides when: this port rolls the transaction back at
 * the beginning of the next commissioning session.
 *
 * Only slots and network changes owned by the current attempt are undone.
 * Earlier committed fabrics and their Thread network are restored unchanged.
 */
void matter_clusters_failsafe_expire(struct matter_device_info *info);

/**
 * Bring a restored identity back onto the network.
 *
 * A node that reloads its fabric table from storage is commissioned but not
 * REACHABLE: the Thread dataset has not been handed to the stack and no SRP
 * instance exists, so the controller resolves nothing and reports the accessory
 * dead. Commissioning does both of those as a side effect of
 * AddOrUpdateThreadNetwork and AddNOC; this is that same pair, for the boot
 * path that has no commissioner to trigger them.
 *
 * Call it after loading @p info and only when a fabric was actually restored.
 *
 * @return MATTER_OK when Thread started and every fabric was advertised,
 *         MATTER_E_STATE when there is no stored dataset to start from.
 */
int matter_clusters_resume(struct matter_device_info *info);

#ifdef __cplusplus
}
#endif

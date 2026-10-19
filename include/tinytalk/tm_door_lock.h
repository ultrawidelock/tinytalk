/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tm_door_lock.h
 * @brief The Door Lock cluster, as a module an application puts on an
 *        endpoint (tm_app.h): LockState, LockDoor and UnlockDoor,
 *        AutoRelockTime and the LockOperation event, persisted through tm_kv.
 *
 * FeatureMap 0: no users, credentials or schedules. An application that needs
 * them serves its own Door Lock cluster instead of this one.
 */
#pragma once

#include <stdint.h>

#include <tinytalk/tm_app.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Where tm_door_lock_endpoint puts it, and the sample with it. */
#define MATTER_ENDPOINT_LOCK 1u

#define MATTER_CLUSTER_DOOR_LOCK 0x0101u

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
 * Door Lock ClusterRevision: 8, the value the working Nordic reference build
 * reports (the source project's
 * integrations/nrfconnect-door-lock/patches/approach-direction-cluster.patch
 * shows it in the zap context).
 */
#define MATTER_DL_CLUSTER_REVISION 8u

/*
 * ---- Aliro (TM_DOOR_LOCK_ALIRO, CONFIG_TINYTALK_DOOR_LOCK_ALIRO) ----------
 *
 * The USER, ALIRO_PROVISIONING and ALIRO_BLE_UWB features (DoorLock/Enums.h,
 * Feature). A controller reads the nine reader attributes to decide whether
 * this lock can be a credential reader, then sends SetAliroReaderConfig with
 * the reader's private key, and hands credential keys over on the
 * user/credential path. The application's reader takes them through the
 * hooks below; the cluster keeps the user table and what a controller may
 * read back.
 */
#define MATTER_DL_FEATURE_USER               0x0100u
#define MATTER_DL_FEATURE_ALIRO_PROVISIONING 0x2000u
#define MATTER_DL_FEATURE_ALIRO_BLE_UWB      0x4000u

/* DoorLock/AttributeIds.h. */
#define MATTER_ATTR_DL_USERS_MAX                 0x0011u
#define MATTER_ATTR_DL_CREDENTIAL_RULES          0x001Bu
#define MATTER_ATTR_DL_CREDS_PER_USER_MAX        0x001Cu
#define MATTER_ATTR_DL_ALIRO_VERIFICATION_KEY    0x0080u
#define MATTER_ATTR_DL_ALIRO_GROUP_ID            0x0081u
#define MATTER_ATTR_DL_ALIRO_GROUP_SUB_ID        0x0082u
#define MATTER_ATTR_DL_ALIRO_EXPEDITED_VERSIONS  0x0083u
#define MATTER_ATTR_DL_ALIRO_GROUP_RESOLVING_KEY 0x0084u
#define MATTER_ATTR_DL_ALIRO_BLE_UWB_VERSIONS    0x0085u
#define MATTER_ATTR_DL_ALIRO_BLE_ADV_VERSION     0x0086u
#define MATTER_ATTR_DL_ALIRO_ISSUER_KEYS_MAX     0x0087u
#define MATTER_ATTR_DL_ALIRO_ENDPOINT_KEYS_MAX   0x0088u

/* DoorLock/CommandIds.h. */
#define MATTER_CMD_DL_SET_USER                       0x001Au
#define MATTER_CMD_DL_GET_USER                       0x001Bu
#define MATTER_CMD_DL_GET_USER_RESPONSE              0x001Cu
#define MATTER_CMD_DL_CLEAR_USER                     0x001Du
#define MATTER_CMD_DL_SET_CREDENTIAL                 0x0022u
#define MATTER_CMD_DL_SET_CREDENTIAL_RESPONSE        0x0023u
#define MATTER_CMD_DL_GET_CREDENTIAL_STATUS          0x0024u
#define MATTER_CMD_DL_GET_CREDENTIAL_STATUS_RESPONSE 0x0025u
#define MATTER_CMD_DL_CLEAR_CREDENTIAL               0x0026u
#define MATTER_CMD_DL_SET_ALIRO_READER_CONFIG        0x0028u
#define MATTER_CMD_DL_CLEAR_ALIRO_READER_CONFIG      0x0029u

/* CredentialTypeEnum: the three that carry a reader trust anchor. */
#define MATTER_DL_CRED_ALIRO_ISSUER_KEY            6u
#define MATTER_DL_CRED_ALIRO_EVICTABLE_ENDPOINT    7u
#define MATTER_DL_CRED_ALIRO_NONEVICTABLE_ENDPOINT 8u
/* ClearUser and ClearCredential: every one of them (door-lock-server.cpp). */
#define MATTER_DL_INDEX_ALL 0xFFFEu
/* OperationSourceEnum Aliro: the bolt moved for a credential. */
#define MATTER_DL_OP_SOURCE_ALIRO 10u

#define MATTER_DL_USERS_MAX          10u
#define MATTER_DL_CREDS_PER_USER_MAX 5u
#define MATTER_ALIRO_SIGNING_KEY_LEN      32u
#define MATTER_ALIRO_VERIFICATION_KEY_LEN 65u
#define MATTER_ALIRO_GROUP_ID_LEN         16u
#define MATTER_ALIRO_PROTOCOL_VERSION     0x0100u
#define MATTER_ALIRO_BLE_ADV_VERSION      0u
#define MATTER_ALIRO_ISSUER_KEYS_MAX      5u
#define MATTER_ALIRO_ENDPOINT_KEYS_MAX    6u

/**
 * Where the keys land, in the application's reader. Every hook returns 0 when
 * done and persisted; anything else makes the command report FAILURE, so a
 * controller is never told a key was kept that the next reboot forgets. The
 * cluster is called with the node's lock held.
 */
struct tm_door_lock_aliro_hooks {
	/** SetAliroReaderConfig: the reader identity. reader_id is
	 *  group_id || group_sub_id; the signing key is never kept here. */
	int (*reader_config)(const uint8_t signing_key[MATTER_ALIRO_SIGNING_KEY_LEN],
			     const uint8_t verification_key[MATTER_ALIRO_VERIFICATION_KEY_LEN],
			     const uint8_t group_id[MATTER_ALIRO_GROUP_ID_LEN],
			     const uint8_t group_sub_id[MATTER_ALIRO_GROUP_ID_LEN],
			     const uint8_t grk[MATTER_ALIRO_GROUP_ID_LEN]);
	/** ClearAliroReaderConfig. */
	int (*reader_clear)(void);
	/** A credential public key at (type, index), filed under user_index
	 *  (0: none). 0 added, 1 already present, -ENOSPC full, other < 0
	 *  refused. */
	int (*credential_set)(uint8_t cred_type,
			      const uint8_t key[MATTER_ALIRO_VERIFICATION_KEY_LEN],
			      uint16_t cred_index, uint16_t user_index);
	/** Remove (type, index); index MATTER_DL_INDEX_ALL for every one of the
	 *  type, and type 0 with it for every type. */
	int (*credential_clear)(uint8_t cred_type, uint16_t cred_index);
	/** What is stored at (type, index): copies the key and returns the user
	 *  index it is filed under (0 when none), or < 0 when nothing is there. */
	int (*credential_lookup)(uint8_t cred_type, uint16_t cred_index,
				 uint8_t key[MATTER_ALIRO_VERIFICATION_KEY_LEN]);
	/** ClearUser: drop the credentials filed under user_index
	 *  (MATTER_DL_INDEX_ALL: every user). */
	int (*user_clear)(uint16_t user_index);
};

/** Install the hooks. Before matter_commission_init(); NULL refuses every
 *  provisioning command with FAILURE. */
void tm_door_lock_aliro_configure(const struct tm_door_lock_aliro_hooks *hooks);

/**
 * What the reader holds, for the attributes a controller reads back: after a
 * reboot, once the reader has loaded its identity. NULL for all three when it
 * has none (the dev identity). Takes the node's lock.
 */
void tm_door_lock_aliro_set_identity(const uint8_t verification_key[MATTER_ALIRO_VERIFICATION_KEY_LEN],
				     const uint8_t group_id[MATTER_ALIRO_GROUP_ID_LEN],
				     const uint8_t grk[MATTER_ALIRO_GROUP_ID_LEN]);

/** The cluster, for an application's own endpoint table. */
extern const struct tm_cluster tm_door_lock;

/** Endpoint MATTER_ENDPOINT_LOCK, a Door Lock device carrying tm_door_lock. */
extern const struct tm_endpoint tm_door_lock_endpoint;

/**
 * Move the bolt, or whatever stands in for it, to @p lock_state
 * (MATTER_DL_LOCK_STATE_*). Provided by the application. Called with the
 * node's lock held when a controller locks or unlocks, and once from
 * matter_commission_init() with the LockState stored before the last reboot
 * (Locked if none), so the bolt starts where a controller will read it.
 */
void tm_door_lock_actuate(uint8_t lock_state);

/** The LockState a controller reads now. */
uint8_t tm_door_lock_state(void);

/**
 * The bolt moved without a controller asking: a key, a thumb turn, an
 * automatic relock. Reports @p lock_state to subscribers and records a
 * LockOperation event from @p source (MATTER_DL_OP_SOURCE_*) with no fabric.
 * Takes the node's lock, so never call it from tm_door_lock_actuate(). Does
 * not call tm_door_lock_actuate(): the bolt is already there.
 */
void tm_door_lock_set(uint8_t lock_state, uint8_t source);

/**
 * Record a LockOperation event, to be carried by the next report. Lock held.
 *
 * Call after the state has changed, not before: the event says what happened.
 * LockDoor, UnlockDoor and tm_door_lock_set() record their own, so this is
 * for the rest.
 *
 * @param operation MATTER_DL_LOCK_OP_LOCK or _UNLOCK.
 * @param source MATTER_DL_OP_SOURCE_*.
 * @param fabric_index the fabric that asked, or 0 when none did -- reported as
 *        null, together with @p source_node, because an automatic relock has
 *        no fabric and claiming one would name the wrong controller.
 * @param source_node the node that asked; ignored when @p fabric_index is 0.
 */
void tm_door_lock_record(uint8_t operation, uint8_t source, uint8_t fabric_index,
			 uint64_t source_node);

/** Forget the stored LockState and AutoRelockTime. */
int tm_door_lock_erase(void);

#ifdef __cplusplus
}
#endif

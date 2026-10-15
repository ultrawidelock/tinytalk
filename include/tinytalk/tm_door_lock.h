/* SPDX-License-Identifier: ISC */

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

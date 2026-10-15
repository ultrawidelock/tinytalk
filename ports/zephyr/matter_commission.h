/* SPDX-License-Identifier: ISC */

/**
 * @file matter_commission.h — start answering commissioning attempts.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/sys/util.h>

#include <tinymatter/matter_clusters.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Register the commissioning handlers on the 0xFFF6 transport.
 *
 * Call after bt_enable() and psa_crypto_init(). Nothing here touches the
 * radio: whether the board is discoverable as a commissionable node is decided
 * by the application's advertising, which asks for the Matter payload while
 * this node holds no fabric -- see matter_commission_has_fabric() and
 * matter_commission_readvertise().
 *
 * @return 0, or -ENOMEM if a packet pool cannot be set up. A bad verifier is
 *         reported by log and refused per attempt rather than failing
 *         startup.
 */
int matter_commission_init(void);

/**
 * Whether this node currently holds a commissioned Matter fabric.
 *
 * Asked by the advertiser. A device with no fabric MUST stay commissionable,
 * or a board that lost its fabric to a failed pairing is invisible to Add
 * Accessory and impossible to recover without erasing it.
 */
bool matter_commission_has_fabric(void);

/**
 * True while an AdministratorCommissioning window is open.
 *
 * The advertiser needs this: a node that HAS a fabric normally stops offering
 * itself for commissioning, and doing that during a commissioning window hides
 * it from the very ecosystem the window was opened for.
 */
bool matter_commission_window_open(void);

/**
 * True exactly once after an UnlockDoor command was invoked; reading clears it.
 *
 * For a main loop that has to tell a deliberate unlock from any other: the
 * Matter path runs on OpenThread's thread, so the loop polls this instead of
 * being called from there.
 */
bool matter_commission_take_deliberate_unlock(void);

/**
 * Open a basic commissioning window (the factory setup code) for @p timeout_s,
 * as OpenBasicCommissioningWindow does. For a local gesture such as a button.
 *
 * @return 0, or -EBUSY when a window is already open.
 */
int matter_commission_open_window(uint16_t timeout_s);

/**
 * Finish the one packet previously accepted by the Matter BLE transport.
 * Called exactly once by the transport after final confirmation or failure.
 */
void matter_commission_ble_tx_complete(int status);

#if IS_ENABLED(CONFIG_TINYMATTER_DOOR_LOCK_ALARMS)
/**
 * Record a DoorLockAlarm, if the bolt says it is one.
 *
 * The bolt test lives here rather than in the caller because the lock state is
 * this file's, held under the same mutex as everything else in it: a forced
 * door or a door left ajar is only an alarm while the lock is LOCKED, and a
 * sensor cannot know that on its own. An alarm raised while the owner has the
 * lock open is noise, and this node has one report channel to spend.
 *
 * @param alarm_code MATTER_DL_ALARM_*.
 */
void matter_commission_record_alarm(uint8_t alarm_code);
#endif

/*
 * ---- provided by the application -------------------------------------------
 *
 * The two things only the application knows about. Both are called with the
 * node's lock held, so they must be quick and must not call back in.
 */

/**
 * Rebuild the advertising set: offer the 0xFFF6 commissionable service while
 * !matter_commission_has_fabric() || matter_commission_window_open(), and
 * withdraw it otherwise. Called when either of those changes.
 */
void matter_commission_readvertise(void);

/**
 * The Door Lock cluster's LockState changed (MATTER_DL_LOCK_STATE_*). Move the
 * bolt, or whatever stands in for it.
 */
void matter_commission_lock_state(uint8_t lock_state);

#ifdef __cplusplus
}
#endif

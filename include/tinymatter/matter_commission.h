/* SPDX-License-Identifier: ISC */

/**
 * @file matter_commission.h: the node, what the application calls, and the
 *        two hooks it provides.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <tinymatter/matter_clusters.h>
#include <tinymatter/tm_platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Who this node is and how it is commissioned. */
struct matter_commission_config {
	uint16_t vendor_id;
	uint16_t product_id;
	/** SPAKE2+ verifier, hex: w0 (32 B) then L (65 B). From
	 *  scripts/spake2p_verifier.py, with the salt and count below. */
	const char *verifier_hex;
	/** SPAKE2+ salt, hex, 16 to 32 bytes. */
	const char *salt_hex;
	/** PBKDF2 iterations the verifier was derived with. */
	uint32_t iterations;
};

/**
 * Register the commissioning handlers on the 0xFFF6 transport and restore any
 * stored fabric.
 *
 * Call once the BLE transport, storage and crypto are up. @p cfg must outlive
 * the node. Nothing here touches the radio: whether the board is discoverable as a commissionable node is decided
 * by the application's advertising, which asks for the Matter payload while
 * this node holds no fabric -- see matter_commission_has_fabric() and
 * matter_commission_readvertise().
 *
 * @return 0, -EINVAL without a config, or -ENOMEM if a packet pool cannot be
 *         set up. A bad verifier is reported by log and refused per attempt
 *         rather than failing startup.
 */
int matter_commission_init(const struct matter_commission_config *cfg);

/** Run one deferred work item; the port calls this for tm_work_schedule(). */
void matter_commission_work(enum tm_work w);

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

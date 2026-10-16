/* SPDX-License-Identifier: ISC */

/**
 * @file matter_ble_zephyr.h
 * @brief What the Zephyr BLE transport offers the application, beyond the
 *        matter_ble.h seam: the advert payload and the GATT service switch.
 *
 * Only for an application that owns its advertising set. Otherwise
 * matter_ble_advertise() (matter_ble.h) does both.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_ble.h>

#ifdef __cplusplus
extern "C" {
#endif

/** UUID plus ChipBLEDeviceIdentificationInfo: what BT_DATA_SVC_DATA16 carries. */
#define MATTER_BLE_SVC_DATA_LEN 10u

/**
 * Build the commissionable-node service data element.
 *
 * This does NOT start advertising: the application owns the advertising set
 * and asks for these bytes while the node has no fabric.
 *
 * @param out receives MATTER_BLE_SVC_DATA_LEN bytes, caller-owned and required to
 *        outlive the advertisement -- bt_data holds the pointer, not a copy.
 * @return 0 or -EINVAL.
 */
int matter_ble_commissionable_svc_data(uint8_t *out, size_t cap);

/**
 * Put the 0xFFF6 service in the GATT database, or take it out.
 *
 * Call it from whatever decides which advert this node carries, so the table
 * and the advert say the same thing: a node that is not offering to be
 * commissioned must not publish a commissioning service. Idempotent, and cheap
 * enough for the advertising worker to call on every pass.
 *
 * Withdrawal is refused with -EBUSY while a commissioning link is up; the
 * caller is expected to ask again rather than to force it.
 *
 * macOS makes this load-bearing rather than tidy -- see the comment on the
 * service definition.
 *
 * @return 0 on success or no change, -EBUSY if a link is up, or a Zephyr error.
 */
int matter_ble_publish(bool on);

#ifdef __cplusplus
}
#endif

/* SPDX-License-Identifier: ISC */

/**
 * @file matter_ble_zephyr.h — the 0xFFF6 commissioning transport.
 *
 * Everything here is Zephyr-side glue. The protocol lives in
 * the core (src/), which knows nothing about BLE.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A fully reassembled Matter message.
 *
 * Called on the node's own work queue, never in the BLE RX callback, so a
 * handler may take its time. @p msg points into the handler's private
 * reassembly area, may be decrypted in place, and is only valid until the
 * handler returns.
 */
typedef void (*matter_ble_msg_cb)(uint8_t *msg, size_t len);

/*
 * There is no init call. The work queue is started by SYS_INIT at APPLICATION
 * priority, because the GATT service is registered statically and the two must
 * come up together.
 */
void matter_ble_set_msg_handler(matter_ble_msg_cb cb);

/**
 * The link went away and BTP state was thrown out.
 *
 * Anything layered on top has to forget its own state too: a commissioner that
 * drops mid-PASE and reconnects is starting over, and answering its first
 * message from halfway through the old exchange would fail in a way that looks
 * like a protocol bug rather than a dropped link.
 *
 * Called from the Bluetooth callback, so do the cheap thing here and defer real
 * work to the next message.
 */
typedef void (*matter_ble_link_cb)(void);

void matter_ble_set_link_handler(matter_ble_link_cb cb);

/**
 * Completion of a message accepted by matter_ble_send().
 *
 * Exactly one callback follows every send that returned zero: zero after the
 * final indication was confirmed, or a negative status if fragmentation,
 * indication, reset, or disconnect terminated it. Immediate send rejection is
 * returned directly and does not also call this hook.
 */
typedef void (*matter_ble_tx_cb)(int status);

void matter_ble_set_tx_handler(matter_ble_tx_cb cb);

/**
 * Fragment and indicate a Matter message.
 * @p msg is borrowed, not copied, and must remain unchanged until the TX
 * callback fires after a zero return. It may be reused immediately on error.
 * @return 0, -ENOTCONN before the BTP handshake, -EAGAIN if the peer has not
 *         subscribed to C2, -EBUSY while another message is still going out.
 */
int matter_ble_send(const uint8_t *msg, size_t len);

/** UUID plus ChipBLEDeviceIdentificationInfo: what BT_DATA_SVC_DATA16 carries. */
#define MATTER_BLE_SVC_DATA_LEN 10u

/**
 * Build the commissionable-node service data element.
 *
 * This does NOT start advertising, deliberately. The reader owns the single
 * advertising set (the source project's credential BLE port), and it stays that way: Zephyr's legacy
 * bt_le_adv_start API has exactly one set, and the alternative -- CONFIG_BT_EXT_ADV
 * with two sets -- measured +24,844 B of flash and +2,464 B of RAM on this board
 * before either advertiser was rewritten to use it. On a part where CASE and the
 * Interaction Model are still unbuilt, that is not a trade worth making for
 * something the protocol does not ask for: a Matter node advertises as
 * commissionable only while it has no fabric, which is exactly when this reader
 * has nothing to advertise as a credential reader either.
 *
 * So the reader asks for these bytes when it has no identity yet, and stops
 * asking once it has one.
 *
 * @param out receives MATTER_BLE_SVC_DATA_LEN bytes, caller-owned and required to
 *        outlive the advertisement -- bt_data holds the pointer, not a copy.
 * @return 0 or -EINVAL.
 */
int matter_ble_commissionable_svc_data(uint8_t *out, size_t cap);

/** Override the advertised discriminator; 0 restores the built-in one. */
void matter_ble_set_discriminator(uint16_t discriminator);

/** The discriminator currently advertised. */
uint16_t matter_ble_discriminator(void);

/**
 * Put the 0xFFF6 service in the GATT database, or take it out.
 *
 * Call it from whatever decides which advert this node carries, so the table
 * and the advert say the same thing: a node advertising the credential payload
 * is not offering to be commissioned and must not publish a commissioning
 * service. Idempotent, and cheap enough for the advertising worker to call on
 * every pass.
 *
 * Withdrawal is refused with -EBUSY while a commissioning link is up; the
 * caller is expected to ask again rather than to force it.
 *
 * macOS makes this load-bearing rather than tidy -- see the comment on the
 * service definition. Publishing 0xFFF6 costs the board every Web Bluetooth
 * client on that host, SMP firmware updates included.
 *
 * @return 0 on success or no change, -EBUSY if a link is up, or a Zephyr error.
 */
int matter_ble_publish(bool on);

#ifdef __cplusplus
}
#endif

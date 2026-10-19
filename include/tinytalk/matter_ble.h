/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_ble.h
 * @brief The BLE commissioning transport a port provides: BTP over the 0xFFF6
 *        GATT service, carrying whole Matter messages to and from the node.
 *
 * The framing is in the core (matter_btp.h); a port carries C1 writes into it
 * and its fragments out as C2 indications. ports/zephyr/matter_ble_zephyr.c is
 * the reference.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** This contract's version. An adapter in another module BUILD_ASSERTs the
 *  value it was written for, so a change here stops its build. */
#define MATTER_BLE_API 1

/**
 * A fully reassembled Matter message.
 *
 * Called on the node's own work queue, never in the BLE RX callback, so a
 * handler may take its time. @p msg points into the handler's private
 * reassembly area, may be decrypted in place, and is only valid until the
 * handler returns.
 */
typedef void (*matter_ble_msg_cb)(uint8_t *msg, size_t len);

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

/** Override the advertised discriminator; 0 restores the built-in one. */
void matter_ble_set_discriminator(uint16_t discriminator);

/** The discriminator currently advertised. */
uint16_t matter_ble_discriminator(void);

/* ---- provided by the transport, called by the application ----------------
 *
 * Everything above is the node's half of the seam. These two are the
 * application's: it brings the radio up once and decides when the node offers
 * itself for commissioning (while !matter_commission_has_fabric() ||
 * matter_commission_window_open()), and the transport does the rest. Neither
 * takes the node's lock, so matter_commission_readvertise(), which the node
 * calls with its lock held, defers the call to a work item.
 */

/**
 * Bring the BLE controller and host up.
 *
 * Call it before matter_commission_init(). Idempotent: a second call returns
 * zero.
 *
 * @return 0 or a negative errno from the stack.
 */
int matter_ble_start(void);

/**
 * Offer the node for commissioning over BLE, or stop offering it.
 *
 * On: publish the 0xFFF6 service and start the connectable commissionable
 * advert with the current discriminator. Off: stop the advert and withdraw the
 * service. Either way the advert is rebuilt, so call it again after the
 * discriminator changes. A connection stops connectable advertising; the
 * transport repeats the last request once the connection object is free again.
 *
 * @return 0, -EBUSY if the service could not be withdrawn because a
 *         commissioning link holds the connection (the next readvertise
 *         retries), or a negative errno from the stack.
 */
int matter_ble_advertise(bool on);

#ifdef __cplusplus
}
#endif

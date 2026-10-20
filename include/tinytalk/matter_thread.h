/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_thread.h — the seam between a commissioner's dataset and a radio.
 *
 * matter_clusters.c is platform-agnostic C11 and the host suite compiles it
 * without Zephyr, so it cannot call OpenThread. It calls these two instead; the
 * port forwards them to otDatasetSetActiveTlvs() and otThreadGetDeviceRole(),
 * and the host suite substitutes a double whose answers a test can choose.
 *
 * The split into start and wait is deliberate. Apple sends
 * AddOrUpdateThreadNetwork, then ArmFailSafe, then ConnectNetwork, and the
 * attach can begin at the first of those rather than the last -- a Thread
 * attach costs seconds and the round trips in between are free.
 */
/*
 *
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** This contract's version. An adapter in another module BUILD_ASSERTs the
 *  value it was written for, so a change here stops its build. */
#define MATTER_THREAD_API 2

/**
 * Hand @p dataset to the Thread stack and start attaching.
 *
 * @p dataset is raw meshcop TLVs exactly as the commissioner sent them, which
 * is also exactly what otDatasetSetActiveTlvs() consumes -- nothing between
 * here and the radio has to understand the format.
 *
 * Returns as soon as the attach is under way; it does not wait for it.
 *
 * @return MATTER_OK if the stack accepted the dataset, MATTER_E_INVAL if it
 *         rejected it, MATTER_E_STATE if Thread could not be enabled.
 */
int matter_thread_start(const uint8_t *dataset, size_t len);

/**
 * Detach and discard the active Thread dataset.
 *
 * Used only to roll back a first commissioning attempt which applied its
 * candidate network and then expired. A multi-admin attempt never calls this:
 * its candidate must match the already committed network.
 */
int matter_thread_clear(void);

/**
 * Whether this node is ALREADY attached to the network @p xpanid names.
 *
 * Exists for one caller: AddOrUpdateThreadNetwork, which a second administrator
 * sends with the dataset of the network this node is already on. Restarting the
 * stack in that case is not a no-op -- it detaches, costs tens of seconds of
 * re-attach, and takes the BLE commissioning link down with it while the
 * commissioner waits. Answering "already there" lets that restart be skipped.
 *
 * Deliberately asks about the network rather than just "are you attached": a
 * commissioner is entitled to move this node to a DIFFERENT Thread network, and
 * that case must still restart the stack.
 *
 * @param xpanid the Extended PAN ID to compare against, @ref
 *        MATTER_THREAD_XPANID_LEN bytes.
 * @return true only if the node is attached (child, router or leader) AND the
 *         network it is attached to has that Extended PAN ID. False on any
 *         doubt, so the caller falls back to restarting, which is always
 *         correct if slower.
 */
bool matter_thread_attached_to(const uint8_t *xpanid);

/**
 * Wait, bounded, for the node to attach.
 *
 * @param timeout_ms give up after this long. The caller is answering a
 *        commissioner that is blocked on the reply, so this must be shorter
 *        than the ConnectMaxTimeSeconds this node advertises.
 * @return MATTER_OK once attached (child, router or leader), MATTER_E_TIMEOUT
 *         if it never got there. A timeout is a real answer, not an error to
 *         paper over: the commissioner has to be told the node is not on the
 *         network rather than left to discover it by failing to find it.
 */
int matter_thread_wait_attached(uint32_t timeout_ms);

/**
 * The largest datagram this node sends.
 *
 * Set by the ReportData answering a subscription to everything, not by any
 * handshake message: a controller subscribes to the whole data model as soon as
 * it owns the node. Headroom over the report itself covers both headers and the
 * AEAD tag.
 *
 * It was 1664, sized from a 1479 B report measured BEFORE send_report_chunk()
 * existed. Chunking capped every outbound payload at MATTER_IM_PAYLOAD_MAX, so
 * headers + payload + tag can no longer exceed MATTER_MAX_MESSAGE_LEN, and the
 * 432 B above that were buying nothing this node can build. The value is that
 * ceiling; matter_commission.c BUILD_ASSERTs the identity, because the three
 * terms it is derived from live in headers this one does not include.
 *
 * Lowering it does not narrow what gets delivered, only what gets DIAGNOSED. A
 * message between this size and the old 1664 was framed, copied and sent, and
 * then dropped by the network for exceeding the MTU, with nothing logged. It
 * now trips the capacity check in send_framed() and says so.
 */
#define MATTER_THREAD_REPLY_MAX 1232u

/** The port a Matter node listens on operationally (lib/core/CHIPConfig.h:335). */
#define MATTER_OPERATIONAL_PORT 5540u

/*
 * What Apple's border router needs from the SRP functions below, learnt on
 * hardware. A port does the first three itself; the fourth is the
 * application's, with the port's two reset calls.
 *
 *  1. The commissionable record asks a lease of its own, 120 s, not the
 *     operational records' 2 h: a node that loses power with a window open
 *     otherwise leaves a _matterc record that Apple Home dials over Thread
 *     instead of using BLE (7d3fbd5, 2026-10-16). An open window renews it.
 *  2. A record is removed by name. Removing the host, even with its key
 *     lease, does not remove its services: Apple's border router kept one
 *     for over 22 min (74ef5d2, 2026-10-16).
 *  3. The window record's name is persisted while it is registered, and a
 *     record a crash or reset left behind is registered again under that
 *     name and removed at the next boot (74ef5d2, 2026-10-16).
 *  4. Every record is retracted before a factory-reset reboot:
 *     matter_thread_advertise_reset(), then wait while
 *     matter_thread_advertise_pending() (8aba77d, 2026-10-16).
 *
 * Refusing PASE over IP without an open window is the node's job
 * (fcf7890, src/matter_commission.c) and needs nothing from a port.
 */

/**
 * Register this node's operational service so a commissioner can find it.
 *
 * Being ON the Thread network is not the same as being reachable: a
 * commissioner that finished network setup closes BLE and looks the node up in
 * DNS-SD, which on Thread means the border router answering on its behalf. It
 * only can if the node has told it, over SRP, that
 * "<instance>._matter._tcp.local" is at this address and port.
 *
 * @param instance_name "<compressed-fabric-id>-<node-id>", from
 *        matter_fabric_instance_name(). Borrowed for the length of the call.
 * @return MATTER_OK once the registration is under way -- the SRP server's
 *         answer arrives later and asynchronously -- or MATTER_E_STATE.
 */
int matter_thread_advertise(const char *instance_name, uint16_t port);

/**
 * Withdraw one operational service, the counterpart of matter_thread_advertise().
 *
 * Needed by exactly one caller: RemoveFabric. A removed fabric's record
 * otherwise stays on the border router until its lease expires, and a
 * commissioner that resolves it finds a node that answers Sigma1 with
 * "destination matches NO fabric" -- a live address vouching for a dead
 * authority, measured costing 45 s of resolve-then-timeout per attempt on
 * 2026-08-07.
 *
 * @param instance_name the name advertise was called with. Unknown names return
 *        MATTER_OK: the record this exists to withdraw is already not there.
 */
int matter_thread_unadvertise(const char *instance_name);

/**
 * Publish the COMMISSIONABLE service, "_matterc._udp", while a window is open.
 *
 * The operational service above says "this node exists on your fabric". This one
 * says "this node will accept a NEW administrator right now", and they are
 * separate registrations because they are true at different times.
 *
 * Apple Home never needs it: it commissions over BLE, which this node has always
 * advertised. Every other controller browses DNS-SD for
 * "_matterc._udp,_S<short-discriminator>" and gives up when nothing answers,
 * which is what made a second administrator impossible to add from anything but
 * an Apple device.
 *
 * @param discriminator the 12-bit value the window was opened with -- the one
 *        the commissioner CHOSE, not the compile-time default, since that is
 *        what it is browsing for.
 * @param port where PASE will be accepted; the operational port is correct.
 * @return MATTER_OK once the registration is under way, or MATTER_E_STATE.
 */
int matter_thread_advertise_commissionable(uint16_t discriminator, uint16_t port);

/**
 * Withdraw the commissionable service.
 *
 * Leaving it up after the window closes advertises an invitation the node will
 * refuse, so a controller that browses gets a PASE failure rather than an empty
 * result -- the difference between "not offered" and "offered and broken".
 *
 * Safe to call when nothing is registered.
 */
int matter_thread_unadvertise_commissionable(void);

/**
 * Where a subscriber can be reached, kept opaque on purpose.
 *
 * A raw IPv6 address and port rather than an OpenThread type: this header is
 * the portable seam and the host suite builds it without any Thread stack.
 */
struct matter_thread_peer {
	uint8_t addr[16];
	uint16_t port;
	bool valid;
};

/**
 * Snapshot the peer of the datagram being processed right now.
 *
 * Only meaningful inside matter_thread_on_datagram(); outside it there is no
 * "current" datagram and @p out is marked invalid. Kept because a subscription
 * outlives the request that created it, and a report has to go somewhere.
 */
void matter_thread_peer_current(struct matter_thread_peer *out);

/**
 * Send one datagram to @p peer, outside any receive callback.
 *
 * The reply path returns its bytes to the caller and the transport sends them;
 * that cannot express a message this node originates, which is what a
 * subscription report is.
 *
 * @return MATTER_OK, or MATTER_E_STATE when the socket is down or @p peer was
 *         never captured.
 */
int matter_thread_send_to(const struct matter_thread_peer *peer, const uint8_t *msg, size_t len);

/**
 * Release every SRP registration this node holds.
 *
 * Call when the fabrics they name are discarded. A registration outlives the
 * fabric it advertises otherwise, and since the instance name is derived from
 * the fabric and node ids, a NEW commissioner never matches it -- so the table
 * fills with names for fabrics that no longer exist and the next commissioning
 * fails immediately after PASE with nothing to resolve.
 */
void matter_thread_advertise_reset(void);

/**
 * Whether removals started by matter_thread_advertise_reset() are in flight.
 *
 * An application that reboots after a reset, a factory reset above all, waits
 * while this is true, bounded, so the border router hears every removal
 * before the node goes quiet. A port whose reset completes before it returns
 * answers false.
 */
bool matter_thread_advertise_pending(void);

/** How many of the interface's IPv6 addresses General Diagnostics reports. */
#define MATTER_THREAD_IFACE_ADDRS_MAX 4u

/** The Thread interface as General Diagnostics' NetworkInterfaces shows it. */
struct matter_thread_iface {
	/** Attached as child, router or leader. */
	bool attached;
	/** The IEEE 802.15.4 extended address, as HardwareAddress. */
	uint8_t ext_addr[8];
	uint8_t n_addrs;
	uint8_t addrs[MATTER_THREAD_IFACE_ADDRS_MAX][16];
	/** The stack's Thread version, as NetworkCommissioning ThreadVersion
	 *  reports it: 2 for Thread 1.1, 3 for 1.2, 4 for 1.3, 5 for 1.4. */
	uint16_t thread_version;
};

/**
 * Describe the Thread interface. Added in MATTER_THREAD_API 2.
 *
 * Read on every NetworkInterfaces read, so it has to be quick. Unicast
 * addresses only, at most MATTER_THREAD_IFACE_ADDRS_MAX of them.
 *
 * @return MATTER_OK, or MATTER_E_STATE with no Thread stack, @p out zeroed.
 */
int matter_thread_interface(struct matter_thread_iface *out);

/** How many networks NetworkCommissioning's ScanNetworks reports. */
#define MATTER_THREAD_SCAN_MAX 4u

/** One network an active scan heard, as ThreadInterfaceScanResultStruct. */
struct matter_thread_scan_result {
	uint8_t ext_addr[8];
	uint8_t xpanid[8];
	char name[17];
	uint16_t pan_id;
	uint8_t channel;
	uint8_t version;
	int8_t rssi;
	uint8_t lqi;
};

/**
 * Run an IEEE 802.15.4 active scan on every channel and report what answered.
 * Added in MATTER_THREAD_API 2.
 *
 * Blocks until the scan ends, which takes seconds; the caller is answering a
 * ScanNetworks a commissioner is waiting on. Refused with MATTER_E_STATE where
 * blocking would stall the Thread stack itself, its receive callback included.
 *
 * @param out at least @p cap results; @p n receives how many were filled.
 * @return MATTER_OK, or MATTER_E_STATE when no scan could run.
 */
int matter_thread_scan(struct matter_thread_scan_result *out, uint8_t cap, uint8_t *n);

/**
 * Accept one reply while the inbound OpenThread callback is still current.
 * MATTER_OK means the transport accepted ownership; any error means no byte
 * was accepted and the exact owned reply may be retried.
 */
typedef int (*matter_thread_reply_send_fn)(void *ctx, const uint8_t *msg, size_t len);

/**
 * Handle one datagram that arrived on the operational port.
 *
 * Supplied by the application rather than called by it: the datagram arrives on
 * OpenThread's own thread, and the port has no business knowing what a Sigma1
 * is. The reply goes back through @p reply rather than being sent from inside,
 * for the same reason -- sending is the port's job and parsing is not.
 * @p msg is a private copy of the datagram and may be decrypted in place.
 *
 * @p send is invoked synchronously, under the OpenThread-then-Matter lock
 * order, for a non-empty reply. Application effects are committed only when
 * it returns MATTER_OK. A failed reliable reply remains owned and the exact
 * packet is offered again when MRP retransmits the request.
 *
 * @return how many reply bytes @p send accepted, or 0 for no reply/failure.
 */
size_t matter_thread_on_datagram(uint8_t *msg, size_t len, uint8_t *reply, size_t cap,
				 matter_thread_reply_send_fn send, void *send_ctx);

#ifdef __cplusplus
}
#endif

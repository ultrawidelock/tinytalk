/* SPDX-License-Identifier: ISC */

/**
 * @file matter_mrp.h — Message Reliability Protocol: backoff, retransmit, dedup.
 *
 * Matter runs over UDP, so reliability is the application's problem. MRP is the
 * answer: mark a message as needing an acknowledgement, retransmit on an
 * exponential backoff until it is acked, and drop counters you have already
 * seen.
 *
 * Two objects with two different lifetimes, deliberately not merged:
 *   struct matter_mrp_window  per SESSION   — duplicate suppression
 *   struct matter_mrp         per EXCHANGE  — one un-acked message, one owed ack
 *
 * NO TIMERS LIVE HERE. Every entry point takes `now_ms` and the object only
 * computes deadlines, so the caller owns the timer. The backoff applies the
 * MRP_BACKOFF_MARGIN term per Matter Core §4.12.2.1, as CHIP does.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Backoff parameters, Matter Core section 4.11.8, as integer ratios so the
 * schedule needs no floating point. 1127/1024 is CHIP's fixed-point spelling of
 * 1.1 and 16/10 of 1.6; both are exact enough that the two derivations agree to
 * the millisecond floor across every case the suite checks.
 */
#define MATTER_MRP_MARGIN_NUM  1127u
#define MATTER_MRP_MARGIN_DEN  1024u
#define MATTER_MRP_BASE_NUM    16u
#define MATTER_MRP_BASE_DEN    10u
/** Jitter is (JITTER_BASE + rand[0,255]) / JITTER_BASE, i.e. 1.0 .. 1.249. */
#define MATTER_MRP_JITTER_BASE 1024u
/** Retransmissions before the backoff starts growing. */
#define MATTER_MRP_THRESHOLD   1u
/** CHIP caps the exponent here, "reasonable maximum after 5 tries". */
#define MATTER_MRP_MAX_EXP     4u

/** Total transmissions including the first: 1 + CHIP's MAX_RETRANS of 4. */
#define MATTER_MRP_MAX_TRANSMISSIONS 5u

/** Peer retransmit intervals advertised by default (ms). */
#define MATTER_MRP_IDLE_INTERVAL_MS   500u
#define MATTER_MRP_ACTIVE_INTERVAL_MS 300u

/**
 * Grace period to piggyback an ack on a real outbound message before giving up
 * and sending a bare one (ReliableMessageProtocolConfig.h:95, exchange.py:29).
 */
#define MATTER_MRP_STANDALONE_ACK_MS 200u

/**
 * Flat addition to every retransmit deadline on a Thread transport
 * (ReliableMessageProtocolConfig.h:178-184: 1500 ms when CHIP_ENABLE_OPENTHREAD
 * and not Linux, 0 otherwise). It is separate from matter_mrp_backoff_ms()
 * because the spec formula does not contain it -- it is CHIP's allowance for
 * mesh latency, applied where the transport is known. This node is a Thread
 * node, so matter_mrp_arm() adds it.
 */
#define MATTER_MRP_SENDER_BOOST_MS 1500u

/** Counter window width in bits (CHIPConfig.h:309). One uint32_t. */
#define MATTER_MRP_WINDOW_BITS 32u

/**
 * Delay before the n'th retransmission of a message already sent `send_count`
 * times, per Matter Core 4.12.2.1:
 *
 *   i = MRP_BACKOFF_MARGIN * base
 *   t = i * MRP_BACKOFF_BASE^max(0, n - MRP_BACKOFF_THRESHOLD)
 *   t = t * (1.0 + random(0,1) * MRP_BACKOFF_JITTER)
 *
 * @param base_ms    peer's advertised idle or active retransmit interval.
 * @param send_count transmissions ALREADY made, so 1 after the first send. Zero
 *                   is treated as 1; there is no backoff before a first send.
 * @param jitter     one random byte. Pass 0 for a deterministic schedule.
 * @return delay in ms, saturating at UINT32_MAX. Excludes SENDER_BOOST.
 */
uint32_t matter_mrp_backoff_ms(uint32_t base_ms, uint8_t send_count, uint8_t jitter);

/**
 * Longest time from an initial reliable transmission until MRP gives up,
 * using the maximum permitted jitter and the Thread sender allowance for each
 * deadline. The result is bounded below the modular-clock ambiguity point.
 */
uint32_t matter_mrp_retry_horizon_ms(uint32_t base_ms);

/**
 * Replay window over a peer's message counters.
 *
 * `bitmap` bit i records that counter `max_counter - (i + 1)` has been seen, so
 * a message up to MATTER_MRP_WINDOW_BITS behind the high-water mark is still
 * placed exactly. Anything older than that is refused, because there is no
 * longer any evidence either way and accepting is the unsafe guess.
 */
struct matter_mrp_window {
	uint32_t max_counter;
	uint32_t bitmap;
	/** Until the first commit there is no high-water mark to compare against. */
	bool synced;
};

void matter_mrp_window_init(struct matter_mrp_window *w);

/**
 * Test a counter WITHOUT recording it.
 *
 * Split from commit on purpose. The counter is only trustworthy once the
 * message it rode in on has been authenticated, so the caller must check,
 * decrypt, and only then commit. Committing first would let anyone who can put
 * a UDP datagram on the mesh drag `max_counter` forward and lock out the real
 * peer.
 *
 * @return MATTER_OK if new, MATTER_E_DUP if already seen or too old.
 */
int matter_mrp_window_check(const struct matter_mrp_window *w, uint32_t counter);

/** Record an authenticated counter, advancing the window if it is ahead. */
void matter_mrp_window_commit(struct matter_mrp_window *w, uint32_t counter);

/**
 * Per-exchange reliability state.
 *
 * At most ONE un-acked message at a time, which is the protocol's own rule and
 * not a simplification: MRP has no send window, so an exchange with a message
 * in flight must wait (CircuitMatter enforces the same thing at
 * exchange.py:67-68). The exchange layer owns the message bytes; this struct
 * holds only the counter and the deadlines.
 */
struct matter_mrp {
	/** Peer's retransmit interval, idle or active. */
	uint32_t base_ms;
	/** Counter of the message awaiting an ack. */
	uint32_t tx_counter;
	/** Absolute ms deadline for the next retransmission. */
	uint32_t tx_due_ms;
	/** Counter we owe the peer an ack for. */
	uint32_t ack_counter;
	/** Absolute ms deadline to send a standalone ack. */
	uint32_t ack_due_ms;
	uint8_t send_count;
	bool tx_pending;
	bool ack_pending;
};

/** What matter_mrp_poll() says is due now. */
enum matter_mrp_action {
	/** Nothing to do; consult matter_mrp_next_deadline(). */
	MATTER_MRP_IDLE = 0,
	/** Resend the message with counter `counter`, then call matter_mrp_arm(). */
	MATTER_MRP_RETRANSMIT,
	/** Send a bare ack for `counter`; no piggyback opportunity came. */
	MATTER_MRP_SEND_ACK,
	/** Retransmissions exhausted. The exchange is dead; tear it down. */
	MATTER_MRP_GIVE_UP,
};

/*
 * BARELY WIRED UP ON THE DWM3001CDK, AND DELIBERATELY SO. Read this before
 * "fixing" it.
 *
 * The RESPONDER side drives only matter_mrp_window_* -- duplicate suppression
 * and the replay window -- and never arms a retransmit timer. Everything it
 * SENDS is a reply to something the peer just sent, except the subscription
 * report, and the peer retransmits its own requests until it is answered. So
 * the one thing a timer there would add is resending a lost report.
 *
 * The one exception is the Matter CLIENT's handshake
 * (apps/dwm3001cdk-lock/src/matter_client.c in the project this was extracted
 * from, not carried here), which arms a real timer. That is
 * the condition named at the bottom of this note, met: a Sigma1 is originated
 * rather than replied to, and somebody is standing at the door while it goes.
 *
 * Which is exactly what the heartbeat already covers. matter_commission.c
 * re-reports every SUBSCRIPTION_HEARTBEAT_S (120 s) against a max_interval of
 * 600 s, so a lost report costs the subscriber a stale LockState for at most
 * two minutes and never costs it the subscription. Against that: a retransmit
 * timer needs a saved copy of every outstanding message on a part with about
 * 4 KB of RAM left, and it wakes a sleepy end device whose poll period is
 * 3,000 ms to resend a 67-byte report the heartbeat will resend anyway.
 *
 * Wire it up when this node gains something that must arrive PROMPTLY and is
 * not a reply -- an event, or a report whose staleness matters in seconds
 * rather than minutes. Until then the cost is real and the benefit is not.
 *
 * The engine stays because it is tested (tests/host, matter_mrp) and because
 * the ESP32 port and any future initiator need it; it is unused here, not dead.
 */

/** @param base_ms peer's retransmit interval, e.g. MATTER_MRP_ACTIVE_INTERVAL_MS. */
void matter_mrp_init(struct matter_mrp *m, uint32_t base_ms);

/**
 * Register a reliable message as sent and set its retransmit deadline. Call
 * after every transmission of it, the first included: each call bumps
 * send_count, which is what grows the backoff.
 *
 * @return MATTER_OK, or MATTER_E_STATE if a DIFFERENT counter is already in
 *         flight, since MRP permits only one.
 */
int matter_mrp_arm(struct matter_mrp *m, uint32_t counter, uint32_t now_ms, uint8_t jitter);

/**
 * Apply a received acknowledgement.
 * @return MATTER_OK if it cleared the in-flight message, MATTER_E_STATE if
 *         nothing was in flight, MATTER_E_INVAL if it acked a different counter
 *         (stale or forged -- either way the in-flight message stays pending).
 */
int matter_mrp_on_ack(struct matter_mrp *m, uint32_t counter);

/**
 * Note an inbound message that requested an acknowledgement, starting the
 * piggyback grace period.
 */
void matter_mrp_on_reliable_recv(struct matter_mrp *m, uint32_t counter, uint32_t now_ms);

/**
 * Claim the owed ack so an outbound message can carry it, clearing the pending
 * standalone. @return true if there was one, and *counter is set.
 */
bool matter_mrp_take_ack(struct matter_mrp *m, uint32_t *counter);

/**
 * What is due at now_ms.
 * @param counter receives the message counter the action refers to.
 */
enum matter_mrp_action matter_mrp_poll(struct matter_mrp *m, uint32_t now_ms, uint32_t *counter);

/**
 * Deadline of the soonest pending event, for arming one timer.
 * @param out_ms receives an absolute ms deadline, untouched when false.
 * @return false when nothing is pending and no timer is needed.
 */
bool matter_mrp_next_deadline(const struct matter_mrp *m, uint32_t *out_ms);

#ifdef __cplusplus
}
#endif

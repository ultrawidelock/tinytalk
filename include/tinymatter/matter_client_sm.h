/* SPDX-License-Identifier: ISC */

/**
 * @file matter_client_sm.h — when to talk to the bound lock, and when to stop.
 *
 * matter_case_client.h is the handshake; this is what decides to run one. It
 * sits between an unlock that has already been granted locally and a peer that
 * may be resolvable, reachable, both or neither:
 *
 *   want -> resolve -> Sigma1 -> Sigma3 -> ready -> invoke
 *                  \______ failed ______/
 *                             |
 *                          backoff
 *
 * THE RULE THIS EXISTS TO ENFORCE: none of it may delay the local unlock. The
 * bolt on this board is a Wallet notification and an LED, and both have already
 * happened by the time anything here runs. So every entry point returns
 * immediately, nothing blocks, and a peer that is unreachable costs the person
 * at the door nothing at all.
 *
 * Like matter_pase_sm.h, no time or randomness is taken from the environment:
 * every function that could care takes @p now_ms, so the whole schedule --
 * backoff, staleness, the retry horizon -- is testable without a clock.
 *
 * Time is compared as a SIGNED difference throughout. A uint32_t millisecond
 * clock wraps every 49.7 days, and `now >= deadline` is wrong for the tick
 * either side of that; `(int32_t)(now - deadline) >= 0` is right across it.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * How long a granted unlock is still worth sending.
 *
 * NOT a network timeout -- it is a statement about doors. Somebody walked up,
 * the local lock opened, and the bound lock is being told to open too. If that
 * message has not gone out within a few seconds the person is through the door
 * or has given up and left, and a lock that opens by itself half a minute later
 * is a surprise rather than a feature. So a pending want EXPIRES; it is not
 * retried until it succeeds.
 *
 * Retrying the SESSION is a different question and has no such limit: a warm
 * session costs nothing to keep and is the whole reason a second walk-up is
 * instant.
 */
#define MATTER_CLIENT_WANT_TTL_MS 8000u

/** First backoff step, doubling each failure up to the cap below. */
#define MATTER_CLIENT_BACKOFF_MS     1000u
#define MATTER_CLIENT_BACKOFF_MAX_MS 60000u

/**
 * How long to wait for each half of the handshake before calling it failed.
 *
 * Generous, because the peer may be an intermittently connected device that
 * only listens every few hundred milliseconds, and because MRP is doing its own
 * retransmission underneath this. What this timer catches is the case MRP
 * cannot: a peer that acknowledges and then never answers.
 */
#define MATTER_CLIENT_STEP_MS 5000u

/** Where the client is in the sequence above. */
enum matter_client_state {
	/** Nothing is wanted and no session is held. */
	MATTER_CLIENT_IDLE = 0,
	/** The peer's address is not known yet. */
	MATTER_CLIENT_RESOLVING,
	/** Sigma1 is out; waiting for Sigma2. */
	MATTER_CLIENT_SIGMA1,
	/** Sigma3 is out; waiting for the peer to accept it. */
	MATTER_CLIENT_SIGMA3,
	/** A session exists. This is the warm path a second walk-up takes. */
	MATTER_CLIENT_READY,
	/** The last attempt failed; nothing may be sent before the retry time. */
	MATTER_CLIENT_BACKOFF,
};

/** What the caller should do now, having called matter_client_sm_poll(). */
enum matter_client_action {
	/** Nothing, and nothing to wait for either. */
	MATTER_CLIENT_DO_NOTHING = 0,
	/** Look the peer up. Report back with matter_client_sm_resolved(). */
	MATTER_CLIENT_DO_RESOLVE,
	/** Send a Sigma1. */
	MATTER_CLIENT_DO_SIGMA1,
	/** Send a Sigma3. */
	MATTER_CLIENT_DO_SIGMA3,
	/** The session is up and an unlock is still worth sending. */
	MATTER_CLIENT_DO_INVOKE,
};

/** Small enough to keep one per binding entry. */
struct matter_client_sm {
	uint8_t state;
	/** Consecutive failures, for the backoff step. Cleared by a success. */
	uint8_t attempts;
	/** An unlock is pending. Cleared when it is sent, or when it goes stale. */
	bool want;
	/** The peer's address is known. Survives a failed handshake. */
	bool have_peer;
	/** When @ref want was recorded, for MATTER_CLIENT_WANT_TTL_MS. */
	uint32_t want_ms;
	/** When the current wait gives up; meaningless outside a wait state. */
	uint32_t deadline_ms;
	/** Earliest a new attempt may start. Only read in MATTER_CLIENT_BACKOFF. */
	uint32_t retry_ms;
};

/** Idle, no session, no want, no peer. */
void matter_client_sm_init(struct matter_client_sm *sm);

/**
 * An unlock was granted locally and the bound lock should hear about it.
 *
 * Returns immediately, whatever state the client is in -- this is called from
 * the walk-up path. A want arriving while one is already pending REPLACES it:
 * two unlocks a second apart are one intention, not two.
 */
void matter_client_sm_want(struct matter_client_sm *sm, uint32_t now_ms);

/**
 * Is there still a walk-up worth acting on?
 *
 * True while a want is pending AND younger than MATTER_CLIENT_WANT_TTL_MS.
 * Exported because a caller that has just finished a handshake needs to know
 * whether anyone is still waiting for it, and answering that by comparing
 * timestamps at the call site is how the wrap-safe arithmetic in this file
 * gets quietly reimplemented wrongly somewhere else.
 *
 * Pure: it reports the want, it does not drop one. matter_client_sm_poll() is
 * what expires it.
 */
bool matter_client_sm_wants(const struct matter_client_sm *sm, uint32_t now_ms);

/**
 * Advance the clock-driven transitions and say what to do.
 *
 * The state does not move until the caller reports back through one of the
 * functions below, so polling twice without acting asks for the same thing
 * twice. That is deliberate -- a poll that consumed the request would lose it
 * whenever the send it asked for could not be attempted -- and it means the
 * caller must act at most once per action it takes.
 */
enum matter_client_action matter_client_sm_poll(struct matter_client_sm *sm, uint32_t now_ms);

/** The address lookup finished. @p ok false counts as a failed attempt. */
void matter_client_sm_resolved(struct matter_client_sm *sm, bool ok, uint32_t now_ms);

/** A Sigma1 or Sigma3 left this node. Starts that step's deadline. */
void matter_client_sm_sent(struct matter_client_sm *sm, uint32_t now_ms);

/** A Sigma2 arrived and opened. The next poll asks for a Sigma3. */
void matter_client_sm_sigma2(struct matter_client_sm *sm, uint32_t now_ms);

/** The session is up. Clears the backoff, because something worked. */
void matter_client_sm_established(struct matter_client_sm *sm);

/**
 * The invoke was sent. @p ok false means the peer refused it, which is NOT a
 * session failure -- the session is fine and the command was not accepted, so
 * the session is kept and the want is dropped rather than retried into a peer
 * that has already said no.
 */
void matter_client_sm_invoked(struct matter_client_sm *sm, bool ok);

/**
 * The attempt failed: a step timed out, a message was refused, or a primitive
 * gave up. Moves to backoff and doubles the wait.
 */
void matter_client_sm_failed(struct matter_client_sm *sm, uint32_t now_ms);

/**
 * The session is gone -- the peer rebooted, the fabric was removed, or MRP ran
 * out of retransmissions on it.
 *
 * Not a failure by itself: the address is still good and the next want starts a
 * fresh handshake without waiting out a backoff. Losing a session this node was
 * not using is a fact, not an error.
 */
void matter_client_sm_session_lost(struct matter_client_sm *sm);

/**
 * How long until this needs polling again, in milliseconds.
 *
 * 0 means "now"; UINT32_MAX means there is nothing to wait for and no timer
 * needs to run at all -- which is the normal state of a lock nobody is standing
 * in front of, and the reason this does not poll on a tick.
 */
uint32_t matter_client_sm_next_ms(const struct matter_client_sm *sm, uint32_t now_ms);

#ifdef __cplusplus
}
#endif

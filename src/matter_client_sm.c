/* SPDX-License-Identifier: ISC */

/*
 * See matter_client_sm.h.
 */
#include <tinymatter/matter_client_sm.h>

#include <string.h>

/** Has @p now reached @p when? Correct across the 49.7-day wrap; see the header. */
static bool reached(uint32_t now, uint32_t when)
{
	return (int32_t)(now - when) >= 0;
}

/** Milliseconds from @p now until @p when, or 0 if it has already passed. */
static uint32_t until(uint32_t now, uint32_t when)
{
	return reached(now, when) ? 0u : (when - now);
}

/** The backoff for @p attempts consecutive failures, doubling to the cap. */
static uint32_t backoff_ms(uint8_t attempts)
{
	uint32_t ms = MATTER_CLIENT_BACKOFF_MS;

	/* Shifted by a loop rather than by (attempts - 1) so a large attempt
	 * count cannot shift a uint32_t by more than its own width, which is
	 * undefined rather than merely large. */
	for (uint8_t i = 1u; i < attempts; i++) {
		if (ms >= MATTER_CLIENT_BACKOFF_MAX_MS) {
			break;
		}
		ms *= 2u;
	}
	return (ms > MATTER_CLIENT_BACKOFF_MAX_MS) ? MATTER_CLIENT_BACKOFF_MAX_MS : ms;
}

bool matter_client_sm_wants(const struct matter_client_sm *sm, uint32_t now_ms)
{
	return sm != NULL && sm->want &&
	       !reached(now_ms, sm->want_ms + MATTER_CLIENT_WANT_TTL_MS);
}

/** Drop a want that is older than a door can care about. */
static void expire_want(struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm->want && !matter_client_sm_wants(sm, now_ms)) {
		sm->want = false;
	}
}

void matter_client_sm_init(struct matter_client_sm *sm)
{
	if (sm == NULL) {
		return;
	}
	memset(sm, 0, sizeof(*sm));
	sm->state = (uint8_t)MATTER_CLIENT_IDLE;
}

void matter_client_sm_want(struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm == NULL) {
		return;
	}
	/*
	 * The timestamp is refreshed even when a want was already pending: the
	 * person is still at the door, so the reason the TTL exists has not
	 * started running yet.
	 */
	sm->want = true;
	sm->want_ms = now_ms;
}

enum matter_client_action matter_client_sm_poll(struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm == NULL) {
		return MATTER_CLIENT_DO_NOTHING;
	}
	expire_want(sm, now_ms);

	switch ((enum matter_client_state)sm->state) {
	case MATTER_CLIENT_IDLE:
		if (!sm->want) {
			return MATTER_CLIENT_DO_NOTHING;
		}
		if (!sm->have_peer) {
			uint32_t left = until(now_ms, sm->want_ms + MATTER_CLIENT_WANT_TTL_MS);

			sm->state = (uint8_t)MATTER_CLIENT_RESOLVING;
			/*
			 * A LOOKUP MAY NOT OUTLIVE THE WANT THAT ASKED FOR IT.
			 * MATTER_CLIENT_STEP_MS is most of
			 * MATTER_CLIENT_WANT_TTL_MS, so a lookup that answers
			 * nothing used to spend the whole budget and leave no
			 * room for the retry the backoff had already scheduled.
			 * Failing at the want's own edge instead buys two or
			 * three attempts out of one walk-up.
			 *
			 * Only this step is clamped. A handshake past Sigma1
			 * deliberately runs to completion even once the want is
			 * gone (see the header): the session it leaves behind is
			 * what makes the NEXT walk-up instant, and there is no
			 * such prize for a DNS query.
			 */
			sm->deadline_ms = now_ms + (left < MATTER_CLIENT_STEP_MS
							    ? left
							    : MATTER_CLIENT_STEP_MS);
			return MATTER_CLIENT_DO_RESOLVE;
		}
		return MATTER_CLIENT_DO_SIGMA1;

	case MATTER_CLIENT_RESOLVING:
	case MATTER_CLIENT_SIGMA1:
	case MATTER_CLIENT_SIGMA3:
		/*
		 * A step that ran out of time is a failed attempt, even though
		 * nothing said so: the peer may be asleep, gone, or answering
		 * somebody else. Backing off is the only thing left.
		 */
		if (reached(now_ms, sm->deadline_ms)) {
			matter_client_sm_failed(sm, now_ms);
		}
		return MATTER_CLIENT_DO_NOTHING;

	case MATTER_CLIENT_READY:
		return sm->want ? MATTER_CLIENT_DO_INVOKE : MATTER_CLIENT_DO_NOTHING;

	case MATTER_CLIENT_BACKOFF:
		if (!reached(now_ms, sm->retry_ms)) {
			return MATTER_CLIENT_DO_NOTHING;
		}
		/*
		 * The backoff has run out. Whether anything happens now is the
		 * want's business, not the backoff's -- a lock nobody is
		 * standing in front of has no reason to retry a handshake it
		 * only ever wanted for an unlock that has since expired.
		 */
		sm->state = (uint8_t)MATTER_CLIENT_IDLE;
		return matter_client_sm_poll(sm, now_ms);
	}

	return MATTER_CLIENT_DO_NOTHING;
}

void matter_client_sm_resolved(struct matter_client_sm *sm, bool ok, uint32_t now_ms)
{
	if (sm == NULL) {
		return;
	}
	if (!ok) {
		sm->have_peer = false;
		matter_client_sm_failed(sm, now_ms);
		return;
	}
	sm->have_peer = true;
	sm->state = (uint8_t)MATTER_CLIENT_IDLE;
}

void matter_client_sm_sent(struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm == NULL) {
		return;
	}
	/*
	 * Which step this starts is decided by where the client already is, not
	 * by an argument: the caller just did what the last poll asked for, and
	 * a second opinion about which message that was is a second place to be
	 * wrong.
	 */
	if (sm->state == (uint8_t)MATTER_CLIENT_IDLE) {
		sm->state = (uint8_t)MATTER_CLIENT_SIGMA1;
	} else if (sm->state == (uint8_t)MATTER_CLIENT_SIGMA1) {
		sm->state = (uint8_t)MATTER_CLIENT_SIGMA3;
	}
	sm->deadline_ms = now_ms + MATTER_CLIENT_STEP_MS;
}

void matter_client_sm_sigma2(struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm == NULL || sm->state != (uint8_t)MATTER_CLIENT_SIGMA1) {
		return;
	}
	/* Still in SIGMA1 until the Sigma3 goes out; matter_client_sm_sent()
	 * moves it. Extending the deadline is what makes the gap between
	 * opening a Sigma2 and sending the answer not count against the peer. */
	sm->deadline_ms = now_ms + MATTER_CLIENT_STEP_MS;
}

void matter_client_sm_established(struct matter_client_sm *sm)
{
	if (sm == NULL) {
		return;
	}
	sm->state = (uint8_t)MATTER_CLIENT_READY;
	sm->attempts = 0u;
}

void matter_client_sm_invoked(struct matter_client_sm *sm, bool ok)
{
	if (sm == NULL) {
		return;
	}
	/*
	 * The want is cleared either way. A peer that refused the command will
	 * refuse it again -- a missing ACL entry, a PIN it wanted and did not
	 * get -- and hammering it changes nothing except the log. The session
	 * stays: it is good, and the refusal came over it.
	 */
	sm->want = false;
	if (ok) {
		sm->attempts = 0u;
	}
}

void matter_client_sm_failed(struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm == NULL) {
		return;
	}
	if (sm->attempts < UINT8_MAX) {
		sm->attempts++;
	}
	sm->state = (uint8_t)MATTER_CLIENT_BACKOFF;
	sm->retry_ms = now_ms + backoff_ms(sm->attempts);
}

void matter_client_sm_session_lost(struct matter_client_sm *sm)
{
	if (sm == NULL) {
		return;
	}
	/*
	 * Only a session that existed is lost. Calling this while a handshake is
	 * in flight would otherwise cancel the backoff that handshake's failure
	 * is about to set, and turn a peer that is refusing into a peer this
	 * node retries without pause.
	 */
	if (sm->state == (uint8_t)MATTER_CLIENT_READY) {
		sm->state = (uint8_t)MATTER_CLIENT_IDLE;
	}
}

uint32_t matter_client_sm_next_ms(const struct matter_client_sm *sm, uint32_t now_ms)
{
	if (sm == NULL) {
		return UINT32_MAX;
	}

	switch ((enum matter_client_state)sm->state) {
	case MATTER_CLIENT_RESOLVING:
	case MATTER_CLIENT_SIGMA1:
	case MATTER_CLIENT_SIGMA3:
		return until(now_ms, sm->deadline_ms);

	case MATTER_CLIENT_BACKOFF:
		/* No want, no reason to wake for the retry -- but the want may
		 * arrive during the backoff, and then the poll that records it
		 * is the one that needs this deadline. */
		return sm->want ? until(now_ms, sm->retry_ms) : UINT32_MAX;

	case MATTER_CLIENT_IDLE:
	case MATTER_CLIENT_READY:
		/* Work is pending only while a want is, and a want that is not
		 * acted on now is acted on when it expires. */
		return sm->want ? 0u : UINT32_MAX;
	}

	return UINT32_MAX;
}

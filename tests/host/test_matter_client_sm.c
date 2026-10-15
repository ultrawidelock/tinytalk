/**
 * @file test_matter_client_sm.c — the schedule, without a clock.
 *
 * Everything here is a decision about time: how long a granted unlock is still
 * worth sending, how long to wait on each half of a handshake, how long to stay
 * out of the way after a failure. On hardware those are all invisible -- a lock
 * that retries too eagerly and one that gives up too early look identical from
 * the outside, which is a slow bug to find with a board and an easy one to pin
 * here.
 *
 * The state machine takes every timestamp as an argument, so this drives it
 * from a variable rather than a clock and can step over a backoff, a staleness
 * horizon, or the 49.7-day wrap in one line.
 */
#include <stdbool.h>
#include <string.h>

#include <tinymatter/matter_client_sm.h>

#include "test.h"

/** Walk one client from a cold start to a session, checking each step. */
static void handshake(struct matter_client_sm *sm, uint32_t *now)
{
	T_EQ("wants a lookup first", (int)matter_client_sm_poll(sm, *now),
	     (int)MATTER_CLIENT_DO_RESOLVE);
	matter_client_sm_resolved(sm, true, *now);
	T_EQ("then a Sigma1", (int)matter_client_sm_poll(sm, *now), (int)MATTER_CLIENT_DO_SIGMA1);
	matter_client_sm_sent(sm, *now);

	*now += 200u;
	matter_client_sm_sigma2(sm, *now);
	T_EQ("a Sigma3 is the caller's job, not a poll's",
	     (int)matter_client_sm_poll(sm, *now), (int)MATTER_CLIENT_DO_NOTHING);
	matter_client_sm_sent(sm, *now);

	*now += 200u;
	matter_client_sm_established(sm);
}

void test_matter_client_sm(void)
{
	struct matter_client_sm sm;
	uint32_t now;

	t_group("a lock nobody is standing in front of");

	matter_client_sm_init(&sm);
	T_EQ("does nothing", (int)matter_client_sm_poll(&sm, 1000u), (int)MATTER_CLIENT_DO_NOTHING);
	/*
	 * The whole point of the idle state: no timer runs at all. A client that
	 * asked to be polled on a tick would keep this radio awake for a peer
	 * nobody has asked it to talk to.
	 */
	T_OK("and asks for no timer", matter_client_sm_next_ms(&sm, 1000u) == UINT32_MAX);

	t_group("a cold unlock: resolve, handshake, invoke");

	matter_client_sm_init(&sm);
	now = 100000u;
	matter_client_sm_want(&sm, now);
	T_OK("a want asks to be served immediately", matter_client_sm_next_ms(&sm, now) == 0u);

	handshake(&sm, &now);

	T_EQ("and now the unlock goes out", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_INVOKE);
	matter_client_sm_invoked(&sm, true);
	T_EQ("once", (int)matter_client_sm_poll(&sm, now), (int)MATTER_CLIENT_DO_NOTHING);
	T_OK("and the timer stops again", matter_client_sm_next_ms(&sm, now) == UINT32_MAX);

	t_group("the second walk-up, which is the reason the session is kept");

	now += 60000u;
	matter_client_sm_want(&sm, now);
	/*
	 * No resolve, no Sigma1, no Sigma3. This is the difference between an
	 * unlock that lands while the person is reaching for the door and one
	 * that lands after a full CASE handshake.
	 */
	T_EQ("goes straight to the invoke", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_INVOKE);
	matter_client_sm_invoked(&sm, true);

	t_group("a want that nobody could serve in time");

	matter_client_sm_init(&sm);
	now = 5000u;
	matter_client_sm_want(&sm, now);
	T_EQ("asks for a lookup", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_RESOLVE);

	/*
	 * The lookup never answers. Once the want is stale there is nothing left
	 * to do for it -- opening a door half a minute after somebody walked up
	 * is a surprise, not a late success.
	 */
	now += MATTER_CLIENT_WANT_TTL_MS + 1u;
	T_EQ("and then stops trying", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_NOTHING);
	T_OK("with no timer left running", matter_client_sm_next_ms(&sm, now) == UINT32_MAX);

	t_group("a peer that acknowledges and then says nothing");

	matter_client_sm_init(&sm);
	now = 200000u;
	sm.have_peer = true;
	matter_client_sm_want(&sm, now);
	T_EQ("Sigma1 goes out", (int)matter_client_sm_poll(&sm, now), (int)MATTER_CLIENT_DO_SIGMA1);
	matter_client_sm_sent(&sm, now);
	T_OK("and the step deadline is what we wait on",
	     matter_client_sm_next_ms(&sm, now) == MATTER_CLIENT_STEP_MS);

	/* MRP cannot catch this: the peer DID acknowledge, it just never
	 * answered. Only a deadline here notices. */
	now += MATTER_CLIENT_STEP_MS;
	T_EQ("the step times out", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_NOTHING);
	T_EQ("into a backoff", (int)sm.state, (int)MATTER_CLIENT_BACKOFF);
	T_EQ("of one step", (int)sm.attempts, 1);

	t_group("the backoff doubles, and then stops doubling");

	matter_client_sm_init(&sm);
	now = 0u;
	{
		const uint32_t want[] = {1000u, 2000u, 4000u, 8000u, 16000u, 32000u, 60000u, 60000u};

		for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
			matter_client_sm_init(&sm);
			for (size_t f = 0; f <= i; f++) {
				matter_client_sm_failed(&sm, now);
			}
			T_OK("the wait is the doubling one, capped",
			     (sm.retry_ms - now) == want[i]);
		}
	}

	t_group("what a backoff does and does not hold up");

	matter_client_sm_init(&sm);
	now = 300000u;
	sm.have_peer = true;
	matter_client_sm_failed(&sm, now);
	T_OK("with nothing wanted, the retry needs no timer",
	     matter_client_sm_next_ms(&sm, now) == UINT32_MAX);

	matter_client_sm_want(&sm, now);
	T_EQ("a want during the backoff waits it out", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_NOTHING);
	T_OK("and now the retry is worth waking for",
	     matter_client_sm_next_ms(&sm, now) == MATTER_CLIENT_BACKOFF_MS);

	now += MATTER_CLIENT_BACKOFF_MS;
	T_EQ("then tries again", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_SIGMA1);

	t_group("a lookup that fails is not a peer that moved");

	matter_client_sm_init(&sm);
	now = 400000u;
	sm.have_peer = true;
	matter_client_sm_want(&sm, now);
	matter_client_sm_resolved(&sm, false, now);
	T_OK("the address is dropped", !sm.have_peer);
	T_EQ("and it backs off", (int)sm.state, (int)MATTER_CLIENT_BACKOFF);

	t_group("a peer that refuses the command still has a good session");

	matter_client_sm_init(&sm);
	now = 500000u;
	matter_client_sm_want(&sm, now);
	handshake(&sm, &now);
	T_EQ("the invoke goes out", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_INVOKE);

	/*
	 * ACCESS_DENIED for a missing ACL entry is the common case here, and it
	 * will be denied again a second later. Keeping the session and dropping
	 * the want is what stops a misconfigured pair from talking in a loop.
	 */
	matter_client_sm_invoked(&sm, false);
	T_EQ("the session is kept", (int)sm.state, (int)MATTER_CLIENT_READY);
	T_EQ("and the unlock is not retried into it", (int)matter_client_sm_poll(&sm, now),
	     (int)MATTER_CLIENT_DO_NOTHING);

	t_group("losing a session, and losing one that was never there");

	matter_client_sm_init(&sm);
	now = 600000u;
	matter_client_sm_want(&sm, now);
	handshake(&sm, &now);
	matter_client_sm_session_lost(&sm);
	T_EQ("a lost session goes back to the start", (int)sm.state, (int)MATTER_CLIENT_IDLE);
	T_EQ("with no backoff to wait out", (int)sm.attempts, 0);

	/*
	 * Mid-handshake this must do nothing. Clearing the state here would
	 * cancel the backoff the failure is about to set, and a peer that is
	 * refusing would be retried with no pause at all.
	 */
	matter_client_sm_init(&sm);
	sm.have_peer = true;
	matter_client_sm_want(&sm, 700000u);
	(void)matter_client_sm_poll(&sm, 700000u);
	matter_client_sm_sent(&sm, 700000u);
	matter_client_sm_session_lost(&sm);
	T_EQ("a handshake in flight is left alone", (int)sm.state, (int)MATTER_CLIENT_SIGMA1);

	t_group("the 49.7-day wrap, where an unsigned comparison is wrong");

	matter_client_sm_init(&sm);
	now = 0xFFFFFF00u;
	matter_client_sm_want(&sm, now);
	/* The TTL deadline is 0x1D60, a SMALLER number than now. */
	T_EQ("a want made just before the wrap is still fresh after it",
	     (int)matter_client_sm_poll(&sm, 0xFFFFFFFFu), (int)MATTER_CLIENT_DO_RESOLVE);
	T_OK("and its remaining time is not negative",
	     matter_client_sm_next_ms(&sm, 0xFFFFFFFFu) <= MATTER_CLIENT_STEP_MS);

	matter_client_sm_init(&sm);
	now = 0xFFFFFF00u;
	matter_client_sm_want(&sm, now);
	T_EQ("and it does expire on the far side", (int)matter_client_sm_poll(&sm, 0x00002000u),
	     (int)MATTER_CLIENT_DO_NOTHING);

	t_group("a lookup may not outlive the want that asked for it");
	{
		struct matter_client_sm sm;
		uint32_t now = 100000u;

		matter_client_sm_init(&sm);
		matter_client_sm_want(&sm, now);

		/*
		 * The want is already most of the way through its life when the
		 * lookup starts. Before the clamp the step took its full
		 * MATTER_CLIENT_STEP_MS regardless, so a lookup that answered
		 * nothing consumed what was left of the want AND the retry the
		 * backoff had scheduled inside it.
		 */
		now += MATTER_CLIENT_WANT_TTL_MS - 1000u;
		T_EQ("the lookup starts", (int)matter_client_sm_poll(&sm, now),
		     (int)MATTER_CLIENT_DO_RESOLVE);

		/* One second short of the want's own edge: still waiting. */
		now += 999u;
		T_EQ("still waiting just before the want dies",
		     (int)matter_client_sm_poll(&sm, now), (int)MATTER_CLIENT_DO_NOTHING);
		T_EQ("and it has not given up yet", (int)sm.state, (int)MATTER_CLIENT_RESOLVING);

		/* At the edge it gives up, rather than at start + STEP_MS. */
		now += 1u;
		T_EQ("at the want's edge the lookup is abandoned",
		     (int)matter_client_sm_poll(&sm, now), (int)MATTER_CLIENT_DO_NOTHING);
		T_EQ("as a failed attempt", (int)sm.state, (int)MATTER_CLIENT_BACKOFF);
	}

	t_group("a lookup with the whole want ahead of it still gets its full step");
	{
		struct matter_client_sm sm;
		uint32_t now = 100000u;

		matter_client_sm_init(&sm);
		matter_client_sm_want(&sm, now);
		T_EQ("the lookup starts", (int)matter_client_sm_poll(&sm, now),
		     (int)MATTER_CLIENT_DO_RESOLVE);

		now += MATTER_CLIENT_STEP_MS - 1u;
		T_EQ("still waiting", (int)matter_client_sm_poll(&sm, now),
		     (int)MATTER_CLIENT_DO_NOTHING);
		T_EQ("in the lookup", (int)sm.state, (int)MATTER_CLIENT_RESOLVING);

		now += 1u;
		(void)matter_client_sm_poll(&sm, now);
		T_EQ("and gives up on its own step, not early", (int)sm.state,
		     (int)MATTER_CLIENT_BACKOFF);
	}

	t_group("a handshake still outlives its want, and says nothing was unlocked");
	{
		struct matter_client_sm sm;
		uint32_t now = 100000u;

		matter_client_sm_init(&sm);
		matter_client_sm_want(&sm, now);
		matter_client_sm_resolved(&sm, true, now);
		T_EQ("a Sigma1 is asked for", (int)matter_client_sm_poll(&sm, now),
		     (int)MATTER_CLIENT_DO_SIGMA1);
		matter_client_sm_sent(&sm, now);

		/*
		 * The want dies mid-handshake. The handshake is deliberately NOT
		 * abandoned -- the session it leaves behind is what makes the
		 * next walk-up instant -- but nothing may be unlocked for it.
		 */
		now += MATTER_CLIENT_WANT_TTL_MS + 1u;
		T_OK("the want is gone", !matter_client_sm_wants(&sm, now));

		matter_client_sm_sigma2(&sm, now);
		matter_client_sm_sent(&sm, now);
		matter_client_sm_established(&sm);
		T_EQ("the session is up", (int)sm.state, (int)MATTER_CLIENT_READY);
		T_EQ("and nothing is invoked for a want nobody is waiting on",
		     (int)matter_client_sm_poll(&sm, now), (int)MATTER_CLIENT_DO_NOTHING);
		T_EQ("the session is kept for the next walk-up", (int)sm.state,
		     (int)MATTER_CLIENT_READY);

		/* And the next walk-up uses it immediately. */
		matter_client_sm_want(&sm, now);
		T_EQ("which invokes at once", (int)matter_client_sm_poll(&sm, now),
		     (int)MATTER_CLIENT_DO_INVOKE);
	}

	t_group("the want predicate agrees with the poll that expires it");
	{
		struct matter_client_sm sm;
		uint32_t now = 100000u;

		matter_client_sm_init(&sm);
		T_OK("no want, no wanting", !matter_client_sm_wants(&sm, now));
		matter_client_sm_want(&sm, now);
		T_OK("a fresh want is wanted", matter_client_sm_wants(&sm, now));
		T_OK("still wanted one ms before the TTL",
		     matter_client_sm_wants(&sm, now + MATTER_CLIENT_WANT_TTL_MS - 1u));
		T_OK("and not at the TTL itself",
		     !matter_client_sm_wants(&sm, now + MATTER_CLIENT_WANT_TTL_MS));
		T_OK("a NULL wants nothing", !matter_client_sm_wants(NULL, now));
	}

	t_group("nothing here dereferences a NULL");

	matter_client_sm_init(NULL);
	matter_client_sm_want(NULL, 0u);
	matter_client_sm_resolved(NULL, true, 0u);
	matter_client_sm_sent(NULL, 0u);
	matter_client_sm_sigma2(NULL, 0u);
	matter_client_sm_established(NULL);
	matter_client_sm_invoked(NULL, true);
	matter_client_sm_failed(NULL, 0u);
	matter_client_sm_session_lost(NULL);
	T_OK("a NULL is not wanting anything", !matter_client_sm_wants(NULL, 0u));
	T_EQ("a poll without a client does nothing", (int)matter_client_sm_poll(NULL, 0u),
	     (int)MATTER_CLIENT_DO_NOTHING);
	T_OK("and asks for no timer", matter_client_sm_next_ms(NULL, 0u) == UINT32_MAX);
}

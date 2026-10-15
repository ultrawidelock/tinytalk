/**
 * @file test_matter_mrp.c — MRP backoff schedule, replay window, retransmits.
 *
 * The schedule numbers below were NOT read back out of matter_mrp.c. They were
 * derived twice, independently, before the C existed: once from the spec's
 * float formula as CircuitMatter writes it (circuitmatter/exchange.py:117-121)
 * plus the MRP_BACKOFF_MARGIN term CircuitMatter defines and never applies, and
 * once from CHIP's integer arithmetic (ReliableMessageMgr.cpp:268-327). Both
 * derivations agreed to the millisecond floor on all 24 combinations of
 * {500,300} ms base x {1..6} transmissions x {0,255} jitter, and the agreed
 * values are what is pinned here.
 *
 * The centrepiece is "a message nobody answers", which walks the full five
 * transmissions on a fake clock and checks every absolute deadline. That is the
 * subtask's pass criterion: simulated loss produces the correct timing.
 */
#include <string.h>

#include <tinytalk/matter_mrp.h>

#include "test.h"

void test_matter_mrp(void)
{
	struct matter_mrp_window w;
	struct matter_mrp m;
	uint32_t c;

	t_group("backoff: idle base, no jitter");

	/* base 500: 550, 880, 1408, 2252, 3604, then the exponent cap holds it. */
	T_EQ("n=1 is the margined base", matter_mrp_backoff_ms(500u, 1u, 0u), 550L);
	T_EQ("n=2", matter_mrp_backoff_ms(500u, 2u, 0u), 880L);
	T_EQ("n=3", matter_mrp_backoff_ms(500u, 3u, 0u), 1408L);
	T_EQ("n=4", matter_mrp_backoff_ms(500u, 4u, 0u), 2252L);
	T_EQ("n=5", matter_mrp_backoff_ms(500u, 5u, 0u), 3604L);
	T_EQ("n=6 is capped at the n=5 value", matter_mrp_backoff_ms(500u, 6u, 0u), 3604L);
	T_EQ("n=200 is still capped", matter_mrp_backoff_ms(500u, 200u, 0u), 3604L);

	/* n=0 cannot happen from matter_mrp_arm(), but the pure function is public
	 * and must not divide the schedule by a threshold it never reached. */
	T_EQ("n=0 behaves as n=1", matter_mrp_backoff_ms(500u, 0u, 0u), 550L);

	t_group("backoff: active base, no jitter");

	T_EQ("active n=1", matter_mrp_backoff_ms(300u, 1u, 0u), 330L);
	T_EQ("active n=2", matter_mrp_backoff_ms(300u, 2u, 0u), 528L);
	T_EQ("active n=3", matter_mrp_backoff_ms(300u, 3u, 0u), 844L);
	T_EQ("active n=4", matter_mrp_backoff_ms(300u, 4u, 0u), 1351L);
	T_EQ("active n=5", matter_mrp_backoff_ms(300u, 5u, 0u), 2162L);

	t_group("backoff: jitter only ever lengthens");

	/* Full jitter is (1024+255)/1024 = 1.249, so every value grows by ~25%. */
	T_EQ("jittered n=1", matter_mrp_backoff_ms(500u, 1u, 255u), 686L);
	T_EQ("jittered n=2", matter_mrp_backoff_ms(500u, 2u, 255u), 1099L);
	T_EQ("jittered n=3", matter_mrp_backoff_ms(500u, 3u, 255u), 1758L);
	T_EQ("jittered n=4", matter_mrp_backoff_ms(500u, 4u, 255u), 2812L);
	T_EQ("jittered n=5", matter_mrp_backoff_ms(500u, 5u, 255u), 4501L);

	for (unsigned int n = 1u; n <= 6u; n++) {
		uint32_t lo = matter_mrp_backoff_ms(500u, (uint8_t)n, 0u);
		uint32_t hi = matter_mrp_backoff_ms(500u, (uint8_t)n, 255u);

		T_OK("jitter never shortens the wait", hi >= lo);
		T_OK("jitter adds at most 25%", hi <= lo + (lo / 4u) + 1u);
	}

	t_group("backoff: the schedule grows and stays bounded");
	{
		uint32_t prev = 0u;

		for (unsigned int n = 1u; n <= 5u; n++) {
			uint32_t v = matter_mrp_backoff_ms(500u, (uint8_t)n, 0u);

			T_OK("each retry waits longer than the last", v > prev);
			prev = v;
		}
	}

	/* A peer that advertises an absurd interval must not push a deadline past
	 * the point where the wraparound compare can still order it. */
	T_OK("huge base saturates", matter_mrp_backoff_ms(0xFFFFFFFFu, 5u, 255u) == 0x40000000u);
	T_EQ("zero base is zero", matter_mrp_backoff_ms(0u, 3u, 255u), 0L);

	t_group("replay window: nothing seen yet");

	matter_mrp_window_init(&w);
	T_EQ("any counter is new before the first commit", matter_mrp_window_check(&w, 12345u),
	     MATTER_OK);
	matter_mrp_window_commit(&w, 12345u);
	T_EQ("and it is a duplicate afterwards", matter_mrp_window_check(&w, 12345u), MATTER_E_DUP);

	t_group("replay window: inside the bitmap");

	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 100u);
	T_EQ("one behind is new", matter_mrp_window_check(&w, 99u), MATTER_OK);
	matter_mrp_window_commit(&w, 99u);
	T_EQ("one behind is now a duplicate", matter_mrp_window_check(&w, 99u), MATTER_E_DUP);
	T_EQ("its neighbour is unaffected", matter_mrp_window_check(&w, 98u), MATTER_OK);
	T_EQ("the high-water mark stayed put", (long)w.max_counter, 100L);

	/* The window is exactly 32 wide: 32 behind is still remembered, 33 is not. */
	T_EQ("32 behind is inside", matter_mrp_window_check(&w, 68u), MATTER_OK);
	matter_mrp_window_commit(&w, 68u);
	T_EQ("32 behind records", matter_mrp_window_check(&w, 68u), MATTER_E_DUP);
	T_EQ("33 behind is too old to vouch for", matter_mrp_window_check(&w, 67u), MATTER_E_DUP);

	t_group("replay window: sliding forward");

	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 100u);
	matter_mrp_window_commit(&w, 101u);
	T_EQ("new high-water mark", (long)w.max_counter, 101L);
	T_EQ("the old max slid into the bitmap", matter_mrp_window_check(&w, 100u), MATTER_E_DUP);
	T_EQ("the new max is a duplicate too", matter_mrp_window_check(&w, 101u), MATTER_E_DUP);
	T_EQ("ahead of the mark is new", matter_mrp_window_check(&w, 102u), MATTER_OK);

	/* A slide of exactly the window width is the last one that can still place
	 * the old mark, and the one where a naive `bitmap <<= ahead` would shift a
	 * uint32_t by 32 and invoke undefined behaviour. */
	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 100u);
	matter_mrp_window_commit(&w, 132u);
	T_EQ("slid by exactly 32", (long)w.max_counter, 132L);
	T_EQ("the old mark still fits, at the last slot", matter_mrp_window_check(&w, 100u),
	     MATTER_E_DUP);
	T_EQ("one older has fallen off", matter_mrp_window_check(&w, 99u), MATTER_E_DUP);
	T_EQ("the gap is new", matter_mrp_window_check(&w, 101u), MATTER_OK);

	/* One wider and the old mark itself is off the end, so nothing is kept. */
	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 100u);
	matter_mrp_window_commit(&w, 133u);
	T_EQ("slid by 33", (long)w.max_counter, 133L);
	T_EQ("the old mark is gone with the rest", matter_mrp_window_check(&w, 101u), MATTER_OK);

	/* A jump further than the window is wide cannot be described by shifting, so
	 * the bitmap is dropped rather than left claiming things it no longer knows. */
	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 100u);
	matter_mrp_window_commit(&w, 101u);
	matter_mrp_window_commit(&w, 200u);
	T_EQ("big jump takes the mark", (long)w.max_counter, 200L);
	T_EQ("gap members read as new", matter_mrp_window_check(&w, 199u), MATTER_OK);
	T_EQ("the pre-jump history is now too old", matter_mrp_window_check(&w, 100u),
	     MATTER_E_DUP);

	t_group("replay window: counters wrap");

	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 0xFFFFFFFEu);
	T_EQ("across the wrap is still forward", matter_mrp_window_check(&w, 1u), MATTER_OK);
	matter_mrp_window_commit(&w, 1u);
	T_EQ("mark wrapped", (long)w.max_counter, 1L);
	T_EQ("the pre-wrap max is a duplicate", matter_mrp_window_check(&w, 0xFFFFFFFEu),
	     MATTER_E_DUP);
	T_EQ("the skipped wrap value is new", matter_mrp_window_check(&w, 0xFFFFFFFFu), MATTER_OK);

	/* Matter Core 4.5.4.2 splits modulo-2^32 space exactly in half: with the
	 * mark at 1, [2, 0x80000000] is new and 0x80000001 is the first value too
	 * old to have an opinion about. Both sides of that edge are pinned because
	 * it is the only thing standing between a replay and acceptance. */
	T_EQ("the last new counter", matter_mrp_window_check(&w, 0x80000000u), MATTER_OK);
	T_EQ("one past it is refused", matter_mrp_window_check(&w, 0x80000001u), MATTER_E_DUP);

	t_group("replay window: check does not record");

	matter_mrp_window_init(&w);
	matter_mrp_window_commit(&w, 500u);
	T_EQ("check says new", matter_mrp_window_check(&w, 501u), MATTER_OK);
	T_EQ("and says new again", matter_mrp_window_check(&w, 501u), MATTER_OK);
	T_EQ("the mark did not move", (long)w.max_counter, 500L);

	t_group("retransmit: a message nobody answers");
	{
		/* base 500, jitter 0, +1500 ms Thread sender boost per transmission:
		 * 2050, 2380, 2908, 3752, 5104 -> the absolute deadlines below. */
		static const uint32_t due[] = {2050u, 4430u, 7338u, 11090u, 16194u};
		uint32_t now = 0u;

		matter_mrp_init(&m, MATTER_MRP_IDLE_INTERVAL_MS);
		T_EQ("first send", matter_mrp_arm(&m, 0xAA55u, now, 0u), MATTER_OK);

		for (unsigned int i = 0; i < 5u; i++) {
			T_EQ("deadline", (long)m.tx_due_ms, (long)due[i]);
			T_EQ("send count", m.send_count, (long)(i + 1u));

			c = 0u;
			T_EQ("nothing is due one ms early", matter_mrp_poll(&m, due[i] - 1u, &c),
			     MATTER_MRP_IDLE);

			c = 0u;
			if (i < 4u) {
				T_EQ("retransmit is due", matter_mrp_poll(&m, due[i], &c),
				     MATTER_MRP_RETRANSMIT);
				T_EQ("for the right counter", (long)c, 0xAA55L);
				now = due[i];
				T_EQ("re-arm", matter_mrp_arm(&m, 0xAA55u, now, 0u), MATTER_OK);
			} else {
				/* Five transmissions have gone out; the sixth is not
				 * allowed, so the exchange is over. */
				T_EQ("the fifth deadline gives up", matter_mrp_poll(&m, due[i], &c),
				     MATTER_MRP_GIVE_UP);
				T_EQ("naming the abandoned counter", (long)c, 0xAA55L);
			}
		}

		T_EQ("give up is stable", matter_mrp_poll(&m, 99999u, &c), MATTER_MRP_GIVE_UP);
		T_EQ("total transmissions", m.send_count, (long)MATTER_MRP_MAX_TRANSMISSIONS);
		T_EQ("maximum-jitter default retry horizon",
		     (long)matter_mrp_retry_horizon_ms(MATTER_MRP_IDLE_INTERVAL_MS), 18356L);
	}

	t_group("retransmit: an ack ends it");

	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	T_EQ("send", matter_mrp_arm(&m, 7u, 1000u, 0u), MATTER_OK);
	T_EQ("330 + 1500 boost", (long)m.tx_due_ms, 2830L);
	T_EQ("an ack for another counter is refused", matter_mrp_on_ack(&m, 8u), MATTER_E_INVAL);
	T_OK("and leaves the message in flight", m.tx_pending);
	T_EQ("the right ack clears it", matter_mrp_on_ack(&m, 7u), MATTER_OK);
	T_OK("nothing in flight", !m.tx_pending);
	T_EQ("nothing is due any more", matter_mrp_poll(&m, 99999u, &c), MATTER_MRP_IDLE);
	T_EQ("a second ack has nothing to clear", matter_mrp_on_ack(&m, 7u), MATTER_E_STATE);
	T_OK("no deadline to arm a timer for", !matter_mrp_next_deadline(&m, &c));

	/* The backoff restarts from scratch for the next message, rather than
	 * carrying the previous message's send count into it. */
	T_EQ("next message", matter_mrp_arm(&m, 8u, 5000u, 0u), MATTER_OK);
	T_EQ("send count restarted", m.send_count, 1L);
	T_EQ("so does the schedule", (long)m.tx_due_ms, 5000L + 330L + 1500L);

	t_group("retransmit: only one message in flight");

	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	T_EQ("first", matter_mrp_arm(&m, 1u, 0u, 0u), MATTER_OK);
	T_EQ("a second counter is refused", matter_mrp_arm(&m, 2u, 0u, 0u), MATTER_E_STATE);
	T_EQ("the first is untouched", (long)m.tx_counter, 1L);
	T_EQ("send count did not move", m.send_count, 1L);

	t_group("acks: piggyback beats standalone");

	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	T_OK("nothing owed yet", !matter_mrp_take_ack(&m, &c));
	matter_mrp_on_reliable_recv(&m, 42u, 1000u);
	T_EQ("grace period is 200 ms", (long)m.ack_due_ms, 1200L);
	T_EQ("nothing due inside the grace period", matter_mrp_poll(&m, 1199u, &c),
	     MATTER_MRP_IDLE);

	c = 0u;
	T_OK("an outbound message claims the ack", matter_mrp_take_ack(&m, &c));
	T_EQ("for the right counter", (long)c, 42L);
	T_OK("and it is no longer owed", !matter_mrp_take_ack(&m, &c));
	T_EQ("so no standalone goes out", matter_mrp_poll(&m, 99999u, &c), MATTER_MRP_IDLE);

	t_group("acks: standalone when the grace period lapses");

	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	matter_mrp_on_reliable_recv(&m, 42u, 1000u);
	c = 0u;
	T_EQ("standalone at the deadline", matter_mrp_poll(&m, 1200u, &c), MATTER_MRP_SEND_ACK);
	T_EQ("naming the counter", (long)c, 42L);

	/* Cumulative acks: a newer reliable message subsumes the older owed ack and
	 * restarts the grace period from itself. */
	matter_mrp_on_reliable_recv(&m, 43u, 1500u);
	T_EQ("the newer counter replaces it", (long)m.ack_counter, 43L);
	T_EQ("grace restarted", (long)m.ack_due_ms, 1700L);
	T_EQ("and the old deadline no longer fires", matter_mrp_poll(&m, 1699u, &c),
	     MATTER_MRP_IDLE);

	t_group("acks: a retransmission outranks a standalone");

	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	T_EQ("send", matter_mrp_arm(&m, 9u, 0u, 0u), MATTER_OK);
	matter_mrp_on_reliable_recv(&m, 42u, 0u);
	c = 0u;
	T_EQ("both overdue, the resend wins", matter_mrp_poll(&m, 9999u, &c),
	     MATTER_MRP_RETRANSMIT);
	T_EQ("naming the outbound counter", (long)c, 9L);

	t_group("deadlines: one timer, soonest first");

	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	T_OK("idle needs no timer", !matter_mrp_next_deadline(&m, &c));

	T_EQ("send", matter_mrp_arm(&m, 1u, 0u, 0u), MATTER_OK);
	c = 0u;
	T_OK("tx only", matter_mrp_next_deadline(&m, &c));
	T_EQ("is the tx deadline", (long)c, 1830L);

	matter_mrp_on_reliable_recv(&m, 2u, 0u);
	c = 0u;
	T_OK("both pending", matter_mrp_next_deadline(&m, &c));
	T_EQ("the ack at 200 is sooner than the resend at 1830", (long)c, 200L);

	t_group("deadlines: the millisecond clock wraps");
	{
		/* Arming 100 ms before the uint32 wrap must leave a deadline that still
		 * compares as being in the future once the clock has rolled over. */
		uint32_t late = 0xFFFFFFFFu - 100u;

		matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
		T_EQ("send just before the wrap", matter_mrp_arm(&m, 1u, late, 0u), MATTER_OK);
		T_EQ("the deadline wrapped", (long)m.tx_due_ms, (long)(uint32_t)(late + 1830u));
		T_EQ("not due just before the wrap", matter_mrp_poll(&m, 0xFFFFFFF0u, &c),
		     MATTER_MRP_IDLE);
		T_EQ("not due just after the wrap", matter_mrp_poll(&m, 100u, &c), MATTER_MRP_IDLE);
		T_EQ("due past the wrapped deadline", matter_mrp_poll(&m, 1800u, &c),
		     MATTER_MRP_RETRANSMIT);
	}

	t_group("null arguments");

	T_EQ("window check", matter_mrp_window_check(NULL, 0u), MATTER_E_INVAL);
	T_EQ("arm", matter_mrp_arm(NULL, 0u, 0u, 0u), MATTER_E_INVAL);
	T_EQ("ack", matter_mrp_on_ack(NULL, 0u), MATTER_E_INVAL);
	T_EQ("poll", matter_mrp_poll(NULL, 0u, &c), MATTER_MRP_IDLE);
	T_OK("take ack", !matter_mrp_take_ack(NULL, &c));
	T_OK("next deadline", !matter_mrp_next_deadline(NULL, &c));

	/* Every out-parameter is optional; the callers that only want the action or
	 * only want to clear state should not have to invent a variable. */
	matter_mrp_init(&m, MATTER_MRP_ACTIVE_INTERVAL_MS);
	matter_mrp_on_reliable_recv(&m, 5u, 0u);
	T_OK("take ack without an out-parameter", matter_mrp_take_ack(&m, NULL));
	T_EQ("poll without an out-parameter", matter_mrp_poll(&m, 0u, NULL), MATTER_MRP_IDLE);
	T_OK("next deadline without an out-parameter", !matter_mrp_next_deadline(&m, NULL));
	matter_mrp_window_init(NULL);
	matter_mrp_window_commit(NULL, 0u);
	matter_mrp_init(NULL, 0u);
	matter_mrp_on_reliable_recv(NULL, 0u, 0u);
	T_OK("null writes survive", 1);
}

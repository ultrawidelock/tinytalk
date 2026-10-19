/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_mrp.c — MRP backoff schedule, retransmit state, replay window.
 */
/*
 * Two things here are easy to get subtly wrong and are therefore spelled out.
 *
 * TIME IS MODULAR. Deadlines are absolute uint32 milliseconds and the clock
 * wraps every 49.7 days, so a deadline is never compared with `<`. Every
 * comparison goes through elapsed(), which subtracts and reads the result as
 * signed -- the standard time_after() idiom. It is correct only while the
 * interval stays under 2^31 ms, which is why the schedule clamps at
 * MATTER_MRP_MAX_DELAY_MS rather than letting a peer-advertised interval push a
 * deadline past the point where "later" stops being distinguishable from
 * "earlier".
 *
 * ARITHMETIC IS 64-BIT. base_ms is peer-supplied and the schedule multiplies it
 * by 1127 and then by 65536; in 32 bits that overflows for any base above about
 * 58 ms, which is to say almost always. The intermediate is uint64_t and the
 * result saturates.
 */
#include <tinytalk/matter_mrp.h>

/**
 * Ceiling on any single delay.
 *
 * Not a tuning knob: elapsed() can only order two instants that are less than
 * 2^31 ms apart, so a deadline further out than that would compare as being in
 * the past and fire immediately, in a loop. 2^30 ms is 12.4 days, which is far
 * above any legitimate value -- the largest idle interval the spec permits is
 * one hour, which schedules a worst case near 9 hours -- and far below the
 * point where the ordering breaks.
 */
#define MATTER_MRP_MAX_DELAY_MS 0x40000000u

/**
 * Counters up to this far ahead of the high-water mark are new; beyond it they
 * are read as very old and refused. Matter Core 4.5.4.2, quoted in CHIP's
 * transport/PeerMessageCounter.h:230-235 and implemented at :239.
 */
#define MATTER_MRP_FUTURE_LIMIT 0x7FFFFFFFu

/** Milliseconds from `since` to `now`, correct across the uint32 wrap. */
static int32_t elapsed(uint32_t now, uint32_t since)
{
	return (int32_t)(now - since);
}

/** True when `now` has reached or passed `deadline`. */
static bool reached(uint32_t now, uint32_t deadline)
{
	return elapsed(now, deadline) >= 0;
}

/**
 * Compute the MRP backoff delay in milliseconds given a base interval, send count, and random
 * jitter, applying exponential backoff with saturation at the protocol maximum.
 */
uint32_t matter_mrp_backoff_ms(uint32_t base_ms, uint8_t send_count, uint8_t jitter)
{
	uint64_t t;
	uint64_t num = 1u;
	uint64_t den = 1u;
	unsigned int exponent;
	unsigned int n = (send_count == 0u) ? 1u : (unsigned int)send_count;

	/* i = MRP_BACKOFF_MARGIN * base */
	t = ((uint64_t)base_ms * MATTER_MRP_MARGIN_NUM) / MATTER_MRP_MARGIN_DEN;

	/* max(0, n - MRP_BACKOFF_THRESHOLD), capped as CHIP caps it. */
	exponent = (n > MATTER_MRP_THRESHOLD) ? (n - MATTER_MRP_THRESHOLD) : 0u;
	if (exponent > MATTER_MRP_MAX_EXP) {
		exponent = MATTER_MRP_MAX_EXP;
	}

	/* Accumulate the ratio before dividing: 16^e/10^e in one step, not e
	 * roundings, so this matches the float form to the millisecond floor. */
	for (unsigned int i = 0; i < exponent; i++) {
		num *= MATTER_MRP_BASE_NUM;
		den *= MATTER_MRP_BASE_DEN;
	}
	t = (t * num) / den;

	/* t *= 1.0 + random(0,1) * MRP_BACKOFF_JITTER */
	t = (t * (MATTER_MRP_JITTER_BASE + (uint64_t)jitter)) / MATTER_MRP_JITTER_BASE;

	if (t > MATTER_MRP_MAX_DELAY_MS) {
		t = MATTER_MRP_MAX_DELAY_MS;
	}
	return (uint32_t)t;
}

uint32_t matter_mrp_retry_horizon_ms(uint32_t base_ms)
{
	uint64_t horizon = 0u;

	for (uint8_t send_count = 1u; send_count <= MATTER_MRP_MAX_TRANSMISSIONS;
	     send_count++) {
		uint64_t delay =
			(uint64_t)matter_mrp_backoff_ms(base_ms, send_count, UINT8_MAX) +
			MATTER_MRP_SENDER_BOOST_MS;

		if (delay > MATTER_MRP_MAX_DELAY_MS) {
			delay = MATTER_MRP_MAX_DELAY_MS;
		}
		horizon += delay;
		if (horizon >= MATTER_MRP_MAX_DELAY_MS) {
			return MATTER_MRP_MAX_DELAY_MS;
		}
	}
	return (uint32_t)horizon;
}

/**
 * Initialize an MRP replay detection window to accept the first message.
 */
void matter_mrp_window_init(struct matter_mrp_window *w)
{
	if (w == NULL) {
		return;
	}
	w->max_counter = 0u;
	w->bitmap = 0u;
	w->synced = false;
}

/**
 * Check whether a message counter is a replay, a new message, or too old to verify against the
 * sliding window; does not update the window.
 */
int matter_mrp_window_check(const struct matter_mrp_window *w, uint32_t counter)
{
	uint32_t behind;

	if (w == NULL) {
		return MATTER_E_INVAL;
	}
	/* No high-water mark yet, so nothing can be a replay of anything. */
	if (!w->synced) {
		return MATTER_OK;
	}

	behind = w->max_counter - counter;
	if (behind == 0u) {
		return MATTER_E_DUP; /* the high-water mark itself */
	}
	if (behind <= MATTER_MRP_WINDOW_BITS) {
		uint32_t bit = 1u << (behind - 1u);

		return ((w->bitmap & bit) != 0u) ? MATTER_E_DUP : MATTER_OK;
	}
	/* Outside the bitmap. In modulo-2^32 the only available signal is which
	 * way round the gap is shorter, so anything within 2^31-1 ahead counts as
	 * new and everything else as too old to vouch for. */
	if ((counter - w->max_counter) <= MATTER_MRP_FUTURE_LIMIT) {
		return MATTER_OK;
	}
	return MATTER_E_DUP;
}

/**
 * Update the sliding window to mark a message counter as seen and advance the high-water mark;
 * handles wrapping and slide-off of old counters.
 */
void matter_mrp_window_commit(struct matter_mrp_window *w, uint32_t counter)
{
	uint32_t ahead;
	uint32_t behind;

	if (w == NULL) {
		return;
	}
	if (!w->synced) {
		w->max_counter = counter;
		w->bitmap = 0u;
		w->synced = true;
		return;
	}

	behind = w->max_counter - counter;
	if (behind == 0u) {
		return; /* already the high-water mark */
	}
	if (behind <= MATTER_MRP_WINDOW_BITS) {
		w->bitmap |= 1u << (behind - 1u);
		return;
	}

	/* A new high-water mark. Everything the window used to describe slides
	 * further into the past by `ahead`; what falls off the end is forgotten,
	 * and the old max becomes an ordinary set bit.
	 *
	 * The >= is not an off-by-one: shifting a uint32_t by 32 or more is
	 * undefined in C, and a slide that wide keeps nothing anyway. CHIP gets the
	 * same answer for free because std::bitset defines the wide shift as zero
	 * (PeerMessageCounter.h:354-362); in plain C it has to be said out loud. */
	ahead = counter - w->max_counter;
	if (ahead >= MATTER_MRP_WINDOW_BITS) {
		w->bitmap = 0u;
	} else {
		w->bitmap <<= ahead;
	}
	/* The old mark itself is exactly `ahead` behind, so it still fits at the
	 * last slot when the slide is exactly the window width. */
	if (ahead <= MATTER_MRP_WINDOW_BITS) {
		w->bitmap |= 1u << (ahead - 1u);
	}
	w->max_counter = counter;
}

/**
 * Initialize an MRP state machine with a base retransmission interval in milliseconds.
 */
void matter_mrp_init(struct matter_mrp *m, uint32_t base_ms)
{
	if (m == NULL) {
		return;
	}
	m->base_ms = base_ms;
	m->tx_counter = 0u;
	m->tx_due_ms = 0u;
	m->ack_counter = 0u;
	m->ack_due_ms = 0u;
	m->send_count = 0u;
	m->tx_pending = false;
	m->ack_pending = false;
}

/**
 * Arm MRP transmission tracking for a datagram counter: record the counter and send count, compute
 * the backoff delay with SENDER_BOOST, and store the time due.
 */
int matter_mrp_arm(struct matter_mrp *m, uint32_t counter, uint32_t now_ms, uint8_t jitter)
{
	uint64_t delay;

	if (m == NULL) {
		return MATTER_E_INVAL;
	}
	if (m->tx_pending && m->tx_counter != counter) {
		return MATTER_E_STATE;
	}
	if (!m->tx_pending) {
		m->tx_counter = counter;
		m->send_count = 0u;
		m->tx_pending = true;
	}
	if (m->send_count < UINT8_MAX) {
		m->send_count++;
	}

	/* SENDER_BOOST is added here rather than inside the schedule: it is a
	 * transport allowance, not part of the spec formula, and this is the layer
	 * that knows the transport is Thread. */
	delay = (uint64_t)matter_mrp_backoff_ms(m->base_ms, m->send_count, jitter) +
		MATTER_MRP_SENDER_BOOST_MS;
	if (delay > MATTER_MRP_MAX_DELAY_MS) {
		delay = MATTER_MRP_MAX_DELAY_MS;
	}
	m->tx_due_ms = now_ms + (uint32_t)delay;
	return MATTER_OK;
}

/**
 * Mark an in-flight message as acknowledged if the counter matches; returns MATTER_E_STATE if no
 * message is pending or MATTER_E_INVAL if the counter does not match.
 */
int matter_mrp_on_ack(struct matter_mrp *m, uint32_t counter)
{
	if (m == NULL) {
		return MATTER_E_INVAL;
	}
	if (!m->tx_pending) {
		return MATTER_E_STATE;
	}
	/* An ack naming a counter we are not waiting on is stale or forged. Either
	 * way the in-flight message stays in flight; dropping it on an unmatched
	 * ack is how a replayed datagram cancels a real retransmission. */
	if (m->tx_counter != counter) {
		return MATTER_E_INVAL;
	}
	m->tx_pending = false;
	m->send_count = 0u;
	return MATTER_OK;
}

/**
 * Record receipt of a reliable message and arm the standalone acknowledgment timeout; a second
 * reliable message before the first ack goes out replaces the owed counter.
 */
void matter_mrp_on_reliable_recv(struct matter_mrp *m, uint32_t counter, uint32_t now_ms)
{
	if (m == NULL) {
		return;
	}
	/* A second reliable message before the first ack went out replaces the owed
	 * counter: MRP acks are cumulative, so the newer one subsumes the older,
	 * and the grace period restarts from this message. */
	m->ack_counter = counter;
	m->ack_due_ms = now_ms + MATTER_MRP_STANDALONE_ACK_MS;
	m->ack_pending = true;
}

/**
 * Retrieve and clear the pending acknowledgment counter if one is due; returns false if no
 * acknowledgment is pending.
 */
bool matter_mrp_take_ack(struct matter_mrp *m, uint32_t *counter)
{
	if (m == NULL || !m->ack_pending) {
		return false;
	}
	if (counter != NULL) {
		*counter = m->ack_counter;
	}
	m->ack_pending = false;
	return true;
}

/**
 * Poll for the next MRP action to take: retransmit a message, send a standalone acknowledgment, or
 * remain idle; returns MATTER_MRP_GIVE_UP if max retransmissions reached.
 */
enum matter_mrp_action matter_mrp_poll(struct matter_mrp *m, uint32_t now_ms, uint32_t *counter)
{
	if (m == NULL) {
		return MATTER_MRP_IDLE;
	}

	/* Retransmission outranks a standalone ack, because the retransmitted
	 * message can carry the ack and the standalone would then be redundant. */
	if (m->tx_pending && reached(now_ms, m->tx_due_ms)) {
		if (counter != NULL) {
			*counter = m->tx_counter;
		}
		if (m->send_count >= MATTER_MRP_MAX_TRANSMISSIONS) {
			return MATTER_MRP_GIVE_UP;
		}
		return MATTER_MRP_RETRANSMIT;
	}
	if (m->ack_pending && reached(now_ms, m->ack_due_ms)) {
		if (counter != NULL) {
			*counter = m->ack_counter;
		}
		return MATTER_MRP_SEND_ACK;
	}
	return MATTER_MRP_IDLE;
}

/**
 * Return the next MRP deadline and whether any retransmission or acknowledgment is pending; used to
 * schedule the next poll.
 */
bool matter_mrp_next_deadline(const struct matter_mrp *m, uint32_t *out_ms)
{
	uint32_t best;

	if (m == NULL) {
		return false;
	}
	if (m->tx_pending && m->ack_pending) {
		best = (elapsed(m->ack_due_ms, m->tx_due_ms) < 0) ? m->ack_due_ms : m->tx_due_ms;
	} else if (m->tx_pending) {
		best = m->tx_due_ms;
	} else if (m->ack_pending) {
		best = m->ack_due_ms;
	} else {
		return false;
	}

	if (out_ms != NULL) {
		*out_ms = best;
	}
	return true;
}

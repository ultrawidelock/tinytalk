/* SPDX-License-Identifier: ISC */

/**
 * @file matter_btp.c — BTP handshake codec, fragmenter and reassembler.
 */
/*
 * The reassembler is where a peer gets to drive this node's memory, so two
 * things are settled before any copying happens: the declared total length is
 * checked against the caller's buffer at the Start fragment, and every
 * subsequent fragment is checked against what remains. A fragment that would
 * overrun is refused rather than clamped, because silently keeping a prefix of
 * a message is worse than dropping the connection.
 *
 * Sequence numbers are strict: a fragment must carry exactly the number
 * expected. BTP has no reordering and no gap recovery, so a mismatch means the
 * two sides disagree about the stream and the only safe move is to stop.
 */
#include <string.h>

#include <tinymatter/matter_btp.h>

/** ATT notification overhead: opcode + handle (BtpEngine.cpp:69). */
#define ATT_OVERHEAD 3u

/**
 * Read a little-endian 16-bit unsigned integer from the buffer.
 */
static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/**
 * Write a little-endian 16-bit unsigned integer to the buffer.
 */
static void wr16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

/**
 * Decode a Matter BTP handshake request from a buffer: extract protocol versions (8 4-bit slots
 * across 4 bytes), MTU, and window size. Returns MATTER_OK on success, MATTER_E_INVAL if header
 * check fails, MATTER_E_TRUNC if buffer is too short.
 */
int matter_btp_req_decode(const uint8_t *buf, size_t len, struct matter_btp_handshake_req *out)
{
	if (buf == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (len < MATTER_BTP_REQ_LEN) {
		return MATTER_E_TRUNC;
	}
	if (buf[0] != MATTER_BTP_CHECK_1 || buf[1] != MATTER_BTP_CHECK_2) {
		return MATTER_E_INVAL;
	}

	memset(out, 0, sizeof(*out));
	/* Eight 4-bit slots across four bytes, even index in the low nibble
	 * (BleLayer.cpp SetSupportedProtocolVersion). */
	for (size_t i = 0; i < MATTER_BTP_VERSION_SLOTS; i++) {
		uint8_t byte = buf[2u + (i / 2u)];

		out->versions[i] =
			((i % 2u) == 0u) ? (uint8_t)(byte & 0x0Fu) : (uint8_t)((byte >> 4) & 0x0Fu);
	}
	out->mtu = rd16(&buf[6]);
	out->window_size = buf[8];
	return MATTER_OK;
}

/**
 * Encode a Matter BTP handshake request into a buffer: write header check bytes, 8 protocol
 * versions (4-bit slots, even indices in low nibble), MTU, and window size. Returns MATTER_OK on
 * success, MATTER_E_NOSPACE if buffer capacity is insufficient.
 */
int matter_btp_req_encode(const struct matter_btp_handshake_req *r, uint8_t *buf, size_t cap,
			  size_t *written)
{
	if (r == NULL || buf == NULL) {
		return MATTER_E_INVAL;
	}
	if (cap < MATTER_BTP_REQ_LEN) {
		return MATTER_E_NOSPACE;
	}

	buf[0] = MATTER_BTP_CHECK_1;
	buf[1] = MATTER_BTP_CHECK_2;
	memset(&buf[2], 0, 4u);
	for (size_t i = 0; i < MATTER_BTP_VERSION_SLOTS; i++) {
		uint8_t v = (uint8_t)(r->versions[i] & 0x0Fu);

		if ((i % 2u) == 0u) {
			buf[2u + (i / 2u)] |= v;
		} else {
			buf[2u + (i / 2u)] |= (uint8_t)(v << 4);
		}
	}
	wr16(&buf[6], r->mtu);
	buf[8] = r->window_size;

	if (written != NULL) {
		*written = MATTER_BTP_REQ_LEN;
	}
	return MATTER_OK;
}

/**
 * Decode a Matter BTP handshake response from a buffer: extract selected version, fragment size,
 * and window size. Returns MATTER_OK on success, MATTER_E_INVAL if header check fails,
 * MATTER_E_TRUNC if buffer is too short.
 */
int matter_btp_resp_decode(const uint8_t *buf, size_t len, struct matter_btp_handshake_resp *out)
{
	if (buf == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	if (len < MATTER_BTP_RESP_LEN) {
		return MATTER_E_TRUNC;
	}
	if (buf[0] != MATTER_BTP_CHECK_1 || buf[1] != MATTER_BTP_CHECK_2) {
		return MATTER_E_INVAL;
	}

	out->version = buf[2];
	out->fragment_size = rd16(&buf[3]);
	out->window_size = buf[5];
	return MATTER_OK;
}

/**
 * Encode a Matter BTP handshake response into a buffer: write header check bytes, selected version,
 * fragment size, and window size. Returns MATTER_OK on success, MATTER_E_NOSPACE if buffer capacity
 * is insufficient.
 */
int matter_btp_resp_encode(const struct matter_btp_handshake_resp *r, uint8_t *buf, size_t cap,
			   size_t *written)
{
	if (r == NULL || buf == NULL) {
		return MATTER_E_INVAL;
	}
	if (cap < MATTER_BTP_RESP_LEN) {
		return MATTER_E_NOSPACE;
	}

	buf[0] = MATTER_BTP_CHECK_1;
	buf[1] = MATTER_BTP_CHECK_2;
	buf[2] = r->version;
	wr16(&buf[3], r->fragment_size);
	buf[5] = r->window_size;

	if (written != NULL) {
		*written = MATTER_BTP_RESP_LEN;
	}
	return MATTER_OK;
}

/**
 * Accept a BLE transport handshake request and produce a response. Negotiate the highest mutually
 * supported BTP version (V4), derive the fragment size from both MTU values (clamped to min/max
 * bounds), and use the minimum window size from both sides. Return MATTER_E_INVAL if pointers are
 * null, MATTER_E_TYPE if no common version exists, MATTER_OK on success.
 */
int matter_btp_accept(const struct matter_btp_handshake_req *req, uint16_t local_att_mtu,
		      uint8_t local_window, struct matter_btp_handshake_resp *out)
{
	uint16_t fragment;
	bool supported = false;

	if (req == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}

	/* Only V4 exists, so "highest mutually supported" is a search for it. A
	 * zero slot ends the list, and slots after it are not examined. */
	for (size_t i = 0; i < MATTER_BTP_VERSION_SLOTS; i++) {
		if (req->versions[i] == 0u) {
			break;
		}
		if (req->versions[i] == MATTER_BTP_VERSION) {
			supported = true;
			break;
		}
	}
	if (!supported) {
		return MATTER_E_TYPE;
	}

	/* A central that could not read its own MTU sends 0; the floor applies
	 * either way (BleLayer.h:132). */
	fragment = MATTER_BTP_MIN_FRAGMENT;
	if (req->mtu > ATT_OVERHEAD && (uint16_t)(req->mtu - ATT_OVERHEAD) > fragment) {
		fragment = (uint16_t)(req->mtu - ATT_OVERHEAD);
	}
	if (local_att_mtu > ATT_OVERHEAD) {
		uint16_t local = (uint16_t)(local_att_mtu - ATT_OVERHEAD);

		if (local < fragment) {
			fragment = local;
		}
	}
	if (fragment > MATTER_BTP_MAX_FRAGMENT) {
		fragment = MATTER_BTP_MAX_FRAGMENT;
	}
	if (fragment < MATTER_BTP_MIN_FRAGMENT) {
		fragment = MATTER_BTP_MIN_FRAGMENT;
	}

	out->version = MATTER_BTP_VERSION;
	out->fragment_size = fragment;
	out->window_size = (req->window_size < local_window) ? req->window_size : local_window;
	return MATTER_OK;
}

/**
 * Initialize a BTP RX reassembler: clear state, set buffer and capacity, mark idle, and set the
 * expected first sequence number.
 */
void matter_btp_rx_init(struct matter_btp_rx *rx, uint8_t *buf, size_t cap, uint8_t first_seq)
{
	if (rx == NULL) {
		return;
	}
	memset(rx, 0, sizeof(*rx));
	rx->buf = buf;
	rx->cap = cap;
	rx->state = MATTER_BTP_IDLE;
	rx->next_seq = first_seq;
}

/**
 * Reset a BTP RX reassembler for the next message: clear buffered data and state flags, but
 * preserve sequence numbers (they belong to the connection, not the message).
 */
void matter_btp_rx_reset(struct matter_btp_rx *rx)
{
	if (rx == NULL) {
		return;
	}
	/* Sequence numbers survive a reset: they belong to the connection, not to
	 * the message that just finished. */
	rx->len = 0u;
	rx->declared = 0u;
	rx->state = MATTER_BTP_IDLE;
	rx->got_ack = false;
}

/**
 * Process an incoming BTP fragment: validate sequence number, extract flags and optional ACK,
 * accumulate payload across fragments, and detect message completion. Enforces strict ordering (no
 * reordering or gaps), prevents receiver restart mid-message, and caps total payload against
 * declared length. Returns MATTER_OK on continuation, MATTER_END on completion, MATTER_E_STATE on
 * sequence error or mid-message restart, MATTER_E_TRUNC on truncation, MATTER_E_NOSPACE on buffer
 * overflow.
 */
int matter_btp_rx_fragment(struct matter_btp_rx *rx, const uint8_t *frag, size_t len)
{
	size_t off = 0u;
	uint8_t flags;
	uint8_t seq;
	size_t payload;

	if (rx == NULL || frag == NULL) {
		return MATTER_E_INVAL;
	}
	if (rx->state == MATTER_BTP_ERROR) {
		return MATTER_E_STATE;
	}
	if (len < 1u) {
		rx->state = MATTER_BTP_ERROR;
		return MATTER_E_TRUNC;
	}

	flags = frag[off++];
	rx->got_ack = false;

	if ((flags & MATTER_BTP_FLAG_ACK) != 0u) {
		if (len < off + 1u) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_TRUNC;
		}
		rx->ack = frag[off++];
		rx->got_ack = true;
	}

	if (len < off + 1u) {
		rx->state = MATTER_BTP_ERROR;
		return MATTER_E_TRUNC;
	}
	seq = frag[off++];

	/* No reordering, no gap recovery: the number must be exactly the next one
	 * (BtpEngine.cpp:262). */
	if (seq != rx->next_seq) {
		rx->state = MATTER_BTP_ERROR;
		return MATTER_E_STATE;
	}
	rx->last_seq = seq;
	rx->next_seq++;

	/* A fragment with no data flags is a standalone ack and ends here. */
	if ((flags & (MATTER_BTP_FLAG_START | MATTER_BTP_FLAG_CONTINUE | MATTER_BTP_FLAG_END)) ==
	    0u) {
		return MATTER_OK;
	}

	if (rx->state == MATTER_BTP_IDLE) {
		if ((flags & MATTER_BTP_FLAG_START) == 0u) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_STATE;
		}
		if (len < off + 2u) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_TRUNC;
		}
		rx->declared = rd16(&frag[off]);
		off += 2u;

		/* Settle the whole message against our buffer before copying a byte,
		 * so the peer cannot pick how much of it we hold. */
		if ((size_t)rx->declared > rx->cap) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_NOSPACE;
		}
		rx->len = 0u;
		rx->state = MATTER_BTP_IN_PROGRESS;
	} else if (rx->state == MATTER_BTP_IN_PROGRESS) {
		/* Start mid-message means the sender restarted without telling us
		 * (BtpEngine.cpp:318-322). */
		if ((flags & MATTER_BTP_FLAG_START) != 0u) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_STATE;
		}
		if ((flags & (MATTER_BTP_FLAG_CONTINUE | MATTER_BTP_FLAG_END)) == 0u) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_STATE;
		}
	} else {
		/* A completed message must be taken away before the next one starts. */
		rx->state = MATTER_BTP_ERROR;
		return MATTER_E_STATE;
	}

	payload = len - off;
	if (payload > rx->cap - rx->len) {
		rx->state = MATTER_BTP_ERROR;
		return MATTER_E_NOSPACE;
	}
	/* Never accept more than was promised. CHIP trims the overshoot; refusing
	 * is the same decision the sequence check already makes, and it keeps
	 * "what we hold" equal to "what was declared" at every step. */
	if (payload > (size_t)rx->declared - rx->len) {
		rx->state = MATTER_BTP_ERROR;
		return MATTER_E_STATE;
	}
	if (payload > 0u) {
		if (rx->buf == NULL) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_INVAL;
		}
		memcpy(&rx->buf[rx->len], &frag[off], payload);
		rx->len += payload;
	}

	if ((flags & MATTER_BTP_FLAG_END) != 0u) {
		if (rx->len != (size_t)rx->declared) {
			rx->state = MATTER_BTP_ERROR;
			return MATTER_E_TRUNC;
		}
		rx->state = MATTER_BTP_COMPLETE;
		return MATTER_END;
	}
	return MATTER_OK;
}

/**
 * Initialize a BTP TX fragmenter with a message of length <= 0xFFFF, a fragment size within min/max
 * bounds. Return MATTER_E_INVAL if pointers/sizes are invalid, MATTER_OK on success.
 */
int matter_btp_tx_init(struct matter_btp_tx *tx, const uint8_t *msg, size_t len,
		       uint16_t fragment_size, uint8_t first_seq)
{
	if (tx == NULL) {
		return MATTER_E_INVAL;
	}
	if (msg == NULL && len != 0u) {
		return MATTER_E_INVAL;
	}
	if (fragment_size < MATTER_BTP_MIN_FRAGMENT || fragment_size > MATTER_BTP_MAX_FRAGMENT) {
		return MATTER_E_INVAL;
	}
	/* The Start fragment describes the total in 16 bits and nothing longer can
	 * be expressed, let alone reassembled. */
	if (len > 0xFFFFu) {
		return MATTER_E_INVAL;
	}

	tx->msg = msg;
	tx->len = len;
	tx->off = 0u;
	tx->fragment_size = fragment_size;
	tx->next_seq = first_seq;
	tx->started = false;
	return MATTER_OK;
}

/**
 * Encode the next BTP transmission fragment from buffered message: emit flags, optional ACK,
 * sequence number, and payload chunk. Splits message across fragments respecting fragment_size;
 * Start fragment includes declared length, End fragment marks completion. Returns MATTER_OK on
 * success, MATTER_END when all bytes sent, MATTER_E_NOSPACE if fragment or output buffer capacity
 * exceeded.
 */
int matter_btp_tx_next(struct matter_btp_tx *tx, const uint8_t *ack, uint8_t *out, size_t cap,
		       size_t *written)
{
	size_t hdr;
	size_t room;
	size_t take;
	size_t off = 0u;
	uint8_t flags = 0u;

	if (tx == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	/* A zero-length message still needs one fragment; anything else is done
	 * once every byte has been placed. */
	if (tx->started && tx->off >= tx->len) {
		return MATTER_END;
	}

	hdr = 1u + 1u; /* flags + seq */
	if (ack != NULL) {
		hdr += 1u;
	}
	if (!tx->started) {
		hdr += 2u; /* the total length rides on the Start fragment only */
	}
	if ((size_t)tx->fragment_size <= hdr) {
		return MATTER_E_NOSPACE;
	}
	room = (size_t)tx->fragment_size - hdr;

	take = tx->len - tx->off;
	if (take > room) {
		take = room;
	}
	if (cap < hdr + take) {
		return MATTER_E_NOSPACE;
	}

	if (!tx->started) {
		flags |= MATTER_BTP_FLAG_START;
	} else {
		flags |= MATTER_BTP_FLAG_CONTINUE;
	}
	if (tx->off + take >= tx->len) {
		flags |= MATTER_BTP_FLAG_END;
	}
	if (ack != NULL) {
		flags |= MATTER_BTP_FLAG_ACK;
	}

	out[off++] = flags;
	if (ack != NULL) {
		out[off++] = *ack;
	}
	out[off++] = tx->next_seq;
	tx->next_seq++;
	if (!tx->started) {
		wr16(&out[off], (uint16_t)tx->len);
		off += 2u;
		tx->started = true;
	}
	if (take > 0u) {
		memcpy(&out[off], &tx->msg[tx->off], take);
		off += take;
		tx->off += take;
	}

	if (written != NULL) {
		*written = off;
	}
	return MATTER_OK;
}

/**
 * Encode a standalone BTP acknowledgement: set the ACK flag, write the ack and seq fields. Return
 * MATTER_E_INVAL if out is null, MATTER_E_NOSPACE if cap < 3, MATTER_OK on success; write the
 * 3-byte frame size if written is not null.
 */
int matter_btp_standalone_ack(uint8_t ack, uint8_t seq, uint8_t *out, size_t cap, size_t *written)
{
	if (out == NULL) {
		return MATTER_E_INVAL;
	}
	if (cap < 3u) {
		return MATTER_E_NOSPACE;
	}
	out[0] = MATTER_BTP_FLAG_ACK;
	out[1] = ack;
	out[2] = seq;
	if (written != NULL) {
		*written = 3u;
	}
	return MATTER_OK;
}

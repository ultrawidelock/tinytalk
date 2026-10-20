/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_msg.h — Matter message header and protocol (exchange) header.
 *
 * Two headers, one wire format. The message header is the part that travels in
 * clear even on a secure session; the protocol header sits at the front of the
 * (decrypted) payload and names the exchange the message belongs to.
 *
 *   message header   flags:u8  session_id:u16  security_flags:u8  counter:u32
 *                    [source_node_id:u64 if S]  [dest:u64|u16 by DSIZ]
 *   protocol header  exchange_flags:u8  opcode:u8  exchange_id:u16
 *                    [vendor_id:u16 if V]  protocol_id:u16  [ack_counter:u32 if A]
 *
 * All little-endian. One file because they are one wire format read back to
 * back.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Message flags, MessageHeader.h:129-132 / message.py:93,99. */
/** Source node ID present. */
#define MATTER_MSG_FLAG_S        0x04u
/** Destination size, low two bits. */
#define MATTER_MSG_DSIZ_MASK     0x03u
#define MATTER_MSG_DSIZ_NONE     0x00u
#define MATTER_MSG_DSIZ_NODE     0x01u
#define MATTER_MSG_DSIZ_GROUP    0x02u
/** DSIZ 3 is reserved and must be refused rather than ignored. */
#define MATTER_MSG_DSIZ_RESERVED 0x03u
/** Version lives in the top nibble and must be 0 (MessageHeader.h:118-124,502). */
#define MATTER_MSG_VERSION_MASK  0xF0u

/* Security flags, MessageHeader.h:148-155 / message.py:21-26. */
#define MATTER_SEC_FLAG_P            0x80u /**< privacy */
#define MATTER_SEC_FLAG_C            0x40u /**< control message */
#define MATTER_SEC_FLAG_MX           0x20u /**< message extensions present */
/** Session type, low two bits; only unicast and group are assigned. */
#define MATTER_SEC_SESSION_TYPE_MASK 0x03u
#define MATTER_SESSION_TYPE_UNICAST  0x00u
#define MATTER_SESSION_TYPE_GROUP    0x01u

/* Exchange flags, MessageHeader.h:103-115 / message.py:13-18. */
#define MATTER_EX_FLAG_I  0x01u /**< sender is the exchange initiator */
#define MATTER_EX_FLAG_A  0x02u /**< carries an acknowledgement */
#define MATTER_EX_FLAG_R  0x04u /**< requests an acknowledgement */
#define MATTER_EX_FLAG_SX 0x08u /**< secured extensions present */
#define MATTER_EX_FLAG_V  0x10u /**< vendor ID precedes the protocol ID */

/** Fixed part, before any optional field. */
#define MATTER_MSG_HEADER_MIN   8u
#define MATTER_PROTO_HEADER_MIN 6u
/** Both headers at their largest: 8 + 8 + 8, and 4 + 2 + 2 + 4. */
#define MATTER_MSG_HEADER_MAX   24u
#define MATTER_PROTO_HEADER_MAX 12u

/**
 * Matter message header decoded from the wire: flags, session ID, security flags, message counter,
 * optional source/destination node ID (unicast) or group ID (multicast).
 */
struct matter_msg_header {
	uint8_t flags;
	uint16_t session_id;
	uint8_t security_flags;
	uint32_t message_counter;
	/** Meaningful only when flags has MATTER_MSG_FLAG_S. */
	uint64_t source_node_id;
	/** Meaningful only when DSIZ is MATTER_MSG_DSIZ_NODE. */
	uint64_t dest_node_id;
	/** Meaningful only when DSIZ is MATTER_MSG_DSIZ_GROUP. */
	uint16_t dest_group_id;
};

/**
 * Matter protocol/exchange header decoded from the message body: exchange flags, opcode, exchange
 * ID, optional vendor ID, protocol ID, and optional ACK counter.
 */
struct matter_proto_header {
	uint8_t exchange_flags;
	uint8_t opcode;
	uint16_t exchange_id;
	/** Meaningful only when exchange_flags has MATTER_EX_FLAG_V. */
	uint16_t vendor_id;
	uint16_t protocol_id;
	/** Meaningful only when exchange_flags has MATTER_EX_FLAG_A. */
	uint32_t ack_counter;
};

/** True when the session is secured, i.e. not the unsecured unicast session 0. */
bool matter_msg_is_secure(const struct matter_msg_header *h);

/**
 * @param consumed receives the header length, which is where the payload starts.
 * @return MATTER_OK, MATTER_E_TRUNC if the buffer ends inside the header, or
 *         MATTER_E_INVAL for a non-zero version or the reserved DSIZ.
 */
int matter_msg_header_decode(const uint8_t *buf, size_t len, struct matter_msg_header *h,
			     size_t *consumed);
int matter_msg_header_encode(const struct matter_msg_header *h, uint8_t *buf, size_t cap,
			     size_t *written);

int matter_proto_header_decode(const uint8_t *buf, size_t len, struct matter_proto_header *h,
			       size_t *consumed);
int matter_proto_header_encode(const struct matter_proto_header *h, uint8_t *buf, size_t cap,
			       size_t *written);

/*
 * ------------------------------------------------- outbound message counter ---
 *
 * The counter this node stamps on messages it sends. Its peer-facing twin, the
 * replay window over counters RECEIVED, is in matter_mrp.h with the duplicate
 * suppression it serves.
 *
 * The initial value is random in [1, 2^28] rather than 0. That is not for
 * uniqueness -- a counter starting at 0 would be just as unique -- but to keep
 * an observer from reading how long a session has been open off the wire
 * (MessageCounter.h:83-89).
 */

/** 28-bit mask on the seed (MessageCounter.h:42; CircuitMatter session.py:364). */
#define MATTER_COUNTER_INIT_MASK 0x0FFFFFFFu

enum matter_counter_kind {
	/**
	 * Secure session. Exhausts at 2^32-1 rather than wrapping: reusing a
	 * counter under the same key would repeat an AEAD nonce, so the session
	 * has to be re-established instead (MessageHeader.h / MessageCounter.h:
	 * 93-102).
	 */
	MATTER_COUNTER_SESSION = 0,
	/** Unsecured session. Wraps, because there is no key to compromise. */
	MATTER_COUNTER_UNSECURED = 1,
};

/**
 * RX/TX counter state: the last value used and the counter kind (unsecured or session).
 */
struct matter_counter {
	uint32_t last_used;
	uint8_t kind;
};

/**
 * @param entropy a random word; only its low 28 bits are used. Supplied by the
 *        caller rather than drawn here, so this layer needs no RNG seam and the
 *        host tests need no fake for one.
 */
void matter_counter_init(struct matter_counter *c, uint32_t entropy, enum matter_counter_kind kind);

/**
 * Advance and return the next counter to send.
 * @return MATTER_OK, or MATTER_E_STATE when a secure session's counter is spent.
 */
int matter_counter_next(struct matter_counter *c, uint32_t *out);

#ifdef __cplusplus
}
#endif

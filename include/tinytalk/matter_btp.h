/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file matter_btp.h — BTP, the Matter commissioning transport over BLE GATT.
 *
 * A Matter message is far larger than a BLE ATT payload, so BTP chops it into
 * fragments, numbers them, and acknowledges them. This file is the framing
 * only: no GATT, no Zephyr, no timers. The 0xFFF6 service that carries it is a
 * separate piece.
 *
 *   handshake req   0x65 0x6C  versions[4]  mtu:u16  window:u8      (9 bytes)
 *   handshake resp  0x65 0x6C  version:u8   fragment:u16  window:u8 (6 bytes)
 *   data fragment   flags:u8  [ack:u8 if A]  seq:u8  [len:u16 if S]  payload
 *
 * Little-endian, like the rest of Matter. BTP V4 is the only supported version.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fragment header flags (BtpEngine.h:80-86). */
#define MATTER_BTP_FLAG_START    0x01u
#define MATTER_BTP_FLAG_CONTINUE 0x02u
#define MATTER_BTP_FLAG_END      0x04u
#define MATTER_BTP_FLAG_ACK      0x08u

/** The only version CHIP supports, "BTP as defined by CHIP v1.0" (BleLayer.h:96). */
#define MATTER_BTP_VERSION 4u

/** Handshake check bytes, 0b01100101 and 0b01101100 (BleLayer.cpp:78-79). */
#define MATTER_BTP_CHECK_1 0x65u
#define MATTER_BTP_CHECK_2 0x6Cu

#define MATTER_BTP_REQ_LEN  9u
#define MATTER_BTP_RESP_LEN 6u

/** Eight 4-bit version slots packed into four bytes (BleLayer.h:87,124). */
#define MATTER_BTP_VERSION_SLOTS 8u

/** 23-byte minimum ATT_MTU less the 3-byte ATT header (BtpEngine.cpp:69). */
#define MATTER_BTP_MIN_FRAGMENT 20u
/** BtpEngine.cpp:70. */
#define MATTER_BTP_MAX_FRAGMENT 244u

/** flags + ack + seq + length: the largest header, on an acked Start fragment. */
#define MATTER_BTP_MAX_HEADER 5u

/**
 * Central's offer.
 *
 * @param versions unpacked one per element, high to low preference. A zero ends
 *        the list, so a zero in slot 0 means the peer offered nothing.
 * @param mtu the negotiated ATT MTU, or 0 when the central could not determine
 *        it -- which is a real case, not a malformed message (BleLayer.h:132).
 */
struct matter_btp_handshake_req {
	uint8_t versions[MATTER_BTP_VERSION_SLOTS];
	uint16_t mtu;
	uint8_t window_size;
};

/** Peripheral's answer: what was actually selected. */
struct matter_btp_handshake_resp {
	uint8_t version;
	uint16_t fragment_size;
	uint8_t window_size;
};

int matter_btp_req_decode(const uint8_t *buf, size_t len, struct matter_btp_handshake_req *out);
int matter_btp_req_encode(const struct matter_btp_handshake_req *r, uint8_t *buf, size_t cap,
			  size_t *written);
int matter_btp_resp_decode(const uint8_t *buf, size_t len, struct matter_btp_handshake_resp *out);
int matter_btp_resp_encode(const struct matter_btp_handshake_resp *r, uint8_t *buf, size_t cap,
			   size_t *written);

/**
 * Choose the response to a request: highest mutually supported version, and a
 * fragment size that fits both sides.
 *
 * @param local_att_mtu this device's ATT MTU. The usable fragment is 3 bytes
 *        less, for the ATT notification header.
 * @param local_window largest receive window this device will honour.
 * @return MATTER_OK, or MATTER_E_TYPE when no offered version is supported --
 *         the connection cannot proceed and the caller must drop it.
 */
int matter_btp_accept(const struct matter_btp_handshake_req *req, uint16_t local_att_mtu,
		      uint8_t local_window, struct matter_btp_handshake_resp *out);

/** Reassembly state, mirroring BtpEngine's (BtpEngine.h:71-77). */
enum matter_btp_state {
	MATTER_BTP_IDLE = 0,
	MATTER_BTP_IN_PROGRESS = 1,
	MATTER_BTP_COMPLETE = 2,
	/** Sticky. The framing desynchronised; the connection must be torn down. */
	MATTER_BTP_ERROR = 3,
};

/**
 * Inbound reassembler.
 *
 * The reassembly area is CALLER-OWNED and its size is the hard ceiling on an
 * inbound message: a Start fragment declaring more than @c cap is refused
 * before a byte is copied, so a peer cannot choose this node's memory use.
 */
struct matter_btp_rx {
	uint8_t *buf;
	size_t cap;
	size_t len;
	/** Total length the Start fragment promised. */
	uint16_t declared;
	uint8_t state;
	/** Sequence number the next fragment must carry. */
	uint8_t next_seq;
	/** Newest sequence number received, which is what an ack names. */
	uint8_t last_seq;
	/** Set when the fragment just handled carried an ack for our transmissions. */
	bool got_ack;
	uint8_t ack;
};

/**
 * @param first_seq sequence number the first inbound fragment must carry. This
 *        is ROLE-DEPENDENT and not always zero: CHIP's BtpEngine::Init() takes
 *        an expect_first_ack flag and sets rx to 1 / tx to 0 for a peripheral,
 *        the other way round for a central (BtpEngine.cpp Init). This node is
 *        the peripheral, so it expects 1 and sends from 0.
 */
void matter_btp_rx_init(struct matter_btp_rx *rx, uint8_t *buf, size_t cap, uint8_t first_seq);

/**
 * Feed one received fragment.
 *
 * @return MATTER_OK when more is expected, MATTER_END when the message is
 *         complete (@c rx->buf holds @c rx->len bytes), MATTER_E_TRUNC for a
 *         fragment shorter than its own header, MATTER_E_STATE for a sequence
 *         gap or a flag combination that does not fit the current state, or
 *         MATTER_E_NOSPACE when the message will not fit the reassembly area.
 *         Any error latches MATTER_BTP_ERROR.
 */
int matter_btp_rx_fragment(struct matter_btp_rx *rx, const uint8_t *frag, size_t len);

/** Discard a completed message and make the reassembler ready for the next. */
void matter_btp_rx_reset(struct matter_btp_rx *rx);

/**
 * Outbound fragmenter. Borrows the message; nothing is copied, so @p msg must
 * outlive the walk.
 */
struct matter_btp_tx {
	const uint8_t *msg;
	size_t len;
	size_t off;
	uint16_t fragment_size;
	uint8_t next_seq;
	bool started;
};

/**
 * @param fragment_size negotiated BTP PDU size, header included.
 * @param first_seq the sequence number to put on the first fragment.
 * @return MATTER_E_INVAL for a fragment size outside [20, 244], or a message
 *         longer than the 16-bit length field can describe.
 */
int matter_btp_tx_init(struct matter_btp_tx *tx, const uint8_t *msg, size_t len,
		       uint16_t fragment_size, uint8_t first_seq);

/**
 * Emit the next fragment.
 *
 * @param ack an acknowledgement to piggyback, or NULL for none. Piggybacking
 *        costs one byte of payload, which is why it is the caller's choice.
 * @return MATTER_OK, MATTER_END when the message is fully emitted (nothing
 *         written), or MATTER_E_NOSPACE.
 */
int matter_btp_tx_next(struct matter_btp_tx *tx, const uint8_t *ack, uint8_t *out, size_t cap,
		       size_t *written);

/** Build a fragment that carries only an acknowledgement (BtpEngine.h:52-53). */
int matter_btp_standalone_ack(uint8_t ack, uint8_t seq, uint8_t *out, size_t cap, size_t *written);

#ifdef __cplusplus
}
#endif

/**
 * @file test_matter_btp.c — BTP handshake, fragmentation and reassembly.
 *
 * ONE SOURCE. Every other Matter suite here pins bytes that two independent
 * implementations agree on; CircuitMatter has no BLE, so BTP has only CHIP.
 * The partial substitute is that CHIP's OWN test vectors are reproduced below
 * verbatim from src/ble/tests/TestBtpEngine.cpp:60-123 -- the same byte arrays,
 * fed to our reassembler, expecting the same state transitions. That is
 * stronger than re-reading the header and restating it, but it is still one
 * implementation, so treat this suite as the weakest link in the module.
 *
 * Those vectors start at sequence 1 because CHIP inits a peripheral with
 * rx=1/tx=0 (BtpEngine.cpp Init, expect_first_ack=false), which is why
 * matter_btp_rx_init() takes a first sequence rather than assuming zero.
 */
#include <string.h>

#include <tinymatter/matter_btp.h>

#include "test.h"

void test_matter_btp(void)
{
	uint8_t buf[512];
	uint8_t out[64];
	struct matter_btp_rx rx;
	struct matter_btp_handshake_req req;
	struct matter_btp_handshake_resp resp;
	size_t n = 0u;

	t_group("handshake: the request is 9 bytes with two check bytes");

	memset(&req, 0, sizeof(req));
	req.versions[0] = MATTER_BTP_VERSION;
	req.mtu = 247u;
	req.window_size = 6u;
	T_EQ("encode", matter_btp_req_encode(&req, out, sizeof(out), &n), MATTER_OK);
	T_EQ("length", (long)n, 9L);
	/* 0x65 0x6c, version 4 in the first low nibble, MTU 247 = 0x00f7 LE, window 6. */
	t_vec("request", out, n, "656c04000000f70006");

	t_group("handshake: versions are 4-bit slots, even index low nibble");

	memset(&req, 0, sizeof(req));
	req.versions[0] = 1u;
	req.versions[1] = 2u;
	req.versions[2] = 3u;
	req.versions[3] = 4u;
	req.mtu = 23u;
	req.window_size = 1u;
	T_EQ("encode packed", matter_btp_req_encode(&req, out, sizeof(out), &n), MATTER_OK);
	t_vec("two versions per byte", out, n, "656c21430000170001");

	{
		struct matter_btp_handshake_req back;

		T_EQ("decode", matter_btp_req_decode(out, n, &back), MATTER_OK);
		T_EQ("slot 0", back.versions[0], 1L);
		T_EQ("slot 1", back.versions[1], 2L);
		T_EQ("slot 2", back.versions[2], 3L);
		T_EQ("slot 3", back.versions[3], 4L);
		T_EQ("slot 4 is unused", back.versions[4], 0L);
		T_EQ("mtu", back.mtu, 23L);
		T_EQ("window", back.window_size, 1L);
	}

	t_group("handshake: the response is 6 bytes");

	memset(&resp, 0, sizeof(resp));
	resp.version = MATTER_BTP_VERSION;
	resp.fragment_size = 244u;
	resp.window_size = 6u;
	T_EQ("encode", matter_btp_resp_encode(&resp, out, sizeof(out), &n), MATTER_OK);
	T_EQ("length", (long)n, 6L);
	t_vec("response", out, n, "656c04f40006");

	{
		struct matter_btp_handshake_resp back;

		T_EQ("decode", matter_btp_resp_decode(out, n, &back), MATTER_OK);
		T_EQ("version", back.version, 4L);
		T_EQ("fragment", back.fragment_size, 244L);
		T_EQ("window", back.window_size, 6L);
	}

	t_group("handshake: refusals");

	out[0] = 0x00u;
	T_EQ("bad first check byte", matter_btp_req_decode(out, 9u, &req), MATTER_E_INVAL);
	out[0] = MATTER_BTP_CHECK_1;
	out[1] = 0x00u;
	T_EQ("bad second check byte", matter_btp_req_decode(out, 9u, &req), MATTER_E_INVAL);
	for (size_t k = 0; k < 9u; k++) {
		T_EQ("short request", matter_btp_req_decode(out, k, &req), MATTER_E_TRUNC);
	}
	for (size_t k = 0; k < 6u; k++) {
		T_EQ("short response", matter_btp_resp_decode(out, k, &resp), MATTER_E_TRUNC);
	}
	T_EQ("no room to encode", matter_btp_req_encode(&req, out, 8u, &n), MATTER_E_NOSPACE);
	T_EQ("null", matter_btp_req_decode(NULL, 9u, &req), MATTER_E_INVAL);

	t_group("handshake: choosing what to answer");

	memset(&req, 0, sizeof(req));
	req.versions[0] = MATTER_BTP_VERSION;
	req.mtu = 247u;
	req.window_size = 6u;
	T_EQ("accept", matter_btp_accept(&req, 247u, 6u, &resp), MATTER_OK);
	T_EQ("version 4", resp.version, 4L);
	T_EQ("fragment is MTU less the ATT header", resp.fragment_size, 244L);
	T_EQ("window", resp.window_size, 6L);

	/* The smaller of the two sides wins, and the window likewise. */
	T_EQ("our MTU is smaller", matter_btp_accept(&req, 70u, 4u, &resp), MATTER_OK);
	T_EQ("fragment follows ours", resp.fragment_size, 67L);
	T_EQ("window follows ours", resp.window_size, 4L);

	req.mtu = 40u;
	T_EQ("their MTU is smaller", matter_btp_accept(&req, 247u, 6u, &resp), MATTER_OK);
	T_EQ("fragment follows theirs", resp.fragment_size, 37L);

	/* A central that cannot read its own MTU sends 0; that is legal and must
	 * fall back to the floor rather than produce a nonsense fragment size. */
	req.mtu = 0u;
	T_EQ("unknown MTU", matter_btp_accept(&req, 247u, 6u, &resp), MATTER_OK);
	T_EQ("floor applies", resp.fragment_size, (long)MATTER_BTP_MIN_FRAGMENT);

	/* A huge MTU is capped: BTP's own maximum is smaller than ATT's. */
	req.mtu = 4000u;
	T_EQ("huge MTU", matter_btp_accept(&req, 4000u, 6u, &resp), MATTER_OK);
	T_EQ("capped", resp.fragment_size, (long)MATTER_BTP_MAX_FRAGMENT);

	memset(&req, 0, sizeof(req));
	req.versions[0] = 3u; /* only a version we do not speak */
	T_EQ("no common version", matter_btp_accept(&req, 247u, 6u, &resp), MATTER_E_TYPE);
	memset(&req, 0, sizeof(req));
	T_EQ("empty version list", matter_btp_accept(&req, 247u, 6u, &resp), MATTER_E_TYPE);
	/* A zero slot ends the list, so a version after it is not considered. */
	req.versions[0] = 0u;
	req.versions[1] = MATTER_BTP_VERSION;
	T_EQ("version after the terminator is ignored", matter_btp_accept(&req, 247u, 6u, &resp),
	     MATTER_E_TYPE);

	t_group("reassembly: CHIP's own one-fragment vector");
	{
		/* TestBtpEngine.cpp:62-68 verbatim: Start|End, seq 1, length 1, 0xff. */
		static const uint8_t f0[] = {0x05u, 0x01u, 0x01u, 0x00u, 0xffu};

		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("complete in one", matter_btp_rx_fragment(&rx, f0, sizeof(f0)), MATTER_END);
		T_EQ("state", rx.state, (long)MATTER_BTP_COMPLETE);
		T_EQ("length", (long)rx.len, 1L);
		T_EQ("payload", buf[0], 0xffL);
		T_OK("no ack rode along", !rx.got_ack);
	}

	t_group("reassembly: CHIP's own two-fragment vector");
	{
		/* TestBtpEngine.cpp:81-82. */
		static const uint8_t f0[] = {0x01u, 0x01u, 0x02u, 0x00u, 0xfeu};
		static const uint8_t f1[] = {0x04u, 0x02u, 0xffu};

		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("start", matter_btp_rx_fragment(&rx, f0, sizeof(f0)), MATTER_OK);
		T_EQ("in progress", rx.state, (long)MATTER_BTP_IN_PROGRESS);
		T_EQ("end", matter_btp_rx_fragment(&rx, f1, sizeof(f1)), MATTER_END);
		T_EQ("state", rx.state, (long)MATTER_BTP_COMPLETE);
		T_EQ("length", (long)rx.len, 2L);
		t_vec("reassembled", buf, rx.len, "feff");
	}

	t_group("reassembly: CHIP's own three-fragment vector");
	{
		/* TestBtpEngine.cpp:101-103. */
		static const uint8_t f0[] = {0x01u, 0x01u, 0x03u, 0x00u, 0xfdu};
		static const uint8_t f1[] = {0x02u, 0x02u, 0xfeu};
		static const uint8_t f2[] = {0x04u, 0x03u, 0xffu};

		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("start", matter_btp_rx_fragment(&rx, f0, sizeof(f0)), MATTER_OK);
		T_EQ("continue", matter_btp_rx_fragment(&rx, f1, sizeof(f1)), MATTER_OK);
		T_EQ("still in progress", rx.state, (long)MATTER_BTP_IN_PROGRESS);
		T_EQ("end", matter_btp_rx_fragment(&rx, f2, sizeof(f2)), MATTER_END);
		T_EQ("length", (long)rx.len, 3L);
		t_vec("reassembled", buf, rx.len, "fdfeff");
	}

	t_group("reassembly: a peer cannot choose our memory use");
	{
		/* A Start fragment declaring more than the reassembly area is refused
		 * before a single byte is copied. */
		static const uint8_t big[] = {0x01u, 0x01u, 0xffu, 0xffu, 0x00u};
		uint8_t small[8];

		matter_btp_rx_init(&rx, small, sizeof(small), 1u);
		T_EQ("declared length beyond our buffer",
		     matter_btp_rx_fragment(&rx, big, sizeof(big)), MATTER_E_NOSPACE);
		T_EQ("latched error", rx.state, (long)MATTER_BTP_ERROR);
		T_EQ("nothing accumulated", (long)rx.len, 0L);
		/* The error is sticky: the framing has desynchronised. */
		T_EQ("stays refused", matter_btp_rx_fragment(&rx, big, sizeof(big)),
		     MATTER_E_STATE);
	}

	t_group("reassembly: refusals");
	{
		static const uint8_t start2[] = {0x01u, 0x01u, 0x02u, 0x00u, 0xaau};
		static const uint8_t cont[] = {0x02u, 0x02u, 0xbbu};

		/* A sequence gap means the two sides disagree about the stream. */
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		{
			static const uint8_t wrong_seq[] = {0x05u, 0x09u, 0x01u, 0x00u, 0xffu};

			T_EQ("wrong sequence number",
			     matter_btp_rx_fragment(&rx, wrong_seq, sizeof(wrong_seq)),
			     MATTER_E_STATE);
		}

		/* Continue before Start: nothing is being reassembled yet. */
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		{
			static const uint8_t orphan[] = {0x02u, 0x01u, 0xaau};

			T_EQ("continue with nothing started",
			     matter_btp_rx_fragment(&rx, orphan, sizeof(orphan)), MATTER_E_STATE);
		}

		/* Start again mid-message: the sender restarted without telling us. */
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("start", matter_btp_rx_fragment(&rx, start2, sizeof(start2)), MATTER_OK);
		{
			static const uint8_t restart[] = {0x01u, 0x02u, 0x02u, 0x00u, 0xccu};

			T_EQ("start inside a message",
			     matter_btp_rx_fragment(&rx, restart, sizeof(restart)), MATTER_E_STATE);
		}

		/* End arriving with fewer bytes than were promised. */
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		{
			static const uint8_t start3[] = {0x01u, 0x01u, 0x03u, 0x00u, 0xaau};
			static const uint8_t short_end[] = {0x04u, 0x02u};

			T_EQ("start promising 3",
			     matter_btp_rx_fragment(&rx, start3, sizeof(start3)), MATTER_OK);
			T_EQ("end delivering 1",
			     matter_btp_rx_fragment(&rx, short_end, sizeof(short_end)),
			     MATTER_E_TRUNC);
		}

		/* More payload than was promised, which CHIP trims and we refuse. */
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		{
			static const uint8_t overshoot[] = {0x05u, 0x01u, 0x01u, 0x00u,
							    0xaau, 0xbbu, 0xccu};

			T_EQ("more data than declared",
			     matter_btp_rx_fragment(&rx, overshoot, sizeof(overshoot)),
			     MATTER_E_STATE);
		}

		/* Fragments too short to hold their own header. */
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("empty fragment", matter_btp_rx_fragment(&rx, start2, 0u), MATTER_E_TRUNC);
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("flags but no sequence", matter_btp_rx_fragment(&rx, start2, 1u),
		     MATTER_E_TRUNC);
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("start without its length", matter_btp_rx_fragment(&rx, start2, 3u),
		     MATTER_E_TRUNC);

		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("start", matter_btp_rx_fragment(&rx, start2, sizeof(start2)), MATTER_OK);
		T_EQ("truncated continue", matter_btp_rx_fragment(&rx, cont, 1u), MATTER_E_TRUNC);

		T_EQ("null", matter_btp_rx_fragment(NULL, start2, 5u), MATTER_E_INVAL);
	}

	t_group("reassembly: acks ride along and standalone acks carry no data");
	{
		/* Ack flag set: the ack byte sits between the flags and the sequence. */
		static const uint8_t with_ack[] = {0x0Du, 0x07u, 0x01u, 0x01u, 0x00u, 0xffu};
		static const uint8_t bare_ack[] = {0x08u, 0x09u, 0x02u};

		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);
		T_EQ("start and end, with an ack",
		     matter_btp_rx_fragment(&rx, with_ack, sizeof(with_ack)), MATTER_END);
		T_OK("ack seen", rx.got_ack);
		T_EQ("ack value", rx.ack, 7L);
		T_EQ("payload still landed", (long)rx.len, 1L);

		matter_btp_rx_reset(&rx);
		T_EQ("reset clears the message", (long)rx.len, 0L);
		T_EQ("and the state", rx.state, (long)MATTER_BTP_IDLE);

		/* A standalone ack advances the sequence but reassembles nothing. */
		T_EQ("standalone ack", matter_btp_rx_fragment(&rx, bare_ack, sizeof(bare_ack)),
		     MATTER_OK);
		T_OK("ack seen", rx.got_ack);
		T_EQ("ack value", rx.ack, 9L);
		T_EQ("no message started", rx.state, (long)MATTER_BTP_IDLE);
		T_EQ("nothing accumulated", (long)rx.len, 0L);
	}

	t_group("fragmentation: round-trips through our own reassembler");
	{
		struct matter_btp_tx tx;
		uint8_t msg[300];
		size_t total = 0u;
		int fragments = 0;

		for (size_t i = 0; i < sizeof(msg); i++) {
			msg[i] = (uint8_t)(i & 0xFFu);
		}

		/* The default 20-byte fragment is the interesting case: it is the
		 * floor, so a 300-byte message takes many hops. */
		T_EQ("init", matter_btp_tx_init(&tx, msg, sizeof(msg), MATTER_BTP_MIN_FRAGMENT, 1u),
		     MATTER_OK);
		matter_btp_rx_init(&rx, buf, sizeof(buf), 1u);

		for (;;) {
			int rc = matter_btp_tx_next(&tx, NULL, out, sizeof(out), &n);

			if (rc == MATTER_END) {
				break;
			}
			T_EQ("emit", rc, MATTER_OK);
			T_OK("fragment fits the negotiated size", n <= MATTER_BTP_MIN_FRAGMENT);
			fragments++;
			total += n;

			rc = matter_btp_rx_fragment(&rx, out, n);
			T_OK("accepted", rc == MATTER_OK || rc == MATTER_END);
			if (rc == MATTER_END) {
				break;
			}
		}

		T_EQ("reassembled length", (long)rx.len, (long)sizeof(msg));
		T_OK("bytes match", memcmp(buf, msg, sizeof(msg)) == 0);
		/* 300 bytes: first fragment carries 20-4=16, the rest 20-2=18 each,
		 * so 1 + ceil(284/18) = 1 + 16 = 17. */
		T_EQ("fragment count", fragments, 17);
		T_EQ("state", rx.state, (long)MATTER_BTP_COMPLETE);
	}

	t_group("fragmentation: one fragment when it fits");
	{
		struct matter_btp_tx tx;
		static const uint8_t msg[] = {0xffu};

		T_EQ("init", matter_btp_tx_init(&tx, msg, sizeof(msg), MATTER_BTP_MIN_FRAGMENT, 1u),
		     MATTER_OK);
		T_EQ("emit", matter_btp_tx_next(&tx, NULL, out, sizeof(out), &n), MATTER_OK);
		/* Exactly CHIP's one-fragment vector, produced rather than consumed. */
		t_vec("matches CHIP's vector", out, n, "05010100ff");
		T_EQ("nothing left", matter_btp_tx_next(&tx, NULL, out, sizeof(out), &n),
		     MATTER_END);
	}

	t_group("fragmentation: an ack costs a byte of payload");
	{
		struct matter_btp_tx tx;
		uint8_t msg[40];
		uint8_t ack = 0x07u;
		size_t without = 0u;
		size_t with = 0u;

		memset(msg, 0xAA, sizeof(msg));

		T_EQ("init", matter_btp_tx_init(&tx, msg, sizeof(msg), 20u, 0u), MATTER_OK);
		T_EQ("no ack", matter_btp_tx_next(&tx, NULL, out, sizeof(out), &without),
		     MATTER_OK);
		T_EQ("flags are start only", out[0], (long)MATTER_BTP_FLAG_START);

		T_EQ("init again", matter_btp_tx_init(&tx, msg, sizeof(msg), 20u, 0u), MATTER_OK);
		T_EQ("with ack", matter_btp_tx_next(&tx, &ack, out, sizeof(out), &with), MATTER_OK);
		T_EQ("flags carry the ack bit", out[0],
		     (long)(MATTER_BTP_FLAG_START | MATTER_BTP_FLAG_ACK));
		T_EQ("ack sits before the sequence", out[1], 0x07L);
		T_EQ("both fill the fragment", (long)with, (long)without);
	}

	t_group("fragmentation: refusals");
	{
		struct matter_btp_tx tx;
		uint8_t msg[4];

		T_EQ("fragment below the floor", matter_btp_tx_init(&tx, msg, sizeof(msg), 19u, 0u),
		     MATTER_E_INVAL);
		T_EQ("fragment above the ceiling",
		     matter_btp_tx_init(&tx, msg, sizeof(msg), 245u, 0u), MATTER_E_INVAL);
		T_EQ("null message with a length", matter_btp_tx_init(&tx, NULL, 4u, 20u, 0u),
		     MATTER_E_INVAL);
		T_EQ("null tx", matter_btp_tx_init(NULL, msg, 4u, 20u, 0u), MATTER_E_INVAL);

		T_EQ("init", matter_btp_tx_init(&tx, msg, sizeof(msg), 20u, 0u), MATTER_OK);
		T_EQ("output buffer too small", matter_btp_tx_next(&tx, NULL, out, 4u, &n),
		     MATTER_E_NOSPACE);
		T_EQ("null out", matter_btp_tx_next(&tx, NULL, NULL, sizeof(out), &n),
		     MATTER_E_INVAL);
	}

	t_group("standalone ack");

	T_EQ("build", matter_btp_standalone_ack(0x07u, 0x03u, out, sizeof(out), &n), MATTER_OK);
	T_EQ("three bytes", (long)n, 3L);
	t_vec("flags, ack, sequence", out, n, "080703");
	T_EQ("no room", matter_btp_standalone_ack(0u, 0u, out, 2u, &n), MATTER_E_NOSPACE);
	T_EQ("null", matter_btp_standalone_ack(0u, 0u, NULL, 8u, &n), MATTER_E_INVAL);
}

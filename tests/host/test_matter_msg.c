/**
 * @file test_matter_msg.c — Matter message and protocol header codec.
 *
 * Unlike the TLV suite there is no foreign golden-byte vector to pin these
 * against, so the vectors below are DERIVED from the field layout, and the
 * layout itself is what was cross-checked: CHIP's
 * workspace/modules/lib/matter/src/transport/raw/MessageHeader.h (:103-115,
 * :118-132, :148-155) and CircuitMatter's circuitmatter/message.py (:13-26,
 * :61, :88) state the same bit positions and the same little-endian field
 * order. Two independent implementations agreeing is the evidence here; the
 * bytes below are then arithmetic on top of it.
 *
 * What the suite leans on hardest is refusal, because every optional field in
 * both headers is selected by a flag bit the peer controls.
 */
#include <string.h>

#include <tinymatter/matter_msg.h>

#include "test.h"

void test_matter_msg(void)
{
	uint8_t buf[32];
	size_t n;
	struct matter_msg_header m;
	struct matter_proto_header p;

	t_group("message header: fixed part only");

	memset(&m, 0, sizeof(m));
	m.message_counter = 1u;
	T_EQ("encode minimal", matter_msg_header_encode(&m, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("minimal length", (long)n, 8L);
	t_vec("minimal header", buf, n, "0000000001000000");

	memset(&m, 0, sizeof(m));
	m.session_id = 0x1234u;
	m.security_flags = MATTER_SEC_FLAG_P;
	m.message_counter = 0xDEADBEEFu;
	T_EQ("encode fields", matter_msg_header_encode(&m, buf, sizeof(buf), &n), MATTER_OK);
	t_vec("session/sec/counter are little-endian", buf, n, "00341280efbeadde");

	t_group("message header: optional fields follow the flags");

	memset(&m, 0, sizeof(m));
	m.flags = MATTER_MSG_FLAG_S;
	m.source_node_id = 0x0102030405060708ull;
	T_EQ("encode with source", matter_msg_header_encode(&m, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("source adds 8", (long)n, 16L);
	t_vec("source node id", buf, n, "04000000000000000807060504030201");

	memset(&m, 0, sizeof(m));
	m.flags = MATTER_MSG_DSIZ_GROUP;
	m.dest_group_id = 0xABCDu;
	T_EQ("encode with group", matter_msg_header_encode(&m, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("group adds 2", (long)n, 10L);
	t_vec("group id", buf, n, "0200000000000000cdab");

	t_group("message header: round-trip every flag combination");
	{
		static const uint8_t dsiz[] = {MATTER_MSG_DSIZ_NONE, MATTER_MSG_DSIZ_NODE,
					       MATTER_MSG_DSIZ_GROUP};
		int cases = 0;

		for (size_t s = 0; s < 2u; s++) {
			for (size_t d = 0; d < sizeof(dsiz); d++) {
				struct matter_msg_header out;
				size_t got = 0;

				memset(&m, 0, sizeof(m));
				m.flags = (uint8_t)((s ? MATTER_MSG_FLAG_S : 0u) | dsiz[d]);
				m.session_id = 0x5AA5u;
				m.security_flags = MATTER_SEC_FLAG_C;
				m.message_counter = 0x01020304u;
				m.source_node_id = 0x1122334455667788ull;
				m.dest_node_id = 0x8877665544332211ull;
				m.dest_group_id = 0x0F0Fu;

				T_EQ("rt encode",
				     matter_msg_header_encode(&m, buf, sizeof(buf), &n), MATTER_OK);
				T_EQ("rt decode", matter_msg_header_decode(buf, n, &out, &got),
				     MATTER_OK);
				T_EQ("rt length agrees", (long)got, (long)n);
				T_EQ("rt flags", out.flags, m.flags);
				T_EQ("rt session", out.session_id, m.session_id);
				T_EQ("rt counter", (long)out.message_counter,
				     (long)m.message_counter);
				T_OK("rt source",
				     out.source_node_id == ((m.flags & MATTER_MSG_FLAG_S)
								    ? m.source_node_id
								    : 0u));
				T_OK("rt dest node",
				     out.dest_node_id == (((m.flags & MATTER_MSG_DSIZ_MASK) ==
							   MATTER_MSG_DSIZ_NODE)
								  ? m.dest_node_id
								  : 0u));
				cases++;
			}
		}
		T_EQ("all six combinations covered", cases, 6);
	}

	t_group("message header: refusals");

	/* DSIZ 3 is reserved. Accepting it would put our payload offset out of step
	 * with the sender's, which is worse than refusing. */
	buf[0] = MATTER_MSG_DSIZ_RESERVED;
	memset(&buf[1], 0, 7u);
	T_EQ("reserved DSIZ", matter_msg_header_decode(buf, 8u, &m, &n), MATTER_E_INVAL);

	buf[0] = 0x10u; /* version 1 */
	T_EQ("non-zero version", matter_msg_header_decode(buf, 8u, &m, &n), MATTER_E_INVAL);

	buf[0] = 0x00u;
	for (size_t k = 0; k < 8u; k++) {
		T_EQ("short fixed part", matter_msg_header_decode(buf, k, &m, &n), MATTER_E_TRUNC);
	}

	/* Flags promise a source node ID that the buffer does not contain. */
	buf[0] = MATTER_MSG_FLAG_S;
	for (size_t k = 8u; k < 16u; k++) {
		T_EQ("truncated optional field", matter_msg_header_decode(buf, k, &m, &n),
		     MATTER_E_TRUNC);
	}
	T_EQ("full length parses", matter_msg_header_decode(buf, 16u, &m, &n), MATTER_OK);

	memset(&m, 0, sizeof(m));
	m.flags = MATTER_MSG_FLAG_S;
	T_EQ("encode into a short buffer", matter_msg_header_encode(&m, buf, 15u, &n),
	     MATTER_E_NOSPACE);

	t_group("message header: secure-session predicate");

	memset(&m, 0, sizeof(m));
	T_EQ("session 0 unicast is unsecured", (long)matter_msg_is_secure(&m), 0L);
	m.session_id = 1u;
	T_EQ("non-zero session is secured", (long)matter_msg_is_secure(&m), 1L);
	memset(&m, 0, sizeof(m));
	m.security_flags = MATTER_SESSION_TYPE_GROUP;
	T_EQ("group session is secured even at id 0", (long)matter_msg_is_secure(&m), 1L);

	t_group("protocol header");

	memset(&p, 0, sizeof(p));
	p.opcode = 0x20u;
	p.exchange_id = 0x1122u;
	p.protocol_id = 0x0001u;
	T_EQ("encode minimal proto", matter_proto_header_encode(&p, buf, sizeof(buf), &n),
	     MATTER_OK);
	T_EQ("minimal proto length", (long)n, 6L);
	t_vec("proto minimal", buf, n, "002022110100");

	memset(&p, 0, sizeof(p));
	p.exchange_flags = MATTER_EX_FLAG_I | MATTER_EX_FLAG_R;
	p.opcode = 0x21u;
	p.exchange_id = 0x0001u;
	p.protocol_id = 0x0001u;
	T_EQ("encode I|R", matter_proto_header_encode(&p, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("I|R is still 6", (long)n, 6L);
	t_vec("proto I|R", buf, n, "052101000100");

	t_group("protocol header: optional fields and round-trip");
	{
		int cases = 0;

		for (unsigned int v = 0; v < 2u; v++) {
			for (unsigned int a = 0; a < 2u; a++) {
				struct matter_proto_header out;
				size_t got = 0;
				size_t want = 6u + (v ? 2u : 0u) + (a ? 4u : 0u);

				memset(&p, 0, sizeof(p));
				p.exchange_flags = (uint8_t)((v ? MATTER_EX_FLAG_V : 0u) |
							     (a ? MATTER_EX_FLAG_A : 0u));
				p.opcode = 0x42u;
				p.exchange_id = 0xBEEFu;
				p.vendor_id = 0xFFF1u;
				p.protocol_id = 0x0002u;
				p.ack_counter = 0x11223344u;

				T_EQ("proto rt encode",
				     matter_proto_header_encode(&p, buf, sizeof(buf), &n),
				     MATTER_OK);
				T_EQ("proto length matches flags", (long)n, (long)want);
				T_EQ("proto rt decode",
				     matter_proto_header_decode(buf, n, &out, &got), MATTER_OK);
				T_EQ("proto rt consumed", (long)got, (long)n);
				T_EQ("proto rt opcode", out.opcode, p.opcode);
				T_EQ("proto rt exchange", out.exchange_id, p.exchange_id);
				T_EQ("proto rt protocol", out.protocol_id, p.protocol_id);
				T_OK("proto rt vendor", out.vendor_id == (v ? p.vendor_id : 0u));
				T_OK("proto rt ack", out.ack_counter == (a ? p.ack_counter : 0u));
				cases++;
			}
		}
		T_EQ("all four proto combinations covered", cases, 4);
	}

	t_group("protocol header: refusals");

	memset(buf, 0, sizeof(buf));
	for (size_t k = 0; k < 6u; k++) {
		T_EQ("short proto header", matter_proto_header_decode(buf, k, &p, &n),
		     MATTER_E_TRUNC);
	}

	/* Flags promise a vendor ID and an ack counter; the buffer has neither. */
	buf[0] = MATTER_EX_FLAG_V | MATTER_EX_FLAG_A;
	for (size_t k = 6u; k < 12u; k++) {
		T_EQ("proto optional truncated", matter_proto_header_decode(buf, k, &p, &n),
		     MATTER_E_TRUNC);
	}
	T_EQ("proto full length parses", matter_proto_header_decode(buf, 12u, &p, &n), MATTER_OK);

	memset(&p, 0, sizeof(p));
	p.exchange_flags = MATTER_EX_FLAG_V | MATTER_EX_FLAG_A;
	T_EQ("proto encode into a short buffer", matter_proto_header_encode(&p, buf, 11u, &n),
	     MATTER_E_NOSPACE);

	t_group("outbound counter: starts random in [1, 2^28]");
	{
		struct matter_counter c;
		uint32_t v = 0u;

		/* Only the low 28 bits of the seed are used, so a peer cannot learn
		 * more about our RNG than that from the first counter it sees. */
		matter_counter_init(&c, 0xFFFFFFFFu, MATTER_COUNTER_SESSION);
		T_EQ("seed masked to 28 bits", (long)c.last_used, 0x0FFFFFFFL);
		T_EQ("first", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("first is one past the masked seed", (long)v, 0x10000000L);

		/* The stored value is the PREDECESSOR, so even a zero seed hands out 1
		 * rather than 0: the peer starts its idea of our counter at 0 and the
		 * first message must be strictly greater. */
		matter_counter_init(&c, 0u, MATTER_COUNTER_SESSION);
		T_EQ("zero seed", (long)c.last_used, 0L);
		T_EQ("first from a zero seed", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("is 1, never 0", (long)v, 1L);

		T_EQ("second", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("increments by one", (long)v, 2L);
		T_EQ("third", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("and again", (long)v, 3L);
	}

	t_group("outbound counter: a secure session runs out, it does not wrap");
	{
		struct matter_counter c;
		uint32_t v = 0u;

		/* Wrapping would repeat an AEAD nonce under a key still in use, so the
		 * counter refuses and the session has to be re-established. */
		matter_counter_init(&c, 0u, MATTER_COUNTER_SESSION);
		c.last_used = 0xFFFFFFFEu;
		T_EQ("last usable value", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("is the maximum", (long)(unsigned long)v, (long)0xFFFFFFFFL);
		T_EQ("and then it is spent", matter_counter_next(&c, &v), MATTER_E_STATE);
		T_EQ("still spent on a retry", matter_counter_next(&c, &v), MATTER_E_STATE);
		T_EQ("without having moved", (long)(unsigned long)c.last_used, (long)0xFFFFFFFFL);

		/* The unsecured session has no key to protect, so it wraps instead. */
		matter_counter_init(&c, 0u, MATTER_COUNTER_UNSECURED);
		c.last_used = 0xFFFFFFFFu;
		T_EQ("unsecured wraps", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("round to zero", (long)v, 0L);
		T_EQ("and carries on", matter_counter_next(&c, &v), MATTER_OK);
		T_EQ("from one", (long)v, 1L);
	}

	T_EQ("null arguments", matter_msg_header_decode(NULL, 8u, &m, &n), MATTER_E_INVAL);
	T_EQ("null proto arguments", matter_proto_header_encode(NULL, buf, sizeof(buf), &n),
	     MATTER_E_INVAL);
	{
		struct matter_counter c;
		uint32_t v = 0u;

		T_EQ("null counter", matter_counter_next(NULL, &v), MATTER_E_INVAL);
		matter_counter_init(&c, 0u, MATTER_COUNTER_SESSION);
		T_EQ("null out", matter_counter_next(&c, NULL), MATTER_E_INVAL);
		matter_counter_init(NULL, 0u, MATTER_COUNTER_SESSION);
		T_OK("null init survives", 1);
	}
}

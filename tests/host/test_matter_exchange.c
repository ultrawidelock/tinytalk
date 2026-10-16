/**
 * @file test_matter_exchange.c — the unsecured exchange PASE rides on.
 *
 * Inbound messages are built here with matter_msg.c's own encoders rather than
 * pasted as hex. That is deliberate and not circular: those encoders are pinned
 * bit by bit against CHIP and CircuitMatter in test_matter_msg.c, so using them
 * to construct a peer's message tests THIS layer's decisions -- which messages
 * it refuses, which exchange it binds to, when it owes an acknowledgement --
 * rather than re-testing the header layout underneath it.
 *
 * The refusals matter more than the happy path. Every field checked here was
 * chosen by an unauthenticated stranger: the unsecured session is exactly the
 * window where a commissioner has proved nothing.
 */
#include <string.h>

#include <tinytalk/matter_exchange.h>

#include "test.h"

#define PEER_EXCHANGE_ID 0x1A2Bu
#define SEED             0x0BADF00Du
/* An initiator's ephemeral node id, as seen on the wire from a real iPhone. */
#define PEER_NODE_ID     0x6557F7497EA9A507ULL

/** Build a message as a peer would send it. */
static size_t inbound(uint8_t *buf, size_t cap, uint8_t opcode, uint32_t counter,
		      uint16_t exchange_id, uint16_t session_id, uint16_t protocol_id,
		      uint8_t extra_sec_flags, uint8_t extra_ex_flags, const uint8_t *payload,
		      size_t payload_len)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	size_t mh_len = 0u;
	size_t ph_len = 0u;

	memset(&mh, 0, sizeof(mh));
	/* A real commissioner sets S and carries an ephemeral source node id;
	 * the responder has to echo it back as the DESTINATION. */
	mh.flags = MATTER_MSG_DSIZ_NONE | MATTER_MSG_FLAG_S;
	mh.source_node_id = PEER_NODE_ID;
	mh.session_id = session_id;
	mh.security_flags = (uint8_t)(MATTER_SESSION_TYPE_UNICAST | extra_sec_flags);
	mh.message_counter = counter;

	memset(&ph, 0, sizeof(ph));
	/* The peer is the initiator, and asks to be acknowledged. */
	ph.exchange_flags = (uint8_t)(MATTER_EX_FLAG_I | MATTER_EX_FLAG_R | extra_ex_flags);
	ph.opcode = opcode;
	ph.exchange_id = exchange_id;
	ph.protocol_id = protocol_id;

	(void)matter_msg_header_encode(&mh, buf, cap, &mh_len);
	(void)matter_proto_header_encode(&ph, buf + mh_len, cap - mh_len, &ph_len);
	if (payload_len > 0u) {
		memcpy(buf + mh_len + ph_len, payload, payload_len);
	}
	return mh_len + ph_len + payload_len;
}

/** A plain PBKDFParamRequest-shaped message on the happy path. */
static size_t inbound_ok(uint8_t *buf, size_t cap, uint8_t opcode, uint32_t counter,
			 const uint8_t *payload, size_t payload_len)
{
	return inbound(buf, cap, opcode, counter, PEER_EXCHANGE_ID, MATTER_SESSION_ID_UNSECURED,
		       MATTER_PROTOCOL_SECURE_CHANNEL, 0u, 0u, payload, payload_len);
}

static void t_matter_exchange_ack_for_self_initiated(void);
static void t_matter_exchange_keepalive_replay(void);
static void t_matter_tx_pool(void);

void test_matter_exchange(void)
{
	struct matter_exchange x;
	struct matter_exchange_in in;
	uint8_t msg[256];
	uint8_t out[256];
	uint8_t pt[256];
	size_t n;
	size_t out_len = 0u;
	static const uint8_t k_payload[] = {0x15, 0x30, 0x01, 0x20, 0xAA, 0xBB, 0x18};

	t_group("a message in, a reply out");
	{
		struct matter_msg_header mh;
		struct matter_proto_header ph;
		size_t mh_len = 0u;
		size_t ph_len = 0u;

		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 100u, k_payload, sizeof(k_payload));

		T_EQ("accepted", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		T_EQ("opcode", in.opcode, 0x20L);
		T_EQ("payload length", (long)in.payload_len, (long)sizeof(k_payload));
		T_OK("payload bytes", memcmp(in.payload, k_payload, sizeof(k_payload)) == 0);
		T_OK("peer asked to be acknowledged", in.ack_requested);
		T_OK("an acknowledgement is now owed", x.ack_pending);
		T_EQ("and it is for that counter", (long)x.ack_counter, 100L);
		T_EQ("bound to the peer's exchange", x.exchange_id, (long)PEER_EXCHANGE_ID);

		T_EQ("reply frames",
		     matter_exchange_reply(&x, 0x21u, k_payload, sizeof(k_payload), out,
					   sizeof(out), &out_len),
		     MATTER_OK);
		T_EQ("decode our own message header",
		     matter_msg_header_decode(out, out_len, &mh, &mh_len), MATTER_OK);
		T_EQ("unsecured session", mh.session_id, 0L);
		T_EQ("unicast", mh.security_flags & MATTER_SEC_SESSION_TYPE_MASK,
		     (long)MATTER_SESSION_TYPE_UNICAST);
		/* SessionManager.cpp:301-303: the responder addresses its reply to
		 * the initiator's ephemeral node id. Without this the peer cannot
		 * match the reply to its session and silently ignores it. */
		T_EQ("destination is a node id", mh.flags & MATTER_MSG_DSIZ_MASK,
		     (long)MATTER_MSG_DSIZ_NODE);
		T_OK("and it is the initiator's", mh.dest_node_id == PEER_NODE_ID);
		T_OK("we send no source node id of our own", (mh.flags & MATTER_MSG_FLAG_S) == 0u);

		T_EQ("decode our own protocol header",
		     matter_proto_header_decode(out + mh_len, out_len - mh_len, &ph, &ph_len),
		     MATTER_OK);
		T_EQ("opcode", ph.opcode, 0x21L);
		T_EQ("same exchange", ph.exchange_id, (long)PEER_EXCHANGE_ID);
		/* The responder never claims to be the initiator, however many
		 * messages it goes on to send. */
		T_OK("I is clear", (ph.exchange_flags & MATTER_EX_FLAG_I) == 0u);
		T_OK("R is set", (ph.exchange_flags & MATTER_EX_FLAG_R) != 0u);
		T_OK("A is set", (ph.exchange_flags & MATTER_EX_FLAG_A) != 0u);
		T_EQ("acking the peer's counter", (long)ph.ack_counter, 100L);
		T_OK("nothing owed now", !x.ack_pending);
		T_EQ("payload carried through", (long)(out_len - mh_len - ph_len),
		     (long)sizeof(k_payload));
		T_OK("payload bytes",
		     memcmp(out + mh_len + ph_len, k_payload, sizeof(k_payload)) == 0);
		T_EQ("Secure Channel", ph.protocol_id, (long)MATTER_PROTOCOL_SECURE_CHANNEL);
	}

	t_group("a retransmission is acknowledged but not acted on twice");
	{
		uint8_t first[sizeof(out)];
		size_t first_len;
		size_t replay_len = 0u;

		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 7u, k_payload, sizeof(k_payload));
		T_EQ("first time", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("reply",
		     matter_exchange_reply(&x, 0x21u, NULL, 0u, out, sizeof(out), &out_len),
		     MATTER_OK);
		first_len = out_len;
		memcpy(first, out, first_len);
		T_OK("ack consumed", !x.ack_pending);

		/* The peer did not hear the reply and sends the same message again. */
		T_EQ("second time is a duplicate",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_DUP);
		/* It still has to be acknowledged: the peer is retransmitting
		 * because it believes the ack was lost, and staying silent makes
		 * that true forever. */
		T_OK("but it is owed an acknowledgement again", x.ack_pending);
		T_EQ("for the same counter", (long)x.ack_counter, 7L);
		T_EQ("the exact response is replayed",
		     matter_exchange_replay(&x, out, sizeof(out), &replay_len), MATTER_OK);
		T_EQ("with the original length", (long)replay_len, (long)first_len);
		T_OK("with the original wire bytes and counter",
		     memcmp(out, first, first_len) == 0);
		T_OK("the replay carries the acknowledgement", !x.ack_pending);
		T_EQ("and cannot be emitted without another duplicate",
		     matter_exchange_replay(&x, out, sizeof(out), &replay_len), MATTER_E_STATE);
	}

	t_group("an oversized response falls back to a standalone ack");
	{
		uint8_t large[MATTER_EXCHANGE_REPLAY_MAX];
		size_t replay_len = 0u;

		memset(large, 0xa5, sizeof(large));
		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 8u, NULL, 0u);
		T_EQ("first request", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("large reply frames",
		     matter_exchange_reply(&x, 0x21u, large, sizeof(large), out, sizeof(out),
				       &out_len),
		     MATTER_OK);
		T_EQ("duplicate is suppressed",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_DUP);
		T_EQ("oversized reply was not cached",
		     matter_exchange_replay(&x, out, sizeof(out), &replay_len), MATTER_E_STATE);
		T_EQ("but the peer can still be acknowledged",
		     matter_exchange_standalone_ack(&x, out, sizeof(out), &replay_len), MATTER_OK);
	}

	t_group("what this layer refuses");
	{
		matter_exchange_init(&x, SEED, true);
		n = inbound(msg, sizeof(msg), 0x20u, 1u, PEER_EXCHANGE_ID, 0x0005u,
			    MATTER_PROTOCOL_SECURE_CHANNEL, 0u, 0u, NULL, 0u);
		T_EQ("a secured session id", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_E_INVAL);

		n = inbound(msg, sizeof(msg), 0x20u, 1u, PEER_EXCHANGE_ID,
			    MATTER_SESSION_ID_UNSECURED, 0x0001u, 0u, 0u, NULL, 0u);
		T_EQ("a protocol that is not Secure Channel",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_INVAL);

		n = inbound(msg, sizeof(msg), 0x20u, 1u, PEER_EXCHANGE_ID,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL,
			    MATTER_SESSION_TYPE_GROUP, 0u, NULL, 0u);
		T_EQ("a group session", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_E_INVAL);

		n = inbound(msg, sizeof(msg), 0x20u, 1u, PEER_EXCHANGE_ID,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL,
			    MATTER_SEC_FLAG_P, 0u, NULL, 0u);
		T_EQ("privacy we do not implement",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_INVAL);

		n = inbound(msg, sizeof(msg), 0x20u, 1u, PEER_EXCHANGE_ID,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL,
			    MATTER_SEC_FLAG_MX, 0u, NULL, 0u);
		T_EQ("message extensions we do not implement",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_INVAL);

		/* A vendor-scoped protocol id lives in a different namespace, so
		 * the protocol_id comparison would have meant nothing. */
		n = inbound(msg, sizeof(msg), 0x20u, 1u, PEER_EXCHANGE_ID,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL, 0u,
			    MATTER_EX_FLAG_V, NULL, 0u);
		T_EQ("a vendor-scoped protocol",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_INVAL);

		T_OK("none of them opened an exchange", !x.open);
	}

	t_group("one exchange at a time");
	{
		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 1u, NULL, 0u);
		T_EQ("the first one binds", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);

		n = inbound(msg, sizeof(msg), 0x20u, 2u, PEER_EXCHANGE_ID + 1u,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL, 0u, 0u,
			    NULL, 0u);
		T_EQ("a second commissioner is refused",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_STATE);
		T_EQ("still the first exchange", x.exchange_id, (long)PEER_EXCHANGE_ID);
	}

	t_group("standalone acknowledgement");
	{
		struct matter_proto_header ph;
		struct matter_msg_header mh;
		size_t mh_len = 0u;
		size_t ph_len = 0u;

		matter_exchange_init(&x, SEED, true);
		T_EQ("nothing to acknowledge yet",
		     matter_exchange_standalone_ack(&x, out, sizeof(out), &out_len),
		     MATTER_E_STATE);

		n = inbound_ok(msg, sizeof(msg), 0x24u, 42u, NULL, 0u);
		T_EQ("message", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		T_EQ("ack frames", matter_exchange_standalone_ack(&x, out, sizeof(out), &out_len),
		     MATTER_OK);

		(void)matter_msg_header_decode(out, out_len, &mh, &mh_len);
		T_EQ("decode",
		     matter_proto_header_decode(out + mh_len, out_len - mh_len, &ph, &ph_len),
		     MATTER_OK);
		T_EQ("StandaloneAck opcode", ph.opcode, (long)MATTER_SC_OP_ACK);
		T_EQ("empty payload", (long)(out_len - mh_len - ph_len), 0L);
		T_OK("carries the ack", (ph.exchange_flags & MATTER_EX_FLAG_A) != 0u);
		T_EQ("of the right counter", (long)ph.ack_counter, 42L);
		/* An ack that asked to be acknowledged would never terminate. */
		T_OK("does not request one back", (ph.exchange_flags & MATTER_EX_FLAG_R) == 0u);

		T_EQ("and only once",
		     matter_exchange_standalone_ack(&x, out, sizeof(out), &out_len),
		     MATTER_E_STATE);
	}

	t_group("an ack that could not be encoded is still owed");
	{
		size_t small_len = 0u;

		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 5u, k_payload, sizeof(k_payload));
		T_EQ("message", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		T_OK("owed", x.ack_pending);

		T_EQ("reply does not fit",
		     matter_exchange_reply(&x, 0x21u, k_payload, sizeof(k_payload), out, 8u,
					   &small_len),
		     MATTER_E_NOSPACE);
		/* Clearing the flag on a failed encode would drop the ack
		 * silently, and the peer would retransmit until it gave up. */
		T_OK("still owed", x.ack_pending);

		T_EQ("and a real buffer works",
		     matter_exchange_reply(&x, 0x21u, k_payload, sizeof(k_payload), out,
					   sizeof(out), &out_len),
		     MATTER_OK);
		T_OK("now consumed", !x.ack_pending);
	}

	t_group("over BLE, MRP is off entirely");
	{
		/*
		 * BTP is already reliable, so Matter does not run MRP on top of it:
		 * AllowsMRP() is "the peer address is UDP" (SecureSession.h:161,
		 * UnauthenticatedSessionTable.h:87) and ExchangeContext.cpp:109-112
		 * only sets R when the session allows it.
		 *
		 * A real iPhone proved this the hard way: it sent
		 * PBKDFParamRequest with exchange flags 0x01 -- I only -- and
		 * dropped the link on a reply that came back with R set.
		 */
		struct matter_proto_header ph;
		struct matter_msg_header mh;
		size_t mh_len = 0u;
		size_t ph_len = 0u;

		matter_exchange_init(&x, SEED, false);
		/* The peer does not set R either; this mirrors the capture. */
		n = inbound(msg, sizeof(msg), 0x20u, 11u, PEER_EXCHANGE_ID,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL, 0u, 0u,
			    k_payload, sizeof(k_payload));
		/* inbound() always sets R; clear it so the message matches what an
		 * iPhone actually sends. The exchange flags are the first byte of
		 * the protocol header, so find where that starts rather than
		 * assuming -- it moves when the message header carries a node id. */
		{
			struct matter_msg_header probe;
			size_t probe_len = 0u;

			T_EQ("locate the protocol header",
			     matter_msg_header_decode(msg, n, &probe, &probe_len), MATTER_OK);
			msg[probe_len] &= (uint8_t)~MATTER_EX_FLAG_R;
		}

		T_EQ("accepted", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		T_OK("peer did not request an ack", !in.ack_requested);
		T_OK("so none is owed", !x.ack_pending);

		T_EQ("reply frames",
		     matter_exchange_reply(&x, 0x21u, k_payload, sizeof(k_payload), out,
					   sizeof(out), &out_len),
		     MATTER_OK);
		(void)matter_msg_header_decode(out, out_len, &mh, &mh_len);
		T_EQ("decode",
		     matter_proto_header_decode(out + mh_len, out_len - mh_len, &ph, &ph_len),
		     MATTER_OK);
		T_OK("R is NOT set", (ph.exchange_flags & MATTER_EX_FLAG_R) == 0u);
		T_OK("A is NOT set", (ph.exchange_flags & MATTER_EX_FLAG_A) == 0u);
		T_OK("I still clear", (ph.exchange_flags & MATTER_EX_FLAG_I) == 0u);
		T_EQ("still the same exchange", ph.exchange_id, (long)PEER_EXCHANGE_ID);

		/* Nothing to acknowledge means no standalone ack exists either. */
		T_EQ("no standalone ack over BLE",
		     matter_exchange_standalone_ack(&x, out, sizeof(out), &out_len),
		     MATTER_E_STATE);

		/* Even if a peer DID set R, MRP stays off: the transport decides. */
		matter_exchange_init(&x, SEED, false);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 12u, NULL, 0u);
		T_EQ("accepted", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		T_OK("peer asked", in.ack_requested);
		T_OK("but nothing is owed", !x.ack_pending);
		T_EQ("reply",
		     matter_exchange_reply(&x, 0x21u, NULL, 0u, out, sizeof(out), &out_len),
		     MATTER_OK);
		(void)matter_msg_header_decode(out, out_len, &mh, &mh_len);
		(void)matter_proto_header_decode(out + mh_len, out_len - mh_len, &ph, &ph_len);
		T_OK("still no A", (ph.exchange_flags & MATTER_EX_FLAG_A) == 0u);
		T_OK("still no R", (ph.exchange_flags & MATTER_EX_FLAG_R) == 0u);
	}

	t_group("the secure session PASE hands over");
	{
		/*
		 * Everything here is what a commissioner does the moment PASE
		 * finishes: it stops talking in the clear, addresses us by the
		 * session id we announced, and opens a NEW exchange.
		 *
		 * The plaintext is built with our own encoders and sealed with
		 * matter_crypto_seal(), which is pinned against OpenSSL vectors in
		 * test_matter_crypto.c -- so this checks the wiring (which key,
		 * which node id, which session id), not the cipher.
		 */
		struct matter_session_keys keys;
		struct matter_msg_header mh;
		struct matter_proto_header ph;
		uint8_t plain[64];
		size_t plain_len = 0u;
		size_t sealed = 0u;

		for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
			keys.i2r[i] = (uint8_t)(0x10u + i);
			keys.r2i[i] = (uint8_t)(0x40u + i);
			keys.attestation_challenge[i] = (uint8_t)(0x70u + i);
		}

		matter_exchange_init(&x, SEED, false);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
		T_EQ("PASE message first", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);

		T_EQ("promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu),
		     MATTER_OK);
		T_OK("secure now", x.secure);
		/* PASE's exchange is finished; the peer opens a new one. */
		T_OK("exchange released", !x.open);

		/* Build an Interaction Model message the way the peer would. */
		memset(&ph, 0, sizeof(ph));
		ph.exchange_flags = MATTER_EX_FLAG_I;
		ph.opcode = 0x02u; /* ReadRequest */
		ph.exchange_id = 0x7777u;
		ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
		T_EQ("proto header",
		     matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len), MATTER_OK);
		plain[plain_len++] = 0x15u; /* a scrap of TLV payload */
		plain[plain_len++] = 0x18u;

		memset(&mh, 0, sizeof(mh));
		mh.flags = MATTER_MSG_DSIZ_NONE;
		mh.session_id = 0xABCDu; /* addressed to the id we announced */
		mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
		mh.message_counter = 900u;
		T_EQ("seal",
		     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					sizeof(msg), &sealed),
		     MATTER_OK);

		T_EQ("accepted", matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("Interaction Model", in.protocol_id, (long)MATTER_PROTOCOL_INTERACTION_MODEL);
		T_EQ("opcode survived decryption", in.opcode, 0x02L);
		T_EQ("payload length", (long)in.payload_len, 2L);
		T_OK("payload bytes", in.payload[0] == 0x15u && in.payload[1] == 0x18u);
		T_EQ("bound to the new exchange", x.exchange_id, 0x7777L);

		/* Wrong key must fail the tag, not produce plausible rubbish. */
		T_EQ("promote with r2i as the decrypt key",
		     matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu), MATTER_OK);
		memcpy(x.keys.i2r, keys.r2i, MATTER_KEY_LEN);
		T_EQ("tag refuses", matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)),
		     MATTER_E_TYPE);

		/* Once keys exist the clear channel is closed. */
		T_EQ("re-promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu),
		     MATTER_OK);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 4u, NULL, 0u);
		T_EQ("cleartext is refused after PASE",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_INVAL);

		/* A secure session id we never announced is not ours. */
		T_EQ("re-promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu),
		     MATTER_OK);
		mh.session_id = 0x0001u;
		(void)matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					 sizeof(msg), &sealed);
		T_EQ("wrong session id refused",
		     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_E_INVAL);
	}

	t_group("sending on the secure session");
	{
		/*
		 * Opened here as the PEER would open it, which is the whole point:
		 * a responder that encrypts with the wrong key, addresses the wrong
		 * session or builds the nonce from the wrong node id produces
		 * ciphertext that looks perfectly well formed and that nothing on
		 * this side can tell is wrong. Only decrypting it the way the
		 * commissioner will decrypt it catches that.
		 */
		struct matter_session_keys keys;
		struct matter_msg_header mh;
		struct matter_proto_header ph;
		struct matter_msg_header got;
		uint8_t plain[64];
		uint8_t body[8] = {0x15u, 0x24u, 0x00u, 0x01u, 0x18u};
		size_t plain_len = 0u;
		size_t sealed = 0u;
		size_t opened = 0u;
		size_t off = 0u;
		size_t wire_header_len = 0u;

		for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
			keys.i2r[i] = (uint8_t)(0x10u + i);
			keys.r2i[i] = (uint8_t)(0x40u + i);
			keys.attestation_challenge[i] = (uint8_t)(0x70u + i);
		}

		matter_exchange_init(&x, SEED, false);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
		T_EQ("PASE message first", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu),
		     MATTER_OK);

		/* The peer opens its exchange, so there is one to answer on. */
		memset(&ph, 0, sizeof(ph));
		ph.exchange_flags = MATTER_EX_FLAG_I;
		ph.opcode = 0x02u;
		ph.exchange_id = 0x7777u;
		ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
		plain_len = 0u;
		T_EQ("proto header",
		     matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len), MATTER_OK);
		memset(&mh, 0, sizeof(mh));
		mh.flags = MATTER_MSG_DSIZ_NONE;
		mh.session_id = 0xABCDu;
		mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
		mh.message_counter = 900u;
		T_EQ("peer request seals",
		     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					sizeof(msg), &sealed),
		     MATTER_OK);
		T_EQ("wire header locates the ciphertext",
		     matter_msg_header_decode(msg, sealed, &mh, &wire_header_len), MATTER_OK);
		T_EQ("peer request decrypts in its private receive buffer",
		     matter_exchange_recv_in_place(&x, msg, sealed, &in), MATTER_OK);
		T_OK("in-place plaintext replaced exactly the ciphertext",
		     memcmp(msg + wire_header_len, plain, plain_len) == 0);
		T_OK("decoded payload borrows the mutable receive buffer",
		     in.payload >= msg && in.payload <= msg + sealed);

		/* The exact-alias path decrypts before checking CCM's tag. Prove that
		 * a failed check cannot leave attacker-controlled plaintext behind in
		 * the receive buffer for a later handler to consume by accident. */
		mh.message_counter = 901u;
		T_EQ("tamper candidate seals",
		     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					sizeof(msg), &sealed),
		     MATTER_OK);
		msg[sealed - 1u] ^= 0x80u;
		T_EQ("tampered header still decodes",
		     matter_msg_header_decode(msg, sealed, &mh, &wire_header_len), MATTER_OK);
		T_EQ("tampered in-place request is refused",
		     matter_exchange_recv_in_place(&x, msg, sealed, &in), MATTER_E_TYPE);
		for (size_t i = 0u; i < plain_len; i++) {
			T_EQ("failed authentication zeroes plaintext", msg[wire_header_len + i], 0L);
		}

		/* Now answer it. */
		T_EQ("ReportData sends",
		     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x05u, body, 5u,
					  out, sizeof(out), &out_len),
		     MATTER_OK);
		T_OK("longer than the cleartext", out_len > 5u + MATTER_TAG_LEN);

		/*
		 * Decrypt exactly as the commissioner would: with r2i, because it
		 * is the initiator and this node is the responder, and with node
		 * id 0 in the nonce because PASE has no operational identity.
		 */
		T_EQ("peer opens it with r2i",
		     matter_crypto_open(out, out_len, keys.r2i, MATTER_PASE_NODE_ID, &got, pt,
					sizeof(pt), &opened),
		     MATTER_OK);

		/* Addressed with the PEER's session id, not ours (SessionManager.cpp:264). */
		T_EQ("peer session id", got.session_id, 0x1234L);
		/* And carrying no node ids at all (SessionManager.cpp:262-265). */
		T_EQ("no destination", (long)(got.flags & MATTER_MSG_DSIZ_MASK),
		     (long)MATTER_MSG_DSIZ_NONE);
		T_OK("no source node id", (got.flags & MATTER_MSG_FLAG_S) == 0u);

		/* The plaintext is the proto header followed by the payload. */
		{
			struct matter_proto_header rph;
			size_t rph_len = 0u;

			T_EQ("proto header decodes",
			     matter_proto_header_decode(pt, opened, &rph, &rph_len), MATTER_OK);
			T_EQ("ReportData opcode", rph.opcode, 0x05L);
			T_EQ("Interaction Model", rph.protocol_id,
			     (long)MATTER_PROTOCOL_INTERACTION_MODEL);
			T_EQ("same exchange", rph.exchange_id, 0x7777L);
			/* I stays clear: the peer opened this exchange, not us. */
			T_OK("not marked initiator", (rph.exchange_flags & MATTER_EX_FLAG_I) == 0u);
			/* MRP is off over BLE, so neither flag is ever set. */
			T_OK("no reliability flags",
			     (rph.exchange_flags & (MATTER_EX_FLAG_R | MATTER_EX_FLAG_A)) == 0u);
			off = rph_len;
			T_EQ("payload length", (long)(opened - off), 5L);
			T_OK("payload survived", memcmp(pt + off, body, 5u) == 0);
		}

		/* A replayed counter must not come back out of our own sender. */
		{
			size_t again = 0u;
			struct matter_msg_header got2;
			size_t opened2 = 0u;

			T_EQ("second send",
			     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x05u,
						  body, 5u, out, sizeof(out), &again),
			     MATTER_OK);
			T_EQ("second opens",
			     matter_crypto_open(out, again, keys.r2i, MATTER_PASE_NODE_ID, &got2,
						pt, sizeof(pt), &opened2),
			     MATTER_OK);
			T_OK("counter advanced", got2.message_counter != got.message_counter);
		}

		/* No room for the tag must fail rather than emit a short message. */
		T_EQ("cramped buffer refused",
		     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x05u, body, 5u,
					  out, 12u, &out_len),
		     MATTER_E_NOSPACE);
	}

	t_group("the peer moves to a new exchange");
	{
		/*
		 * Matter gives every interaction its own exchange. After the read
		 * that follows PASE is answered, the commissioner opens ANOTHER
		 * one for its next request -- and a responder that holds the first
		 * refuses everything after it.
		 *
		 * Observed, not theorised: a real iPhone accepted a ReportData,
		 * then sent 137 bytes on a new exchange, was refused with
		 * MATTER_E_STATE, and hung up.
		 */
		struct matter_session_keys keys;
		struct matter_msg_header mh;
		struct matter_proto_header ph;
		uint8_t plain[64];
		size_t plain_len = 0u;
		size_t sealed = 0u;

		for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
			keys.i2r[i] = (uint8_t)(0x10u + i);
			keys.r2i[i] = (uint8_t)(0x40u + i);
			keys.attestation_challenge[i] = (uint8_t)(0x70u + i);
		}

		matter_exchange_init(&x, SEED, false);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
		T_EQ("PASE message first", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu),
		     MATTER_OK);

		/* First interaction: the read. */
		memset(&mh, 0, sizeof(mh));
		mh.flags = MATTER_MSG_DSIZ_NONE;
		mh.session_id = 0xABCDu;
		mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
		memset(&ph, 0, sizeof(ph));
		ph.exchange_flags = MATTER_EX_FLAG_I;
		ph.opcode = 0x02u;
		ph.exchange_id = 0x7777u;
		ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
		plain_len = 0u;
		(void)matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len);
		mh.message_counter = 900u;
		(void)matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					 sizeof(msg), &sealed);
		T_EQ("read accepted", matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("bound to the read's exchange", x.exchange_id, 0x7777L);
		T_EQ("reported exchange id", in.exchange_id, 0x7777L);
		T_OK("peer is the initiator", in.initiator);

		/* Second interaction: a NEW exchange, as an invoke would arrive. */
		ph.exchange_id = 0x7778u;
		ph.opcode = 0x08u; /* InvokeCommandRequest */
		plain_len = 0u;
		(void)matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len);
		mh.message_counter = 901u;
		(void)matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					 sizeof(msg), &sealed);
		T_EQ("a new exchange is followed",
		     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_OK);
		T_EQ("rebound", x.exchange_id, 0x7778L);
		T_EQ("opcode carried through", in.opcode, 0x08L);

		/* A reply now goes out on the NEW exchange, not the old one. */
		T_EQ("reply frames",
		     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x09u, NULL, 0u,
					  out, sizeof(out), &out_len),
		     MATTER_OK);
		{
			struct matter_msg_header got;
			struct matter_proto_header rph;
			size_t opened = 0u;
			size_t rph_len = 0u;

			T_EQ("peer opens it",
			     matter_crypto_open(out, out_len, keys.r2i, MATTER_PASE_NODE_ID, &got,
						pt, sizeof(pt), &opened),
			     MATTER_OK);
			T_EQ("proto header", matter_proto_header_decode(pt, opened, &rph, &rph_len),
			     MATTER_OK);
			T_EQ("answered on the new exchange", rph.exchange_id, 0x7778L);
		}

		/* With I clear it is a reply to something we never sent: refused. */
		ph.exchange_id = 0x7779u;
		ph.exchange_flags = 0u;
		plain_len = 0u;
		(void)matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len);
		mh.message_counter = 902u;
		(void)matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					 sizeof(msg), &sealed);
		T_EQ("a new exchange with I clear is refused",
		     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_E_STATE);
		T_EQ("still on the old exchange", x.exchange_id, 0x7778L);
		/* Refusal still says what it refused, or nobody can debug it. */
		T_EQ("refusal names the exchange", in.exchange_id, 0x7779L);
		T_OK("and that I was clear", !in.initiator);

		/* The unsecured session keeps the old rule: one exchange only,
		 * because there a second exchange id is a second stranger. */
		matter_exchange_init(&x, SEED, false);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
		T_EQ("first unsecured message",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		n = inbound(msg, sizeof(msg), 0x20u, 4u, PEER_EXCHANGE_ID + 1u,
			    MATTER_SESSION_ID_UNSECURED, MATTER_PROTOCOL_SECURE_CHANNEL, 0u, 0u,
			    NULL, 0u);
		T_EQ("a second unsecured exchange is still refused",
		     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_E_STATE);
		T_EQ("unchanged", x.exchange_id, (long)PEER_EXCHANGE_ID);
	}

	t_group("replying before anything arrived");
	{
		matter_exchange_init(&x, SEED, true);
		T_EQ("has no exchange to reply on",
		     matter_exchange_reply(&x, 0x21u, NULL, 0u, out, sizeof(out), &out_len),
		     MATTER_E_STATE);
	}

	/*
	 * Two CASE sessions at once, which is not hypothetical: Apple opens one
	 * for the phone and a second for the home hub, and both keep talking.
	 *
	 * This is the invariant the port's session table stands on. While the
	 * port held ONE exchange the second handshake overwrote the first, every
	 * later message from the phone was refused as "not ours", and the
	 * subscription established seconds earlier went silent -- with the
	 * accessory stuck on "Adding to Home" and nothing logged as an error.
	 * The port routes by session id now; this asserts the thing that makes
	 * routing meaningful, that two promoted exchanges share no state.
	 */
	t_group("two sessions, side by side");
	{
		struct matter_exchange xa;
		struct matter_exchange xb;
		struct matter_session_keys ka;
		struct matter_session_keys kb;
		struct matter_proto_header ph;
		struct matter_msg_header mh;
		struct matter_exchange_in in;
		uint8_t plain[128];
		uint8_t pt[256];
		size_t plain_len = 0u;
		size_t sealed_a = 0u;
		size_t sealed_b = 0u;
		uint8_t msg_a[256];
		uint8_t msg_b[256];

		for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
			ka.i2r[i] = (uint8_t)(0x10u + i);
			ka.r2i[i] = (uint8_t)(0x40u + i);
			ka.attestation_challenge[i] = (uint8_t)(0x70u + i);
			/* Deliberately unrelated: a shared byte would let a
			 * mix-up still decrypt and hide the bug. */
			kb.i2r[i] = (uint8_t)(0xA1u + i);
			kb.r2i[i] = (uint8_t)(0xC5u + i);
			kb.attestation_challenge[i] = (uint8_t)(0xE9u + i);
		}

		matter_exchange_init(&xa, SEED, true);
		matter_exchange_init(&xb, SEED, true);
		T_EQ("session A promotes",
		     matter_exchange_promote(&xa, 0x4EF9u, 0x7BEAu, &ka, 0x5EEDu), MATTER_OK);
		T_EQ("session B promotes",
		     matter_exchange_promote(&xb, 0x62BBu, 0x7BEBu, &kb, 0x5EEEu), MATTER_OK);
		/* The two node-id pairs differ too, because they are what the
		 * AEAD nonce is built from: identical ids would let a message
		 * sealed for one session open on the other. */
		matter_exchange_set_op_node_ids(&xa, 0x1111u, 0x2222u);
		matter_exchange_set_op_node_ids(&xb, 0x3333u, 0x4444u);

		memset(&ph, 0, sizeof(ph));
		ph.exchange_flags = MATTER_EX_FLAG_I;
		ph.opcode = 0x02u;
		ph.exchange_id = 0x9001u;
		ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
		T_EQ("proto header",
		     matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len), MATTER_OK);
		plain[plain_len++] = 0x15u;
		plain[plain_len++] = 0x18u;

		memset(&mh, 0, sizeof(mh));
		mh.flags = MATTER_MSG_DSIZ_NONE;
		mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
		mh.session_id = 0x4EF9u;
		mh.message_counter = 501u;
		T_EQ("seal for A",
		     matter_crypto_seal(&mh, ka.i2r, 0x2222u, plain, plain_len, msg_a,
					sizeof(msg_a), &sealed_a),
		     MATTER_OK);
		mh.session_id = 0x62BBu;
		mh.message_counter = 502u;
		T_EQ("seal for B",
		     matter_crypto_seal(&mh, kb.i2r, 0x4444u, plain, plain_len, msg_b,
					sizeof(msg_b), &sealed_b),
		     MATTER_OK);

		/* B is established SECOND and must not disturb A. */
		T_EQ("B opens its own", matter_exchange_recv(&xb, msg_b, sealed_b, &in, pt,
							     sizeof(pt)),
		     MATTER_OK);
		T_EQ("B's opcode", in.opcode, 0x02L);
		T_EQ("A still opens its own AFTER B was established",
		     matter_exchange_recv(&xa, msg_a, sealed_a, &in, pt, sizeof(pt)), MATTER_OK);
		T_EQ("A's opcode", in.opcode, 0x02L);
		T_EQ("A's session id is untouched", (long)xa.local_session_id, 0x4EF9L);
		T_EQ("B's session id is untouched", (long)xb.local_session_id, 0x62BBL);

		/*
		 * And they are genuinely distinct: neither can open the other's
		 * traffic. Without this the two assertions above would still
		 * pass on a single shared session.
		 *
		 * E_INVAL, not the E_TYPE a wrong key gives: the session id in
		 * the header does not match, so it is refused before any
		 * decryption is attempted. Cheaper, and it means a misrouted
		 * message cannot even reach the AEAD.
		 */
		T_EQ("A refuses B's message",
		     matter_exchange_recv(&xa, msg_b, sealed_b, &in, pt, sizeof(pt)),
		     MATTER_E_INVAL);
		T_EQ("B refuses A's message",
		     matter_exchange_recv(&xb, msg_a, sealed_a, &in, pt, sizeof(pt)),
		     MATTER_E_INVAL);
	}

	t_group("this node opens an exchange of its own");
	{
		/*
		 * A subscription report is the first thing this node ever sends
		 * that answers nothing. Until it could, a controller took the
		 * InvokeResponse SUCCESS for its Lock/Unlock and then waited for
		 * a LockState report that never came -- the Home tile spinning
		 * on "Unlocking" over a session that was perfectly healthy.
		 *
		 * MRP is ON here: this is the UDP case, which is the only one
		 * where a server-initiated exchange happens at all.
		 */
		struct matter_session_keys keys;
		struct matter_msg_header mh;
		struct matter_proto_header ph;
		struct matter_msg_header got;
		uint8_t plain[64];
		uint8_t body[5] = {0x15u, 0x24u, 0x00u, 0x01u, 0x18u};
		size_t plain_len = 0u;
		size_t sealed = 0u;
		size_t opened = 0u;

		for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
			keys.i2r[i] = (uint8_t)(0x10u + i);
			keys.r2i[i] = (uint8_t)(0x40u + i);
			keys.attestation_challenge[i] = (uint8_t)(0x70u + i);
		}

		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
		T_EQ("PASE message first", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
		     MATTER_OK);
		T_EQ("promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu),
		     MATTER_OK);

		/*
		 * The peer opens ITS exchange and asks to be acknowledged, so
		 * there is both a live peer exchange id and an ack owed. Both
		 * have to survive this node opening one of its own.
		 */
		memset(&ph, 0, sizeof(ph));
		ph.exchange_flags = MATTER_EX_FLAG_I | MATTER_EX_FLAG_R;
		ph.opcode = 0x02u;
		ph.exchange_id = 0x7777u;
		ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
		plain_len = 0u;
		T_EQ("proto header", matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len),
		     MATTER_OK);
		memset(&mh, 0, sizeof(mh));
		mh.flags = MATTER_MSG_DSIZ_NONE;
		mh.session_id = 0xABCDu;
		mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
		mh.message_counter = 900u;
		T_EQ("peer request seals",
		     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
					sizeof(msg), &sealed),
		     MATTER_OK);
		T_EQ("peer request accepted",
		     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_OK);
		T_OK("an ack is owed", x.ack_pending);

		/* Now this node opens 0x0042 and reports on it, unprompted. */
		T_EQ("report sends",
		     matter_exchange_send_initiator(&x, 0x0042u, MATTER_PROTOCOL_INTERACTION_MODEL,
						    0x05u, body, sizeof(body), out, sizeof(out),
						    &out_len),
		     MATTER_OK);
		T_EQ("peer opens it with r2i",
		     matter_crypto_open(out, out_len, keys.r2i, MATTER_PASE_NODE_ID, &got, pt,
					sizeof(pt), &opened),
		     MATTER_OK);
		/* Still addressed with the PEER's session id: the SESSION role is
		 * unchanged, only the exchange role differs. */
		T_EQ("peer session id", got.session_id, 0x1234L);
		{
			struct matter_proto_header rph;
			size_t rph_len = 0u;

			T_EQ("proto header decodes",
			     matter_proto_header_decode(pt, opened, &rph, &rph_len), MATTER_OK);
			T_OK("marked initiator", (rph.exchange_flags & MATTER_EX_FLAG_I) != 0u);
			T_EQ("our exchange id, not the peer's", rph.exchange_id, 0x0042L);
			T_OK("asks to be acknowledged", (rph.exchange_flags & MATTER_EX_FLAG_R) != 0u);
			/*
			 * An ack names a counter WITHIN an exchange, so carrying
			 * the peer's pending ack out on an exchange it never saw
			 * acknowledges nothing it can match.
			 */
			T_OK("no ack piggybacked", (rph.exchange_flags & MATTER_EX_FLAG_A) == 0u);
		}
		T_EQ("the peer's exchange is untouched", (long)x.exchange_id, 0x7777L);
		T_OK("and the ack it owes is still owed", x.ack_pending);
	}

	t_matter_exchange_ack_for_self_initiated();
	t_matter_exchange_keepalive_replay();
	t_matter_tx_pool();
}

/*
 * The acknowledgement for a report this node initiated.
 *
 * Measured on hardware before the fix: every LockState report drew ten
 * "CASE message refused (-4)" -- two subscriptions x five MRP transmissions --
 * because the controller answers a report with I CLEAR on the REPORT's exchange
 * id, which is not the peer's exchange id, and that used to be refused as a
 * reply to a conversation this node never started. The report was therefore
 * never acknowledged and was retransmitted for the whole MRP schedule.
 */
static void t_matter_exchange_ack_for_self_initiated(void)
{
	struct matter_exchange x;
	struct matter_exchange_in in;
	struct matter_session_keys keys;
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	uint8_t msg[256];
	uint8_t pt[256];
	uint8_t out[256];
	uint8_t plain[64];
	uint8_t body[5] = {0x15u, 0x24u, 0x00u, 0x01u, 0x18u};
	size_t out_len = 0u;
	size_t plain_len = 0u;
	size_t sealed = 0u;
	size_t n;

	memset(&keys, 0, sizeof(keys));
	for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
		keys.i2r[i] = (uint8_t)(0x10u + i);
		keys.r2i[i] = (uint8_t)(0x40u + i);
		keys.attestation_challenge[i] = (uint8_t)(0x70u + i);
	}

	matter_exchange_init(&x, SEED, true);
	n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
	T_EQ("PASE message first", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
	T_EQ("promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu), MATTER_OK);

	/* The peer's own exchange, live, so the ack below is genuinely on a
	 * different id rather than on the only one in play. */
	memset(&ph, 0, sizeof(ph));
	ph.exchange_flags = MATTER_EX_FLAG_I;
	ph.opcode = 0x02u;
	ph.exchange_id = 0x7777u;
	ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
	T_EQ("proto header", matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len),
	     MATTER_OK);
	memset(&mh, 0, sizeof(mh));
	mh.flags = MATTER_MSG_DSIZ_NONE;
	mh.session_id = 0xABCDu;
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = 900u;
	T_EQ("peer request seals",
	     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
				sizeof(msg), &sealed),
	     MATTER_OK);
	T_EQ("peer request accepted", matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)),
	     MATTER_OK);

	T_EQ("report sends on our own exchange",
	     matter_exchange_send_initiator(&x, 0x0042u, MATTER_PROTOCOL_INTERACTION_MODEL, 0x05u,
					    body, sizeof(body), out, sizeof(out), &out_len),
	     MATTER_OK);

	/* The controller's standalone ack: I clear, A set, our exchange id. */
	memset(&ph, 0, sizeof(ph));
	ph.exchange_flags = MATTER_EX_FLAG_A;
	ph.opcode = MATTER_SC_OP_ACK;
	ph.exchange_id = 0x0042u;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;
	ph.ack_counter = 1u;
	plain_len = 0u;
	T_EQ("ack header", matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len),
	     MATTER_OK);
	memset(&mh, 0, sizeof(mh));
	mh.flags = MATTER_MSG_DSIZ_NONE;
	mh.session_id = 0xABCDu;
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = 901u;
	sealed = 0u;
	T_EQ("ack seals",
	     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
				sizeof(msg), &sealed),
	     MATTER_OK);

	T_EQ("the ack for our own exchange is ACCEPTED",
	     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_OK);
	T_OK("and it is seen as carrying an ack", in.carries_ack);
	T_EQ("naming the report's counter", (long)in.acked_counter, 1L);
	T_EQ("the peer's exchange is untouched", (long)x.exchange_id, 0x7777L);

	/*
	 * The rule it must not have relaxed: I clear on an id NOBODY opened is
	 * still a reply to a conversation that does not exist.
	 */
	memset(&ph, 0, sizeof(ph));
	ph.exchange_flags = MATTER_EX_FLAG_A;
	ph.opcode = MATTER_SC_OP_ACK;
	ph.exchange_id = 0x0099u;
	ph.protocol_id = MATTER_PROTOCOL_SECURE_CHANNEL;
	plain_len = 0u;
	T_EQ("stray header", matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len),
	     MATTER_OK);
	mh.message_counter = 902u;
	sealed = 0u;
	T_EQ("stray seals",
	     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
				sizeof(msg), &sealed),
	     MATTER_OK);
	T_EQ("an ack for an exchange nobody opened is still refused",
	     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_E_STATE);

	t_group("a retransmitted StatusResponse on this node's exchange");
	/*
	 * The peer closes the report exchange with a StatusResponse, R set, I
	 * clear. If the first acknowledgement is lost the peer retransmits it,
	 * and the DUP path frames a FRESH initiator ack from what recv left
	 * behind -- so everything it reads from `in` and from the exchange has
	 * to be valid on the MATTER_E_DUP return, not only on MATTER_OK.
	 */
	memset(&ph, 0, sizeof(ph));
	ph.exchange_flags = MATTER_EX_FLAG_A | MATTER_EX_FLAG_R;
	ph.opcode = 0x01u;
	ph.exchange_id = 0x0042u;
	ph.protocol_id = MATTER_PROTOCOL_INTERACTION_MODEL;
	ph.ack_counter = 1u;
	plain_len = 0u;
	T_EQ("StatusResponse header",
	     matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len), MATTER_OK);
	mh.message_counter = 903u;
	sealed = 0u;
	T_EQ("StatusResponse seals",
	     matter_crypto_seal(&mh, keys.i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg,
				sizeof(msg), &sealed),
	     MATTER_OK);
	T_EQ("first arrival is accepted",
	     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_OK);
	T_OK("it does not claim to initiate", !in.initiator);
	T_OK("and asks for an ack", in.ack_requested);
	T_EQ("on this node's exchange", (long)in.exchange_id, 0x0042L);
	out_len = 0u;
	T_EQ("the initiator ack frames",
	     matter_exchange_ack_initiator(&x, in.exchange_id, out, sizeof(out), &out_len),
	     MATTER_OK);

	/* The identical bytes again: the ack above was lost on the air. */
	T_EQ("the retransmit is refused as a duplicate",
	     matter_exchange_recv(&x, msg, sealed, &in, pt, sizeof(pt)), MATTER_E_DUP);
	T_OK("but still says it does not initiate", !in.initiator);
	T_OK("still asks for an ack", in.ack_requested);
	T_EQ("still names the exchange", (long)in.exchange_id, 0x0042L);
	T_EQ("and its counter", (long)in.message_counter, 903L);
	T_OK("the owed ack was re-armed", x.ack_pending);
	out_len = 0u;
	T_EQ("so a fresh initiator ack frames",
	     matter_exchange_ack_initiator(&x, in.exchange_id, out, sizeof(out), &out_len),
	     MATTER_OK);
	{
		struct matter_msg_header got;
		struct matter_proto_header rph;
		size_t rph_len = 0u;
		size_t opened = 0u;

		T_EQ("the peer opens it",
		     matter_crypto_open(out, out_len, keys.r2i, MATTER_PASE_NODE_ID, &got, pt,
					sizeof(pt), &opened),
		     MATTER_OK);
		T_EQ("its proto header decodes",
		     matter_proto_header_decode(pt, opened, &rph, &rph_len), MATTER_OK);
		T_EQ("a standalone ack", (long)rph.opcode, (long)MATTER_SC_OP_ACK);
		T_EQ("on the report's exchange", (long)rph.exchange_id, 0x0042L);
		T_OK("marked INITIATOR", (rph.exchange_flags & MATTER_EX_FLAG_I) != 0u);
		T_EQ("acknowledging the retransmitted counter", (long)rph.ack_counter, 903L);
		T_OK("and asking for nothing back",
		     (rph.exchange_flags & MATTER_EX_FLAG_R) == 0u);
	}
}

/* One message from the controller on session 0xABCD, sealed as it would be. */
static size_t replay_in(uint8_t *msg, size_t cap, const struct matter_session_keys *keys,
			uint8_t flags, uint8_t opcode, uint16_t protocol, uint16_t exchange_id,
			uint32_t ack_counter, uint32_t counter, const uint8_t *body, size_t body_len)
{
	struct matter_msg_header mh;
	struct matter_proto_header ph;
	uint8_t plain[64];
	size_t plain_len = 0u;
	size_t sealed = 0u;

	memset(&ph, 0, sizeof(ph));
	ph.exchange_flags = flags;
	ph.opcode = opcode;
	ph.exchange_id = exchange_id;
	ph.protocol_id = protocol;
	ph.ack_counter = ack_counter;
	(void)matter_proto_header_encode(&ph, plain, sizeof(plain), &plain_len);
	memcpy(plain + plain_len, body, body_len);
	plain_len += body_len;
	memset(&mh, 0, sizeof(mh));
	mh.flags = MATTER_MSG_DSIZ_NONE;
	mh.session_id = 0xABCDu;
	mh.security_flags = MATTER_SESSION_TYPE_UNICAST;
	mh.message_counter = counter;
	(void)matter_crypto_seal(&mh, keys->i2r, MATTER_PASE_NODE_ID, plain, plain_len, msg, cap,
				 &sealed);
	return sealed;
}

/* What the controller reads out of a message this node sent. */
static void replay_out(const uint8_t *out, size_t out_len,
		       const struct matter_session_keys *keys, struct matter_proto_header *ph,
		       uint32_t *counter)
{
	struct matter_msg_header got;
	uint8_t pt[256];
	size_t opened = 0u;
	size_t ph_len = 0u;

	memset(ph, 0, sizeof(*ph));
	*counter = 0u;
	if (matter_crypto_open(out, out_len, keys->r2i, MATTER_PASE_NODE_ID, &got, pt, sizeof(pt),
			       &opened) == MATTER_OK) {
		(void)matter_proto_header_decode(pt, opened, ph, &ph_len);
		*counter = got.message_counter;
	}
}

/*
 * The exchanges around the first keep-alive of tinylock round 1, 2026-10-17,
 * with the phone's ids and counters: its last invoke on 0x8b75, then the
 * keep-alive on 0xe00c at 02:52:09. After that the
 * phone sent nothing but StatusResponses. This checks that nothing on this
 * side was left open: every reliable message from the phone is acknowledged
 * on the exchange it came on, with the flags the peer matches against, and a
 * request on a fresh exchange afterwards is accepted and answered.
 */
static void t_matter_exchange_keepalive_replay(void)
{
	static const uint8_t k_status_ok[] = {0x15u, 0x24u, 0x00u, 0x00u, 0x24u,
					      0xFFu, 0x0Cu, 0x18u};
	static const uint8_t k_keepalive[] = {0x15u, 0x24u, 0x00u, 0x01u, 0x36u, 0x02u, 0x18u,
					      0x28u, 0x04u, 0x24u, 0xFFu, 0x0Cu, 0x18u};
	struct matter_exchange x;
	struct matter_exchange_in in;
	struct matter_session_keys keys;
	struct matter_proto_header ph;
	uint8_t msg[256];
	uint8_t pt[256];
	uint8_t out[256];
	size_t out_len = 0u;
	size_t n;
	uint32_t report_counter = 0u;
	uint32_t c = 0u;

	t_group("the 02:52:09 keep-alive leaves no exchange open");

	memset(&keys, 0, sizeof(keys));
	for (size_t i = 0; i < MATTER_KEY_LEN; i++) {
		keys.i2r[i] = (uint8_t)(0x10u + i);
		keys.r2i[i] = (uint8_t)(0x40u + i);
		keys.attestation_challenge[i] = (uint8_t)(0x70u + i);
	}
	matter_exchange_init(&x, SEED, true);
	n = inbound_ok(msg, sizeof(msg), 0x20u, 3u, NULL, 0u);
	T_EQ("PASE message first", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
	T_EQ("promote", matter_exchange_promote(&x, 0xABCDu, 0x1234u, &keys, 0x5EEDu), MATTER_OK);

	/* 02:51:04: InvokeRequest on the phone's 0x8b75, answered there. */
	n = replay_in(msg, sizeof(msg), &keys, MATTER_EX_FLAG_I | MATTER_EX_FLAG_R, 0x08u,
		      MATTER_PROTOCOL_INTERACTION_MODEL, 0x8b75u, 0u, 152699872u, NULL, 0u);
	T_EQ("the invoke is accepted", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
	     MATTER_OK);
	T_EQ("the InvokeResponse frames",
	     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x09u, k_status_ok,
				  sizeof(k_status_ok), out, sizeof(out), &out_len),
	     MATTER_OK);
	replay_out(out, out_len, &keys, &ph, &c);
	T_EQ("on 0x8b75", (long)ph.exchange_id, 0x8b75L);
	T_EQ("as responder, reliable, acking the invoke", (long)ph.exchange_flags,
	     (long)(MATTER_EX_FLAG_R | MATTER_EX_FLAG_A));
	T_EQ("its counter", (long)ph.ack_counter, 152699872L);

	/* 02:52:09: the keep-alive, on an exchange this node opens. */
	out_len = 0u;
	T_EQ("the keep-alive frames",
	     matter_exchange_send_initiator(&x, 0xe00cu, MATTER_PROTOCOL_INTERACTION_MODEL, 0x05u,
					    k_keepalive, sizeof(k_keepalive), out, sizeof(out),
					    &out_len),
	     MATTER_OK);
	T_EQ("43 B on the air, as logged", (long)out_len, 43L);
	replay_out(out, out_len, &keys, &ph, &report_counter);
	T_EQ("on 0xe00c", (long)ph.exchange_id, 0xe00cL);
	T_EQ("initiator, reliable, no ack", (long)ph.exchange_flags,
	     (long)(MATTER_EX_FLAG_I | MATTER_EX_FLAG_R));

	/* The phone's StatusResponse: I clear, acking the keep-alive, reliable. */
	n = replay_in(msg, sizeof(msg), &keys, MATTER_EX_FLAG_A | MATTER_EX_FLAG_R, 0x01u,
		      MATTER_PROTOCOL_INTERACTION_MODEL, 0xe00cu, report_counter, 152699875u,
		      k_status_ok, sizeof(k_status_ok));
	T_EQ("the StatusResponse is accepted",
	     matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)), MATTER_OK);
	T_OK("it acknowledges the keep-alive",
	     in.carries_ack && in.acked_counter == report_counter);
	out_len = 0u;
	T_EQ("the ack frames",
	     matter_exchange_ack_initiator(&x, in.exchange_id, out, sizeof(out), &out_len),
	     MATTER_OK);
	T_EQ("34 B, as logged", (long)out_len, 34L);
	replay_out(out, out_len, &keys, &ph, &c);
	T_EQ("a standalone ack", (long)ph.opcode, (long)MATTER_SC_OP_ACK);
	T_EQ("on 0xe00c", (long)ph.exchange_id, 0xe00cL);
	T_EQ("initiator and ack, not reliable", (long)ph.exchange_flags,
	     (long)(MATTER_EX_FLAG_I | MATTER_EX_FLAG_A));
	T_EQ("naming the StatusResponse", (long)ph.ack_counter, 152699875L);
	T_OK("nothing is owed after it", !x.ack_pending);

	/* The tap that never arrived: a TimedRequest on a new exchange. */
	n = replay_in(msg, sizeof(msg), &keys, MATTER_EX_FLAG_I | MATTER_EX_FLAG_R, 0x0au,
		      MATTER_PROTOCOL_INTERACTION_MODEL, 0x8b76u, 0u, 152699876u, NULL, 0u);
	T_EQ("a later request is accepted", matter_exchange_recv(&x, msg, n, &in, pt, sizeof(pt)),
	     MATTER_OK);
	out_len = 0u;
	T_EQ("and answered",
	     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x01u, k_status_ok,
				  sizeof(k_status_ok), out, sizeof(out), &out_len),
	     MATTER_OK);
	replay_out(out, out_len, &keys, &ph, &c);
	T_EQ("on its own exchange", (long)ph.exchange_id, 0x8b76L);
	T_EQ("acking it", (long)ph.ack_counter, 152699876L);
}

static void t_matter_tx_pool(void)
{
	struct matter_tx_pool pool;
	struct matter_tx_slot slots[2];
	uint8_t backing[2][96];
	struct matter_tx_slot *a;
	struct matter_tx_slot *b;
	uint32_t a_token;
	uint32_t b_token;

	t_group("owned outbound packet slots");
	T_EQ("pool initializes",
	     matter_tx_pool_init(&pool, slots, &backing[0][0], 2u, sizeof(backing[0])), MATTER_OK);
	a = matter_tx_pool_acquire(&pool, 1u);
	b = matter_tx_pool_acquire(&pool, 1u);
	T_OK("two slots acquired", a != NULL && b != NULL && a != b);
	T_OK("bounded exhaustion is explicit", matter_tx_pool_acquire(&pool, 1u) == NULL);
	a_token = a->token;
	b_token = b->token;
	memcpy(a->data, "first", 5u);
	memcpy(b->data, "second", 6u);
	T_EQ("first committed", matter_tx_slot_commit(a, 5u), MATTER_OK);
	T_EQ("second committed", matter_tx_slot_commit(b, 6u), MATTER_OK);
	T_OK("FIFO returns first", matter_tx_pool_ready(&pool, 1u) == a);
	T_EQ("completion cannot release a merely queued slot",
	     matter_tx_pool_complete(&pool, a_token), MATTER_E_STATE);
	T_EQ("first accepted", matter_tx_slot_in_flight(a), MATTER_OK);
	T_OK("in-flight bytes remain owned", memcmp(a->data, "first", 5u) == 0);
	T_EQ("rejected attempt returns exact packet to ready",
	     matter_tx_pool_retry(&pool, a_token, 100u, 1000u), MATTER_OK);
	T_OK("retry preserves token, length, and bytes",
	     a->state == MATTER_TX_SLOT_READY && a->token == a_token && a->len == 5u &&
		     memcmp(a->data, "first", 5u) == 0);
	T_OK("retry remains owned before expiry",
	     matter_tx_pool_expired(&pool, 1u, 1099u) == NULL);
	T_EQ("retry packet can be accepted again", matter_tx_slot_in_flight(a), MATTER_OK);
	T_OK("next ready skips in-flight", matter_tx_pool_ready(&pool, 1u) == b);
	T_EQ("wrong completion rejected", matter_tx_pool_complete(&pool, 0xDEADBEEFu),
	     MATTER_E_STATE);
	T_EQ("transport completion frees first", matter_tx_pool_complete(&pool, a_token), MATTER_OK);
	T_EQ("duplicate completion rejected", matter_tx_pool_complete(&pool, a_token),
	     MATTER_E_STATE);
	a = matter_tx_pool_acquire(&pool, 2u);
	T_OK("wrap-timeout slot acquired", a != NULL);
	a_token = a->token;
	memcpy(a->data, "retry", 5u);
	T_EQ("wrap-timeout slot committed", matter_tx_slot_commit(a, 5u), MATTER_OK);
	T_EQ("wrap-timeout slot accepted", matter_tx_slot_in_flight(a), MATTER_OK);
	T_EQ("deadline can cross uint32 wrap",
	     matter_tx_pool_retry(&pool, a_token, 0xFFFFFF00u, 1000u), MATTER_OK);
	T_OK("not expired one ms before wrapped deadline",
	     matter_tx_pool_expired(&pool, 2u, 743u) == NULL);
	T_EQ("retry accepted before deadline", matter_tx_slot_in_flight(a), MATTER_OK);
	T_EQ("second failure does not extend deadline",
	     matter_tx_pool_retry(&pool, a_token, 500u, 1000u), MATTER_OK);
	T_OK("expired at original wrapped deadline",
	     matter_tx_pool_expired(&pool, 2u, 744u) == a);
	T_EQ("expired retry can be released", matter_tx_pool_reject(&pool, a_token), MATTER_OK);
	a = matter_tx_pool_acquire(&pool, 2u);
	T_OK("freed slot is reusable", a != NULL);
	T_EQ("building slot can be cancelled", matter_tx_pool_cancel(&pool, a->token), MATTER_OK);
	T_EQ("cancel is exact-once", matter_tx_pool_cancel(&pool, a->token), MATTER_E_STATE);
	a = matter_tx_pool_acquire(&pool, 2u);
	T_OK("cancelled slot can be reused", a != NULL);
	T_EQ("zero length cannot publish", matter_tx_slot_commit(a, 0u), MATTER_E_INVAL);
	T_EQ("oversize cannot publish", matter_tx_slot_commit(a, a->capacity + 1u),
	     MATTER_E_INVAL);
	T_EQ("queued transport rejection frees second", matter_tx_pool_reject(&pool, b_token),
	     MATTER_OK);

	t_group("framing inside owned packet headroom");
	{
		struct matter_exchange x;
		struct matter_exchange_in in;
		struct matter_msg_header mh;
		struct matter_proto_header ph;
		uint8_t inbound_msg[96];
		uint8_t pt[96];
		uint8_t owned[96];
		uint8_t payload[] = {0x15u, 0x24u, 0x00u, 0x2Au, 0x18u};
		size_t n;
		size_t framed = 0u;
		size_t mh_len = 0u;
		size_t ph_len = 0u;

		matter_exchange_init(&x, SEED, true);
		n = inbound_ok(inbound_msg, sizeof(inbound_msg), 0x20u, 100u, NULL, 0u);
		T_EQ("exchange opens",
		     matter_exchange_recv(&x, inbound_msg, n, &in, pt, sizeof(pt)), MATTER_OK);
		memcpy(owned + MATTER_EXCHANGE_HEADER_MAX, payload, sizeof(payload));
		T_EQ("overlapping payload frames",
		     matter_exchange_send(&x, MATTER_PROTOCOL_INTERACTION_MODEL, 0x05u,
				  owned + MATTER_EXCHANGE_HEADER_MAX, sizeof(payload), owned,
				  sizeof(owned), &framed),
		     MATTER_OK);
		T_EQ("message header decodes", matter_msg_header_decode(owned, framed, &mh, &mh_len),
		     MATTER_OK);
		T_EQ("protocol header decodes",
		     matter_proto_header_decode(owned + mh_len, framed - mh_len, &ph, &ph_len),
		     MATTER_OK);
		T_OK("payload survived overlap",
		     memcmp(owned + mh_len + ph_len, payload, sizeof(payload)) == 0);
	}
}

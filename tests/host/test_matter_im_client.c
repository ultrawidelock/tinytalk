/**
 * @file test_matter_im_client.c — the outbound command, read back by this node's server.
 *
 * The same trick test_matter_case_client.c uses, for the same reason: an
 * InvokeRequest is only correct with respect to whatever decodes it, and the
 * decoder that matters is a commercial lock. So the request this file encodes
 * is handed to matter_im_invoke_request_decode() -- the unmodified server half
 * this node already answers its commissioner with -- and the response the
 * server encodes is handed back to the client decoder.
 *
 * Every field that could be silently dropped is checked on the far side, not
 * merely in the bytes: an endpoint that encodes as zero, a timedRequest flag
 * that never arrives, or a PIN that lands under the wrong tag all produce a
 * message that decodes cleanly and does the wrong thing.
 */
#include <stdbool.h>
#include <string.h>

#include <tinymatter/matter_clusters.h>
#include <tinymatter/matter_im.h>
#include <tinymatter/matter_im_client.h>
#include <tinymatter/matter_tlv.h>

#include "test.h"

/** A DoorLock endpoint, cluster and command, as the binding target names them. */
#define PEER_ENDPOINT 1u

/** Read the PINCode back out of a CommandFields element, if it carried one. */
static bool pin_of(const uint8_t *fields, size_t len, const uint8_t **pin, size_t *pin_len)
{
	struct matter_tlv_reader r;

	matter_tlv_reader_init(&r, fields, len);
	if (matter_tlv_next(&r) != MATTER_OK || !matter_tlv_is_container(&r)) {
		return false;
	}
	if (matter_tlv_enter(&r) != MATTER_OK) {
		return false;
	}
	for (;;) {
		int rc = matter_tlv_next(&r);

		if (rc != MATTER_OK) {
			break;
		}
		if (matter_tlv_tag(&r) == MATTER_TLV_CTX(0u) &&
		    matter_tlv_get_bytes(&r, pin, pin_len) == MATTER_OK) {
			return true;
		}
	}
	return false;
}

void test_matter_im_client(void)
{
	struct matter_im_client_invoke inv;
	struct matter_im_client_response resp;
	struct matter_im_invoke got;
	struct matter_im_client_pin pin;
	struct matter_tlv_writer w;
	uint8_t buf[MATTER_IM_CLIENT_INVOKE_MAX];
	uint8_t msg[256];
	const uint8_t *got_pin = NULL;
	size_t got_pin_len = 0u;
	size_t n = 0u;

	t_group("an UnlockDoor this node's own server accepts");

	memset(&inv, 0, sizeof(inv));
	inv.endpoint = PEER_ENDPOINT;
	inv.cluster = MATTER_CLUSTER_DOOR_LOCK;
	inv.command = MATTER_CMD_DL_UNLOCK_DOOR;
	inv.timed_request = true;

	T_EQ("it encodes", matter_im_client_invoke_encode(&inv, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("and the server decodes it", matter_im_invoke_request_decode(buf, n, &got), MATTER_OK);
	T_EQ("on the right endpoint", (int)got.endpoint, (int)PEER_ENDPOINT);
	T_EQ("the right cluster", (int)got.cluster, (int)MATTER_CLUSTER_DOOR_LOCK);
	T_EQ("the right command", (int)got.command, (int)MATTER_CMD_DL_UNLOCK_DOOR);
	/*
	 * The one flag that decides whether a real lock runs the command or
	 * answers NEEDS_TIMED_INTERACTION and does nothing. A dropped bool here
	 * is a refusal that reads exactly like a permissions problem.
	 */
	T_OK("and it says a TimedRequest came first", got.timed_request);
	T_OK("a response is not suppressed", !got.suppress_response);
	T_OK("no fields were sent", !got.has_fields);

	t_group("the same command carrying a PIN");

	pin.pin = (const uint8_t *)"123456";
	pin.pin_len = 6u;
	inv.fields = matter_im_client_unlock_fields;
	inv.fields_ctx = &pin;

	T_EQ("it encodes", matter_im_client_invoke_encode(&inv, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("the server decodes it", matter_im_invoke_request_decode(buf, n, &got), MATTER_OK);
	T_OK("and the fields arrived", got.has_fields);
	T_OK("with the PIN under field 0",
	     pin_of(got.fields, got.fields_len, &got_pin, &got_pin_len));
	T_EQ("of the right length", (int)got_pin_len, 6);
	T_OK("and the right digits", memcmp(got_pin, "123456", 6u) == 0);

	t_group("no PIN means no field, not an empty one");

	pin.pin = NULL;
	pin.pin_len = 0u;
	T_EQ("it encodes", matter_im_client_invoke_encode(&inv, buf, sizeof(buf), &n), MATTER_OK);
	T_EQ("the server decodes it", matter_im_invoke_request_decode(buf, n, &got), MATTER_OK);
	T_OK("the fields structure is there", got.has_fields);
	/*
	 * A lock that requires no PIN is entitled to reject one it did not ask
	 * for, so an absent PIN has to be absent rather than zero-length.
	 */
	T_OK("and it is empty", !pin_of(got.fields, got.fields_len, &got_pin, &got_pin_len));

	t_group("the TimedRequest that has to precede it");

	T_EQ("it encodes", matter_im_client_timed_request_encode(2000u, buf, sizeof(buf), &n),
	     MATTER_OK);
	{
		uint16_t timeout = 0u;

		T_EQ("and the server reads the window back",
		     matter_im_timed_request_decode(buf, n, &timeout), MATTER_OK);
		T_EQ("unchanged", (int)timeout, 2000);
	}

	t_group("a peer that answers with a status");

	/*
	 * ACCESS_DENIED is what a bound lock says when its ACL has no entry for
	 * this node, which is the single most likely way this feature fails in
	 * the field. Recognising it is what turns a silent non-unlock into one
	 * log line naming the fix.
	 */
	matter_tlv_writer_init(&w, msg, sizeof(msg));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(0u), false);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0u), MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), PEER_ENDPOINT);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), MATTER_CLUSTER_DOOR_LOCK);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), MATTER_CMD_DL_UNLOCK_DOOR);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0xFFu), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);
	T_EQ("the response encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);

	T_EQ("and decodes", matter_im_client_response_decode(msg, n, &resp), MATTER_OK);
	T_OK("as a status rather than data", resp.is_status);
	T_EQ("naming the refusal", (int)resp.status, (int)MATTER_IM_STATUS_UNSUPPORTED_ACCESS);
	T_EQ("on the path that was invoked", (int)resp.command,
	     (int)MATTER_CMD_DL_UNLOCK_DOOR);
	T_EQ("of the right cluster", (int)resp.cluster, (int)MATTER_CLUSTER_DOOR_LOCK);
	T_OK("with no cluster-specific code", !resp.has_cluster_status);
	T_OK("and no fields", !resp.has_fields);

	t_group("a peer that answers with data");

	matter_tlv_writer_init(&w, msg, sizeof(msg));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(0u), false);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(0u), MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), PEER_ENDPOINT);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(1u), MATTER_CLUSTER_DOOR_LOCK);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(2u), 0x25u);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(0u), 7u);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	T_EQ("the response encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);

	T_EQ("and decodes", matter_im_client_response_decode(msg, n, &resp), MATTER_OK);
	T_OK("as data rather than a status", !resp.is_status);
	/*
	 * A command that answered with a payload succeeded by definition.
	 * Leaving the caller to work that out is how a success gets logged as a
	 * failure, so the decoder says so.
	 */
	T_EQ("which counts as success", (int)resp.status, (int)MATTER_IM_STATUS_SUCCESS);
	T_OK("and the payload is borrowed whole", resp.has_fields);
	T_OK("from inside the message", resp.fields >= msg && resp.fields < msg + n);

	t_group("responses this node will not act on");

	T_EQ("nothing at all", matter_im_client_response_decode(NULL, 0u, &resp), MATTER_E_INVAL);
	T_EQ("nowhere to put it", matter_im_client_response_decode(msg, n, NULL), MATTER_E_INVAL);
	/* A complete element that is simply not a structure -- a signed int.
	 * Distinct from the truncation below, which stops before its own value
	 * and so never gets as far as having a type at all. */
	T_EQ("a whole element of the wrong shape",
	     matter_im_client_response_decode((const uint8_t *)"\x00\x2A", 2u, &resp),
	     MATTER_E_TYPE);
	T_EQ("an element that stops mid-value",
	     matter_im_client_response_decode((const uint8_t *)"\x01", 1u, &resp), MATTER_E_TRUNC);
	T_EQ("truncated", matter_im_client_response_decode(msg, n / 2u, &resp), MATTER_E_TRUNC);

	/* An InvokeResponseMessage with an empty response array. One command
	 * went out, so no answer to it is a malformed answer. */
	matter_tlv_writer_init(&w, msg, sizeof(msg));
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(1u), MATTER_TLV_ARRAY);
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);
	T_EQ("encodes", matter_tlv_writer_finish(&w, &n), MATTER_OK);
	T_EQ("an answer to nothing", matter_im_client_response_decode(msg, n, &resp),
	     MATTER_E_INVAL);

	t_group("requests this node will not send");

	T_EQ("with nowhere to write", matter_im_client_invoke_encode(&inv, NULL, 0u, &n),
	     MATTER_E_INVAL);
	T_EQ("with no command to send", matter_im_client_invoke_encode(NULL, buf, sizeof(buf), &n),
	     MATTER_E_INVAL);
	T_EQ("into a buffer too small", matter_im_client_invoke_encode(&inv, buf, 8u, &n),
	     MATTER_E_NOSPACE);
	T_EQ("a TimedRequest into a buffer too small",
	     matter_im_client_timed_request_encode(2000u, buf, 2u, &n), MATTER_E_NOSPACE);
}

/* SPDX-License-Identifier: ISC */

/**
 * @file matter_im_client.h — sending a command, rather than answering one.
 *
 * matter_im.h is this node as an Interaction Model SERVER: it decodes what a
 * commissioner asked for and encodes the answer. This is the other direction,
 * and it is what the binding feature needs -- the lock telling another lock to
 * unlock:
 *
 *   out  TimedRequest          (protocol 0x0001, opcode 0x0A)
 *   in   StatusResponse        (protocol 0x0001, opcode 0x01)
 *   out  InvokeRequest         (protocol 0x0001, opcode 0x08)
 *   in   InvokeResponse        (protocol 0x0001, opcode 0x09)
 *
 * The TimedRequest is not optional for UnlockDoor. DoorLock's lock and unlock
 * commands are Timed Invoke commands, so a peer that receives a bare
 * InvokeRequest for one answers NEEDS_TIMED_INTERACTION and does nothing -- a
 * refusal that looks exactly like a permissions problem and is not one. This
 * node's own server already enforces the same rule on its commissioner
 * (matter_im_timed_request_decode), so the failure is worth recognising from
 * both ends.
 *
 * ONE COMMAND PER MESSAGE, never a batch, matching what this node's server
 * accepts and what its Sigma2 advertises in MaxPathsPerInvoke.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinymatter/matter_status.h>
#include <tinymatter/matter_tlv.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Enough for an InvokeRequest carrying a door lock PIN.
 *
 * The framing is about 30 bytes and the largest field this sends is a PIN,
 * which the spec caps well under this. Sized for the message rather than for
 * the MTU because the caller supplies the buffer and a needlessly large one on
 * this part is RAM that the session buffers want.
 */
#define MATTER_IM_CLIENT_INVOKE_MAX 128u

/** A TimedRequest is a timeout and a revision, and nothing else. */
#define MATTER_IM_CLIENT_TIMED_MAX 16u

/**
 * Write the fields of the command being sent.
 *
 * The mirror of @ref matter_im_command_fields_fn, which does the same job for
 * the responses this node's server produces. Write exactly one element, a
 * STRUCTURE, tagged @p tag.
 *
 * A callback rather than a byte buffer because what the fields MEAN is the
 * cluster's business and not the Interaction Model's -- the same division
 * matter_im.c already draws when it borrows an inbound CommandFields without
 * decoding it.
 */
typedef void (*matter_im_client_fields_fn)(void *ctx, struct matter_tlv_writer *w,
					   matter_tlv_tag_t tag);

/** What one outbound command names and carries. */
struct matter_im_client_invoke {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t command;
	/** Writes CommandFields. NULL for a command that takes no arguments. */
	matter_im_client_fields_fn fields;
	void *fields_ctx;
	/**
	 * Announce that a TimedRequest preceded this. Required for DoorLock's
	 * UnlockDoor; see the file comment for what happens without it.
	 */
	bool timed_request;
	/**
	 * Ask the peer not to answer.
	 *
	 * Left false by this node. A response is the only way to learn that the
	 * unlock was refused, and "sent and ignored" is the failure that is
	 * hardest to notice from the other side of a door.
	 */
	bool suppress_response;
};

/**
 * Encode an InvokeRequestMessage (app/MessageDef/InvokeRequestMessage.h:41-43).
 *
 *   { suppressResponse, timedRequest,
 *     InvokeRequests: [ { CommandPath: {endpoint, cluster, command},
 *                         CommandFields? } ],
 *     interactionModelRevision }
 *
 * No CommandRef is sent. It exists to match responses to requests inside a
 * BATCH, and with one command per message the response has nothing to be
 * ambiguous about.
 *
 * @return MATTER_OK, MATTER_E_INVAL, or MATTER_E_NOSPACE.
 */
int matter_im_client_invoke_encode(const struct matter_im_client_invoke *inv, uint8_t *out,
				   size_t cap, size_t *out_len);

/**
 * Encode a TimedRequestMessage (app/MessageDef/TimedRequestMessage.h).
 *
 * @param timeout_ms how long the peer should hold the window open. The invoke
 *        must arrive inside it, so this is a statement about this node's own
 *        latency, not a preference.
 */
int matter_im_client_timed_request_encode(uint16_t timeout_ms, uint8_t *out, size_t cap,
					  size_t *out_len);

/** What came back for the one command that was sent. */
struct matter_im_client_response {
	uint16_t endpoint;
	uint32_t cluster;
	uint32_t command;
	/**
	 * The peer's verdict, as a MATTER_IM_STATUS_* value.
	 *
	 * SUCCESS when the peer answered with DATA rather than a status: a
	 * command that returns a response payload succeeded by definition, and
	 * making the caller special-case that is how a success gets logged as a
	 * failure.
	 */
	uint8_t status;
	/** True when the peer answered with a CommandStatusIB rather than data. */
	bool is_status;
	/** A cluster-specific code accompanying a FAILURE status, when present. */
	uint8_t cluster_status;
	bool has_cluster_status;
	/** The response command's fields, when it carried any. Borrowed. */
	const uint8_t *fields;
	size_t fields_len;
	bool has_fields;
};

/**
 * Decode an InvokeResponseMessage (app/MessageDef/InvokeResponseMessage.h:41-43).
 *
 * Accepts exactly one InvokeResponseIB, which may be either a CommandDataIB
 * (the command answered with data) or a CommandStatusIB (it answered with a
 * status). Both are normal; only their absence is not.
 *
 * @return MATTER_OK, MATTER_E_INVAL for a malformed message or one carrying no
 *         response at all, MATTER_E_NOSPACE for a batch, or whatever the TLV
 *         decoder returned.
 */
int matter_im_client_response_decode(const uint8_t *tlv, size_t len,
				     struct matter_im_client_response *out);

/**
 * The PIN a DoorLock UnlockDoor carries, or no PIN at all.
 *
 * @p pin is the code as its ASCII digits: the spec's PINCode is an octet
 * string and controllers send the digits, not a packed integer.
 */
struct matter_im_client_pin {
	const uint8_t *pin;
	size_t pin_len;
};

/**
 * Write the fields of a DoorLock UnlockDoor. Use as @ref
 * matter_im_client_invoke::fields with a struct matter_im_client_pin as ctx.
 *
 * PINCode is field 0 and OPTIONAL (DoorLock Commands.h). Omitting it is right
 * for a lock that does not require one and is REFUSED by a lock whose
 * RequirePINforRemoteOperation is set -- which is the whole reason the binding
 * entry can carry one. What the PIN costs to store is documented where it is
 * stored, not here.
 *
 * A NULL ctx, or one with no PIN, writes the empty structure a lock that wants
 * no PIN expects.
 */
void matter_im_client_unlock_fields(void *ctx, struct matter_tlv_writer *w, matter_tlv_tag_t tag);

#ifdef __cplusplus
}
#endif

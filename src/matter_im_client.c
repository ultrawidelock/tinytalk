/* SPDX-License-Identifier: ISC */

/*
 * See matter_im_client.h.
 */
#include <tinymatter/matter_im_client.h>

#include <string.h>

#include <tinymatter/matter_im.h>
#include <tinymatter/matter_tlv.h>

/*
 * The same tag numbers matter_im.c defines, from the same source. Repeated
 * rather than shared for the reason matter_case_client.c gives: these are the
 * wire format of one protocol, read by two files, and a header that exports
 * them invites a third.
 */

/* SpecificationDefinedRevisions.h:35 */
#define TAG_IM_REVISION 0xFFu

/* InvokeRequestMessage.h:41-43 */
#define TAG_INVOKE_SUPPRESS_RESPONSE 0u
#define TAG_INVOKE_TIMED_REQUEST     1u
#define TAG_INVOKE_REQUESTS          2u

/* InvokeResponseMessage.h:41-43 */
#define TAG_IRESP_SUPPRESS_RESPONSE 0u
#define TAG_IRESP_RESPONSES         1u

/* InvokeResponseIB.h:37-38 */
#define TAG_IRESPIB_COMMAND 0u
#define TAG_IRESPIB_STATUS  1u

/* CommandDataIB.h:37-39 */
#define TAG_CMDDATA_PATH   0u
#define TAG_CMDDATA_FIELDS 1u

/* CommandPathIB.h:40-42. A LIST, like AttributePathIB. */
#define TAG_CMDPATH_ENDPOINT 0u
#define TAG_CMDPATH_CLUSTER  1u
#define TAG_CMDPATH_COMMAND  2u

/* CommandStatusIB.h:37-39 */
#define TAG_CMDSTATUS_PATH   0u
#define TAG_CMDSTATUS_STATUS 1u

/* StatusIB.h:67-68 */
#define TAG_STATUS_STATUS         0u
#define TAG_STATUS_CLUSTER_STATUS 1u

/* TimedRequestMessage.h */
#define TAG_TIMED_TIMEOUT_MS 0u

/* DoorLock UnlockDoor field 0, PINCode (DoorLock Commands.h). */
#define TAG_DL_UNLOCK_PIN 0u

/** Write one CommandPathIB naming the invoked path. */
static void put_command_path(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint16_t endpoint,
			     uint32_t cluster, uint32_t command)
{
	(void)matter_tlv_start_container(w, tag, MATTER_TLV_LIST);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CMDPATH_ENDPOINT), endpoint);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CMDPATH_CLUSTER), cluster);
	(void)matter_tlv_put_u64(w, MATTER_TLV_CTX(TAG_CMDPATH_COMMAND), command);
	(void)matter_tlv_end_container(w);
}

/**
 * Encode an InvokeRequestMessage carrying exactly one command, with its fields
 * spliced in as an already-encoded TLV structure; returns MATTER_OK on success.
 */
int matter_im_client_invoke_encode(const struct matter_im_client_invoke *inv, uint8_t *out,
				   size_t cap, size_t *out_len)
{
	struct matter_tlv_writer w;

	if (inv == NULL || out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(TAG_INVOKE_SUPPRESS_RESPONSE),
				  inv->suppress_response);
	(void)matter_tlv_put_bool(&w, MATTER_TLV_CTX(TAG_INVOKE_TIMED_REQUEST), inv->timed_request);

	(void)matter_tlv_start_container(&w, MATTER_TLV_CTX(TAG_INVOKE_REQUESTS), MATTER_TLV_ARRAY);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	put_command_path(&w, MATTER_TLV_CTX(TAG_CMDDATA_PATH), inv->endpoint, inv->cluster,
			 inv->command);
	if (inv->fields != NULL) {
		inv->fields(inv->fields_ctx, &w, MATTER_TLV_CTX(TAG_CMDDATA_FIELDS));
	}
	(void)matter_tlv_end_container(&w);
	(void)matter_tlv_end_container(&w);

	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/**
 * Encode a TimedRequestMessage carrying the window the peer should hold open;
 * returns MATTER_OK on success.
 */
int matter_im_client_timed_request_encode(uint16_t timeout_ms, uint8_t *out, size_t cap,
					  size_t *out_len)
{
	struct matter_tlv_writer w;

	if (out == NULL || out_len == NULL) {
		return MATTER_E_INVAL;
	}

	matter_tlv_writer_init(&w, out, cap);
	(void)matter_tlv_start_container(&w, MATTER_TLV_ANON, MATTER_TLV_STRUCTURE);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_TIMED_TIMEOUT_MS), timeout_ms);
	(void)matter_tlv_put_u64(&w, MATTER_TLV_CTX(TAG_IM_REVISION), MATTER_IM_REVISION);
	(void)matter_tlv_end_container(&w);

	return matter_tlv_writer_finish(&w, out_len);
}

/** Read a CommandPathIB the reader is sitting on into @p out. */
static int take_command_path(struct matter_tlv_reader *r, struct matter_im_client_response *out)
{
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		uint64_t v = 0u;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_get_u64(r, &v) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDPATH_ENDPOINT)) {
			out->endpoint = (uint16_t)v;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDPATH_CLUSTER)) {
			out->cluster = (uint32_t)v;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDPATH_COMMAND)) {
			out->command = (uint32_t)v;
		}
	}
	return matter_tlv_exit(r);
}

/** Read a StatusIB the reader is sitting on into @p out. */
static int take_status(struct matter_tlv_reader *r, struct matter_im_client_response *out)
{
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		uint64_t v = 0u;

		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_get_u64(r, &v) != MATTER_OK) {
			return MATTER_E_TYPE;
		}
		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_STATUS_STATUS)) {
			out->status = (uint8_t)v;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_STATUS_CLUSTER_STATUS)) {
			out->cluster_status = (uint8_t)v;
			out->has_cluster_status = true;
		}
	}
	return matter_tlv_exit(r);
}

/** Read one InvokeResponseIB, which is either data or a status, never both. */
static int take_response_ib(struct matter_tlv_reader *r, struct matter_im_client_response *out)
{
	int rc = matter_tlv_enter(r);

	if (rc != MATTER_OK) {
		return rc;
	}
	for (;;) {
		rc = matter_tlv_next(r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}

		if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_IRESPIB_COMMAND)) {
			rc = matter_tlv_enter(r);
			if (rc != MATTER_OK) {
				return rc;
			}
			for (;;) {
				/*
				 * Where the element about to be read STARTS.
				 * end_off stops at a container's head and says
				 * nothing about its body (matter_tlv.h:184-185),
				 * so this is the only way to bound a whole one --
				 * the same technique matter_im.c's
				 * decode_command_data() uses for the inbound
				 * direction.
				 */
				size_t elem_start = r->next_off;

				rc = matter_tlv_next(r);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return rc;
				}
				if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDDATA_PATH)) {
					rc = take_command_path(r, out);
				} else if (matter_tlv_tag(r) ==
					   MATTER_TLV_CTX(TAG_CMDDATA_FIELDS)) {
					/* Borrowed whole -- tag, body and end
					 * marker -- and left undecoded, because
					 * what it means belongs to the cluster
					 * that named the command. */
					if (!matter_tlv_is_container(r)) {
						return MATTER_E_TYPE;
					}
					rc = matter_tlv_enter(r);
					if (rc == MATTER_OK) {
						rc = matter_tlv_exit(r);
					}
					if (rc != MATTER_OK) {
						return rc;
					}
					out->fields = r->buf + elem_start;
					out->fields_len = (size_t)(r->next_off - elem_start);
					out->has_fields = true;
				}
				if (rc != MATTER_OK) {
					return rc;
				}
			}
			rc = matter_tlv_exit(r);
			if (rc != MATTER_OK) {
				return rc;
			}
			/* Data came back, so the command ran. See the header on
			 * why this is not left for the caller to infer. */
			out->status = MATTER_IM_STATUS_SUCCESS;
		} else if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_IRESPIB_STATUS)) {
			out->is_status = true;
			rc = matter_tlv_enter(r);
			if (rc != MATTER_OK) {
				return rc;
			}
			for (;;) {
				rc = matter_tlv_next(r);
				if (rc == MATTER_END) {
					break;
				}
				if (rc != MATTER_OK) {
					return rc;
				}
				if (matter_tlv_tag(r) == MATTER_TLV_CTX(TAG_CMDSTATUS_PATH)) {
					rc = take_command_path(r, out);
				} else if (matter_tlv_tag(r) ==
					   MATTER_TLV_CTX(TAG_CMDSTATUS_STATUS)) {
					rc = take_status(r, out);
				}
				if (rc != MATTER_OK) {
					return rc;
				}
			}
			rc = matter_tlv_exit(r);
			if (rc != MATTER_OK) {
				return rc;
			}
		}
	}
	return matter_tlv_exit(r);
}

/**
 * Decode an InvokeResponseMessage carrying exactly one response, which may be
 * command data or a command status; returns MATTER_OK on success.
 */
int matter_im_client_response_decode(const uint8_t *tlv, size_t len,
				     struct matter_im_client_response *out)
{
	struct matter_tlv_reader r;
	unsigned int seen = 0u;
	int rc;

	if (tlv == NULL || out == NULL) {
		return MATTER_E_INVAL;
	}
	memset(out, 0, sizeof(*out));

	matter_tlv_reader_init(&r, tlv, len);
	rc = matter_tlv_next(&r);
	if (rc != MATTER_OK) {
		return (rc == MATTER_END) ? MATTER_E_INVAL : rc;
	}
	if (matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
		return MATTER_E_TYPE;
	}
	rc = matter_tlv_enter(&r);
	if (rc != MATTER_OK) {
		return rc;
	}

	for (;;) {
		rc = matter_tlv_next(&r);
		if (rc == MATTER_END) {
			break;
		}
		if (rc != MATTER_OK) {
			return rc;
		}
		if (matter_tlv_tag(&r) != MATTER_TLV_CTX(TAG_IRESP_RESPONSES)) {
			/* SuppressResponse, MoreChunkedMessages and the
			 * revision, none of which change what was asked. */
			continue;
		}
		if (matter_tlv_element_type(&r) != MATTER_TLV_ARRAY) {
			return MATTER_E_TYPE;
		}
		rc = matter_tlv_enter(&r);
		if (rc != MATTER_OK) {
			return rc;
		}
		for (;;) {
			rc = matter_tlv_next(&r);
			if (rc == MATTER_END) {
				break;
			}
			if (rc != MATTER_OK) {
				return rc;
			}
			if (matter_tlv_element_type(&r) != MATTER_TLV_STRUCTURE) {
				return MATTER_E_TYPE;
			}
			seen++;
			/* One command was sent, so more than one response is
			 * the peer answering a question nobody asked. */
			if (seen > 1u) {
				return MATTER_E_NOSPACE;
			}
			rc = take_response_ib(&r, out);
			if (rc != MATTER_OK) {
				return rc;
			}
		}
		rc = matter_tlv_exit(&r);
		if (rc != MATTER_OK) {
			return rc;
		}
	}

	if (seen != 1u) {
		return MATTER_E_INVAL;
	}
	return matter_tlv_exit(&r);
}

/**
 * Write the fields of a DoorLock UnlockDoor, carrying the PIN when one was
 * supplied and omitting the field entirely when not.
 */
void matter_im_client_unlock_fields(void *ctx, struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	const struct matter_im_client_pin *p = (const struct matter_im_client_pin *)ctx;

	(void)matter_tlv_start_container(w, tag, MATTER_TLV_STRUCTURE);
	if (p != NULL && p->pin != NULL && p->pin_len > 0u) {
		(void)matter_tlv_put_bytes(w, MATTER_TLV_CTX(TAG_DL_UNLOCK_PIN), p->pin, p->pin_len);
	}
	(void)matter_tlv_end_container(w);
}

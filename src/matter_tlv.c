/* SPDX-License-Identifier: ISC */

/**
 * @file matter_tlv.c — Matter TLV codec, encoder then decoder.
 *
 * Control byte = tag control (top 3 bits) | element type (bottom 5). Then the
 * tag octets, then the value. Everything multi-octet is little-endian.
 */
/*
 * Two decisions worth stating, because both are about the 528 B of headroom the
 * thread analyzer measured on this part's system work queue:
 *
 *   - No recursion anywhere. Depth is a counter.
 *   - No dynamic allocation. The caller owns the buffer.
 *
 * Integers are written in the smallest width that holds the value, which is
 * what the spec calls for and what CHIP's own encoder does, so its golden
 * vectors only match if this matches. Getting it wrong the other way (always
 * 8 octets) still decodes correctly everywhere and would pass a round-trip
 * test -- another reason the tests pin CHIP's bytes rather than round-tripping.
 */
#include <string.h>

#include <tinytalk/matter_tlv.h>

/* Tag controls, TLVTags.h:105-112. */
#define TC_ANON       0x00u
#define TC_CONTEXT    0x20u
#define TC_COMMON_2   0x40u
#define TC_COMMON_4   0x60u
#define TC_IMPLICIT_2 0x80u
#define TC_IMPLICIT_4 0xA0u
#define TC_FULLQUAL_6 0xC0u
#define TC_FULLQUAL_8 0xE0u

/* Element types, TLVTypes.h:60-86. */
#define ET_INT8          0x00u
#define ET_INT16         0x01u
#define ET_INT32         0x02u
#define ET_INT64         0x03u
#define ET_UINT8         0x04u
#define ET_UINT16        0x05u
#define ET_UINT32        0x06u
#define ET_UINT64        0x07u
#define ET_BOOL_FALSE    0x08u
#define ET_BOOL_TRUE     0x09u
#define ET_UTF8_LEN1     0x0Cu
#define ET_UTF8_LEN2     0x0Du
#define ET_UTF8_LEN4     0x0Eu
#define ET_UTF8_LEN8     0x0Fu
#define ET_BYTES_LEN1    0x10u
#define ET_BYTES_LEN2    0x11u
#define ET_BYTES_LEN4    0x12u
#define ET_BYTES_LEN8    0x13u
#define ET_NULL          0x14u
#define ET_END_CONTAINER 0x18u

/**
 * Extract the profile (upper 32 bits) from a qualified tag.
 */
static uint32_t tag_profile(matter_tlv_tag_t tag)
{
	return (uint32_t)(tag >> 32);
}

/**
 * Extract the number (lower 32 bits) from a qualified tag.
 */
static uint32_t tag_number(matter_tlv_tag_t tag)
{
	return (uint32_t)(tag & 0xFFFFFFFFu);
}

/** Latch the first error and report whether the writer is still usable. */
static bool fail(struct matter_tlv_writer *w, int rc)
{
	if (w->rc == MATTER_TLV_OK) {
		w->rc = rc;
	}
	return false;
}

/**
 * Test whether writing n bytes would exceed the writer's capacity.
 * Fails the writer and latches the error code if buffer is NULL or space is exhausted; returns true
 * if write can proceed.
 */
static bool room(struct matter_tlv_writer *w, size_t n)
{
	if (w->buf == NULL) {
		return fail(w, MATTER_TLV_E_INVAL);
	}
	if (n > w->cap - w->len) {
		return fail(w, MATTER_TLV_E_NOSPACE);
	}
	return true;
}

/**
 * Copy n bytes from src into the writer buffer at the current position, advancing the position.
 */
static void put_raw(struct matter_tlv_writer *w, const void *src, size_t n)
{
	memcpy(&w->buf[w->len], src, n);
	w->len += n;
}

/** Little-endian, n in 1/2/4/8. */
static void put_le(struct matter_tlv_writer *w, uint64_t v, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		w->buf[w->len + i] = (uint8_t)(v >> (8u * i));
	}
	w->len += n;
}

/**
 * Emit the control byte and tag octets.
 *
 * The tag control is chosen here, and the choice is where an encoder usually
 * goes wrong: a profile tag is written implicit only when it matches the
 * writer's nominated implicit profile, common when the profile is 0, and fully
 * qualified otherwise. A fully-qualified tag splits the 32-bit profile ID into
 * vendor (high 16) then profile number (low 16), each little-endian, ahead of
 * the tag number -- verified against CHIP's Encoding3, where profile
 * 0xAABBCCDD and tag 1 encode as BB AA DD CC 01 00.
 */
static bool put_tag(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint8_t element_type)
{
	uint32_t profile = tag_profile(tag);
	uint32_t number = tag_number(tag);
	uint8_t control;
	size_t tag_octets;

	if (profile == MATTER_TLV_SPECIAL_PROFILE) {
		if (number == MATTER_TLV_ANON_TAG_NUM) {
			control = TC_ANON;
			tag_octets = 0u;
		} else if (number <= UINT8_MAX) {
			control = TC_CONTEXT;
			tag_octets = 1u;
		} else {
			return fail(w, MATTER_TLV_E_INVAL);
		}
	} else if (profile == MATTER_TLV_COMMON_PROFILE) {
		control = (number <= UINT16_MAX) ? TC_COMMON_2 : TC_COMMON_4;
		tag_octets = (number <= UINT16_MAX) ? 2u : 4u;
	} else if (w->implicit_set && profile == w->implicit_profile) {
		control = (number <= UINT16_MAX) ? TC_IMPLICIT_2 : TC_IMPLICIT_4;
		tag_octets = (number <= UINT16_MAX) ? 2u : 4u;
	} else {
		control = (number <= UINT16_MAX) ? TC_FULLQUAL_6 : TC_FULLQUAL_8;
		tag_octets = (number <= UINT16_MAX) ? 6u : 8u;
	}

	if (!room(w, 1u + tag_octets)) {
		return false;
	}

	w->buf[w->len++] = (uint8_t)(control | element_type);

	if (control == TC_FULLQUAL_6 || control == TC_FULLQUAL_8) {
		put_le(w, (profile >> 16) & 0xFFFFu, 2u); /* vendor ID */
		put_le(w, profile & 0xFFFFu, 2u);         /* profile number */
		put_le(w, number, tag_octets - 4u);
	} else if (tag_octets != 0u) {
		put_le(w, number, tag_octets);
	}

	return true;
}

/** True while the writer is healthy. Every public entry point starts here. */
static bool live(struct matter_tlv_writer *w)
{
	return w != NULL && w->rc == MATTER_TLV_OK;
}

/**
 * Initialize a TLV writer to build a buffer.
 * Sets writer to start-of-buffer state with no depth or errors; if buf is NULL, writes fail
 * silently.
 */
void matter_tlv_writer_init(struct matter_tlv_writer *w, uint8_t *buf, size_t cap)
{
	if (w == NULL) {
		return;
	}
	memset(w, 0, sizeof(*w));
	w->buf = buf;
	w->cap = cap;
}

/**
 * Set the implicit tag profile for subsequent context-tag (CTX) writes.
 * Allows the writer to omit the profile qualifier in context tags, compressing the wire format.
 */
void matter_tlv_writer_set_implicit_profile(struct matter_tlv_writer *w, uint32_t profile)
{
	if (w == NULL) {
		return;
	}
	w->implicit_profile = profile;
	w->implicit_set = true;
}

/**
 * Append a boolean value to the TLV output.
 * Encodes as control byte indicating true or false, with the given tag.
 * Returns MATTER_TLV_E_INVAL if writer is NULL; returns the writer's cached error if previous write
 * failed.
 */
int matter_tlv_put_bool(struct matter_tlv_writer *w, matter_tlv_tag_t tag, bool v)
{
	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}
	(void)put_tag(w, tag, v ? ET_BOOL_TRUE : ET_BOOL_FALSE);
	return w->rc;
}

/**
 * Append a null value to the TLV output.
 * Encodes as control byte with no value, with the given tag.
 * Returns MATTER_TLV_E_INVAL if writer is NULL; returns the writer's cached error if previous write
 * failed.
 */
int matter_tlv_put_null(struct matter_tlv_writer *w, matter_tlv_tag_t tag)
{
	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}
	(void)put_tag(w, tag, ET_NULL);
	return w->rc;
}

/**
 * Write a signed 64-bit integer to TLV with automatic width selection (1/2/4/8 bytes based on value
 * range). Returns first error encountered in writer, which is latched and persists across calls.
 */
int matter_tlv_put_i64(struct matter_tlv_writer *w, matter_tlv_tag_t tag, int64_t v)
{
	uint8_t type;
	size_t width;

	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}

	if (v >= INT8_MIN && v <= INT8_MAX) {
		type = ET_INT8;
		width = 1u;
	} else if (v >= INT16_MIN && v <= INT16_MAX) {
		type = ET_INT16;
		width = 2u;
	} else if (v >= INT32_MIN && v <= INT32_MAX) {
		type = ET_INT32;
		width = 4u;
	} else {
		type = ET_INT64;
		width = 8u;
	}

	if (!put_tag(w, tag, type) || !room(w, width)) {
		return w->rc;
	}
	put_le(w, (uint64_t)v, width);
	return w->rc;
}

/**
 * Write an unsigned 64-bit integer to TLV with automatic width selection (1/2/4/8 bytes based on
 * value range). Returns first error encountered in writer, which is latched and persists across
 * calls.
 */
int matter_tlv_put_u64(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint64_t v)
{
	uint8_t type;
	size_t width;

	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}

	if (v <= UINT8_MAX) {
		type = ET_UINT8;
		width = 1u;
	} else if (v <= UINT16_MAX) {
		type = ET_UINT16;
		width = 2u;
	} else if (v <= UINT32_MAX) {
		type = ET_UINT32;
		width = 4u;
	} else {
		type = ET_UINT64;
		width = 8u;
	}

	if (!put_tag(w, tag, type) || !room(w, width)) {
		return w->rc;
	}
	put_le(w, v, width);
	return w->rc;
}

/** Shared body for the two string types; they differ only in the element-type base. */
static int put_string(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint8_t type_len1,
		      const void *data, size_t len)
{
	uint8_t type;
	size_t len_octets;

	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}
	if (data == NULL && len != 0u) {
		(void)fail(w, MATTER_TLV_E_INVAL);
		return w->rc;
	}

	if (len <= UINT8_MAX) {
		type = type_len1;
		len_octets = 1u;
	} else if (len <= UINT16_MAX) {
		type = (uint8_t)(type_len1 + 1u);
		len_octets = 2u;
	} else {
		/* 4-octet lengths are reachable in principle; an 8-octet one is not
		 * on a part with 128 KB of RAM, so it is rejected rather than
		 * carried as untestable code. */
		type = (uint8_t)(type_len1 + 2u);
		len_octets = 4u;
	}

	if (!put_tag(w, tag, type) || !room(w, len_octets + len)) {
		return w->rc;
	}
	put_le(w, (uint64_t)len, len_octets);
	if (len != 0u) {
		put_raw(w, data, len);
	}
	return w->rc;
}

/**
 * Append a UTF-8 string to the TLV output.
 * Encodes length-prefixed text string with the given tag.
 * Returns the writer's cached error if previous write failed or no space.
 */
int matter_tlv_put_utf8(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const char *s,
			size_t len)
{
	return put_string(w, tag, ET_UTF8_LEN1, s, len);
}

/**
 * Append a byte string to the TLV output.
 * Encodes length-prefixed byte array with the given tag.
 * Returns the writer's cached error if previous write failed or no space.
 */
int matter_tlv_put_bytes(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const uint8_t *b,
			 size_t len)
{
	return put_string(w, tag, ET_BYTES_LEN1, b, len);
}

/**
 * Begin a new TLV container (structure, array, or list) in the output.
 * Records the container tag and depth; the writer will track where to close it when end_container
 * is called.
 * Returns MATTER_TLV_E_INVAL if writer is NULL or type is invalid; returns MATTER_TLV_E_DEPTH if
 * nesting exceeds MATTER_TLV_MAX_DEPTH.
 */
int matter_tlv_start_container(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint8_t type)
{
	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}
	if (type != MATTER_TLV_STRUCTURE && type != MATTER_TLV_ARRAY && type != MATTER_TLV_LIST) {
		(void)fail(w, MATTER_TLV_E_INVAL);
		return w->rc;
	}
	if (w->depth >= MATTER_TLV_MAX_DEPTH) {
		(void)fail(w, MATTER_TLV_E_DEPTH);
		return w->rc;
	}
	if (put_tag(w, tag, type)) {
		w->depth++;
	}
	return w->rc;
}

/**
 * Close the current TLV container by writing the end-of-container control byte and decrementing
 * depth. Caller must have opened a container; fails if depth is already zero.
 */
int matter_tlv_end_container(struct matter_tlv_writer *w)
{
	if (!live(w)) {
		return w == NULL ? MATTER_TLV_E_INVAL : w->rc;
	}
	if (w->depth == 0u) {
		(void)fail(w, MATTER_TLV_E_STATE);
		return w->rc;
	}
	if (!room(w, 1u)) {
		return w->rc;
	}
	/* End-of-container carries no tag, so it is a bare control byte. */
	w->buf[w->len++] = ET_END_CONTAINER;
	w->depth--;
	return w->rc;
}

/**
 * Finalize TLV encoding and report the encoded byte count.
 * Validates all containers have been closed (depth is zero).
 * Returns MATTER_TLV_E_INVAL if writer is NULL; returns MATTER_TLV_E_STATE if containers remain
 * open; returns the writer's cached error if previous write failed.
 */
int matter_tlv_writer_finish(struct matter_tlv_writer *w, size_t *out_len)
{
	if (w == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (w->rc != MATTER_TLV_OK) {
		return w->rc;
	}
	if (w->depth != 0u) {
		return fail(w, MATTER_TLV_E_STATE), w->rc;
	}
	if (out_len != NULL) {
		*out_len = w->len;
	}
	return MATTER_TLV_OK;
}

/* ----------------------------------------------------------------- decoder --
 *
 * Bounds are checked before every read, not after, and the parse of one element
 * never trusts a length it has not first fitted inside the buffer. The nesting
 * walk is a counter, so a peer cannot pick this firmware's stack depth.
 */

/** One parsed element. Purely local; the reader copies the fields it keeps. */
struct elem {
	uint8_t type;
	matter_tlv_tag_t tag;
	size_t val_off;
	size_t val_len;
	size_t body_off;
	size_t end;
	bool is_container;
};

/** Tag octet count for each tag control, indexed by control >> 5. */
static const uint8_t tag_octets_by_control[8] = {0u, 1u, 2u, 4u, 2u, 4u, 6u, 8u};

/**
 * Test whether reading n bytes at offset off would stay within reader bounds.
 */
static bool fits(const struct matter_tlv_reader *r, size_t off, size_t n)
{
	return off <= r->len && n <= r->len - off;
}

/**
 * Read an n-byte little-endian unsigned integer from buffer.
 * Returns the value as uint64_t; n must be in range [1, 8].
 */
static uint64_t read_le(const uint8_t *p, size_t n)
{
	uint64_t v = 0;

	for (size_t i = 0; i < n; i++) {
		v |= (uint64_t)p[i] << (8u * i);
	}
	return v;
}

/**
 * Parse the element whose control byte is at @p off.
 *
 * Does not follow container bodies: for a container, end == body_off and the
 * caller decides whether to enter or skip. That is what keeps this function
 * non-recursive.
 */
static int parse_at(const struct matter_tlv_reader *r, size_t off, struct elem *e)
{
	uint8_t control;
	uint8_t tag_octets;
	size_t after_tag;
	size_t width;

	if (!fits(r, off, 1u)) {
		return MATTER_TLV_E_TRUNC;
	}

	control = (uint8_t)(r->buf[off] & 0xE0u);
	e->type = (uint8_t)(r->buf[off] & 0x1Fu);
	tag_octets = tag_octets_by_control[control >> 5];

	if (!fits(r, off + 1u, tag_octets)) {
		return MATTER_TLV_E_TRUNC;
	}

	const uint8_t *tp = &r->buf[off + 1u];

	switch (control) {
	case TC_ANON:
		e->tag = MATTER_TLV_ANON;
		break;
	case TC_CONTEXT:
		e->tag = MATTER_TLV_TAG(MATTER_TLV_SPECIAL_PROFILE, tp[0]);
		break;
	case TC_COMMON_2:
	case TC_COMMON_4:
		e->tag = MATTER_TLV_TAG(MATTER_TLV_COMMON_PROFILE, read_le(tp, tag_octets));
		break;
	case TC_IMPLICIT_2:
	case TC_IMPLICIT_4:
		/* Refused rather than guessed: with no implicit profile supplied there
		 * is no correct value, and inventing one mislabels the tag silently. */
		if (!r->implicit_set) {
			return MATTER_TLV_E_INVAL;
		}
		e->tag = MATTER_TLV_TAG(r->implicit_profile, read_le(tp, tag_octets));
		break;
	default: { /* TC_FULLQUAL_6 / TC_FULLQUAL_8 */
		uint32_t vendor = (uint32_t)read_le(tp, 2u);
		uint32_t profile_num = (uint32_t)read_le(tp + 2u, 2u);

		e->tag = MATTER_TLV_TAG((vendor << 16) | profile_num,
					read_le(tp + 4u, (size_t)tag_octets - 4u));
		break;
	}
	}

	after_tag = off + 1u + tag_octets;
	e->is_container = false;
	e->body_off = 0u;
	e->val_off = after_tag;
	e->val_len = 0u;

	if (e->type <= ET_UINT64) {
		width = (size_t)1u << (e->type & 0x03u);
		if (!fits(r, after_tag, width)) {
			return MATTER_TLV_E_TRUNC;
		}
		e->val_len = width;
		e->end = after_tag + width;
	} else if (e->type == ET_BOOL_FALSE || e->type == ET_BOOL_TRUE || e->type == ET_NULL) {
		e->end = after_tag;
	} else if (e->type >= ET_UTF8_LEN1 && e->type <= ET_BYTES_LEN8) {
		size_t len_octets = (size_t)1u << (e->type & 0x03u);
		uint64_t payload;

		if (!fits(r, after_tag, len_octets)) {
			return MATTER_TLV_E_TRUNC;
		}
		payload = read_le(&r->buf[after_tag], len_octets);
		e->val_off = after_tag + len_octets;
		/* Compare in uint64 before narrowing: a declared length near 2^64 must
		 * be rejected, not wrapped into something that fits. */
		if (payload > (uint64_t)(r->len - e->val_off)) {
			return MATTER_TLV_E_TRUNC;
		}
		e->val_len = (size_t)payload;
		e->end = e->val_off + e->val_len;
	} else if (e->type >= MATTER_TLV_STRUCTURE && e->type <= MATTER_TLV_LIST) {
		e->is_container = true;
		e->body_off = after_tag;
		e->end = after_tag;
	} else {
		/* Includes ET_END_CONTAINER, which callers handle before reaching here,
		 * and every unassigned type value. */
		return MATTER_TLV_E_INVAL;
	}

	return MATTER_TLV_OK;
}

/**
 * Walk forward from @p from to just past the end-of-container marker that
 * closes the level @p from sits in.
 *
 * The nesting counter is the whole trick, and it is capped: deeply nested input
 * costs one loop iteration per element and never a stack frame.
 */
static int scan_past_level_end(const struct matter_tlv_reader *r, size_t from, size_t *out)
{
	size_t off = from;
	unsigned int nest = 0u;

	for (;;) {
		struct elem e;
		int rc;

		if (!fits(r, off, 1u)) {
			return MATTER_TLV_E_TRUNC;
		}
		if (r->buf[off] == ET_END_CONTAINER) {
			off++;
			if (nest == 0u) {
				*out = off;
				return MATTER_TLV_OK;
			}
			nest--;
			continue;
		}

		rc = parse_at(r, off, &e);
		if (rc != MATTER_TLV_OK) {
			return rc;
		}
		if (e.is_container) {
			if (nest >= MATTER_TLV_MAX_DEPTH) {
				return MATTER_TLV_E_DEPTH;
			}
			nest++;
			off = e.body_off;
		} else {
			off = e.end;
		}
	}
}

/**
 * Initialize a TLV reader to parse a buffer.
 * Sets reader to start-of-buffer state; if buf is NULL, len is set to zero and all reads will fail.
 */
void matter_tlv_reader_init(struct matter_tlv_reader *r, const uint8_t *buf, size_t len)
{
	if (r == NULL) {
		return;
	}
	memset(r, 0, sizeof(*r));
	r->buf = buf;
	r->len = (buf == NULL) ? 0u : len;
}

/**
 * Set the implicit tag profile for subsequent context-tag (CTX) reads.
 * Allows the reader to interpret context tags in messages that omit the profile qualifier in the
 * wire format.
 */
void matter_tlv_reader_set_implicit_profile(struct matter_tlv_reader *r, uint32_t profile)
{
	if (r == NULL) {
		return;
	}
	r->implicit_profile = profile;
	r->implicit_set = true;
}

/**
 * Load the next TLV element from the buffer, advancing the reader position.
 * Parses the control byte and tag at the current offset; skips end-of-container markers at top
 * level.
 * Returns MATTER_TLV_OK on success, MATTER_TLV_END when end-of-container marker is reached,
 * MATTER_TLV_E_TRUNC if buffer is incomplete, MATTER_TLV_E_TYPE or MATTER_TLV_E_INVAL on malformed
 * data.
 */
int matter_tlv_next(struct matter_tlv_reader *r)
{
	size_t start;
	struct elem e;
	int rc;

	if (r == NULL || r->buf == NULL) {
		return MATTER_TLV_E_INVAL;
	}

	if (!r->have) {
		start = r->next_off;
	} else if (r->is_container) {
		/* Loaded but never entered, so step over the whole thing. */
		rc = scan_past_level_end(r, r->body_off, &start);
		if (rc != MATTER_TLV_OK) {
			return rc;
		}
	} else {
		start = r->end_off;
	}

	r->have = false;

	if (start >= r->len) {
		/* Running out of bytes is the end at the top level and a truncation
		 * anywhere else -- an open container owes us its end marker. */
		return (r->depth == 0u) ? MATTER_TLV_END : MATTER_TLV_E_TRUNC;
	}

	if (r->buf[start] == ET_END_CONTAINER) {
		if (r->depth == 0u) {
			return MATTER_TLV_E_INVAL;
		}
		r->next_off = start;
		return MATTER_TLV_END;
	}

	rc = parse_at(r, start, &e);
	if (rc != MATTER_TLV_OK) {
		return rc;
	}

	r->type = e.type;
	r->tag = e.tag;
	r->val_off = e.val_off;
	r->val_len = e.val_len;
	r->body_off = e.body_off;
	r->end_off = e.end;
	r->is_container = e.is_container;
	r->next_off = e.end;
	r->have = true;
	return MATTER_TLV_OK;
}

/**
 * Return the tag of the loaded TLV element.
 * Returns the tag value (profile-qualified or anonymous) or MATTER_TLV_ANON if no element loaded or
 * reader is NULL.
 */
matter_tlv_tag_t matter_tlv_tag(const struct matter_tlv_reader *r)
{
	return (r != NULL && r->have) ? r->tag : MATTER_TLV_ANON;
}

/**
 * Return the element type of the loaded TLV element.
 * Returns the numeric type code (MATTER_TLV_STRUCTURE, MATTER_TLV_ARRAY, etc.) or zero if no
 * element loaded or reader is NULL.
 */
uint8_t matter_tlv_element_type(const struct matter_tlv_reader *r)
{
	return (r != NULL && r->have) ? r->type : 0u;
}

/**
 * Test whether the loaded TLV element is a container (structure, array, or list).
 * Returns true if reader is not NULL, an element is loaded, and it is a container; false otherwise.
 */
bool matter_tlv_is_container(const struct matter_tlv_reader *r)
{
	return r != NULL && r->have && r->is_container;
}

/**
 * Extract a boolean value from the current TLV element.
 * Returns MATTER_TLV_E_INVAL if reader or out is NULL; returns MATTER_TLV_E_STATE if no element
 * loaded; returns MATTER_TLV_E_TYPE if element is not a boolean type.
 */
int matter_tlv_get_bool(const struct matter_tlv_reader *r, bool *out)
{
	if (r == NULL || out == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (!r->have) {
		return MATTER_TLV_E_STATE;
	}
	if (r->type != ET_BOOL_FALSE && r->type != ET_BOOL_TRUE) {
		return MATTER_TLV_E_TYPE;
	}
	*out = (r->type == ET_BOOL_TRUE);
	return MATTER_TLV_OK;
}

/**
 * Decode an unsigned 64-bit integer from the current TLV element: read little-endian bytes. Returns
 * MATTER_TLV_E_TYPE if element type is not an unsigned integer (UINT8..UINT64).
 */
int matter_tlv_get_u64(const struct matter_tlv_reader *r, uint64_t *out)
{
	if (r == NULL || out == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (!r->have) {
		return MATTER_TLV_E_STATE;
	}
	if (r->type < ET_UINT8 || r->type > ET_UINT64) {
		return MATTER_TLV_E_TYPE;
	}
	*out = read_le(&r->buf[r->val_off], r->val_len);
	return MATTER_TLV_OK;
}

/**
 * Decode a signed 64-bit integer from the current TLV element: read little-endian bytes and
 * sign-extend if shorter than 64 bits. Returns MATTER_TLV_E_TYPE if element type is not a signed
 * integer.
 */
int matter_tlv_get_i64(const struct matter_tlv_reader *r, int64_t *out)
{
	uint64_t raw;
	unsigned int bits;

	if (r == NULL || out == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (!r->have) {
		return MATTER_TLV_E_STATE;
	}
	if (r->type > ET_INT64) {
		return MATTER_TLV_E_TYPE;
	}

	raw = read_le(&r->buf[r->val_off], r->val_len);
	bits = (unsigned int)(8u * r->val_len);
	if (bits < 64u) {
		/* Sign-extend by hand. Shifting a negative signed value is
		 * implementation-defined, so the arithmetic stays unsigned until the
		 * final conversion. */
		uint64_t sign_bit = (uint64_t)1u << (bits - 1u);

		if ((raw & sign_bit) != 0u) {
			raw |= ~(((uint64_t)1u << bits) - 1u);
		}
	}
	*out = (int64_t)raw;
	return MATTER_TLV_OK;
}

/**
 * Extract a byte or UTF-8 span from the current TLV element.
 * Validates element type matches the allowed range [lo, hi], returns pointer into buffer and byte
 * count.
 * Returns MATTER_TLV_E_INVAL if out or len is NULL; returns MATTER_TLV_E_STATE if no element
 * loaded; returns MATTER_TLV_E_TYPE if element type is outside range.
 */
static int get_span(const struct matter_tlv_reader *r, uint8_t lo, uint8_t hi, const void **out,
		    size_t *len)
{
	if (r == NULL || out == NULL || len == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (!r->have) {
		return MATTER_TLV_E_STATE;
	}
	if (r->type < lo || r->type > hi) {
		return MATTER_TLV_E_TYPE;
	}
	*out = &r->buf[r->val_off];
	*len = r->val_len;
	return MATTER_TLV_OK;
}

/**
 * Extract a byte or UTF-8 span from the current TLV element. Returns pointer and length in output
 * parameters; returns MATTER_TLV_E_TYPE if element is not a byte or UTF-8 span.
 */
int matter_tlv_get_bytes(const struct matter_tlv_reader *r, const uint8_t **out, size_t *len)
{
	return get_span(r, ET_BYTES_LEN1, ET_BYTES_LEN8, (const void **)out, len);
}

/**
 * Extract a UTF-8 string from the current TLV element. Returns pointer and length in output
 * parameters; returns MATTER_TLV_E_TYPE if element is not a UTF-8 span.
 */
int matter_tlv_get_utf8(const struct matter_tlv_reader *r, const char **out, size_t *len)
{
	return get_span(r, ET_UTF8_LEN1, ET_UTF8_LEN8, (const void **)out, len);
}

/**
 * Descend one level into the current TLV container element.
 * Prepares the reader to iterate elements within the container body.
 * Returns MATTER_TLV_E_INVAL if reader is NULL; returns MATTER_TLV_E_STATE if no container is
 * loaded; returns MATTER_TLV_E_DEPTH if nesting exceeds MATTER_TLV_MAX_DEPTH.
 */
int matter_tlv_enter(struct matter_tlv_reader *r)
{
	if (r == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (!r->have || !r->is_container) {
		return MATTER_TLV_E_STATE;
	}
	if (r->depth >= MATTER_TLV_MAX_DEPTH) {
		return MATTER_TLV_E_DEPTH;
	}
	r->depth++;
	r->next_off = r->body_off;
	r->have = false;
	return MATTER_TLV_OK;
}

/**
 * Ascend one level out of a TLV container.
 * Skips any unread elements within the current level and steps past the end-of-container marker.
 * Returns MATTER_TLV_E_INVAL if reader is NULL; returns MATTER_TLV_E_STATE if at top level; returns
 * MATTER_TLV_E_TRUNC if container is not properly closed.
 */
int matter_tlv_exit(struct matter_tlv_reader *r)
{
	size_t from;
	size_t past;
	int rc;

	if (r == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (r->depth == 0u) {
		return MATTER_TLV_E_STATE;
	}

	if (!r->have) {
		from = r->next_off;
	} else if (r->is_container) {
		rc = scan_past_level_end(r, r->body_off, &from);
		if (rc != MATTER_TLV_OK) {
			return rc;
		}
	} else {
		from = r->end_off;
	}

	rc = scan_past_level_end(r, from, &past);
	if (rc != MATTER_TLV_OK) {
		return rc;
	}

	r->depth--;
	r->next_off = past;
	r->have = false;
	return MATTER_TLV_OK;
}

/**
 * Re-tag a context-tagged TLV element by substituting its tag byte: input element must be
 * context-tagged (tag form 0xE0 bits set) and both source and destination tags must be context
 * tags. Single-byte substitution without re-encoding value or length. Returns MATTER_TLV_E_INVAL if
 * input is not a valid context-tagged element or destination tag is out of range.
 */
int matter_tlv_put_encoded(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const uint8_t *elem,
			   size_t len)
{
	if (w == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (w->rc != MATTER_TLV_OK) {
		return w->rc;
	}
	/*
	 * Both tags must be context tags, which makes the whole re-tagging a
	 * one-byte substitution: a context-tagged element is control, tag,
	 * value, and only the tag byte differs between "attribute 2 of a write"
	 * and "attribute 1 of a report". Anything else would mean re-encoding
	 * the header, and this helper exists precisely because re-encoding a
	 * value whose type it does not know is what it must not do.
	 */
	if (elem == NULL || len < 2u || (elem[0] & 0xE0u) != TC_CONTEXT) {
		w->rc = MATTER_TLV_E_INVAL;
		return w->rc;
	}
	if (tag_profile(tag) != MATTER_TLV_SPECIAL_PROFILE || tag_number(tag) > 0xFFu) {
		w->rc = MATTER_TLV_E_INVAL;
		return w->rc;
	}
	if (w->buf == NULL || w->cap - w->len < len) {
		w->rc = MATTER_TLV_E_NOSPACE;
		return w->rc;
	}

	memcpy(w->buf + w->len, elem, len);
	w->buf[w->len + 1u] = (uint8_t)tag_number(tag);
	w->len += len;
	return MATTER_TLV_OK;
}

int matter_tlv_put_encoded_anon(struct matter_tlv_writer *w, const uint8_t *elem, size_t len)
{
	if (w == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (w->rc != MATTER_TLV_OK) {
		return w->rc;
	}
	if (elem == NULL || len < 2u || (elem[0] & 0xE0u) != TC_CONTEXT) {
		w->rc = MATTER_TLV_E_INVAL;
		return w->rc;
	}
	/*
	 * One byte SHORTER than the source, which is the whole difference from
	 * the context-tagged case: an anonymous element is control then value,
	 * with no tag byte between them. The control byte keeps its type and
	 * length bits and loses only its tag control.
	 */
	if (w->buf == NULL || w->cap - w->len < len - 1u) {
		w->rc = MATTER_TLV_E_NOSPACE;
		return w->rc;
	}

	w->buf[w->len] = (uint8_t)((elem[0] & 0x1Fu) | TC_ANON);
	memcpy(w->buf + w->len + 1u, elem + 2u, len - 2u);
	w->len += len - 1u;
	return MATTER_TLV_OK;
}

int matter_tlv_put_raw(struct matter_tlv_writer *w, const uint8_t *bytes, size_t len)
{
	if (w == NULL) {
		return MATTER_TLV_E_INVAL;
	}
	if (w->rc != MATTER_TLV_OK) {
		return w->rc;
	}
	if (bytes == NULL) {
		w->rc = MATTER_TLV_E_INVAL;
		return w->rc;
	}
	if (len == 0u) {
		return MATTER_TLV_OK;
	}
	if (w->buf == NULL || w->cap - w->len < len) {
		w->rc = MATTER_TLV_E_NOSPACE;
		return w->rc;
	}

	put_raw(w, bytes, len);
	return MATTER_TLV_OK;
}

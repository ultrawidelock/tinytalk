/* SPDX-License-Identifier: ISC */

/**
 * @file matter_tlv.h — Matter TLV codec (Matter Core spec, Appendix A).
 *
 * This is NOT BER/DER-TLV.
 * Matter uses its own encoding: one control byte carrying a 3-bit tag control
 * and a 5-bit element type, then 0-8 tag octets, then the value, all
 * little-endian. The two share a name and nothing else, so they stay separate.
 * A tag is one uint64_t -- profile ID in the high 32 bits, tag number in the
 * low 32 -- because a register pair costs less than a struct here.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <tinytalk/matter_status.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Profile ID reserved for anonymous and context-specific tags (TLVTags.h:74). */
#define MATTER_TLV_SPECIAL_PROFILE 0xFFFFFFFFu
/** The Matter common profile (TLVTags.h:97). */
#define MATTER_TLV_COMMON_PROFILE  0x00000000u
/** One past kContextTagMaxNum, so it cannot collide with a context tag (TLVTags.h:34-35). */
#define MATTER_TLV_ANON_TAG_NUM    0x00000100u

/**
 * TLV tag type: a 64-bit unsigned integer encoding context, tag form, and tag number.
 */
typedef uint64_t matter_tlv_tag_t;

#define MATTER_TLV_TAG(profile, num)                                                               \
	(((matter_tlv_tag_t)(uint32_t)(profile) << 32) | (matter_tlv_tag_t)(uint32_t)(num))

/** Anonymous tag: no tag octets on the wire. */
#define MATTER_TLV_ANON      MATTER_TLV_TAG(MATTER_TLV_SPECIAL_PROFILE, MATTER_TLV_ANON_TAG_NUM)
/** Context-specific tag, 0..255. The common case inside a structure. */
#define MATTER_TLV_CTX(n)    MATTER_TLV_TAG(MATTER_TLV_SPECIAL_PROFILE, (uint8_t)(n))
/** Common-profile tag. */
#define MATTER_TLV_COMMON(n) MATTER_TLV_TAG(MATTER_TLV_COMMON_PROFILE, (n))
/** Explicit profile tag. Encodes implicit if it matches the writer's implicit profile. */
#define MATTER_TLV_PROFILE(profile, n) MATTER_TLV_TAG((profile), (n))

/** Container element types, values as on the wire (TLVTypes.h:83-85). */
#define MATTER_TLV_STRUCTURE 0x15u
#define MATTER_TLV_ARRAY     0x16u
#define MATTER_TLV_LIST      0x17u

/*
 * The codec's own names for the shared codes in matter_status.h. Kept because
 * they read better at a TLV call site, and because they are what the existing
 * suite already asserts on.
 */
#define MATTER_TLV_END       MATTER_END
#define MATTER_TLV_OK        MATTER_OK
#define MATTER_TLV_E_NOSPACE MATTER_E_NOSPACE
#define MATTER_TLV_E_INVAL   MATTER_E_INVAL
#define MATTER_TLV_E_DEPTH   MATTER_E_DEPTH
#define MATTER_TLV_E_STATE   MATTER_E_STATE
#define MATTER_TLV_E_TRUNC   MATTER_E_TRUNC
#define MATTER_TLV_E_TYPE    MATTER_E_TYPE

/*
 * Bounded, and matched to the SDK rather than guessed. CHIP's only TLV depth
 * bound is kMaxRecursionDepth = 10 (src/lib/core/TLVUtilities.cpp:44), and the
 * deepest message a minimal device actually sees is an ACL attribute write at
 * SEVEN containers: message struct -> IB array -> IB struct -> AttributeDataIB
 * -> list value -> entry struct -> subjects list. An earlier value of 8 here
 * was reasoned from "Matter's own structures nest ~4 deep" and would have left
 * a single level of margin under a real Apple ACL write.
 *
 * Raising it is free: the depth is a counter, not an array index, so nothing is
 * sized by this. The writer counts rather than recurses, which is the same
 * reason the reader is iterative: stack depth must not be a function of peer
 * input.
 */
#define MATTER_TLV_MAX_DEPTH 10

/**
 * Encoder state. Errors are STICKY: the first failure is latched into rc and
 * every later put becomes a no-op, so a long encode sequence is checked once at
 * matter_tlv_writer_finish() instead of after every call. That is the shape
 * that keeps call sites readable, and it cannot silently truncate -- finish()
 * returns the latched error.
 */
struct matter_tlv_writer {
	uint8_t *buf;
	size_t cap;
	size_t len;
	uint32_t implicit_profile;
	bool implicit_set;
	int rc;
	uint8_t depth;
};

/** Bind an output buffer. Always succeeds; a NULL buffer just latches E_INVAL on first use. */
void matter_tlv_writer_init(struct matter_tlv_writer *w, uint8_t *buf, size_t cap);

/**
 * Nominate a profile ID to encode with the shorter implicit tag control.
 * Without this every profile tag is written fully qualified.
 */
void matter_tlv_writer_set_implicit_profile(struct matter_tlv_writer *w, uint32_t profile);

int matter_tlv_put_bool(struct matter_tlv_writer *w, matter_tlv_tag_t tag, bool v);
int matter_tlv_put_null(struct matter_tlv_writer *w, matter_tlv_tag_t tag);

/** Signed integer, encoded in the smallest width that holds the value. */
int matter_tlv_put_i64(struct matter_tlv_writer *w, matter_tlv_tag_t tag, int64_t v);
/** Unsigned integer, encoded in the smallest width that holds the value. */
int matter_tlv_put_u64(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint64_t v);

/** UTF-8 string. Not validated as UTF-8; the caller owns that. */
int matter_tlv_put_utf8(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const char *s,
			size_t len);
int matter_tlv_put_bytes(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const uint8_t *b,
			 size_t len);

/** @param type one of MATTER_TLV_STRUCTURE, MATTER_TLV_ARRAY, MATTER_TLV_LIST. */
/**
 * Copy an already-encoded element, re-tagged.
 *
 * For a value this node stored but never decoded -- an ACL is a list of
 * structures, and re-encoding one would mean understanding a shape that only
 * the commissioner cares about. Both tags must be context tags, which reduces
 * re-tagging to a one-byte substitution; anything else would require rebuilding
 * a header around a value whose type is unknown here, which is the exact thing
 * this exists to avoid.
 *
 * @param elem one complete element, control byte first.
 * @return MATTER_TLV_OK, or E_INVAL if either tag is not context-specific.
 */
int matter_tlv_put_encoded(struct matter_tlv_writer *w, matter_tlv_tag_t tag, const uint8_t *elem,
			   size_t len);

/**
 * Copy an already-encoded context-tagged element as an ANONYMOUS one.
 *
 * The same substitution as matter_tlv_put_encoded and the same reason for
 * existing, for the one destination that helper cannot express: an array's
 * members carry no tag at all, so re-tagging drops the tag byte rather than
 * replacing it. Needed to rebuild a list from the AttributeDataIBs of a
 * chunked write, whose members arrive tagged as Data and have to end up
 * anonymous inside an array.
 *
 * @param elem one complete context-tagged element, control byte first.
 * @return MATTER_TLV_OK, or E_INVAL if @p elem is not context-tagged.
 */
int matter_tlv_put_encoded_anon(struct matter_tlv_writer *w, const uint8_t *elem, size_t len);

/**
 * Append already-encoded bytes with no re-tagging at all.
 *
 * For members that are ALREADY in the shape the destination wants -- the
 * anonymous members of one array being copied into another. Nothing is
 * validated beyond the bounds check: the caller has walked these elements with
 * a reader and knows their extent, and this cannot re-check a shape it does
 * not parse. Do not reach for it where the tag has to change; that is what the
 * two put_encoded helpers are for.
 *
 * @return MATTER_TLV_OK, or E_NOSPACE.
 */
int matter_tlv_put_raw(struct matter_tlv_writer *w, const uint8_t *bytes, size_t len);

int matter_tlv_start_container(struct matter_tlv_writer *w, matter_tlv_tag_t tag, uint8_t type);
int matter_tlv_end_container(struct matter_tlv_writer *w);

/**
 * Close out the encoding.
 * @param out_len receives the encoded length on success; untouched on failure.
 * @return MATTER_TLV_OK, or the first error latched during encoding, or
 *         MATTER_TLV_E_STATE if a container is still open.
 */
int matter_tlv_writer_finish(struct matter_tlv_writer *w, size_t *out_len);

/*
 * ---------------------------------------------------------------- decoder ---
 *
 * Every byte here arrives from a peer, so the decoder's job is as much refusal
 * as decoding. Two properties it must hold, and both are structural rather
 * than checked:
 *
 *   1. NO RECURSION. Skipping an unentered container walks forward with a
 *      nesting counter capped at MATTER_TLV_MAX_DEPTH. A recursive-descent
 *      skip would let a peer choose this firmware's stack depth, on a part
 *      where the system work queue was measured with 528 B to spare.
 *   2. NO COPYING. Strings and octet strings are returned as a pointer into
 *      the caller's buffer, so decoding allocates nothing and cannot truncate.
 *      The pointer is valid exactly as long as that buffer is.
 *
 * Iteration is CHIP-shaped because the shape is right: next() moves along the
 * current level and steps OVER a container it was not told to enter; enter()
 * descends; exit() skips whatever is left of the current container and lands
 * just past its end marker.
 */
struct matter_tlv_reader {
	const uint8_t *buf;
	size_t len;
	/** Offset the next next() starts scanning from. */
	size_t next_off;
	/** Element type of the loaded element, as it appears on the wire. */
	uint8_t type;
	matter_tlv_tag_t tag;
	/** Value bytes: for strings the payload, for integers the width, else 0. */
	size_t val_off;
	size_t val_len;
	/** Containers only: offset of the first child. */
	size_t body_off;
	/** Offset just past this element, NOT counting a container's body. */
	size_t end_off;
	uint32_t implicit_profile;
	uint8_t depth;
	bool implicit_set;
	bool is_container;
	bool have;
};

void matter_tlv_reader_init(struct matter_tlv_reader *r, const uint8_t *buf, size_t len);

/**
 * Supply the profile ID that implicit-profile tags decode to. Without it, an
 * implicit tag is rejected rather than guessed -- there is no safe default,
 * and inventing one would silently mislabel a tag.
 */
void matter_tlv_reader_set_implicit_profile(struct matter_tlv_reader *r, uint32_t profile);

/**
 * Advance to the next element at the current level.
 * @return MATTER_TLV_OK, MATTER_TLV_END at the end of the level, or an error.
 */
int matter_tlv_next(struct matter_tlv_reader *r);

/** Tag of the loaded element. Undefined unless the last next() returned OK. */
matter_tlv_tag_t matter_tlv_tag(const struct matter_tlv_reader *r);
/** Raw wire element type of the loaded element. */
uint8_t matter_tlv_element_type(const struct matter_tlv_reader *r);
bool matter_tlv_is_container(const struct matter_tlv_reader *r);

int matter_tlv_get_bool(const struct matter_tlv_reader *r, bool *out);
int matter_tlv_get_u64(const struct matter_tlv_reader *r, uint64_t *out);
int matter_tlv_get_i64(const struct matter_tlv_reader *r, int64_t *out);
/** Octet string. @param out receives a pointer INTO the caller's buffer; nothing is copied. */
int matter_tlv_get_bytes(const struct matter_tlv_reader *r, const uint8_t **out, size_t *len);
/** UTF-8 string, not NUL-terminated and not validated as UTF-8. Borrowed like get_bytes. */
int matter_tlv_get_utf8(const struct matter_tlv_reader *r, const char **out, size_t *len);

/** Descend into the loaded container. */
int matter_tlv_enter(struct matter_tlv_reader *r);
/** Skip whatever remains of the current container and land just past its end marker. */
int matter_tlv_exit(struct matter_tlv_reader *r);

#ifdef __cplusplus
}
#endif

/* SPDX-License-Identifier: ISC */

/*
 * tm_kv.h - small persistent values, addressed by number. The project this was
 * extracted from shares this seam across several ports; tinymatter carries the
 * Zephyr settings backend and the Matter key window only.
 *
 * WHAT THIS REPLACES, AND WHY THE KEY IS AN INTEGER. Each framework caps record
 * names differently -- ESP-IDF's NVS at 15 characters, Zephyr's settings at 64 --
 * and ESP-IDF's read side reports a too-long name as "never stored" rather than
 * as an error, which is how an 18-character namespace survived a rename, a test
 * suite and a release in the source project. Every port re-solved that
 * trap by hand, and PORTING.md carried a table of every spelled-out name to
 * police it.
 *
 * A uint16_t key cannot be too long. Backends derive their own storage name
 * from the number -- "uwl/%04x" under Zephyr settings, namespace "uwl" with key
 * "%04x" under NVS -- so both are bounded by construction, four hex digits, and
 * the cap can no longer be exceeded by anyone.
 *
 * Keys are grouped into windows by consumer, because a range is cheaper to
 * reason about than a registry and two consumers must never collide. Take an id
 * from the right window; do not invent a window without a consumer.
 *
 * Backend here: Zephyr settings (tm_kv_zephyr.c). The settings names keep the
 * source project's "uwl/" prefix so the on-flash layout is unchanged.
 *
 * NOT a filesystem and not a database. Small values that must survive a reset
 * and a firmware update -- keys, a provisioning blob, a handful of flags.
 */
#ifndef TM_KV_H
#define TM_KV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Key windows. A consumer owns a range; ids inside it are assigned by the
 * consumer's own header or, where there is only ever one, here.
 */
/* Matter: the fabric table, subscription slots, and the door-lock attributes
 * that persist. These ids are shared by every backend because the portable
 * Matter store now calls this seam directly. */
#define TM_KV_KEY_MATTER_BASE  0x2000u
#define TM_KV_KEY_MATTER_LIMIT 0x2100u

#define TM_KV_KEY_MATTER_SRP_HOST_ID 0x2000u
/* Retired v0.3 fabric schema. Kept assigned so a clean-break loader can erase
 * it without ever mistaking it for current identity. */
#define TM_KV_KEY_MATTER_FAB_VER   0x2010u
#define TM_KV_KEY_MATTER_FAB_OK    0x2011u
#define TM_KV_KEY_MATTER_FAB_TD    0x2012u
#define TM_KV_KEY_MATTER_FAB_XP    0x2013u
#define TM_KV_KEY_MATTER_FAB_ICLEN 0x2014u
#define TM_KV_KEY_MATTER_FAB_ICAC  0x2015u
#define TM_KV_KEY_MATTER_FAB_SLOT0      0x2020u
#define TM_KV_KEY_MATTER_FAB_SLOT_LIMIT 0x2030u

#define TM_KV_KEY_MATTER_SUB_SLOT0      0x2040u
#define TM_KV_KEY_MATTER_SUB_SLOT_LIMIT 0x2050u
#define TM_KV_KEY_MATTER_DL_AUTO_RELOCK 0x2060u

/* Current clean-break, per-record Matter identity schema. */
#define TM_KV_KEY_MATTER_MF2_META    0x2070u
#define TM_KV_KEY_MATTER_MF2_NET     0x2071u
#define TM_KV_KEY_MATTER_MF2_ICAC    0x2072u
#define TM_KV_KEY_MATTER_MF2_FAB0      0x2080u
#define TM_KV_KEY_MATTER_MF2_FAB_LIMIT 0x2085u
#define TM_KV_KEY_MATTER_MF2_ACL0      0x2090u
#define TM_KV_KEY_MATTER_MF2_ACL_LIMIT 0x2095u

#if TM_KV_KEY_MATTER_SRP_HOST_ID < TM_KV_KEY_MATTER_BASE || \
	TM_KV_KEY_MATTER_MF2_ACL_LIMIT > TM_KV_KEY_MATTER_LIMIT
#error "Matter key assignments collide or escape their reserved window"
#endif

/* A key no record can carry: erased flash reads as all ones. */
#define TM_KV_KEY_NONE 0xffffu

/* The largest single value. The source project sized it for its credential
 * provisioning blob (1052 bytes); here it only bounds the fabric store's
 * record buffer, which matter_fab_settings.c asserts fits. */
#define TM_KV_VALUE_MAX 1088u

enum tm_kv_result {
	TM_KV_OK = 0,
	/* No record for that key. Not an error; the caller decides. */
	TM_KV_NOT_FOUND = -1,
	/* The key or length is outside what this store accepts. */
	TM_KV_INVALID = -2,
	/* The live set no longer fits, even after whatever compaction exists. */
	TM_KV_FULL = -3,
	/* The underlying store refused a read, write, or erase. */
	TM_KV_IO = -4,
	/* The store is unreadable or unformatted and could not be recovered. */
	TM_KV_CORRUPT = -5,
};

/**
 * Mount the store, formatting it if there is nothing valid to mount.
 *
 * Safe to call more than once; later calls are no-ops. Returns
 * TM_KV_OK or a negative tm_kv_result.
 */
int tm_kv_init(void);

/**
 * Read a value. On TM_KV_OK, *@p length carries the stored length; on
 * entry it carries the capacity of @p value. A value larger than the buffer is
 * refused with TM_KV_INVALID and *@p length set to the stored length,
 * so a caller can size a second attempt.
 *
 * @p value may be NULL with *@p length zero to ask only for the stored length.
 */
int tm_kv_get(uint16_t key, void *value, size_t *length);

/** Write a value, replacing any earlier one for that key. */
int tm_kv_set(uint16_t key, const void *value, size_t length);

/** Forget one key. TM_KV_NOT_FOUND if it was not stored. */
int tm_kv_delete(uint16_t key);

/**
 * Forget everything, leaving a formatted store.
 *
 * A factory reset of what this store owns. NOT an erase of the underlying
 * region: a caller that wants only its own keys gone must delete them.
 */
int tm_kv_erase_all(void);

#ifdef __cplusplus
}
#endif

#endif /* TM_KV_H */

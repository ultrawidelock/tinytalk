/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * tm_kv.h on Zephyr settings.
 *
 * The whole point of the seam is here, in one function: name_of(). A caller
 * hands over a uint16_t; this file spells it "tmk/%04x" -- eight characters,
 * always, whatever the key -- and Zephyr's 64-character cap stops being
 * something anyone can exceed. There is no table of names to keep in step with
 * a document, because there are no names to get wrong.
 *
 * Reads go through settings_load_subtree_direct() rather than a RAM cache. A
 * cache would cost TM_KV_VALUE_MAX per live key on a part where the
 * Matter image already has about 6 KB free, and the whole point of a key-value
 * store is that the values are not all live at once.
 *
 * NOT the Zephyr settings API in disguise. Settings is a tree with typed
 * handlers and a load phase; this is get/set/delete on one flat namespace.
 * Framework-owned trees such as OpenThread's own store keep using settings
 * directly.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>

#include <tinytalk/tm_kv.h>

/* "tmk/" + four hex digits + NUL. Fixed width so every key costs the same and
 * none can be truncated by a backend cap. */
#define KV_NAME_LEN 9u

K_MUTEX_DEFINE(s_kv_lock);
static bool s_ready;

static void name_of(uint16_t key, char out[KV_NAME_LEN])
{
	(void)snprintf(out, KV_NAME_LEN, "tmk/%04x", (unsigned)key);
}

struct read_ctx {
	void *value;
	size_t cap;
	size_t stored;
	bool found;
	bool too_small;
};

static int read_cb(const char *name, size_t len, settings_read_cb read_fn, void *cb_arg,
		   void *param)
{
	struct read_ctx *ctx = param;
	ssize_t got;

	/* A direct load on a full key path hands back the leaf, which is the
	 * empty string here -- anything else is a deeper name that is not ours. */
	if (name != NULL && name[0] != '\0') {
		return 0;
	}
	ctx->found = true;
	ctx->stored = len;
	if (ctx->value == NULL || ctx->cap < len) {
		ctx->too_small = (ctx->value != NULL || ctx->cap != 0u);
		return 0;
	}
	got = read_fn(cb_arg, ctx->value, len);
	if (got < 0 || (size_t)got != len) {
		/* A stored record that the backend could not read is not absence.
		 * Propagate the callback failure through settings_load_subtree_direct()
		 * so callers receive KV_IO and cannot manufacture default identity. */
		return -EIO;
	}
	return 0;
}

int tm_kv_init(void)
{
	int rc;

	k_mutex_lock(&s_kv_lock, K_FOREVER);
	if (s_ready) {
		k_mutex_unlock(&s_kv_lock);
		return TM_KV_OK;
	}
	/* Idempotent in Zephyr too, and every other consumer on this image calls
	 * it as well; whoever gets there first pays for it. */
	rc = settings_subsys_init();
	if (rc != 0) {
		k_mutex_unlock(&s_kv_lock);
		return TM_KV_IO;
	}
	s_ready = true;
	k_mutex_unlock(&s_kv_lock);
	return TM_KV_OK;
}

int tm_kv_get(uint16_t key, void *value, size_t *length)
{
	char name[KV_NAME_LEN];
	struct read_ctx ctx = { 0 };
	int rc;

	if (length == NULL || key == TM_KV_KEY_NONE) {
		return TM_KV_INVALID;
	}
	if (!s_ready) {
		return TM_KV_CORRUPT;
	}
	ctx.value = value;
	ctx.cap = *length;
	name_of(key, name);

	k_mutex_lock(&s_kv_lock, K_FOREVER);
	rc = settings_load_subtree_direct(name, read_cb, &ctx);
	k_mutex_unlock(&s_kv_lock);
	if (rc != 0) {
		return TM_KV_IO;
	}
	if (!ctx.found) {
		return TM_KV_NOT_FOUND;
	}
	*length = ctx.stored;
	/* Refused rather than truncated, and the stored length goes back so the
	 * caller can size a second attempt. Handing over a short value is how a
	 * half-read key reaches something that treats it as a whole one. */
	return ctx.too_small ? TM_KV_INVALID : TM_KV_OK;
}

int tm_kv_set(uint16_t key, const void *value, size_t length)
{
	char name[KV_NAME_LEN];
	int rc;

	if (key == TM_KV_KEY_NONE || length > TM_KV_VALUE_MAX) {
		return TM_KV_INVALID;
	}
	if (length > 0u && value == NULL) {
		return TM_KV_INVALID;
	}
	if (!s_ready) {
		return TM_KV_CORRUPT;
	}
	name_of(key, name);

	k_mutex_lock(&s_kv_lock, K_FOREVER);
	rc = settings_save_one(name, value, length);
	k_mutex_unlock(&s_kv_lock);
	if (rc == -ENOSPC) {
		return TM_KV_FULL;
	}
	return rc == 0 ? TM_KV_OK : TM_KV_IO;
}

int tm_kv_delete(uint16_t key)
{
	char name[KV_NAME_LEN];
	size_t probe = 0;
	int rc;

	if (key == TM_KV_KEY_NONE) {
		return TM_KV_INVALID;
	}
	if (!s_ready) {
		return TM_KV_CORRUPT;
	}
	/* NOT_FOUND has to be true rather than convenient: settings_delete()
	 * reports success for a name that was never stored, and a caller
	 * clearing a credential deserves to know whether one was there. */
	rc = tm_kv_get(key, NULL, &probe);
	if (rc == TM_KV_NOT_FOUND) {
		return TM_KV_NOT_FOUND;
	}
	name_of(key, name);

	k_mutex_lock(&s_kv_lock, K_FOREVER);
	rc = settings_delete(name);
	k_mutex_unlock(&s_kv_lock);
	return rc == 0 ? TM_KV_OK : TM_KV_IO;
}

/* How many keys one sweep pass collects before deleting them. A batch rather
 * than a full list: the array is stack-resident during a factory reset, and
 * deleting while the subtree is being walked is not something settings
 * promises to survive. */
#define ERASE_BATCH 32u

struct erase_ctx {
	uint16_t keys[ERASE_BATCH];
	size_t n;
};

/* "00a3" -> 0x00a3. Exactly four lowercase hex digits, because that is the only
 * shape name_of() produces; anything else under tmk/ is not ours to delete. */
static bool key_of(const char *name, uint16_t *out)
{
	uint16_t v = 0u;

	if (name == NULL) {
		return false;
	}
	for (size_t i = 0; i < 4u; i++) {
		char c = name[i];

		if (c >= '0' && c <= '9') {
			v = (uint16_t)((v << 4) | (uint16_t)(c - '0'));
		} else if (c >= 'a' && c <= 'f') {
			v = (uint16_t)((v << 4) | (uint16_t)(c - 'a' + 10));
		} else {
			return false;
		}
	}
	if (name[4] != '\0') {
		return false;
	}
	*out = v;
	return true;
}

static int collect_cb(const char *name, size_t len, settings_read_cb read_fn, void *cb_arg,
		      void *param)
{
	struct erase_ctx *ctx = param;
	uint16_t key;

	(void)len;
	(void)read_fn;
	(void)cb_arg;
	if (ctx->n >= ERASE_BATCH || !key_of(name, &key)) {
		return 0;
	}
	ctx->keys[ctx->n++] = key;
	return 0;
}

int tm_kv_erase_all(void)
{
	int rc = TM_KV_OK;

	if (!s_ready) {
		return TM_KV_CORRUPT;
	}
	/*
	 * Enumerate what is actually stored and delete that, rather than trying
	 * every key this seam can name: the namespace is 65535 wide and a real
	 * store holds a handful. Settings has no "drop this subtree" call, and
	 * erasing the partition is not an option -- Matter's fabric table and
	 * OpenThread's own settings share it, and this is a reset of what THIS
	 * store owns.
	 *
	 * Passes repeat until a sweep finds nothing, so a store holding more
	 * than one batch still empties.
	 */
	for (;;) {
		struct erase_ctx ctx = { .n = 0u };
		int scan;

		k_mutex_lock(&s_kv_lock, K_FOREVER);
		scan = settings_load_subtree_direct("tmk", collect_cb, &ctx);
		k_mutex_unlock(&s_kv_lock);
		if (scan != 0) {
			return TM_KV_IO;
		}
		if (ctx.n == 0u) {
			return rc;
		}
		size_t gone = 0u;

		for (size_t i = 0; i < ctx.n; i++) {
			int one = tm_kv_delete(ctx.keys[i]);

			if (one == TM_KV_OK || one == TM_KV_NOT_FOUND) {
				gone++;
			} else {
				rc = one;
			}
		}
		/* A pass that removed nothing would collect the same keys again
		 * forever. Whatever is refusing to go is reported instead. */
		if (gone == 0u) {
			return rc;
		}
	}
}

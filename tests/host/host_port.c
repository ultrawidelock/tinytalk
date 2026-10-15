/* SPDX-License-Identifier: ISC */

/*
 * The host port: tm_platform.h, tm_kv.h, matter_ble.h, the two application
 * hooks and the Thread seams test_matter_thread_stub.c does not cover, so the
 * whole core, the node included, links and runs on a desktop.
 *
 * Single-threaded, so the lock is a no-op. Deferred work is recorded, not
 * run; a test runs an item with matter_commission_work(). The store is RAM.
 * tm_random() is a fixed sequence: reproducible, and NOT a CSPRNG.
 */
#include <string.h>
#include <time.h>

#include <tinymatter/matter_ble.h>
#include <tinymatter/matter_commission.h>
#include <tinymatter/matter_status.h>
#include <tinymatter/matter_thread.h>
#include <tinymatter/tm_kv.h>
#include <tinymatter/tm_platform.h>

/* ---- tm_platform.h -------------------------------------------------------- */

void tm_lock(void)
{
}

void tm_unlock(void)
{
}

bool tm_trylock(void)
{
	return true;
}

int64_t tm_uptime_ms(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Delay of each pending item, or -1. */
static int64_t s_work_delay_ms[TM_WORK_COUNT] = { -1, -1, -1, -1, -1 };

int tm_work_schedule(enum tm_work w, uint32_t delay_ms)
{
	if (s_work_delay_ms[w] < 0) {
		s_work_delay_ms[w] = delay_ms;
	}
	return 0;
}

int tm_work_reschedule(enum tm_work w, uint32_t delay_ms)
{
	s_work_delay_ms[w] = delay_ms;
	return 0;
}

void tm_work_cancel(enum tm_work w)
{
	s_work_delay_ms[w] = -1;
}

int tm_run_deep(void (*fn)(void *ctx), void *ctx)
{
	fn(ctx);
	return 0;
}

int tm_random(void *out, size_t len)
{
	static uint32_t x = 0x9e3779b9u;
	uint8_t *p = out;

	for (size_t i = 0u; i < len; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		p[i] = (uint8_t)x;
	}
	return 0;
}

void tm_device_id(uint8_t out[8])
{
	static const uint8_t id[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

	memcpy(out, id, sizeof(id));
}

/* ---- tm_kv.h, in RAM ------------------------------------------------------- */

#define KV_SLOTS 64u

static struct {
	bool used;
	uint16_t key;
	size_t len;
	uint8_t value[TM_KV_VALUE_MAX];
} s_kv[KV_SLOTS];

int tm_kv_init(void)
{
	return TM_KV_OK;
}

static int kv_find(uint16_t key)
{
	for (size_t i = 0u; i < KV_SLOTS; i++) {
		if (s_kv[i].used && s_kv[i].key == key) {
			return (int)i;
		}
	}
	return -1;
}

int tm_kv_get(uint16_t key, void *value, size_t *length)
{
	int i = kv_find(key);

	if (length == NULL) {
		return TM_KV_INVALID;
	}
	if (i < 0) {
		return TM_KV_NOT_FOUND;
	}
	if (*length < s_kv[i].len) {
		*length = s_kv[i].len;
		return TM_KV_INVALID;
	}
	if (s_kv[i].len > 0u) {
		memcpy(value, s_kv[i].value, s_kv[i].len);
	}
	*length = s_kv[i].len;
	return TM_KV_OK;
}

int tm_kv_set(uint16_t key, const void *value, size_t length)
{
	int i = kv_find(key);

	if (length > TM_KV_VALUE_MAX || (value == NULL && length != 0u)) {
		return TM_KV_INVALID;
	}
	for (size_t j = 0u; i < 0 && j < KV_SLOTS; j++) {
		if (!s_kv[j].used) {
			i = (int)j;
		}
	}
	if (i < 0) {
		return TM_KV_FULL;
	}
	s_kv[i].used = true;
	s_kv[i].key = key;
	s_kv[i].len = length;
	if (length > 0u) {
		memcpy(s_kv[i].value, value, length);
	}
	return TM_KV_OK;
}

int tm_kv_delete(uint16_t key)
{
	int i = kv_find(key);

	if (i >= 0) {
		s_kv[i].used = false;
	}
	return TM_KV_OK;
}

int tm_kv_erase_all(void)
{
	memset(s_kv, 0, sizeof(s_kv));
	return TM_KV_OK;
}

/* ---- matter_ble.h: nothing is connected -------------------------------------- */

static uint16_t s_discriminator = 0xF00u;

void matter_ble_set_msg_handler(matter_ble_msg_cb cb)
{
	(void)cb;
}

void matter_ble_set_link_handler(matter_ble_link_cb cb)
{
	(void)cb;
}

void matter_ble_set_tx_handler(matter_ble_tx_cb cb)
{
	(void)cb;
}

int matter_ble_send(const uint8_t *msg, size_t len)
{
	(void)msg;
	(void)len;
	return -1;
}

void matter_ble_set_discriminator(uint16_t discriminator)
{
	s_discriminator = discriminator != 0u ? discriminator : 0xF00u;
}

uint16_t matter_ble_discriminator(void)
{
	return s_discriminator;
}

/* ---- the application hooks ---------------------------------------------------- */

void matter_commission_readvertise(void)
{
}

void matter_commission_lock_state(uint8_t lock_state)
{
	(void)lock_state;
}

/* ---- the Thread seams the node adds ------------------------------------------ */

int matter_thread_advertise_commissionable(uint16_t discriminator, uint16_t port)
{
	(void)discriminator;
	(void)port;
	return MATTER_OK;
}

int matter_thread_unadvertise_commissionable(void)
{
	return MATTER_OK;
}

void matter_thread_peer_current(struct matter_thread_peer *out)
{
	memset(out, 0, sizeof(*out));
}

int matter_thread_send_to(const struct matter_thread_peer *peer, const uint8_t *msg, size_t len)
{
	(void)peer;
	(void)msg;
	(void)len;
	return MATTER_E_STATE;
}

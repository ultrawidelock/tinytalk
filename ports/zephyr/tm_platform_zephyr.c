/* SPDX-FileCopyrightText: 2026 Aseem Chopra */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tm_platform_zephyr.c
 * @brief tm_platform.h on Zephyr: a mutex, the system work queue, the uptime
 *        clock and the hwinfo device id.
 */
#include <tinytalk/tm_platform.h>
#include <tinytalk/matter_commission.h>

#include <zephyr/drivers/hwinfo.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <errno.h>
#include <string.h>

/* The node's own log (tm_log_zephyr.h); it is registered here, in the one
 * port file every build has. */
LOG_MODULE_REGISTER(tinytalk, CONFIG_TINYTALK_LOG_LEVEL);

static K_MUTEX_DEFINE(s_lock);

void tm_lock(void)
{
	(void)k_mutex_lock(&s_lock, K_FOREVER);
}

void tm_unlock(void)
{
	(void)k_mutex_unlock(&s_lock);
}

bool tm_trylock(void)
{
	return k_mutex_lock(&s_lock, K_NO_WAIT) == 0;
}

int64_t tm_uptime_ms(void)
{
	return k_uptime_get();
}

/* ---- deferred work, on the system work queue ----------------------------- */

static struct k_work_delayable s_work[TM_WORK_COUNT];

static void work_fn(struct k_work *work)
{
	struct k_work_delayable *dw = k_work_delayable_from_work(work);

	matter_commission_work((enum tm_work)(dw - s_work));
}

int tm_work_schedule(enum tm_work w, uint32_t delay_ms)
{
	return k_work_schedule(&s_work[w], K_MSEC(delay_ms)) < 0 ? -EIO : 0;
}

int tm_work_reschedule(enum tm_work w, uint32_t delay_ms)
{
	return k_work_reschedule(&s_work[w], K_MSEC(delay_ms)) < 0 ? -EIO : 0;
}

void tm_work_cancel(enum tm_work w)
{
	(void)k_work_cancel_delayable(&s_work[w]);
}

/* ---- tm_run_deep: the system work queue's stack, not OpenThread's -------- */

#define RUN_DEEP_TIMEOUT_MS 10000

static struct k_work s_deep_work;
static K_SEM_DEFINE(s_deep_done, 0, 1);
static void (*s_deep_fn)(void *ctx);
static void *s_deep_ctx;

static void deep_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	s_deep_fn(s_deep_ctx);
	k_sem_give(&s_deep_done);
}

int tm_run_deep(void (*fn)(void *ctx), void *ctx)
{
	/* Already there (the BLE transport's work): waiting on ourselves would
	 * only time out. */
	if (k_current_get() == k_work_queue_thread_get(&k_sys_work_q)) {
		fn(ctx);
		return 0;
	}
	s_deep_fn = fn;
	s_deep_ctx = ctx;
	k_sem_reset(&s_deep_done);
	if (k_work_submit(&s_deep_work) < 0) {
		return -EIO;
	}
	return k_sem_take(&s_deep_done, K_MSEC(RUN_DEEP_TIMEOUT_MS)) == 0 ? 0 : -ETIMEDOUT;
}

static int platform_init(void)
{
	for (size_t i = 0u; i < TM_WORK_COUNT; i++) {
		k_work_init_delayable(&s_work[i], work_fn);
	}
	k_work_init(&s_deep_work, deep_work_fn);
	return 0;
}
SYS_INIT(platform_init, POST_KERNEL, 0);

void tm_device_id(uint8_t out[8])
{
	memset(out, 0, 8u);
	(void)hwinfo_get_device_id(out, 8u);
}

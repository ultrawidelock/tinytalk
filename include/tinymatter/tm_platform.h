/* SPDX-License-Identifier: ISC */

/**
 * @file tm_platform.h
 * @brief What a port provides so the node runs: a lock, deferred work, a
 *        clock, randomness and a device id.
 *
 * The rest of a port's job has its own header: storage in tm_kv.h, the BLE
 * commissioning transport in matter_ble.h, Thread in matter_thread.h, crypto
 * in matter_crypto.h, matter_attest.h, matter_case.h and matter_spake2p.h,
 * and logging in tm_log.h. ports/zephyr/ implements all of them.
 *
 * Threading: the node may be entered from several contexts (the BLE receive
 * path, the Thread receive path, deferred work, the application). Every entry
 * point takes tm_lock() itself; a single-threaded port makes it a no-op.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Take and release the node's one lock. Not recursive. */
void tm_lock(void);
void tm_unlock(void);
/** Take the lock only if it is free; true when taken. */
bool tm_trylock(void);

/** Milliseconds since boot, monotonic. */
int64_t tm_uptime_ms(void);

/** The node's deferred work items. */
enum tm_work {
	TM_WORK_ADMIN_EXPIRE,  /**< The commissioning window closes. */
	TM_WORK_FAILSAFE,      /**< The commissioning fail-safe expires. */
	TM_WORK_NOTIFY,        /**< Report a lock-state change to subscribers. */
	TM_WORK_HEARTBEAT,     /**< A subscription's max-interval report. */
	TM_WORK_THREAD_REAP,   /**< Give up on unacknowledged Thread messages. */
	TM_WORK_COUNT
};

/**
 * Run matter_commission_work(@p w) once, @p delay_ms from now, from the port's
 * work context (never from inside a node call).
 *
 * tm_work_schedule() leaves an already pending run of @p w where it is;
 * tm_work_reschedule() moves it. Zephyr's k_work_schedule() and
 * k_work_reschedule() are exactly these. Both return 0, or negative when the
 * work could not be queued.
 */
int tm_work_schedule(enum tm_work w, uint32_t delay_ms);
int tm_work_reschedule(enum tm_work w, uint32_t delay_ms);
void tm_work_cancel(enum tm_work w);

/**
 * Run @p fn(@p ctx) to completion on a context whose stack can take a flash
 * write, and wait for it. The node calls this, with its lock held, to commit
 * the fabric table from inside a Thread receive callback whose stack cannot.
 * A port whose callers already have the stack just calls @p fn.
 *
 * @return 0 once @p fn has returned; negative if it could not be run or did
 *         not finish in time, in which case it may still be running.
 */
int tm_run_deep(void (*fn)(void *ctx), void *ctx);

/** Fill @p out from a CSPRNG. 0, or negative on failure. */
int tm_random(void *out, size_t len);

/**
 * A stable per-device id, 8 bytes. Seeds the serial number Basic Information
 * reports; it needs to be unique, not secret.
 */
void tm_device_id(uint8_t out[8]);

#ifdef __cplusplus
}
#endif

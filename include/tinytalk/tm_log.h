/* SPDX-License-Identifier: Apache-2.0 */

/**
 * @file tm_log.h
 * @brief Logging for the core: a port maps it onto its own logger, or it
 *        compiles to nothing.
 *
 * A port that wants the logs builds the core with
 * -DTM_LOG_HEADER="<its header>", and that header defines the six macros
 * below (ports/zephyr/tm_log_zephyr.h maps them onto Zephyr's LOG_*).
 * Without it every call still type-checks its arguments and emits no code.
 */
#pragma once

#if defined(TM_LOG_HEADER)
#include TM_LOG_HEADER
#else

#include <stddef.h>

static inline __attribute__((format(printf, 1, 2))) void tm_log_none(const char *fmt, ...)
{
	(void)fmt;
}

static inline void tm_log_hexdump_none(const void *data, size_t len, const char *what)
{
	(void)data;
	(void)len;
	(void)what;
}

#define TM_LOG_ERR(...) tm_log_none(__VA_ARGS__)
#define TM_LOG_WRN(...) tm_log_none(__VA_ARGS__)
#define TM_LOG_INF(...) tm_log_none(__VA_ARGS__)
#define TM_LOG_DBG(...) tm_log_none(__VA_ARGS__)
#define TM_LOG_HEXDUMP_INF(data, len, what) tm_log_hexdump_none((data), (len), (what))
#define TM_LOG_HEXDUMP_DBG(data, len, what) tm_log_hexdump_none((data), (len), (what))

#endif

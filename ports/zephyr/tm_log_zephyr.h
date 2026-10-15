/* SPDX-License-Identifier: ISC */

/**
 * @file tm_log_zephyr.h
 * @brief tm_log.h on Zephyr's logger. The core is built with
 *        -DTM_LOG_HEADER="tm_log_zephyr.h" (see ports/zephyr/CMakeLists.txt).
 */
#pragma once

#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(tinymatter, CONFIG_TINYMATTER_LOG_LEVEL);

#define TM_LOG_ERR(...) LOG_ERR(__VA_ARGS__)
#define TM_LOG_WRN(...) LOG_WRN(__VA_ARGS__)
#define TM_LOG_INF(...) LOG_INF(__VA_ARGS__)
#define TM_LOG_DBG(...) LOG_DBG(__VA_ARGS__)
#define TM_LOG_HEXDUMP_INF(data, len, what) LOG_HEXDUMP_INF(data, len, what)
#define TM_LOG_HEXDUMP_DBG(data, len, what) LOG_HEXDUMP_DBG(data, len, what)

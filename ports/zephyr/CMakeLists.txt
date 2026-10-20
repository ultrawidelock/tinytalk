# SPDX-FileCopyrightText: 2026 Aseem Chopra
# SPDX-License-Identifier: Apache-2.0

# The Zephyr port: tm_platform.h on the kernel and storage on Zephyr settings
# (tm_kv.h), always; the 0xFFF6 BLE commissioning transport (matter_ble.h) with
# CONFIG_TINYTALK_BLE, and Thread on OpenThread (matter_thread.h) with
# CONFIG_TINYTALK_THREAD.
#
# matter_ble_zephyr.h is on the include path of every target, because the
# application calls it for the advert.

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})

zephyr_library_named(tinytalk_zephyr)
zephyr_library_sources(
  ${CMAKE_CURRENT_SOURCE_DIR}/tm_platform_zephyr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/tm_kv_zephyr.c)
# Each transport is optional; without one the application provides its seam.
zephyr_library_sources_ifdef(CONFIG_TINYTALK_BLE ${CMAKE_CURRENT_SOURCE_DIR}/matter_ble_zephyr.c)
# The scan response UUID, as the 16 little-endian bytes BT_DATA_BYTES wants.
if(CONFIG_TINYTALK_BLE AND CONFIG_TINYTALK_BLE_SCAN_RSP)
  string(REPLACE "-" "" tm_uuid "${CONFIG_TINYTALK_BLE_SCAN_RSP_UUID128}")
  string(LENGTH "${tm_uuid}" tm_uuid_len)
  if(NOT tm_uuid_len EQUAL 32 OR NOT tm_uuid MATCHES "^[0-9A-Fa-f]+$")
    message(FATAL_ERROR "CONFIG_TINYTALK_BLE_SCAN_RSP_UUID128 is not a 128-bit UUID: "
                        "${CONFIG_TINYTALK_BLE_SCAN_RSP_UUID128}")
  endif()
  set(tm_uuid_bytes)
  foreach(i RANGE 30 0 -2)
    string(SUBSTRING "${tm_uuid}" ${i} 2 tm_byte)
    list(APPEND tm_uuid_bytes "0x${tm_byte}")
  endforeach()
  list(JOIN tm_uuid_bytes "," tm_uuid_bytes)
  zephyr_library_compile_definitions(TM_BLE_SCAN_RSP_UUID128=${tm_uuid_bytes})
endif()
zephyr_library_sources_ifdef(CONFIG_TINYTALK_THREAD
  ${CMAKE_CURRENT_SOURCE_DIR}/thread/matter_thread_port.c)

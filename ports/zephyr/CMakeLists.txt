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
zephyr_library_sources_ifdef(CONFIG_TINYTALK_THREAD
  ${CMAKE_CURRENT_SOURCE_DIR}/thread/matter_thread_port.c)

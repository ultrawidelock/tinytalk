# The Zephyr port: tm_platform.h on the kernel, the 0xFFF6 BLE commissioning
# transport (matter_ble.h), storage on Zephyr settings (tm_kv.h), and Thread
# on OpenThread (matter_thread.h).
#
# matter_ble_zephyr.h is on the include path of every target, because the
# application calls it for the advert.

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(CONFIG_TINYMATTER_BLE)
  zephyr_library_named(tinymatter_zephyr)
  zephyr_library_sources(
    ${CMAKE_CURRENT_SOURCE_DIR}/tm_platform_zephyr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/matter_ble_zephyr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tm_kv_zephyr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/thread/matter_thread_port.c)
endif()

# The Zephyr port: the 0xFFF6 BLE commissioning transport, the fabric store on
# Zephyr settings (through tm_kv), and the Thread transport.
#
# The headers here (matter_ble_zephyr.h, matter_fab_settings.h, tm_kv.h) are
# on the include path of every target, because the application calls them.

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if(CONFIG_TINYMATTER_BLE)
  zephyr_library_named(tinymatter_zephyr)
  zephyr_library_sources(
    ${CMAKE_CURRENT_SOURCE_DIR}/matter_ble_zephyr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/matter_commission.c
    ${CMAKE_CURRENT_SOURCE_DIR}/matter_fab_settings.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tm_kv_zephyr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/thread/matter_thread_port.c)
endif()

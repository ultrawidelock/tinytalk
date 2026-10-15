# Hand-written minimal Matter node as a Zephyr module.
# Contributes nothing unless CONFIG_TINYMATTER=y.
#
# Platform-agnostic C11 with no Zephyr dependency, so tests/host compiles the
# same sources directly (the Makefile).

if(CONFIG_TINYMATTER)

  set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

  zephyr_library_named(tinymatter)
  zephyr_library_sources(
    ${SRC}/matter_tlv.c
    ${SRC}/matter_msg.c
    ${SRC}/matter_mrp.c
    ${SRC}/matter_crypto.c
    ${SRC}/matter_btp.c
    ${SRC}/matter_pase.c
    ${SRC}/matter_spake2p.c
    ${SRC}/matter_pase_sm.c
    ${SRC}/matter_exchange.c
    ${SRC}/matter_im.c
    ${SRC}/matter_clusters.c
    ${SRC}/matter_attest.c
    ${SRC}/matter_fabric.c
    ${SRC}/matter_case.c
    ${SRC}/matter_commission.c
    ${SRC}/matter_fab_store.c
    ${SRC}/tm_hash.c)

  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

  # The core's logs, on Zephyr's logger (include/tinymatter/tm_log.h).
  zephyr_library_compile_definitions(TM_LOG_HEADER="tm_log_zephyr.h")
  zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ports/zephyr)

  # The crypto seams (see PORTING.md): P-256 and AES-ECB on PSA Crypto, and
  # SPAKE2+ on either nrf_oberon or Mbed TLS.
  zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/psa/tm_psa.c)
  if(CONFIG_TINYMATTER_SPAKE2P_OBERON)
    include(${CMAKE_CURRENT_SOURCE_DIR}/backends/oberon/oberon.cmake)
  endif()
  if(CONFIG_TINYMATTER_SPAKE2P_MBEDTLS)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/mbedtls/tm_spake2p_mbedtls.c)
  endif()

  # The Zephyr port: platform, BLE transport, storage, Thread.
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ports/zephyr)

endif(CONFIG_TINYMATTER)

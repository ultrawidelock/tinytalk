# Hand-written minimal Matter node as a Zephyr module.
# Contributes nothing unless CONFIG_TINYTALK=y.
#
# Platform-agnostic C11 with no Zephyr dependency, so tests/host compiles the
# same sources directly (the Makefile).

if(CONFIG_TINYTALK)

  set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

  zephyr_library_named(tinytalk)
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
    ${SRC}/matter_diagnostics.c
    ${SRC}/matter_group_keys.c
    ${SRC}/matter_fab_store.c
    ${SRC}/tm_hash.c)

  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

  # Feature switches. Global, because they change struct layouts in the
  # public headers.
  if(NOT CONFIG_TINYTALK_EVENTS)
    zephyr_compile_definitions(TM_NO_EVENTS)
  endif()
  if(NOT CONFIG_TINYTALK_ADMIN_COMMANDS)
    zephyr_compile_definitions(TM_NO_ADMIN_COMMANDS)
  endif()
  if(NOT CONFIG_TINYTALK_SUB_RESUME)
    zephyr_compile_definitions(TM_NO_SUB_RESUME)
  endif()

  # Cluster modules an application puts on its endpoints (tm_app.h).
  if(CONFIG_TINYTALK_DOOR_LOCK)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/clusters/door_lock/tm_door_lock.c)
  endif()
  if(CONFIG_TINYTALK_DOOR_LOCK_ALIRO)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/clusters/door_lock/tm_door_lock_aliro.c)
    zephyr_compile_definitions(TM_DOOR_LOCK_ALIRO=1)
  endif()
  if(CONFIG_TINYTALK_IDENTIFY)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/clusters/identify/tm_identify.c)
  else()
    zephyr_compile_definitions(TM_NO_IDENTIFY)
  endif()

  # The core's logs, on Zephyr's logger (include/tinytalk/tm_log.h).
  zephyr_library_compile_definitions(TM_LOG_HEADER="tm_log_zephyr.h")
  zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ports/zephyr)

  # The crypto seams (see PORTING.md): P-256 and AES-ECB on PSA Crypto, and
  # SPAKE2+ on nrf_oberon, Mbed TLS or tinypsa.
  zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/psa/tm_psa.c)
  # SHA-256 on PSA too: OpenThread already links it, so the core's copy is a
  # duplicate. Global, because the context's layout is in tm_hash.h.
  zephyr_compile_definitions(TM_SHA256_PSA)
  if(CONFIG_TINYTALK_SPAKE2P_OBERON)
    include(${CMAKE_CURRENT_SOURCE_DIR}/backends/oberon/oberon.cmake)
  endif()
  if(CONFIG_TINYTALK_SPAKE2P_MBEDTLS)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/mbedtls/tm_spake2p_mbedtls.c)
  endif()
  if(CONFIG_TINYTALK_SPAKE2P_TINYPSA)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/tinypsa/tm_spake2p_tinypsa.c)
  endif()

  # The Zephyr port: platform, BLE transport, storage, Thread.
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ports/zephyr)

endif(CONFIG_TINYTALK)

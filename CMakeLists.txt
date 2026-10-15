# Hand-written minimal Matter node as a Zephyr module.
# Contributes nothing unless CONFIG_TINYMATTER=y (every existing build stays
# byte-identical). Why this exists at all:
# CHIP does not fit the nRF52833 and rs-matter cannot supply a Door Lock
# cluster, so the DWM3001CDK can only self-provision from Apple Home if the
# node is written by hand.
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
    ${SRC}/tm_hash.c)

  # The CASE initiator, and nothing else, rides with the client build.
  #
  # A separate file behind its own symbol rather than more of matter_case.c,
  # because the point of the option is that an image without it is byte for
  # byte the image that existed before it -- and a preprocessor guard inside a
  # compiled file cannot promise that as plainly as not compiling the file.
  if(CONFIG_TINYMATTER_CLIENT)
    zephyr_library_sources(
      ${SRC}/matter_case_client.c
      ${SRC}/matter_client_sm.c
      ${SRC}/matter_im_client.c
      ${SRC}/matter_binding.c)
    # The client-role code that has no file of its own to live in: the Binding
    # cluster's surface inside matter_clusters.{c,h} -- the target list has to
    # be reachable from a controller and has to sit in struct
    # matter_device_info -- and the two initiator entry points in
    # matter_exchange.c. Neither can move to a separate file, so both are
    # guarded by the macro instead and preprocess away without it.
    #
    # Global rather than library-scoped, for the same reason as
    # MATTER_FEATURE_DL_ALARMS below: the app includes matter_clusters.h, and a
    # header that means one thing to the module and another to its caller is a
    # struct layout mismatch waiting to happen.
    zephyr_compile_definitions(MATTER_FEATURE_CLIENT=1)
  endif()

  # Same reasoning as the client macro above: it changes struct
  # matter_device_info, so the app and the module have to agree on it.
  if(CONFIG_TINYMATTER_MULTI_ADMIN)
    zephyr_compile_definitions(MATTER_FEATURE_MULTI_ADMIN=1)
  endif()

  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

  # The DoorLockAlarm event, off unless CONFIG_TINYMATTER_DOOR_LOCK_ALARMS asks for it.
  #
  # A compile definition rather than a Kconfig symbol because the sources it
  # reaches are platform-agnostic C11 that tests/host builds directly, with no
  # Kconfig anywhere near it -- see matter_clusters.h, which defaults the macro
  # to 0. Global rather than library-scoped: the app includes matter_clusters.h
  # to call the recorder, and a header that means one thing to the module and
  # another to its caller is a struct layout mismatch waiting to happen.
  #
  # Turn it on only for a lock with a sensor that can witness an alarm. Off,
  # every file here preprocesses to what it was before alarms existed, so the
  # default image stays byte-identical.
  if(CONFIG_TINYMATTER_DOOR_LOCK_ALARMS)
    zephyr_compile_definitions(MATTER_FEATURE_DL_ALARMS=1)
  endif()

  # matter_crypto.c uses tm_hash.h for SHA-256/HKDF, compiled above, and the
  # crypto_aes_ecb_encrypt contract, which a crypto backend provides.
  #
  # The crypto seams (see PORTING.md): P-256 and AES-ECB on PSA Crypto, and
  # SPAKE2+ on either nrf_oberon or Mbed TLS.
  if(CONFIG_TINYMATTER_CRYPTO_PSA)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/psa/tm_psa.c)
  endif()
  if(CONFIG_TINYMATTER_SPAKE2P_OBERON)
    include(${CMAKE_CURRENT_SOURCE_DIR}/backends/oberon/oberon.cmake)
  endif()
  if(CONFIG_TINYMATTER_SPAKE2P_MBEDTLS)
    zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/backends/mbedtls/tm_spake2p_mbedtls.c)
  endif()

  # The Zephyr port: BLE transport, fabric store, node glue, Thread or its stub.
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ports/zephyr)

endif(CONFIG_TINYMATTER)

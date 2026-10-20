# SPDX-FileCopyrightText: 2026 Aseem Chopra
# SPDX-License-Identifier: Apache-2.0

# SPAKE2+ on nrf_oberon, the binary library nRF Connect SDK ships in
# nrfxlib/crypto. Nothing is vendored here: the four ocrypto_spake2p_p256_*
# functions matter_spake2p.h declares come from liboberon.
#
# nrf_security already links liboberon, as mbedcrypto_oberon_imported, when its
# PSA driver is the oberon one (CONFIG_PSA_CRYPTO_DRIVER_OBERON), which is the
# case on any nRF part without a CryptoCell. nrfxlib_crypto links it when
# CONFIG_NRF_OBERON is used directly. Linking the same target here only makes
# the dependency explicit; it adds no second copy.
#
# nrf_oberon is under Nordic's own license (nrfxlib/crypto/nrf_oberon/
# license.txt) and is for Nordic devices only. Use backends/mbedtls elsewhere.

if(TARGET mbedcrypto_oberon_imported)
  zephyr_library_link_libraries(mbedcrypto_oberon_imported)
elseif(TARGET nrfxlib_crypto)
  zephyr_library_link_libraries(nrfxlib_crypto)
else()
  message(FATAL_ERROR
    "CONFIG_TINYTALK_SPAKE2P_OBERON needs nrf_oberon: enable CONFIG_NRF_SECURITY "
    "with the oberon PSA driver, or CONFIG_NRF_OBERON, or pick "
    "CONFIG_TINYTALK_SPAKE2P_MBEDTLS.")
endif()

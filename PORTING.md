# Porting tinymatter

## Crypto backends

The core declares its crypto and leaves the implementation to a backend.

| Seam | Backend | Where |
|---|---|---|
| `matter_attest_ec_keygen`, `matter_attest_ecdsa_sign`, `matter_case_ecdh`, `matter_case_sign`, `matter_case_verify`, `crypto_aes_ecb_encrypt` | PSA Crypto | `backends/psa/tm_psa.c` |
| `ocrypto_spake2p_p256_{reduce,check_key,get_key_share,get_ZV}` | nrf_oberon (nRF Connect SDK, Nordic parts only) | `backends/oberon/oberon.cmake`, link only |
| the same four | Mbed TLS 3.6 ECP, any part | `backends/mbedtls/tm_spake2p_mbedtls.c` |

### Why Mbed TLS for the portable SPAKE2+ backend

SPAKE2+ needs a scalar multiple of an arbitrary point and the sum of two
points. The small P-256 libraries (micro-ecc, p256-m) are built around key
generation, ECDH and ECDSA and keep generic point addition internal, so using
one would mean patching it. Mbed TLS exposes both operations in its public ECP
API, is Apache-2.0, and is already carried by Zephyr, ESP-IDF and most MCU
SDKs; nRF Connect SDK v3.3.0 ships 3.6.6, so a Nordic image can switch
backends without a new dependency. Its `mbedtls_ecp_mul()` is documented as
constant-flow with randomized intermediates. The costs: the backend is
written against the 3.6 LTS API, and point addition goes through
`mbedtls_ecp_muladd()`, which is not constant time. The file's header lists
every secret-dependent branch and table lookup.

The backend follows the contracts in nrf_oberon's `ocrypto_spake2p_p256.h`
exactly, so the core cannot tell the two apart. Matter's SPAKE2+ is
draft-bar-cfrg-spake2plus-01, which connectedhomeip cites in
`CHIPCryptoPAL.h`. It differs from RFC 9383 in the key schedule (Ka and Ke are
the halves of Hash(TT)), not in the curve arithmetic these four functions do.
`tests/host/test_spake2p_mbedtls.c` checks the backend against
connectedhomeip's four draft-01 vectors, against the exchange
`tests/host/gen_pase_vector.py` computes, and against the core's PASE
responder.

On the host, `make test` uses this backend by default and needs Mbed TLS 3.6
installed (`brew install mbedtls@3`, or set `MBEDTLS_PREFIX`).
`make test SPAKE=fake` replays one recorded exchange instead and needs no
library.

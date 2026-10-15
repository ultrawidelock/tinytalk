# Porting tinymatter

The core (`src/`, `include/tinymatter/`) is C11 with no operating system and
no crypto library. Everything it cannot do itself, it declares and leaves to
a backend or a port. `make seams` lists exactly those symbols and fails if the
list changes.

## The seams

| Undefined in the core | Provided by | Host tests use |
|---|---|---|
| `tm_sha256{,_init,_update,_final}`, `tm_hmac_sha256`, `tm_hkdf` | `src/tm_hash.c` (portable) | the same file |
| `crypto_aes_ecb_encrypt` | `backends/psa/tm_psa.c` | `tests/host/aes_ref.c` |
| `matter_attest_ec_keygen`, `matter_attest_ecdsa_sign`, `matter_case_ecdh`, `matter_case_sign`, `matter_case_verify` | `backends/psa/tm_psa.c` | `tests/host/test_matter_{attest,case}_stub.c` |
| `ocrypto_spake2p_p256_{reduce,check_key,get_key_share,get_ZV}` | nrf_oberon via `backends/oberon/oberon.cmake`, or `backends/mbedtls/tm_spake2p_mbedtls.c` | the Mbed TLS backend (default) or `tests/host/spakefake` (`SPAKE=fake`) |
| `matter_thread_{start,wait_attached,attached_to,advertise,unadvertise,clear}` | `ports/zephyr/thread/matter_thread_port.c` | `tests/host/test_matter_thread_stub.c` |
| `bzero`, `snprintf`, `mem*`, `str*` | libc | libc |

## Adding a backend

1. Implement the functions of one row above in `backends/<name>/`, with the
   exact prototypes from the core header that declares them
   (`matter_crypto.h`, `matter_attest.h`, `matter_case.h`,
   `matter_spake2p.h`). Include that header so the compiler checks the
   signatures.
2. Match the documented contract, return codes included. For SPAKE2+ that is
   nrf_oberon's `ocrypto_spake2p_p256.h`: `get_ZV` takes `w1` on the prover
   side and `L` on the verifier side, never both.
3. Add a Kconfig option inside the `TINYMATTER_SPAKE2P` choice, and a
   matching line in the root `CMakeLists.txt`.
4. Prove it against outside answers, the way
   `tests/host/test_spake2p_mbedtls.c` checks the Mbed TLS backend against
   connectedhomeip's vectors. A backend that only agrees with itself proves
   nothing.

## Adding an OS port

`ports/zephyr/` is the reference. A port provides:

1. A commissioning transport that carries BTP frames over the 0xFFF6 GATT
   service (`matter_ble_zephyr.c`) and hands whole messages to the node.
2. Persistent storage for the fabric table (`matter_fab_settings.c`, over the
   small key-value seam in `tm_kv.h`).
3. The node glue (`matter_commission.c`): sessions, the exchange, PASE and
   CASE, Interaction Model dispatch, subscriptions, the fail-safe and the
   commissioning window. Its OS surface is Zephyr work queues, timers,
   mutexes, atomics and logging, Zephyr settings for subscription
   persistence, PSA Crypto, and the nRF FICR read that seeds the serial
   number. A new port replaces those.
4. A Thread transport for the six `matter_thread_*` seams.
5. The two application hooks in `matter_commission.h`:
   `matter_commission_readvertise()` and `matter_commission_lock_state()`.

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

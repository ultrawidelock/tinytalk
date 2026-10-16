# Porting tinytalk

The whole node, `src/` and `include/tinytalk/`, is C11 with no operating
system, no radio stack and no crypto library. It needs libc's `mem*`, `str*`
and `snprintf`, and nothing else it does not declare. Everything it declares
and does not define, a port provides. `make seams` lists exactly those symbols
and fails if the list changes (`tests/seams.expected`, 46 symbols).

## What a port provides

| Header | Functions | Zephyr port | Host tests |
|---|---|---|---|
| `tm_platform.h` | `tm_lock`, `tm_unlock`, `tm_trylock`, `tm_uptime_ms`, `tm_work_{schedule,reschedule,cancel}`, `tm_run_deep`, `tm_device_id` | `ports/zephyr/tm_platform_zephyr.c` | `tests/host/host_port.c` |
| `tm_platform.h` | `tm_random` | `backends/psa/tm_psa.c` | `tests/host/host_port.c` |
| `tm_kv.h` | `tm_kv_{init,get,set,delete}` | `ports/zephyr/tm_kv_zephyr.c` | `tests/host/host_port.c` |
| `matter_ble.h` | `matter_ble_send`, `matter_ble_set_{msg,link,tx}_handler`, `matter_ble_{set_,}discriminator` | `ports/zephyr/matter_ble_zephyr.c` | `tests/host/host_port.c` |
| `matter_thread.h` | `matter_thread_{start,clear,wait_attached,attached_to,advertise,unadvertise,advertise_commissionable,unadvertise_commissionable,peer_current,send_to}` | `ports/zephyr/thread/matter_thread_port.c` | `tests/host/test_matter_thread_stub.c`, `tests/host/host_port.c` |
| `matter_crypto.h`, `matter_attest.h`, `matter_case.h` | `crypto_aes_ecb_encrypt`, `matter_attest_ec_keygen`, `matter_attest_ecdsa_sign`, `matter_case_{ecdh,sign,verify}` | `backends/psa/tm_psa.c` | `tests/host/aes_ref.c`, `tests/host/test_matter_{attest,case}_stub.c` |
| `matter_spake2p.h` | `ocrypto_spake2p_p256_{reduce,check_key,get_key_share,get_ZV}` | `backends/oberon/oberon.cmake` or `backends/mbedtls/` | `backends/mbedtls/` or `tests/host/spakefake` (`SPAKE=fake`) |
| `matter_commission.h` | `matter_commission_readvertise` | the application, for example tinylock's door-lock | `tests/host/host_port.c` |
| `tm_log.h` | optional: build with `-DTM_LOG_HEADER="<header>"` | `ports/zephyr/tm_log_zephyr.h` | compiled out |

`tm_hash.c` (SHA-256, HMAC, HKDF) is portable and lives in `src/`; `make seams`
leaves it out on purpose, so the hash shows up as a seam a port may replace.

A cluster module adds what it needs on top: `clusters/door_lock/` wants
`tm_door_lock_actuate()` from the application, and `tm_kv_delete` from the
port for `tm_door_lock_erase()`.

## Calling the node

1. Bring up storage, crypto and the BLE transport.
2. `matter_commission_init(&cfg)` with the vendor and product ids, the
   SPAKE2+ verifier, salt and iteration count from
   `scripts/spake2p_verifier.py`, and the application's endpoint table
   (`tm_app.h`). It restores any stored fabric and runs each cluster's
   `init()`.
3. Deliver what arrives: BLE messages through the handlers the node registers
   with `matter_ble_set_*_handler`, UDP datagrams through
   `matter_thread_on_datagram()`, and each due work item through
   `matter_commission_work()`.
4. Advertise 0xFFF6 while `!matter_commission_has_fabric() ||
   matter_commission_window_open()`, and rebuild the advert whenever
   `matter_commission_readvertise()` is called.

Every node entry point takes `tm_lock()` itself. A single-threaded port makes
the lock a no-op and runs work items from its main loop.

## Adding a cluster

1. Describe it in a `const struct tm_cluster`: its id, every attribute it
   answers in report order (the globals it wants served included), its
   accepted and generated commands, revision and FeatureMap.
2. Fill in the callbacks it needs: `read`, `write`, `invoke` and `response`,
   `event`, `init` for restoring state, `changed` for persisting it. They run
   with the node's lock held, except `changed`.
3. When its state moves, call `tm_attr_changed()` (and `tm_event_emit()` for
   an event) with the lock held. The node reports the change to every
   subscriber whose paths cover it, then calls `changed`.
4. Put it on an endpoint in the table passed to `matter_commission_init()`.

`clusters/door_lock/tm_door_lock.c` is a complete example, and
`tests/host/test_tm_app.c` drives two made-up clusters through the node.
Limits are build-time: `TM_ENDPOINTS_MAX` (4), `TM_CLUSTERS_MAX` (6 per
endpoint), `TM_ATTRS_MAX` (64 in all) and `TM_EVENT_BLOB_MAX` (16 B).

## Adding a crypto backend

1. Implement the functions of one row above in `backends/<name>/`, with the
   exact prototypes from the core header that declares them. Include that
   header so the compiler checks the signatures.
2. Match the documented contract, return codes included. For SPAKE2+ that is
   nrf_oberon's `ocrypto_spake2p_p256.h`: `get_ZV` takes `w1` on the prover
   side and `L` on the verifier side, never both.
3. Prove it against outside answers, the way
   `tests/host/test_spake2p_mbedtls.c` checks the Mbed TLS backend against
   connectedhomeip's vectors. A backend that only agrees with itself proves
   nothing.

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

<!-- DISCLAIMER: maintainer adds this -->

# tinymatter

A from-scratch Matter accessory node in portable C11. Apple Home commissions it
over BLE, and it runs over Thread. It is small enough for an nRF52833 (512 KB
flash, 128 KB RAM). It is not a certified Matter stack.

The whole node, sessions and commissioning included, is in `src/` and needs
no OS, radio stack or crypto library. A port provides 48 functions: a lock,
deferred work, a clock, storage, BLE and Thread transports, and the crypto
(see PORTING.md). Zephyr with OpenThread is the first port, in `ports/zephyr/`.

Extracted from ultrawidelock@d6e23761.

## Why

connectedhomeip, the reference Matter SDK, does not fit a 512 KB / 128 KB part.
tinymatter writes the node by hand instead: TLV, the message layer, MRP, BTP,
PASE with SPAKE2+, CASE, the Interaction Model and a small set of clusters,
with everything platform-specific behind narrow seams.

## What it does

- Commissioning by Apple Home over BLE (BTP on the 0xFFF6 service, PASE).
- Operational CASE sessions and the Interaction Model: read, write, invoke,
  subscribe.
- Thread as an MTD: attach with the dataset the commissioner sends, SRP
  registration, Matter over UDP.
- The Door Lock cluster with no optional features: LockDoor, UnlockDoor,
  LockState, AutoRelockTime and the LockOperation event. In
  `samples/door-lock` it drives LED0.
- Three fabrics, enough for one Apple Home (it uses two) plus one spare.

What it does not do: Matter certification, Wi-Fi, OTA updates, groups, door
lock users or credentials, acting as a controller.

Hardware status: the protocol code was developed and run on hardware in the
source project, with a Door Lock that also carried Aliro, users and
credentials. This repository's featureless Door Lock, its portable node layer
and its builds have been compiled for both boards below and tested on the
host, not yet run on hardware.

## Test credentials

The device attestation certificate, its PAI, the Certification Declaration
and the DAC private key are connectedhomeip's public examples for vendor
0xFFF1, product 0x8001 (see NOTICE). Anyone can sign as this DAC, so every
device built from this repository is an uncertified test accessory, and Apple
Home says so while adding it.

The default setup code is the same for every device built from this tree:
`3650-503-5696` (discriminator 0xF00). The sample prints it at boot. To use
your own, run `scripts/spake2p_verifier.py --passcode <p>` and put its output
in your configuration.

## Layout

```
include/tinymatter/   the node's headers; tm_platform.h, tm_kv.h, matter_ble.h,
                      matter_thread.h and the crypto headers are what a port provides
src/                  the node, portable C11
backends/             crypto: psa/ (P-256, AES, random), oberon/ and mbedtls/ (SPAKE2+)
ports/zephyr/         platform, BLE transport, storage, Thread
samples/door-lock/    the nRF52833 sample
scripts/              SPAKE2+ verifier and pairing-code generator
tests/host/           unit tests and the host port
```

## Build and test

```
make test     # host unit tests
make asan     # the same tests under AddressSanitizer and UndefinedBehaviorSanitizer
make seams    # the 48 symbols the node expects a port to provide
```

On a machine where `cc` or `nm` is not the compiler you want, pass both:
`make test CC=/usr/bin/clang NM="xcrun nm"`.

`make test` uses Mbed TLS 3.6 for the SPAKE2+ curve (`brew install mbedtls@3`,
or set `MBEDTLS_PREFIX`); `make test SPAKE=fake` needs no library.

### The sample

From inside an nRF Connect SDK v3.3.0 workspace:

```
west build -b decawave_dwm3001cdk -d <build-dir> <repo>/samples/door-lock
west flash --erase -d <build-dir>
```

Use `-b nrf52833dk/nrf52833` for the nRF52833 DK. Logs go to SEGGER RTT.

## Sizes

Measured 2026-10-16 from the linker's memory-region report, building
`samples/door-lock` with nRF Connect SDK v3.3.0. The sample takes 16 KB of
flash for settings, which leaves a 496 KB application partition:

| Board | Flash | RAM |
|---|---|---|
| decawave_dwm3001cdk | 340,196 B of 496 KB (66.98%) | 101,792 B of 128 KB (77.66%) |
| nrf52833dk/nrf52833 | 340,440 B of 496 KB (67.03%) | 101,792 B of 128 KB (77.66%) |

## License

ISC, see LICENSE. Third-party data is listed in NOTICE.

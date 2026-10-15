<!-- DISCLAIMER: maintainer adds this -->

# tinymatter

A from-scratch Matter accessory node in portable C11. Apple Home commissions it
over BLE, and it runs over Thread. It is small enough for an nRF52833 (512 KB
flash, 128 KB RAM). The core has no OS dependency; Zephyr with OpenThread is
the first port. It is not a certified Matter stack.

Extracted from ultrawidelock@d6e23761.

## Why

connectedhomeip, the reference Matter SDK, does not fit a 512 KB / 128 KB part.
tinymatter writes the node by hand instead: TLV, the message layer, MRP, BTP,
PASE with SPAKE2+, CASE, the Interaction Model and a small set of clusters,
with the crypto and the OS behind narrow seams (see PORTING.md).

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

Hardware status: the behaviour above was developed and run on hardware in the
source project. Builds from this repository have been compiled for both
boards below and tested on the host, not yet run on hardware.

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

## Build and test

```
make test     # host unit tests
make asan     # the same tests under AddressSanitizer and UndefinedBehaviorSanitizer
make seams    # the symbols the core expects a port or backend to provide
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
`samples/door-lock` with nRF Connect SDK v3.3.0 and its default flash map
(504 KB application partition):

| Board | Flash | RAM |
|---|---|---|
| decawave_dwm3001cdk | 345,784 B of 504 KB (67.00%) | 101,920 B of 128 KB (77.76%) |
| nrf52833dk/nrf52833 | 340,912 B of 504 KB (66.06%) | 101,728 B of 128 KB (77.61%) |

## License

ISC, see LICENSE. Third-party data is listed in NOTICE.

<!-- DISCLAIMER: maintainer adds this -->

# tinymatter

A from-scratch Matter accessory node in portable C11. Apple Home commissions it
over BLE, and it runs over Thread. It is small enough for an nRF52833 (512 KB
flash, 128 KB RAM). The core has no OS dependency; Zephyr with OpenThread is
the first port, and Thread is optional. It is not a certified Matter stack.

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
  registration, Matter over UDP. `overlay-thread.conf` turns it on.
- The Door Lock cluster. In `samples/door-lock` it drives LED0.
- Multi-admin, a second ecosystem beside Apple Home, with
  `CONFIG_TINYMATTER_MULTI_ADMIN=y`. The sample leaves it off; in the source
  project only the client-role image turned it on.

What it does not do: Matter certification, Wi-Fi, OTA updates, groups.

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
west build -b decawave_dwm3001cdk -d <build-dir> <repo>/samples/door-lock \
  -- -DEXTRA_CONF_FILE=overlay-thread.conf
west flash -d <build-dir>
```

Use `-b nrf52833dk/nrf52833` for the nRF52833 DK, and drop the
`EXTRA_CONF_FILE` for a BLE-only build. Logs go to SEGGER RTT.

## Sizes

Measured 2026-10-16 from the linker's memory-region report, building
`samples/door-lock` with nRF Connect SDK v3.3.0 and its default flash map
(504 KB application partition), without `overlay-lto.conf`:

| Board | Thread | Flash | RAM |
|---|---|---|---|
| decawave_dwm3001cdk | off | 220,648 B of 504 KB (42.75%) | 74,312 B of 128 KB (56.70%) |
| decawave_dwm3001cdk | on | 368,232 B of 504 KB (71.35%) | 109,360 B of 128 KB (83.44%) |
| nrf52833dk/nrf52833 | off | 220,940 B of 504 KB (42.81%) | 74,312 B of 128 KB (56.70%) |
| nrf52833dk/nrf52833 | on | 363,372 B of 504 KB (70.41%) | 109,168 B of 128 KB (83.29%) |

Thread on means `-DEXTRA_CONF_FILE=overlay-thread.conf`.

## Fuzzing

`make fuzz` builds five libFuzzer targets from `tests/host/fuzz/` (TLV
decoder, message headers, BTP reassembly, Interaction Model requests, PASE
PBKDFParamRequest and CASE Sigma1) and runs each for `FUZZ_TIME` seconds
(default 600) from the seeds in `tests/host/fuzz/seeds/`. It needs a clang with
libFuzzer, Homebrew LLVM's by default (`FUZZ_CC`). Pass `FUZZ_LDFLAGS` if the
default linker is not the platform one. It only runs when invoked; keep it out
of CI.

Status: the full 10 minutes per target has not been run. One local run on
2026-10-15 was stopped early; before the stop it found no crash and no
sanitizer report:

| Target | Inputs tried | Crashes |
|---|---|---|
| tlv | 483,402 | 0 |
| msg | 2,097,152 | 0 |
| btp | 1,275,854 | 0 |
| im | 1,026,486 | 0 |
| pase_case | 781,804 | 0 |

## License

ISC, see LICENSE. Third-party data is listed in NOTICE.

<!-- DISCLAIMER: maintainer adds this -->

# tinymatter

A from-scratch Matter accessory node in portable C11. Apple Home commissions it
over BLE, and it runs over Thread. It is small enough for an nRF52833 (512 KB
flash, 128 KB RAM). It is not a certified Matter stack.

The whole node, sessions and commissioning included, is in `src/` and needs
no OS, radio stack or crypto library. A port provides 46 functions: a lock,
deferred work, a clock, storage, BLE and Thread transports, and the crypto
(see PORTING.md). Zephyr with OpenThread is the first port, in `ports/zephyr/`.

The node serves endpoint 0 itself. The application describes the rest as a
const table of endpoints and clusters (`tm_app.h`), and a Door Lock cluster
ships as a module (`clusters/door_lock/`).

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
- Application endpoints and clusters from a const table (`tm_app.h`): the
  node builds Descriptor and the global attributes from it, routes reads,
  writes and commands to the cluster, and reports what the application marks
  changed to every subscriber that covers it.
- A Door Lock cluster module with no optional features: LockDoor, UnlockDoor,
  LockState, AutoRelockTime and the LockOperation event, stored across
  reboots. In `samples/door-lock` it drives LED0.
- Three fabrics, enough for one Apple Home (it uses two) plus one spare.

What it does not do: Matter certification, Wi-Fi, OTA updates, groups, door
lock users or credentials, acting as a controller.

Hardware status: the protocol code was developed and run on hardware in the
source project, with a Door Lock that also carried Aliro, users and
credentials. In this repository, commit a42fc6b was commissioned into Apple
Home on a DWM3001CDK on 2026-10-16 and locked and unlocked from it. Later
commits are host-tested and built for both boards below, not yet rerun on
hardware.

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
                      matter_thread.h and the crypto headers are what a port provides;
                      tm_app.h is what an application adds
src/                  the node, portable C11
clusters/             cluster modules for application endpoints: door_lock/
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
make seams    # the 46 symbols the node expects a port to provide
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

For a release image, add `overlay-release.conf`: no logging, no RTT console,
no Bluetooth asserts, 22,004 B less flash. It says nothing over RTT, so debug
with the plain build.

```
west build -b decawave_dwm3001cdk -d <build-dir> <repo>/samples/door-lock -- -DEXTRA_CONF_FILE=overlay-release.conf
```

The sample uses the board's `led0` and `sw0`. LED0 is on while the door is
unlocked. A short press of the button opens a 15-minute commissioning window;
holding it for 5 s erases the fabrics and reboots. On the DWM3001CDK, `led0`
is D9 (green) and `sw0` is SW2. SW1 is the hardware reset: it reboots and
erases nothing.

## Using it in a Zephyr application

Add the repository as a Zephyr module, in the application's `west.yml`:

```yaml
manifest:
  projects:
    - name: tinymatter
      url: <tinymatter-repo-url>
      revision: <commit>
      path: modules/lib/tinymatter
```

or with `list(APPEND ZEPHYR_EXTRA_MODULES <path-to-tinymatter>)` before
`find_package(Zephyr)`, as `samples/door-lock/CMakeLists.txt` does. Then pick
what to build:

| Option | What it adds |
|---|---|
| `CONFIG_TINYMATTER` | the node, the platform port and storage on settings |
| `CONFIG_TINYMATTER_BLE` | BLE commissioning (0xFFF6, BTP); without it the application provides `matter_ble.h` |
| `CONFIG_TINYMATTER_THREAD` | Matter over Thread (OpenThread, SRP, UDP 5540); without it the application provides `matter_thread.h` |
| `CONFIG_TINYMATTER_DOOR_LOCK` | the Door Lock cluster module |
| `CONFIG_TINYMATTER_SPAKE2P_OBERON` or `_MBEDTLS` | the SPAKE2+ backend |

Pass the application's endpoint table to `matter_commission_init()`; PORTING.md
("Adding a cluster") covers writing a cluster.

## Sizes

Measured 2026-10-16 from the linker's memory-region report, building
`samples/door-lock` as shipped (LTO on, logs at INF) with nRF Connect SDK
v3.3.0. The sample takes 16 KB of flash for settings, which leaves a 496 KB
application partition:

| Board | Flash | RAM |
|---|---|---|
| decawave_dwm3001cdk | 309,284 B of 496 KB (60.89%) | 101,984 B of 128 KB (77.81%) |
| nrf52833dk/nrf52833 | 309,496 B of 496 KB (60.94%) | 101,984 B of 128 KB (77.81%) |
| decawave_dwm3001cdk, `overlay-release.conf` | 287,280 B of 496 KB (56.56%) | 93,408 B of 128 KB (71.26%) |
| nrf52833dk/nrf52833, `overlay-release.conf` | 287,312 B of 496 KB (56.57%) | 93,408 B of 128 KB (71.26%) |

What the size levers are worth on the DWM3001CDK, all from one source
state:

| Build | Flash | RAM |
|---|---|---|
| As shipped | 309,284 B | 101,984 B |
| tinymatter's logs off | 298,476 B | 101,984 B |
| `overlay-release.conf` (every log off, RTT off) | 287,280 B | 93,408 B |
| `overlay-release.conf` and Thread 1.1 instead of 1.4 | 282,336 B | 93,024 B |
| LTO off | 342,744 B | 102,048 B |

Thread 1.1 was only measured, not run: the sample stays on 1.4.

Logs off is `-DCONFIG_TINYMATTER_LOG_LEVEL_OFF=y
-DCONFIG_TINYMATTER_BLE_LOG_LEVEL_OFF=y
-DCONFIG_TINYMATTER_THREAD_LOG_LEVEL_OFF=y`; the node then says nothing on RTT.

Of the image without LTO (commit 30a8600), the linker map puts 65,740 B of
flash and 28,548 B of RAM in tinymatter: the node, the Door Lock module, the
PSA backend and the Zephyr port. The rest is OpenThread (75 KB), the BLE
controller and host (71 KB), the 802.15.4 driver (25 KB), nrf_oberon (18 KB)
and Zephyr.

## License

ISC, see LICENSE. Third-party data is listed in NOTICE.

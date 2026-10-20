# tinytalk

A from-scratch Matter accessory node in portable C11, small enough for an
nRF52833 (512 KB flash, 128 KB RAM). Apple Home commissions it over BLE; it
runs over Thread. Not a certified Matter stack.

No OS, radio stack or crypto library: a port provides 48 functions
(`PORTING.md`).

**Does** BLE commissioning (PASE), CASE, read, write, invoke, subscribe,
Thread MTD with SRP, endpoints from a const table, a Door Lock cluster,
three fabrics.

**Does not** certification, Wi-Fi, OTA, groups, door lock users or
credentials, controller role.

52.6 KB flash, 20.9 KB RAM, LTO release build.

## Use

Add as a Zephyr module, then:

```conf
CONFIG_TINYTALK=y             # node, port, settings storage
CONFIG_TINYTALK_BLE=y         # or tinyble's CONFIG_TINYBLE_TINYTALK
CONFIG_TINYTALK_THREAD=y      # or tinygrid's CONFIG_TINYGRID_MATTER
CONFIG_TINYTALK_DOOR_LOCK=y
```

SPAKE2+ backend: `CONFIG_TINYTALK_SPAKE2P_OBERON`, `_MBEDTLS` or `_TINYPSA`.
Pass the endpoint table to `matter_commission_init()`. The door-lock sample
lives in tinylock.

## Test credentials

Attestation is connectedhomeip's public example (vendor 0xFFF1, product
0x8001). Anyone can sign as it, so every build is an uncertified test
accessory. Setup code, the same on every device: `3650-503-5696`. Your own:
`scripts/spake2p_verifier.py --passcode <p>`.

## Test

```sh
make test    # host; Mbed TLS 3.6, or SPAKE=fake for none
make asan    # the same, under ASan and UBSan
make seams   # the 48 symbols a port provides
```

Apache-2.0. Third-party data: `NOTICE`.

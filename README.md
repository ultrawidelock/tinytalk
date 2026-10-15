<!-- DISCLAIMER: maintainer adds this -->

# tinymatter

A from-scratch Matter accessory node in portable C11, small enough for an
nRF52833 (512 KB flash, 128 KB RAM). It is not a certified Matter stack.

Extracted from ultrawidelock@d6e23761.

Status: scaffold. The sections below are filled in as the import lands.

## Build and test

```
make test     # host unit tests
make asan     # the same tests under AddressSanitizer and UndefinedBehaviorSanitizer
make seams    # the symbols the core expects a port or backend to provide
```

On a machine where `cc` or `nm` is not the compiler you want, pass both:
`make test CC=/usr/bin/clang NM="xcrun nm"`.

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

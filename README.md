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

## License

ISC, see LICENSE. Third-party data is listed in NOTICE.

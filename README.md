# Tiny bLSAG

This is a C implementation of bLSAG using [mjosaarinen's tiny_sha3](https://github.com/mjosaarinen/tiny_sha3)
and libsodium ristretto255 in under 200 lines of code, released to the public domain.

### Usage

All you need are the `blsag.{c,h}` and `sha3.{c,h}` files and libsodium 1.0.18 or newer (for the ristretto255 implementation).
The `main.c` file contains an example of signature generation and verification, which can be built using CMake
`cmake -B build && make -C build` landing you with an executable at `build/example`.

### Disclaimer

Keep in mind that this bLSAG implementation **has not been audited** or otherwise thoroughly scrutinized and therefore **is not guaranteed to be secure**.
Treat it as a proof of concept and an exercise, rather than a production-ready implementation.
That said, if you find any bugs or vulnerabilities, please report them.

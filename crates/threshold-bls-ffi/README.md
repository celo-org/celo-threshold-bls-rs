# Threshold BLS FFI

Three binding surfaces over `threshold-bls`, each behind its own Cargo feature.
They serve different consumers and are not interchangeable.

## C bindings (`ffi`)

Used by the iOS and Android consumers. Build the library and take
`cross/threshold.h` alongside it:

```sh
cargo build --package threshold-bls-ffi --no-default-features --features ffi \
    --target <your target> --release
```

`just android` and `just ios` do this for every mobile architecture and stage
the results under `output/`.

**`cross/threshold.h` is generated. Do not edit it.** After any change to the C
surface in `src/ffi.rs`:

```sh
just install-cbindgen   # once
just generate-header
```

and commit the result. CI runs `just check-header`, which regenerates the header,
compiles it as C11, C99, C++, Objective-C and Objective-C++, and fails if the
committed copy is stale. `just check-abi` additionally compiles
`cross/smoke_test.c` against the header, links it to the real library and runs
it — Rust tests cannot catch a header that disagrees with the library it
describes.

### Threshold operations

`partial_sign`, `partial_sign_blinded_message`, `partial_verify` and
`partial_verify_blind_signature` take the share and the public commitment
polynomial as serialized bytes, the same way the WASM surface does. Key
generation is deliberately not part of this API — a trustful central keygen has
no place in production — so a signer receives its share out of band, from a DKG,
and hands the bytes straight to `partial_sign`.

`combine` splits its flattened input into `PARTIAL_SIG_LENGTH` chunks, so build
that buffer by concatenating whole partials.

Two rough edges are deferred to a planned redesign of this surface:
`serialize_pubkey`, `serialize_privkey` and `serialize_sig` return a pointer
without its length, so a caller has to pair it with the matching `PUBKEY_LEN`,
`PRIVKEY_LEN` or `SIGNATURE_LEN` from the header to call `free_vector`
correctly. And `verify_blind_signature`, which verifies a blind signature
without unblinding it first, exists in the WASM surface but has no C
counterpart.

## WASM bindings (`wasm`)

Published as `@celo/blind-threshold-bls` and used by the ODIS signer and
combiner, so this path is production infrastructure.

```sh
wasm-pack build --target nodejs -- --features=wasm
```

The bundled package lands in `pkg/`. `just wasm` runs the same build inside the
release Docker image.

Only the Node target is built here. The browser path documented by SocialConnect
points at an unmerged branch of `blind-threshold-bls-wasm` from 2022.

## JNI bindings (`jvm`)

A single `verify` function for JVM callers, built by `just jvm`. Note that
Android does **not** use this — it reaches the C ABI through JNA.

```sh
cargo build --release --features jvm
```

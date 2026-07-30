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

### Known limitation: the partial-signing operations are unreachable from C

`partial_sign`, `partial_sign_blinded_message`, `partial_verify` and
`partial_verify_blind_signature` take a `KeyShare` or a `PublicPoly`, and
nothing in the C API produces either — the threshold key generation helper is
test-only, since a trustful central keygen has no place in production. A C
caller can only reach these by obtaining the handles out of band. The WASM
surface has the same operations and does not have this problem, because it
takes serialized bytes.

Two more rough edges, both deferred to a planned redesign of this surface:
`serialize_pubkey`, `serialize_privkey` and `serialize_sig` return a pointer
without its length, and the length constants are not exported, so a caller has
to know that public keys are 96 bytes, private keys 32 and signatures 48 in
order to call `free_vector` correctly. And `verify_blind_signature`, which
verifies a blind signature without unblinding it first, exists in the WASM
surface but has no C counterpart.

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

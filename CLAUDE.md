# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# celo-threshold-bls-rs

Threshold BLS signatures over BLS12-377, with blind signing (based on
[eprint 2018/733](https://eprint.iacr.org/2018/733.pdf)) so users can request
signatures without revealing the message. Two crates: `crates/threshold-bls`
(the cryptography) and `crates/threshold-bls-ffi` (bindings).

## Commands

```sh
cargo test --workspace --all-features   # native, works on Apple Silicon
just lint                               # clippy --all-targets --all-features -D warnings
just fmt                                # rustfmt check
cargo test -p threshold-bls poly::      # single test / module filter
```

- CI (`.github/workflows/rust_ci.yml`) runs `cargo nextest run --workspace
  --all-features`, then `cargo test --doc` as a second step. nextest does not
  run doctests, so anything that only executes under plain `cargo test` — the
  doctests in `threshold-bls/src/lib.rs` and `sig/sig.rs` — needs that step to
  be covered.
- `just test` (and `just test-cached`, which adds cargo/target cache volumes)
  runs `cargo test --features wasm` inside the linux/amd64 Docker build image —
  the same environment the released libraries are built in. Requires Docker.
- To exercise one surface on its own, pair the feature with
  `--no-default-features`, e.g.
  `cargo test -p threshold-bls-ffi --no-default-features --features ffi`.
- Release artifacts are built by justfile recipes (`just wasm|jvm|android|ios`,
  outputs under `output/`). All but `ios` require Docker (linux/amd64 image);
  `ios` requires a macOS host with Xcode. The toolchain is pinned to Rust 1.97
  by `rust-toolchain.toml`; the Docker image version via `RUST_VERSION`.
- CI split: GitHub Actions tests, lints, audits, and runs the npm package
  suite in `bindings/js` against a fresh wasm-pack build. CircleCI only
  builds the platform artifacts.

## Architecture

`threshold-bls` is a tower of traits, generic over the curve:

- `group.rs` — the algebra layer: `Element`, `Scalar`, `Point`, and
  `PairingCurve` traits. Everything above is written against these.
- `curve/bls12377.rs` — the only curve implementation, wrapping arkworks.
  Supporting a new curve means implementing `PairingCurve` here.
- `poly.rs` — Shamir secret-sharing polynomials (`Poly`, `Idx`): `eval` to
  deal shares, `commit` for the public polynomial, interpolation to recover.
- `sig/` — one trait per capability, stacked: `Scheme` (associated
  Private/Public/Signature types) → `SignatureScheme` (`bls.rs`) →
  `BlindScheme` (`blind.rs`) → `ThresholdScheme` (`tbls.rs`) →
  `BlindThresholdScheme` (`tblind.rs`). `sig/sig.rs` holds the trait
  definitions; the other files implement them.
- `serialization.rs` — bounded bincode helpers that cap input size so
  attacker-crafted length prefixes can't OOM. Use these, not raw bincode.
- `schemes::bls12_377::{G1Scheme, G2Scheme}` in `lib.rs` are the
  pre-instantiated entry points; the names say which group holds public keys
  (signatures live in the other group).

`threshold-bls-ffi` fixes the scheme to `G2Scheme` (public keys 96 bytes on
G2, signatures 48 bytes on G1); the byte-length constants live in its
`lib.rs`.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Any consumer-visible change (API, behavior, security, feature flags, artifact
properties, toolchain floors) gets an entry under `[Unreleased]` in the same
PR; pure CI plumbing and routine dependency bumps do not. Prefix entries with
the affected surface (`sig:`, `wasm:`, `ffi:`, ...) and link the PR or commit.

## Commit messages

Use [Scoped Commits](https://scopedcommits.com/): `<scope>: <description>`,
where the scope is the subsystem the commit touches (e.g. `ffi`, `wasm`,
`sig`, `build`, `ci`). Use `all` for commits spanning the whole
repo.

## Who consumes which binding

`crates/threshold-bls-ffi` exposes three separate surfaces, gated by Cargo
feature. They serve different consumers and are not interchangeable.

- **`ffi` (C ABI, `src/ffi.rs` + `cross/threshold.h`)** — iOS and Android.
  The mobile consumer is closed source, so a public code search for consumers
  of the C ABI comes back empty. **Do not read that as evidence the C ABI is
  unused.** The build floors (Android API 24, iOS 15.2; `android_api` and
  `ios_deployment_target` in the justfile) track that consumer's minimum
  supported targets (PR #168) — don't bump them unilaterally.
- **`wasm` (`src/wasm.rs`)** — built for Node and published as
  `@celo/blind-threshold-bls`, whose npm packaging, examples and jest suite
  live in `bindings/js` (`src/` there is gitignored and filled from wasm-pack
  output). The ODIS signer and combiner in `celo-org/social-connect` both
  depend on it, so this path is production infrastructure. The
  `wasm-pkg-tests` job in `.github/workflows/rust_ci.yml` builds the package
  and runs that suite. The former standalone repo
  `celo-org/blind-threshold-bls-wasm` is legacy, pending archival.
- **Browser** — no artifact is built here. `social-connect`'s `docs/privacy.md`
  points users at the unmerged `web-compatible` branch of
  `blind-threshold-bls-wasm` (commit `3d1013af`, October 2022), which predates
  every fix since.
- **`jvm` (`src/jni_bridge.rs`)** — a single `verify` function with no known
  consumer. Android reaches the C ABI through JNA, not through this bridge.

## Feature gating in `lib.rs`

Each surface hangs off its own `#[cfg(feature = "...")]`, so the three are
independent: `--all-features` compiles wasm, jvm and ffi together, and builds,
tests and lints all of them in one run.

This replaced a `core::cfg_select!` whose first matching arm won, in the order
wasm, jvm, ffi. Since every CI job passes `--all-features`, only `wasm.rs` was
ever compiled: the `ffi.rs` tests were skipped, clippy never saw `ffi.rs` or
`jni_bridge.rs`, and cbindgen could not expand the macro. Audit reports and CI
runs predating the change cover the wasm surface only.

## The generated C header

`cross/threshold.h` is produced by cbindgen from `ffi.rs` — do not edit it.
Run `just generate-header` after any change to the C surface and commit the
result; `just install-cbindgen` provides the pinned version it insists on.

CI enforces this twice over. `just check-header` regenerates, compiles the
header as C11, C99, C++, Objective-C and Objective-C++, and fails on drift.
`just check-abi` compiles `cross/smoke_test.c` against it, links the cdylib and
runs it, then diffs the exported symbols against
`cross/exported-symbols.txt`. The second is what catches a header that
disagrees with the library; Rust tests call Rust functions with Rust types and
structurally cannot.

Three things constrain how the header can be generated, all of them learned the
hard way:

- `[parse] parse_deps = true` panics on the arkworks generics
  (`G1Curve has 0 params but is being instantiated with 1 values`).
- cbindgen renders a `repr(transparent)` struct as a typedef of the type it
  wraps, so `BlindingFactor` would come out as
  `typedef Token<PrivateKey> BlindingFactor;`. It is declared by hand in
  `after_includes` and excluded, as are the `PrivateKey`/`PublicKey`/`Signature`
  aliases, which resolve to names cbindgen cannot declare. It is the only such
  handle: everything else the C API returns has a serialized form and crosses as
  bytes.
- cbindgen does not evaluate features, so it sees `wasm.rs` too. That is why the
  struct behind the `Keypair` JS class is named `WasmKeypair`.

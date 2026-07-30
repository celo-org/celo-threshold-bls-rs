# Threshold BLS Signatures

## Overview

This crate provides libraries and command line interfaces for producing threshold BLS signatures. The signatures can also be [blind](https://en.wikipedia.org/wiki/Blind_signature) in order to preserve the privacy of the user asking for a signature from another set of parties.

> **Note:** The DKG (Distributed Key Generation) crates have been removed from this repository as they were unstable and not necessary for the BLS crates to work. They were removed in commit [a911f40f0fd31fabae197016b87640f2fdcf1c9f](https://github.com/celo-org/celo-threshold-bls-rs/commit/a911f40f0fd31fabae197016b87640f2fdcf1c9f).

## Building with Docker

The project includes a [justfile](https://just.systems) that supports building for multiple platforms using Docker. All built libraries are placed in the `output` directory, organized by platform. Run `just` to list the available recipes.

Install `just` with your package manager (`brew install just`, `cargo install just`) or with the
[install script](https://just.systems/man/en/pre-built-binaries.html):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/bin
```

### Clean Build

To clean the output directory before building:

```sh
just clean
```

### Build All Platforms

```sh
just all
```

This builds the libraries for all supported platforms.

### Running Tests

The tests run natively, including on Apple Silicon:

```sh
cargo test --workspace --all-features
```

To run them in the linux/amd64 build image instead, which is what CI builds against:

```sh
just test
```

### WASM Build

```sh
just wasm
```

This builds WebAssembly bindings that can be used with Node.js and places them in `output/wasm`.

### JVM Build

```sh
just jvm
```

This builds JVM-compatible libraries and places them in `output/jvm`.

### Minimum mobile OS versions

The mobile builds target:

- **Android**: API level 24 (Android 7.0) — set via `android_api` in the `justfile`
- **iOS**: 15.2 — set via `ios_deployment_target` in the same file

### iOS Build

```sh
just ios
```

This builds a universal static library for iOS (combining aarch64 and x86_64 architectures) and places it in `output/ios`. Note that iOS builds must be run on a macOS host as they cannot be built in Docker.

### Android Build

```sh
just android
```

This builds dynamic libraries for Android architectures (x86, x86_64, arm64-v8a, and armeabi-v7a) and places them in `output/android`.

### Docker Build

The docker image used for building the libraries can be built separately if needed:

```sh
just build-docker-image
```

### Rust version

Rust 1.95.0 is used by default and tested for all builds. If desired, you can build with a different Rust version by setting the `RUST_VERSION` env var:

```sh
just RUST_VERSION=1.95.0 all
```

## Directory Structure

This repository contains Rust crates that implement threshold BLS signatures. The high-level structure of the repository is as follows:

- [`threshold-bls`](crates/threshold-bls): (blind) threshold BLS signatures for BLS12-377
- [`threshold-bls-ffi`](crates/threshold-bls-ffi): FFI and WASM bindings to `threshold-bls` for cross platform interoperability

## Disclaimers

**This software has not been audited. Use at your own risk.**

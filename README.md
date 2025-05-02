<h1 align="center">Threshold BLS Signatures and DKG</h1>

## Overview

This crate provides libraries and command line interfaces for producing threshold BLS signatures. The signatures can also be [blind](https://en.wikipedia.org/wiki/Blind_signature) in order to preserve the privacy of the user asking for a signature from another set of parties. 

Distributed Key Generation for generating the threshold public key is based on [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems
](https://link.springer.com/article/10.1007/s00145-006-0347-3)`

## Building with Docker

The project includes a Makefile that supports building for multiple platforms using Docker. All built libraries are placed in the `output` directory, organized by platform.

### Clean Build

To clean the output directory before building:
```
make clean
```

### Build All Platforms
```
make all
```
This builds the libraries for all supported platforms.

### WASM Build
```
make wasm
```
This builds WebAssembly bindings that can be used with Node.js and places them in `output/wasm`.

### JVM Build
```
make jvm
```
This builds JVM-compatible libraries and places them in `output/jvm`.

### iOS Build
```
make ios
```
This builds a universal static library for iOS (combining aarch64 and x86_64 architectures) and places it in `output/ios`. Note that iOS builds must be run on a macOS host as they cannot be built in Docker.

### Android Build
```
make android
```
This builds dynamic libraries for Android architectures (x86, x86_64, arm64-v8a, armeabi, and armeabi-v7a) and places them in `output/android`.

### Docker Build

The docker image used for building the libraries can be built separately if needed:
```
make build-docker-image
```

### Rust version

Rust 1.62.0 is used by default and tested for all builds. If desired, you can build with a different Rust version by setting the RUST_VERSION env var:
``` 
make RUST_VERSION=1.56.1
```

## Directory Structure

This repository contains several Rust crates that implement the different building blocks of the MPC. The high-level structure of the repository is as follows:

- [`dkg-cli`](crates/dkg-cli): Rust crate that provides a CLI for the distributed key generation
- [`dkg-core`](crates/dkg-core): Rust crate that provides the implementation utilities for the DKG
- [`threshold-bls`](crates/threshold-bls): (blind) threshold BLS signatures for BLS12-381 and BLS12-377
- [`threshold-bls-ffi`](crates/threshold-bls-ffi): FFI and WASM bindings to `threshold-bls` for cross platform interoperability

Note: the dkg crates have been removed from the workspace in this branch as they are not needed to build the bls crates.

## Disclaimers

**This software has not been audited. Use at your own risk.**

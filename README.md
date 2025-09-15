<h1 align="center">Threshold BLS Signatures</h1>

## Overview

This crate provides libraries and command line interfaces for producing threshold BLS signatures. The signatures can also be [blind](https://en.wikipedia.org/wiki/Blind_signature) in order to preserve the privacy of the user asking for a signature from another set of parties. 

> **Note:** The DKG (Distributed Key Generation) crates have been removed from this repository as they were unstable and not necessary for the BLS crates to work. They were removed in commit [a911f40f0fd31fabae197016b87640f2fdcf1c9f].

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

### Running Tests

To run tests:
```
make test
```

This runs the tests in a Docker container which is especially important for Apple Silicon (M1/M2/M3) Macs, as some dependencies have compatibility issues when running natively on ARM64 architecture. The Docker container provides an x86_64 / amd64 environment where all tests run successfully.

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

Rust 1.82.0 is used by default and tested for all builds. If desired, you can build with a different Rust version by setting the RUST_VERSION env var:
``` 
make RUST_VERSION=1.56.1
```

## Directory Structure

This repository contains Rust crates that implement threshold BLS signatures. The high-level structure of the repository is as follows:

- [`threshold-bls`](crates/threshold-bls): (blind) threshold BLS signatures for BLS12-381 and BLS12-377
- [`threshold-bls-ffi`](crates/threshold-bls-ffi): FFI and WASM bindings to `threshold-bls` for cross platform interoperability

## Disclaimers

**This software has not been audited. Use at your own risk.**

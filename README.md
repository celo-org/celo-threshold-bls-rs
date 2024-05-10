<h1 align="center">Threshold BLS Signatures and DKG</h1>

Fork of the Celo [project](https://github.com/celo-org/celo-threshold-bls-rs).

## Overview

This crate provides libraries and command line interfaces for producing threshold BLS signatures. The signatures can also be [blind](https://en.wikipedia.org/wiki/Blind_signature) in order to preserve the privacy of the user asking for a signature from another set of parties. 

Distributed Key Generation for generating the threshold public key is based on [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems
](https://link.springer.com/article/10.1007/s00145-006-0347-3)

## Build Guide

Build with `cargo build (--release)`.

Test with `cargo test`.

All crates require Rust 2021 edition and are tested on the following channels:
- `1.64.0`

If you do not have Rust installed, run: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

## Android and iOS

The library compiles to Android and iOS. This has been tested with Rust v1.64.0.

To compile to Android:

1. Download Android NDK r21 and unzip it
2. Set the `NDK_HOME` env var to the extracted directory
3. `cd cross`
4. `./create-ndk-standalone`
5. `make android`

To compile to ios:
3. `cd cross`
4. `make ios`

## Directory Structure

This repository contains several Rust crates that implement the different building blocks of the MPC. The high-level structure of the repository is as follows:

- [`dkg-cli`](crates/dkg-cli): Rust crate that provides a CLI for the distributed key generation
- [`dkg-core`](crates/dkg-core): Rust crate that provides the implementation utilities for the DKG
- [`threshold-bls`](crates/threshold-bls): (blind) threshold BLS signatures for BLS12-381 and BLS12-377
- [`threshold-bls-ffi`](crates/threshold-bls-ffi): FFI and WASM bindings to `threshold-bls` for cross platform interoperability


## Disclaimers

**This software has not been audited. Use at your own risk.**

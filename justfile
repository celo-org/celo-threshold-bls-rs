# Build recipes for the threshold BLS libraries.
#
# Variables in upper case are the knobs meant to be overridden, either as an
# environment variable (`FEATURES=ffi just android`) or as a command line
# assignment (`just RUST_VERSION=1.95.0 all`). Lower case variables are derived
# and not meant to be set.

RUST_VERSION := env("RUST_VERSION", "1.95.0")

# Cargo features for the Android/iOS cross builds. The mobile consumers link
# against the C ABI (threshold.h), which requires "ffi"; without it the
# produced libraries export no symbols.
FEATURES := env("FEATURES", "ffi")

# Pinned because generated output varies between cbindgen releases, and the
# header is checked in.
cbindgen_version := "0.29.4"

image_name := "celo-bls-rust-" + replace(RUST_VERSION, ".", "_")
output_dir := justfile_directory() / "output"
target_dir := justfile_directory() / "target"
lib_name := "libblind_threshold_bls"
cargo_cache_volume := "celo-bls-cargo-cache"
target_cache_volume := "celo-bls-target-cache"
cargo_features := if FEATURES != "" { "--features " + FEATURES } else { "" }

android_targets := "aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android"
android_api := "24"
ndk_host_tag := env("NDK_HOST_TAG", "linux-x86_64")
# Android 15 devices can run with 16 KB memory pages, which requires the ELF
# segments to be aligned accordingly.
android_rustflags := "-C link-args=-Wl,-z,max-page-size=16384"
# Where `android-libs` stages the shared objects inside the build container.
# The host reads them back from here with `docker cp`.
container_android_dir := "/output/android"

ios_targets := "aarch64-apple-ios x86_64-apple-ios"
ios_deployment_target := "15.2"

# List the available recipes
default:
    @just --list

# Clean the output directory and build every platform from scratch
all: clean build-docker-image wasm jvm ios android

# Remove all built libraries
clean:
    rm -rf {{ output_dir }}

build-docker-image:
    docker build --progress=plain --platform=linux/amd64 --build-arg RUST_VERSION={{ RUST_VERSION }} -t {{ image_name }} .

# Docker bind mounts don't work with CircleCI's setup_remote_docker (the daemon
# runs on a separate VM from the job container), so the recipes below extract
# artifacts with `docker cp` after the container exits.

# Build the WASM bindings for Node.js into output/wasm
wasm: build-docker-image
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{ output_dir }}/wasm
    cid=$(docker create --platform=linux/amd64 \
        -w /app/crates/threshold-bls-ffi \
        {{ image_name }} \
        wasm-pack build --target nodejs -- --features=wasm)
    trap 'docker rm -f "$cid" >/dev/null' EXIT
    docker start -a "$cid"
    docker cp "$cid":/app/crates/threshold-bls-ffi/pkg/. {{ output_dir }}/wasm/

# Build the JNI shared library into output/jvm
jvm: build-docker-image
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{ output_dir }}/jvm
    cid=$(docker create --platform=linux/amd64 \
        -w /app/crates/threshold-bls-ffi \
        {{ image_name }} \
        cargo build --release --features=jvm)
    trap 'docker rm -f "$cid" >/dev/null' EXIT
    docker start -a "$cid"
    docker cp "$cid":/app/target/release/{{ lib_name }}.so {{ output_dir }}/jvm/

# Build the Android shared libraries into output/android
android: build-docker-image
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{ output_dir }}/android
    cid=$(docker create --platform=linux/amd64 \
        -w /app \
        -e FEATURES={{ quote(FEATURES) }} \
        -e NDK_HOME=/opt/android-ndk \
        {{ image_name }} just android-libs)
    trap 'docker rm -f "$cid" >/dev/null' EXIT
    docker start -a "$cid"
    docker cp "$cid":{{ container_android_dir }}/. {{ output_dir }}/android/

# iOS builds cannot run in Docker, so they run on the macOS host.

# Build the universal iOS static library into output/ios
ios: ios-setup
    #!/usr/bin/env bash
    set -euo pipefail
    archives=()
    for target in {{ ios_targets }}; do
        IPHONEOS_DEPLOYMENT_TARGET={{ ios_deployment_target }} \
            cargo build --package threshold-bls-ffi --no-default-features {{ cargo_features }} \
                --target "$target" --release --lib
        archives+=("{{ target_dir }}/$target/release/{{ lib_name }}.a")
    done
    mkdir -p {{ output_dir }}/ios
    lipo -create -output {{ output_dir }}/ios/{{ lib_name }}.a "${archives[@]}"

ios-setup:
    rustup target add {{ ios_targets }}

android-setup:
    rustup target add {{ android_targets }}

# Stages the libraries under the ABI directory names the Android build system
# expects. Runs inside the build container, which provides the NDK.

# Cross-compile the shared library for every Android architecture
android-libs: android-setup
    #!/usr/bin/env bash
    set -euo pipefail
    just build-android-target aarch64-linux-android aarch64-linux-android
    just build-android-target armv7-linux-androideabi armv7a-linux-androideabi
    just build-android-target i686-linux-android i686-linux-android
    just build-android-target x86_64-linux-android x86_64-linux-android

    for abi in x86 x86_64 arm64-v8a armeabi-v7a; do
        mkdir -p {{ container_android_dir }}/"$abi"
    done
    cp {{ target_dir }}/i686-linux-android/release/{{ lib_name }}.so {{ container_android_dir }}/x86/
    cp {{ target_dir }}/x86_64-linux-android/release/{{ lib_name }}.so {{ container_android_dir }}/x86_64/
    cp {{ target_dir }}/aarch64-linux-android/release/{{ lib_name }}.so {{ container_android_dir }}/arm64-v8a/
    cp {{ target_dir }}/armv7-linux-androideabi/release/{{ lib_name }}.so {{ container_android_dir }}/armeabi-v7a/

# Build one Android target with the NDK toolchain. The clang prefix is passed
# separately because it differs from the target triple for armv7.
[private]
build-android-target target clang_prefix:
    #!/usr/bin/env bash
    set -euo pipefail
    ndk_bin="$NDK_HOME/toolchains/llvm/prebuilt/{{ ndk_host_tag }}/bin"
    clang="{{ clang_prefix }}{{ android_api }}-clang"
    # Cargo names the linker variable after the target triple, so it has to be
    # built at runtime and passed through `env`.
    linker_var="CARGO_TARGET_$(echo '{{ target }}' | tr 'a-z-' 'A-Z_')_LINKER"
    env \
        PATH="$ndk_bin:$PATH" \
        CC="$clang" \
        CXX="{{ clang_prefix }}{{ android_api }}-clang++" \
        AR=llvm-ar \
        CARGO_BUILD_RUSTFLAGS="{{ android_rustflags }}" \
        "$linker_var=$clang" \
        cargo build --package threshold-bls-ffi --no-default-features {{ cargo_features }} \
            --target {{ target }} --release --lib

# The tests also run natively; this recipe exists to run them against the same
# linux/amd64 image the released libraries are built in.

# Run the tests in Docker
test: build-docker-image
    docker run --platform=linux/amd64 --rm -w /app {{ image_name }} cargo test --features wasm -- --nocapture

# Run the tests in Docker, caching Cargo and target directories in volumes
test-cached: create-cache-volumes build-docker-image
    docker run --platform=linux/amd64 --rm \
        -v {{ cargo_cache_volume }}:/root/.cargo \
        -v {{ target_cache_volume }}:/app/target \
        -v {{ justfile_directory() }}:/app \
        -w /app {{ image_name }} cargo test --features wasm -- --nocapture

create-cache-volumes:
    docker volume create {{ cargo_cache_volume }}
    docker volume create {{ target_cache_volume }}

lint:
    cargo clippy --all-targets --all-features -- -D warnings

fmt:
    cargo fmt --all -- --check

# Install the pinned cbindgen. Needed once before `generate-header`.
install-cbindgen:
    cargo install cbindgen --version {{ cbindgen_version }} --locked

# Regenerate cross/threshold.h from ffi.rs. Run after any change to the C ABI
# and commit the result; `check-header` fails if it is stale.
generate-header:
    #!/usr/bin/env bash
    set -euo pipefail
    # `command -v` first: under `set -e` a missing binary would abort the recipe
    # before the version check could explain why.
    command -v cbindgen >/dev/null || {
        echo "cbindgen not found; run: just install-cbindgen" >&2
        exit 1
    }
    have=$(cbindgen --version | awk '{print $2}')
    if [ "$have" != "{{ cbindgen_version }}" ]; then
        echo "need cbindgen {{ cbindgen_version }}, found $have; run: just install-cbindgen" >&2
        exit 1
    fi
    cd {{ justfile_directory() }}/crates/threshold-bls-ffi
    cbindgen --output cross/threshold.h

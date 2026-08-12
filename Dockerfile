ARG RUST_VERSION=1.97.1
FROM ubuntu:26.04

ARG RUST_VERSION

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Use a CDN-backed mirror instead of archive.ubuntu.com for CI reliability
# Ubuntu 24.04 uses DEB822 format in /etc/apt/sources.list.d/ubuntu.sources
RUN sed -i 's|http://archive.ubuntu.com|http://mirrors.edge.kernel.org|g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's|http://security.ubuntu.com|http://mirrors.edge.kernel.org|g' /etc/apt/sources.list.d/ubuntu.sources

# Update package lists and install required dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    -o Acquire::Retries=3 \
    curl \
    build-essential \
    git \
    pkg-config \
    libssl-dev \
    ca-certificates \
    unzip

# Install rustup with a default toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}

# Add Cargo's bin directory to the PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# The Android cross build runs `just` inside the container
ARG JUST_VERSION=1.57.0
RUN curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh \
    | bash -s -- --tag "${JUST_VERSION}" --to /usr/local/bin

ARG WASM_PACK_VERSION=0.14.0
# wasm-pack publishes no checksums with its releases, so this hash was taken
# from the bytes GitHub served on 2026-08-11. It pins the artifact rather than
# vouching for it: a later release reusing the tag, or a rewritten asset, fails
# the build instead of shipping.
ARG WASM_PACK_SHA256=278a8d668085821f4d1a637bd864f1713f872b0ae3a118c77562a308c0abfe8d
RUN curl -fsSL -o /tmp/wasm-pack.tar.gz \
    "https://github.com/wasm-bindgen/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" && \
    echo "${WASM_PACK_SHA256}  /tmp/wasm-pack.tar.gz" | sha256sum -c - && \
    tar -xz -C /usr/local/bin --strip-components=1 \
        -f /tmp/wasm-pack.tar.gz "wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack" && \
    rm /tmp/wasm-pack.tar.gz

# Install Android NDK. Google publishes only a SHA-1 for it, in the SDK manifest
# at dl.google.com/android/repository/repository2-3.xml; the download was checked
# against that (22105e410cf29afcf163760cc95522b9fb981121) and this SHA-256 taken
# from the same bytes.
ARG NDK_VERSION=r27d
ARG NDK_SHA256=601246087a682d1944e1e16dd85bc6e49560fe8b6d61255be2829178c8ed15d9
RUN curl -fL https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip -o /tmp/ndk.zip && \
    echo "${NDK_SHA256}  /tmp/ndk.zip" | sha256sum -c - && \
    unzip /tmp/ndk.zip -d /opt && \
    mv /opt/android-ndk-${NDK_VERSION} /opt/android-ndk && \
    rm /tmp/ndk.zip

WORKDIR /app

COPY . .

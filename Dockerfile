ARG RUST_VERSION=1.97.1
FROM ubuntu:24.04

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
RUN curl -fsSL "https://github.com/wasm-bindgen/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
    | tar -xz -C /usr/local/bin --strip-components=1 "wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack"

# Install Android NDK
RUN curl -L https://dl.google.com/android/repository/android-ndk-r27d-linux.zip -o /tmp/ndk.zip && \
    unzip /tmp/ndk.zip -d /opt && \
    mv /opt/android-ndk-r27d /opt/android-ndk && \
    rm /tmp/ndk.zip

WORKDIR /app

COPY . .

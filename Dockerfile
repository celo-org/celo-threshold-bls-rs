ARG RUST_VERSION=1.62.0
FROM ubuntu:20.04

ARG RUST_VERSION

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install required dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    git \
    pkg-config \
    libssl-dev \
    ca-certificates \
    unzip \
    python

# Install rustup without a default toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}

# Add Cargo's bin directory to the PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Rust and set it as the default toolchain
RUN rustup toolchain install ${RUST_VERSION} && rustup default ${RUST_VERSION}

# Install wasm-pack
# There is no cargo-installable version of wasm-pack that will "just work" with Rust 1.41.0 today, because of unpinned upstream dependencies like log.
# So we have to build it from source and pin the dependencies to the versions that work with Rust 1.41.0.
RUN curl -L https://github.com/rustwasm/wasm-pack/archive/refs/tags/v0.8.1.tar.gz \
    | tar xz -C /tmp && \
    cd /tmp/wasm-pack-0.8.1 && \
    sed -i 's/log = ".*"/log = "=0.4.14"/' Cargo.toml && \
    cargo build --release && \
    cp target/release/wasm-pack /usr/local/bin/ && \
    rm -rf /tmp/wasm-pack-0.8.1

# Install Android NDK
RUN curl -L https://dl.google.com/android/repository/android-ndk-r21-linux-x86_64.zip -o /tmp/ndk.zip && \
    unzip /tmp/ndk.zip -d /opt && \
    mv /opt/android-ndk-r21 /opt/android-ndk && \
    rm /tmp/ndk.zip

WORKDIR /app

COPY . .


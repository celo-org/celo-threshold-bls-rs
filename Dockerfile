# Use an official Ubuntu image (20.04 in this example)
FROM ubuntu:20.04

# Set non-interactive mode for apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update package lists and install required dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    git \
    pkg-config \
    libssl-dev \
    ca-certificates

# Install rustup without a default toolchain (we'll install 1.41 manually)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

# Add Cargo's bin directory to the PATH
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Rust 1.41.0 and set it as the default toolchain
RUN rustup toolchain install 1.41.0 && rustup default 1.41.0

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

WORKDIR /app

COPY . .


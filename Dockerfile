ARG RUST_VERSION=1.89.0
FROM ubuntu:22.04

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
    python3 \
    python-is-python3

# Install rustup with a default toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION}

# Add Cargo's bin directory to the PATH
ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install wasm-pack@0.13.1

# Install Android NDK
RUN curl -L https://dl.google.com/android/repository/android-ndk-r27d-linux.zip -o /tmp/ndk.zip && \
    unzip /tmp/ndk.zip -d /opt && \
    mv /opt/android-ndk-r27d /opt/android-ndk && \
    rm /tmp/ndk.zip

WORKDIR /app

COPY . .


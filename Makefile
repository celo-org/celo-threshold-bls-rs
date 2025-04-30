RUST_VERSION ?= 1.62.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR=output
BUILD_TYPE ?= wasm  # Options: wasm, jvm, ios, android

.PHONY: all build run clean build-ios build-android

all: clean build run

build:
ifeq ($(BUILD_TYPE),ios)
	mkdir -p $(OUTPUT_DIR)/ios
	rustup target add aarch64-apple-ios x86_64-apple-ios
	cd crates/threshold-bls-ffi/cross && make ios
	cp crates/threshold-bls-ffi/cross/react-native/ios/* $(OUTPUT_DIR)/ios/
	rm -rf crates/threshold-bls-ffi/cross/react-native
else
	docker build --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION) -t $(IMAGE_NAME) .
endif

run:
ifeq ($(BUILD_TYPE),wasm)
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR):/app/crates/threshold-bls-ffi/pkg \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		wasm-pack build --target nodejs -- --features=wasm
else ifeq ($(BUILD_TYPE),jvm)
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR):/app/crates/threshold-bls-ffi/target \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		cargo build --release --features=jvm
else ifeq ($(BUILD_TYPE),android)
	mkdir -p $(OUTPUT_DIR)/android
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR)/android:/app/crates/threshold-bls-ffi/target/android \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		sh -c "cd cross && export NDK_HOME=/opt/android-ndk && ./create-ndk-standalone.sh && \
		make android && \
		mkdir -p ../target/android && \
		cp -r react-native/android/app/src/main/jniLibs/* ../target/android/"
endif

clean:
	rm -rf $(OUTPUT_DIR)

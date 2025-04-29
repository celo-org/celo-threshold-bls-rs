RUST_VERSION ?= 1.62.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR=output
BUILD_TYPE ?= wasm  # Options: wasm, jvm, ios, android

.PHONY: all build run clean build-ios build-android

all: clean build run

build:
	docker build --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION) -t $(IMAGE_NAME) .

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
else ifeq ($(BUILD_TYPE),ios)
	$(MAKE) build-ios
else ifeq ($(BUILD_TYPE),android)
	$(MAKE) build-android
endif

build-ios:
	mkdir -p $(OUTPUT_DIR)/ios
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR)/ios:/app/crates/threshold-bls-ffi/target/ios \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		sh -c "rustup target add aarch64-apple-ios x86_64-apple-ios && \
		cargo build --release --target aarch64-apple-ios && \
		cargo build --release --target x86_64-apple-ios && \
		mkdir -p target/ios && \
		cp target/aarch64-apple-ios/release/libthreshold_bls.a target/ios/ && \
		cp target/x86_64-apple-ios/release/libthreshold_bls.a target/ios/libthreshold_bls_x86_64.a"

build-android:
	mkdir -p $(OUTPUT_DIR)/android
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR)/android:/app/crates/threshold-bls-ffi/target/android \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		sh -c "cd cross && export NDK_HOME=/opt/android-ndk && ./create-ndk-standalone.sh && \
		make android && \
		mkdir -p ../target/android && \
		cp -r react-native/android/app/src/main/jniLibs/* ../target/android/"

clean:
	rm -rf $(OUTPUT_DIR)

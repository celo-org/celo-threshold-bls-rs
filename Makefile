RUST_VERSION ?= 1.56.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR=output
WASM_PATH=crates/threshold-bls-ffi
JVM_PATH=crates/threshold-bls-ffi
BUILD_TYPE ?= wasm  # Options: wasm, jvm, ios, android

.PHONY: all build run clean build-ios build-android

all: clean build run

build:
	docker build --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION) -t $(IMAGE_NAME) .

run:
ifeq ($(BUILD_TYPE),wasm)
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR):/app/$(WASM_PATH)/pkg \
		-w /app/$(WASM_PATH) \
		$(IMAGE_NAME) \
		wasm-pack build --target nodejs -- --features=wasm
else ifeq ($(BUILD_TYPE),jvm)
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR):/app/$(JVM_PATH)/target \
		-w /app/$(JVM_PATH) \
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
		-v $(PWD)/$(OUTPUT_DIR)/ios:/app/$(JVM_PATH)/target/ios \
		-w /app/$(JVM_PATH) \
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
		-v $(PWD)/$(OUTPUT_DIR)/android:/app/$(JVM_PATH)/target/android \
		-w /app/$(JVM_PATH) \
		$(IMAGE_NAME) \
		sh -c "rustup target add x86_64-linux-android i686-linux-android armv7-linux-androideabi arm-linux-androideabi aarch64-linux-android && \
		cargo build --release --target x86_64-linux-android && \
		cargo build --release --target i686-linux-android && \
		cargo build --release --target armv7-linux-androideabi && \
		cargo build --release --target arm-linux-androideabi && \
		cargo build --release --target aarch64-linux-android && \
		mkdir -p target/android/x86_64 target/android/x86 target/android/armeabi-v7a target/android/armeabi target/android/arm64-v8a && \
		cp target/x86_64-linux-android/release/libthreshold_bls.so target/android/x86_64/ && \
		cp target/i686-linux-android/release/libthreshold_bls.so target/android/x86/ && \
		cp target/armv7-linux-androideabi/release/libthreshold_bls.so target/android/armeabi-v7a/ && \
		cp target/arm-linux-androideabi/release/libthreshold_bls.so target/android/armeabi/ && \
		cp target/aarch64-linux-android/release/libthreshold_bls.so target/android/arm64-v8a/"

clean:
	rm -rf $(OUTPUT_DIR)

RUST_VERSION ?= 1.62.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR = $(PWD)/output

.PHONY: all clean build-docker-image wasm jvm ios android test

all: clean build-docker-image wasm jvm ios android

clean:
	rm -rf $(OUTPUT_DIR)

build-docker-image:
	docker build --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION) -t $(IMAGE_NAME) .

# ios builds cannot be run in docker, so we need to build it locally on Mac OS
ios:
	mkdir -p $(OUTPUT_DIR)/ios
	cd crates/threshold-bls-ffi/cross && make ios
	mkdir -p $(OUTPUT_DIR)/ios
	cp crates/threshold-bls-ffi/cross/target/ios/libblind_threshold_bls.a $(OUTPUT_DIR)/ios/
	rm -rf crates/threshold-bls-ffi/cross/target
	rm -rf target

android:
	make build-docker-image
	mkdir -p $(OUTPUT_DIR)/android
	docker run --platform=linux/amd64 --rm \
		-v $(OUTPUT_DIR)/android:/output/android \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		sh -c "cd cross && export NDK_HOME=/opt/android-ndk && ./create-ndk-standalone.sh && \
		make android"
	
wasm:
	make build-docker-image
	mkdir -p $(OUTPUT_DIR)/wasm
	docker run --platform=linux/amd64 --rm \
		-v $(OUTPUT_DIR)/wasm:/app/crates/threshold-bls-ffi/pkg \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		wasm-pack build --target nodejs -- --features=wasm 

jvm:
	make build-docker-image
	mkdir -p $(OUTPUT_DIR)/jvm
	docker run --platform=linux/amd64 --rm \
		-v $(OUTPUT_DIR)/jvm:/app/target \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		cargo build --release --features=jvm

test:
	make build-docker-image
	docker run --platform=linux/amd64 --rm -w /app ${IMAGE_NAME} cargo test
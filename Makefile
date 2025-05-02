RUST_VERSION ?= 1.62.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR = $(PWD)/output

.PHONY: all clean build-docker-image wasm jvm ios android

all: clean build-docker-image wasm jvm ios android

clean:
	rm -rf $(OUTPUT_DIR)

build-docker-image:
	docker build --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION) -t $(IMAGE_NAME) .

ios:
	cd crates/threshold-bls-ffi/cross
	make ios
	mv ./target/ios $(OUTPUT_DIR)/ios

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
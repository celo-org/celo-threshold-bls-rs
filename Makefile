RUST_VERSION ?= 1.95.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR = $(PWD)/output
CARGO_CACHE_VOLUME = celo-bls-cargo-cache
TARGET_CACHE_VOLUME = celo-bls-target-cache

.PHONY: all clean build-docker-image wasm jvm ios android test test-cached create-cache-volumes

all: clean build-docker-image wasm jvm ios android

clean:
	rm -rf $(OUTPUT_DIR)

build-docker-image:
	docker build --progress=plain --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION) -t $(IMAGE_NAME) .

# ios builds cannot be run in docker, so we need to build it locally on Mac OS
ios:
	mkdir -p $(OUTPUT_DIR)/ios
	cd crates/threshold-bls-ffi/cross && make ios
	mkdir -p $(OUTPUT_DIR)/ios
	cp crates/threshold-bls-ffi/cross/target/ios/libblind_threshold_bls.a $(OUTPUT_DIR)/ios/
	rm -rf crates/threshold-bls-ffi/cross/target
	rm -rf target

# Docker bind-mounts don't work with CircleCI's setup_remote_docker (the daemon
# runs on a separate VM from the job container), so artifacts are extracted via
# `docker cp` after the container exits.

android:
	make build-docker-image
	mkdir -p $(OUTPUT_DIR)/android
	CID=$$(docker create --platform=linux/amd64 \
		-w /app/crates/threshold-bls-ffi/cross \
		-e FEATURES="$(FEATURES)" \
		-e NDK_HOME=/opt/android-ndk \
		$(IMAGE_NAME) make android) && \
		trap "docker rm -f $$CID >/dev/null" EXIT && \
		docker start -a $$CID && \
		docker cp $$CID:/output/android/. $(OUTPUT_DIR)/android/

wasm:
	make build-docker-image
	mkdir -p $(OUTPUT_DIR)/wasm
	CID=$$(docker create --platform=linux/amd64 \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		wasm-pack build --target nodejs -- --features=wasm) && \
		trap "docker rm -f $$CID >/dev/null" EXIT && \
		docker start -a $$CID && \
		docker cp $$CID:/app/crates/threshold-bls-ffi/pkg/. $(OUTPUT_DIR)/wasm/

jvm:
	make build-docker-image
	mkdir -p $(OUTPUT_DIR)/jvm
	CID=$$(docker create --platform=linux/amd64 \
		-w /app/crates/threshold-bls-ffi \
		$(IMAGE_NAME) \
		cargo build --release --features=jni) && \
		trap "docker rm -f $$CID >/dev/null" EXIT && \
		docker start -a $$CID && \
		docker cp $$CID:/app/target/release/libblind_threshold_bls.so $(OUTPUT_DIR)/jvm/

test:
	make build-docker-image
	docker run --platform=linux/amd64 --rm -w /app ${IMAGE_NAME} cargo test --features wasm -- --nocapture

# Create Docker volumes for caching Cargo and target directories
create-cache-volumes:
	docker volume create $(CARGO_CACHE_VOLUME)
	docker volume create $(TARGET_CACHE_VOLUME)

# Use cached volumes for faster testing
test-cached: create-cache-volumes build-docker-image
	docker run --platform=linux/amd64 --rm \
		-v $(CARGO_CACHE_VOLUME):/root/.cargo \
		-v $(TARGET_CACHE_VOLUME):/app/target \
		-v $(PWD):/app \
		-w /app ${IMAGE_NAME} cargo test --features wasm -- --nocapture

lint:
	cargo clippy --all-targets --all-features -- -D warnings

fmt:
	cargo fmt --all -- --check

RUST_VERSION ?= 1.41.0
IMAGE_NAME = celo-bls-rust-$(subst .,_,$(RUST_VERSION))
OUTPUT_DIR=output
WASM_PATH=crates/threshold-bls-ffi

.PHONY: all build run clean

all: clean build run

build:
	docker build --platform=linux/amd64 --build-arg RUST_VERSION=$(RUST_VERSION)  -t $(IMAGE_NAME) .

run:
	docker run --platform=linux/amd64 --rm \
		-v $(PWD)/$(OUTPUT_DIR):/app/$(WASM_PATH)/pkg \
		-w /app/$(WASM_PATH) \
		$(IMAGE_NAME) \
		wasm-pack build --target nodejs -- --features=wasm

clean:
	rm -rf $(OUTPUT_DIR)

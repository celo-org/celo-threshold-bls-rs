# Makefile - based on https://github.com/Terrahop/react-native-rust-demo

NAME = libblind_threshold_bls
LIB = $(NAME).a
SO = $(NAME).so
ARCHS_IOS = aarch64-apple-ios x86_64-apple-ios
ARCHS_ANDROID = aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
ANDROID_API = 24
NDK_HOST_TAG ?= linux-x86_64
NDK_BIN = $(NDK_HOME)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin
ANDROID_DEST = /output/android
IOS_DEST = ./target/ios
CARGO_PARAMS = --no-default-features $(if $(FEATURES),--features $(FEATURES))

TARGET_DIR = ../../../target

all: android ios

android-setup:
	rustup target add $(ARCHS_ANDROID)

android-build: $(ARCHS_ANDROID)

ios-setup:
	rustup target add $(ARCHS_IOS)

ios: ios-setup $(LIB)

clean:
	rm -rf $(IOS_DEST)
	rm -rf $(ANDROID_DEST)
	rm -rf $(TARGET_DIR)

android: android-setup android-build
	mkdir -p $(ANDROID_DEST)
	mkdir -p $(ANDROID_DEST)/x86
	mkdir -p $(ANDROID_DEST)/x86_64
	mkdir -p $(ANDROID_DEST)/arm64-v8a
	mkdir -p $(ANDROID_DEST)/armeabi-v7a

	cp $(TARGET_DIR)/i686-linux-android/release/$(SO) ${ANDROID_DEST}/x86/$(SO)
	cp $(TARGET_DIR)/x86_64-linux-android/release/$(SO) ${ANDROID_DEST}/x86_64/$(SO)
	cp $(TARGET_DIR)/aarch64-linux-android/release/$(SO) ${ANDROID_DEST}/arm64-v8a/$(SO)
	cp $(TARGET_DIR)/armv7-linux-androideabi/release/$(SO) ${ANDROID_DEST}/armeabi-v7a/$(SO)

ANDROID_RUSTFLAGS = -C link-args=-Wl,-z,max-page-size=16384

aarch64-linux-android:
	PATH="$(NDK_BIN):$(PATH)" \
	CC=aarch64-linux-android$(ANDROID_API)-clang \
	CXX=aarch64-linux-android$(ANDROID_API)-clang++ \
	AR=llvm-ar \
	CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android$(ANDROID_API)-clang \
	CARGO_BUILD_RUSTFLAGS="$(ANDROID_RUSTFLAGS)" \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

armv7-linux-androideabi:
	PATH="$(NDK_BIN):$(PATH)" \
	CC=armv7a-linux-androideabi$(ANDROID_API)-clang \
	CXX=armv7a-linux-androideabi$(ANDROID_API)-clang++ \
	AR=llvm-ar \
	CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=armv7a-linux-androideabi$(ANDROID_API)-clang \
	CARGO_BUILD_RUSTFLAGS="$(ANDROID_RUSTFLAGS)" \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

i686-linux-android:
	PATH="$(NDK_BIN):$(PATH)" \
	CC=i686-linux-android$(ANDROID_API)-clang \
	CXX=i686-linux-android$(ANDROID_API)-clang++ \
	AR=llvm-ar \
	CARGO_TARGET_I686_LINUX_ANDROID_LINKER=i686-linux-android$(ANDROID_API)-clang \
	CARGO_BUILD_RUSTFLAGS="$(ANDROID_RUSTFLAGS)" \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

x86_64-linux-android:
	PATH="$(NDK_BIN):$(PATH)" \
	CC=x86_64-linux-android$(ANDROID_API)-clang \
	CXX=x86_64-linux-android$(ANDROID_API)-clang++ \
	AR=llvm-ar \
	CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=x86_64-linux-android$(ANDROID_API)-clang \
	CARGO_BUILD_RUSTFLAGS="$(ANDROID_RUSTFLAGS)" \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

.PHONY: $(ARCHS_IOS)
$(ARCHS_IOS): %:
	IPHONEOS_DEPLOYMENT_TARGET=15.2 \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

$(LIB): $(ARCHS_IOS)
	mkdir -p $(IOS_DEST)
	lipo -create -output $(IOS_DEST)/$(LIB) $(foreach arch,$(ARCHS_IOS),$(TARGET_DIR)/$(arch)/release/$(LIB))

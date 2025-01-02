# Makefile - based on https://github.com/Terrahop/react-native-rust-demo

NAME = libblind_threshold_bls
LIB = $(NAME).a
SO = $(NAME).so
ARCHS_IOS = aarch64-apple-ios x86_64-apple-ios
ARCHS_ANDROID = aarch64-linux-android armv7-linux-androideabi arm-linux-androideabi i686-linux-android x86_64-linux-android
NDK_STANDALONE = ./NDK
ANDROID_DEST = ./react-native/android/app/src/main/jniLibs
IOS_DEST = ./react-native/ios
CARGO_PARAMS = --no-default-features

TARGET_DIR = ../../../target

all: android ios

android-setup:
	rustup target add aarch64-linux-android armv7-linux-androideabi arm-linux-androideabi i686-linux-android x86_64-linux-android

android-build: $(ARCHS_ANDROID)

ios-setup:
	rustup target add aarch64-apple-ios x86_64-apple-ios

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
	mkdir -p $(ANDROID_DEST)/armeabi
	mkdir -p $(ANDROID_DEST)/armeabi-v7a

	cp $(TARGET_DIR)/i686-linux-android/release/$(SO) ${ANDROID_DEST}/x86/$(SO)
	cp $(TARGET_DIR)/x86_64-linux-android/release/$(SO) ${ANDROID_DEST}/x86_64/$(SO)
	cp $(TARGET_DIR)/aarch64-linux-android/release/$(SO) ${ANDROID_DEST}/arm64-v8a/$(SO)
	cp $(TARGET_DIR)/arm-linux-androideabi/release/$(SO) ${ANDROID_DEST}/armeabi/$(SO)
	cp $(TARGET_DIR)/armv7-linux-androideabi/release/$(SO) ${ANDROID_DEST}/armeabi-v7a/$(SO)

aarch64-linux-android:
	PATH="$(PATH)":$(NDK_STANDALONE)/arm64/bin \
	CC=$@-gcc \
	CXX=$@-g++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

arm-linux-androideabi:
	PATH="$(PATH)":$(NDK_STANDALONE)/arm/bin \
	CC=$@-gcc \
	CXX=$@-g++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

armv7-linux-androideabi:
	PATH="$(PATH)":$(NDK_STANDALONE)/arm/bin \
	CC=arm-linux-androideabi-gcc \
	CXX=arm-linux-androideabi-g++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

i686-linux-android:
	PATH="$(PATH)":$(NDK_STANDALONE)/x86/bin \
	CC=$@-gcc \
	CXX=$@-g++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

x86_64-linux-android:
	PATH="$(PATH)":$(NDK_STANDALONE)/x86_64/bin \
	CC=$@-gcc \
	CXX=$@-g++ \
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

.PHONY: $(ARCHS_IOS)
$(ARCHS_IOS): %:
	cargo build $(CARGO_PARAMS) --target $@ --release --lib

$(LIB): $(ARCHS_IOS)
	mkdir -p $(IOS_DEST)
	lipo -create -output $(IOS_DEST)/$@ $(foreach arch,$(ARCHS_IOS),$(wildcard $(TARGET_DIR)/$(arch)/release/$(LIB)))

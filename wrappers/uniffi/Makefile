all: release android-aar

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    BINARY_NAME = libasdk.so
endif
ifeq ($(UNAME_S),Darwin)
    BINARY_NAME = libasdk.dylib
endif
ifeq ($(OS),Windows_NT)
    BINARY_NAME = libasdk.dll
endif

release:
	@echo "Building the UniFFI binary in release mode..."
	cargo build --release

debug:
	@echo "Building the UniFFI binary in debug mode..."
	cargo build

generate_kotlin_debug: debug
	@echo "Generating Kotlin bindings..."
	cargo run --bin uniffi-bindgen generate --library ../../target/debug/$(BINARY_NAME) --language kotlin --out-dir kotlin/src/main/kotlin

test: generate_kotlin_debug
	@echo "Running Kotlin tests..."
	cd kotlin && ./gradlew -x android:test


ANDROID_NDK_HOME ?= $(HOME)/Library/Android/sdk/ndk/android-ndk-r28
ANDROID_TARGETS := \
	aarch64-linux-android \
	armv7-linux-androideabi \
	i686-linux-android \
	x86_64-linux-android

# Map Rust targets to Android ABI directories
TARGET_TO_ABIDIR := \
	aarch64-linux-android:arm64-v8a \
	armv7-linux-androideabi:armeabi-v7a \
	i686-linux-android:x86 \
	x86_64-linux-android:x86_64

# NDK toolchain paths (for macOS ARM)
TOOLCHAIN_PATH ?= $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/darwin-x86_64/bin

android-clang-symlinks:
	@echo "Creating compiler symlinks..."
	cd $(TOOLCHAIN_PATH) && \
	ln -sf aarch64-linux-android24-clang aarch64-linux-android-clang && \
	ln -sf aarch64-linux-android24-clang++ aarch64-linux-android-clang++ && \
	ln -sf armv7a-linux-androideabi24-clang arm-linux-androideabi-clang && \
	ln -sf armv7a-linux-androideabi24-clang++ arm-linux-androideabi-clang++ && \
	ln -sf i686-linux-android24-clang i686-linux-android-clang && \
	ln -sf i686-linux-android24-clang++ i686-linux-android-clang++ && \
	ln -sf x86_64-linux-android24-clang++ x86_64-linux-android-clang++ && \
	ln -sf x86_64-linux-android24-clang x86_64-linux-android-clang

# Build Rust libraries for all Android architectures
android-build-libs: android-clang-symlinks
	@echo "Building native libraries for Android..."
	@for target in $(ANDROID_TARGETS); do \
		echo "Building for $$target..."; \
		cargo build --target $$target;\
	done

# Generate UniFFI bindings for Kotlin
android-generate-bindings: android-build-libs
	@echo "Generating Kotlin bindings..."
	cargo run --bin uniffi-bindgen generate --library ../../target/aarch64-linux-android/debug/libasdk.so --language kotlin --out-dir ./kotlin/android/src/main/kotlin

# Copy native libraries to jniLibs directory
android-copy-libs:
	@echo "Copying native libraries to jniLibs directories..."
	@for target in $(ANDROID_TARGETS); do \
		abidir=$$(echo "$(TARGET_TO_ABIDIR)" | tr ' ' '\n' | grep "^$$target:" | cut -d: -f2); \
		mkdir -p ./kotlin/android/src/main/jniLibs/$$abidir; \
		cp ../../target/$$target/debug/libasdk.so ./kotlin/android/src/main/jniLibs/$$abidir/; \
	done

# Build AAR package using Gradle
android-aar: android-generate-bindings android-copy-libs
	@echo "Building AAR package..."
	cd kotlin && ./gradlew :android:assembleRelease
	@echo "AAR package built at: kotlin/android/build/outputs/aar/android-release.aar"
	cd kotlin && rm -rf ./android/src/main/jniLibs/*/libasdk.so
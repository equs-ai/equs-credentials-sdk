all: kotlin-test android-aar

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

kotlin-release-build:
	@echo "Building the UniFFI binary in release mode..."
	cargo build --release

kotlin-debug-build:
	@echo "Building the UniFFI binary in debug mode..."
	cargo build

kotlin-generate_kotlin_debug: kotlin-debug-build
	@echo "Generating Kotlin bindings..."
	cargo run --bin uniffi-bindgen generate --library ../../target/debug/$(BINARY_NAME) --language kotlin --out-dir kotlin/src/main/kotlin

kotlin-test: kotlin-generate_kotlin_debug
	@echo "Running Kotlin tests..."
	cd kotlin && ./gradlew test -x android:test


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

ios-release-build:
	@echo "Generating binaries for x86_64 and aarch64"
	cargo build --release --target x86_64-apple-ios
	cargo build --release --target aarch64-apple-ios-sim
	cargo build --release --target aarch64-apple-ios

ios-debug-build:
	@echo "Generating binaries for x86_64 and aarch64"
	cargo build --target x86_64-apple-ios
	cargo build --target aarch64-apple-ios-sim
	cargo build --target aarch64-apple-ios

ios-create-fat-lib: ios-debug-build
	@echo "Creating a fat library for x86_64 and aarch64 simulators"
	mkdir -p ../../target/ios-simulator-fat/debug
	lipo -create \
            ../../target/x86_64-apple-ios/debug/libasdk.a \
            ../../target/aarch64-apple-ios-sim/debug/libasdk.a \
            -output ../../target/ios-simulator-fat/debug/libasdk.a

ios-generate-ffi-debug: ios-debug-build
	@echo "Generating framework module mapping and FFI bindings"
	cargo run --bin uniffi-bindgen-swift -- ../../target/aarch64-apple-ios/debug/libasdk.a ../../target/uniffi-xcframework-debug --swift-sources --headers --modulemap --module-name asdkFFI --modulemap-filename module.modulemap
	mkdir -p swift/Sources/asdk
	mv ../../target/uniffi-xcframework-debug/*.swift swift/Sources/asdk/

ios-generate-xcframework-debug: ios-generate-ffi-debug ios-create-fat-lib
	@echo "Generating XCFramework"
	rm -rf ../../target/ios
	xcodebuild -create-xcframework \
            -library ../../target/ios-simulator-fat/debug/libasdk.a -headers ../../target/uniffi-xcframework-debug \
            -library ../../target/aarch64-apple-ios/debug/libasdk.a -headers ../../target/uniffi-xcframework-debug \
            -output ../../target/ios/debug/asdk.xcframework

ios-test: ios-generate-xcframework-debug
	@echo "Run tests"
	cd swift && xcodebuild test -scheme asdk -destination "name=iPhone 16"
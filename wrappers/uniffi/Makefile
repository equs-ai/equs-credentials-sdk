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

NDK_VERSION := 29.0.13599879

ANDROID_NDK_HOME ?= $(ANDROID_HOME)/ndk/$(NDK_VERSION)

ANDROID_TARGETS := \
	aarch64-linux-android \
	armv7-linux-androideabi \
	i686-linux-android \
	x86_64-linux-android

TARGET_TO_ABIDIR := \
	aarch64-linux-android:arm64-v8a \
	armv7-linux-androideabi:armeabi-v7a \
	i686-linux-android:x86 \
	x86_64-linux-android:x86_64

HOST_TAG := $(shell uname | tr '[:upper:]' '[:lower:]')-$(shell uname -m)
TOOLCHAIN_PATH ?= $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/$(HOST_TAG)/bin

android-clang-symlinks:
	@echo "Creating .cargo/config.toml and symlinks"
	mkdir -p ~/.cargo
	echo "" > ~/.cargo/config.toml
	@for target in $(ANDROID_TARGETS); do \
		echo "Adding Rust target: $$target"; \
		rustup target add $$target; \
	done
	@echo 'Generating ~/.cargo/config.toml'
	@echo '[target.aarch64-linux-android]' >> ~/.cargo/config.toml
	@echo 'linker = "${TOOLCHAIN_PATH}/aarch64-linux-android24-clang"' >> ~/.cargo/config.toml
	@echo 'ar = "llvm-ar"' >> ~/.cargo/config.toml
	@echo '[target.armv7-linux-androideabi]' >> ~/.cargo/config.toml
	@echo 'linker = "${TOOLCHAIN_PATH}/arm-linux-androideabi-clang"' >> ~/.cargo/config.toml
	@echo 'ar = "llvm-ar"' >> ~/.cargo/config.toml
	@echo '[target.i686-linux-android]' >> ~/.cargo/config.toml
	@echo 'linker = "${TOOLCHAIN_PATH}/i686-linux-android24-clang"' >> ~/.cargo/config.toml
	@echo 'ar = "llvm-ar"' >> ~/.cargo/config.toml
	@echo '[target.x86_64-linux-android]' >> ~/.cargo/config.toml
	@echo 'linker = "${TOOLCHAIN_PATH}/x86_64-linux-android24-clang"' >> ~/.cargo/config.toml
	@echo 'ar = "llvm-ar"' >> ~/.cargo/config.toml


	@echo "Creating compiler symlinks..."
	cd $(TOOLCHAIN_PATH) && \
	ln -sf aarch64-linux-android24-clang aarch64-linux-android-clang && \
	ln -sf aarch64-linux-android24-clang++ aarch64-linux-android-clang++ && \
	ln -sf armv7a-linux-androideabi24-clang arm-linux-androideabi-clang && \
	ln -sf armv7a-linux-androideabi24-clang++ arm-linux-androideabi-clang++ && \
	ln -sf i686-linux-android24-clang i686-linux-android-clang && \
	ln -sf i686-linux-android24-clang++ i686-linux-android-clang++ && \
	ln -sf x86_64-linux-android24-clang x86_64-linux-android-clang && \
	ln -sf x86_64-linux-android24-clang++ x86_64-linux-android-clang++

android-build-libs-dev: android-clang-symlinks
	@echo "Building native libraries for Android..."
	@for target in $(ANDROID_TARGETS); do \
		echo "Building for $$target..."; \
		cargo build --target $$target; \
	done

android-generate-bindings-dev: android-build-libs-dev
	@echo "Generating Kotlin bindings..."
	cargo run --bin uniffi-bindgen generate --library ../../target/aarch64-linux-android/debug/libasdk.so --language kotlin --out-dir ./kotlin/android/src/main/kotlin

android-copy-libs-dev:
	@echo "Copying native libraries to jniLibs directories..."
	@for target in $(ANDROID_TARGETS); do \
		abidir=$$(echo "$(TARGET_TO_ABIDIR)" | tr ' ' '\n' | grep "^$$target:" | cut -d: -f2); \
		mkdir -p ./kotlin/android/src/main/jniLibs/$$abidir; \
		cp ../../target/$$target/debug/libasdk.so ./kotlin/android/src/main/jniLibs/$$abidir/; \
	done

android-aar-dev: android-generate-bindings-dev android-copy-libs-dev
	@echo "Building AAR package..."
	cd kotlin && ./gradlew :android:assembleRelease
	@echo "AAR package built at: kotlin/android/build/outputs/aar/android-release.aar"
	cd kotlin && rm -rf ./android/src/main/jniLibs/*/libasdk.so


# Build Rust libraries for all Android architectures
android-build-libs: android-clang-symlinks
	@echo "Building native libraries for Android..."
	@for target in $(ANDROID_TARGETS); do \
		echo "Building for $$target..."; \
		cargo build --profile release-strip --target $$target;\
	done

# Generate UniFFI bindings for Kotlin
android-generate-bindings: android-build-libs
	@echo "Generating Kotlin bindings..."
	cargo build --profile release-android --target aarch64-linux-android
	cargo run --profile release-android --bin uniffi-bindgen generate --library ../../target/aarch64-linux-android/release-android/libasdk.so --language kotlin --out-dir kotlin/android/src/main/kotlin

# Copy native libraries to jniLibs directory
android-copy-libs:
	@echo "Copying native libraries to jniLibs directories..."
	@for target in $(ANDROID_TARGETS); do \
		abidir=$$(echo "$(TARGET_TO_ABIDIR)" | tr ' ' '\n' | grep "^$$target:" | cut -d: -f2); \
		mkdir -p ./kotlin/android/src/main/jniLibs/$$abidir; \
		cp ../../target/$$target/release-strip/libasdk.so ./kotlin/android/src/main/jniLibs/$$abidir/; \
	done

# Build AAR package using Gradle
android-aar: android-generate-bindings android-copy-libs
	@echo "Building AAR package..."
	cd kotlin && ./gradlew :android:assembleRelease
	@echo "AAR package built at: kotlin/android/build/outputs/aar/android-release.aar"
	cd kotlin && rm -rf ./android/src/main/jniLibs/*/libasdk.so


# IOS


ios-dev-build:
	@echo "Generating binaries for x86_64 and aarch64"
	cargo build --target x86_64-apple-ios
	cargo build --target aarch64-apple-ios-sim
	cargo build --target aarch64-apple-ios

ios-create-dev-lib: ios-dev-build
	@echo "Creating a debug library for x86_64 and aarch64 simulators"
	mkdir -p ../../target/ios-simulator-debug/debug
	lipo -create \
            ../../target/x86_64-apple-ios/debug/libasdk.a \
            ../../target/aarch64-apple-ios-sim/debug/libasdk.a \
            -output ../../target/ios-simulator-debug/debug/libasdk.a

ios-generate-ffi-dev: ios-dev-build
	@echo "Generating framework module mapping and FFI bindings"
	cargo run --bin uniffi-bindgen-swift -- ../../target/aarch64-apple-ios/debug/libasdk.a ../../target/uniffi-xcframework-debug --swift-sources --headers --modulemap --module-name asdkFFI --modulemap-filename module.modulemap
	mkdir -p swift/Sources/asdk
	mv ../../target/uniffi-xcframework-debug/*.swift swift/Sources/asdk/


ios-copy-libs-dev:
	rm -rf swift/ios/debug
	mkdir -p swift/ios/debug
	cp -r swift/Sources swift/ios/debug/
	cp swift/Package.swift swift/ios/debug/Package.swift

ios-generate-xcframework-dev: ios-generate-ffi-dev ios-create-dev-lib ios-copy-libs-dev
	@echo "Generating XCFramework"
	xcodebuild -create-xcframework \
            -library ../../target/ios-simulator-debug/debug/libasdk.a -headers ../../target/uniffi-xcframework-debug \
            -library ../../target/aarch64-apple-ios/debug/libasdk.a -headers ../../target/uniffi-xcframework-debug \
            -output swift/ios/debug/asdk.xcframework

ios-build:
	@echo "Generating binaries for x86_64 and aarch64"
	cargo build --profile release-strip --target aarch64-apple-ios-sim
	cargo build --profile release-strip --target aarch64-apple-ios

ios-generate-ffi: ios-build
	@echo "Generating framework module mapping and FFI bindings"
	cargo run --profile release-strip --bin uniffi-bindgen-swift -- ../../target/aarch64-apple-ios/release-strip/libasdk.a ../../target/uniffi-xcframework-release --swift-sources --headers --modulemap --module-name asdkFFI --modulemap-filename module.modulemap
	mkdir -p swift/Sources/asdk
	mv ../../target/uniffi-xcframework-release/*.swift swift/Sources/asdk/

ios-copy-libs:
	rm -rf swift/ios/release
	mkdir -p swift/ios/release
	cp -r swift/Sources swift/ios/release/
	cp swift/Package.swift swift/ios/release/Package.swift

ios-generate-xcframework: ios-generate-ffi ios-copy-libs
	@echo "Generating XCFramework"
	xcodebuild -create-xcframework \
            -library ../../target/aarch64-apple-ios/release-strip/libasdk.a -headers ../../target/uniffi-xcframework-release \
            -library ../../target/aarch64-apple-ios-sim/release-strip/libasdk.a -headers ../../target/uniffi-xcframework-release \
            -output swift/ios/release/asdk.xcframework


ios-test: ios-generate-xcframework-dev
	@echo "Run tests"
	rm -rf swift/asdk.xcframework
	cp -R swift/ios/debug/asdk.xcframework swift/asdk.xcframework
	cd swift && xcodebuild test -scheme asdk -destination "name=iPhone 16"
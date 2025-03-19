all: release

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
	cd kotlin && ./gradlew test
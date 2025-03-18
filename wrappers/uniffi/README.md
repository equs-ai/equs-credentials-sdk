# ASDK FFI

This crate provides UniFFI integration for exposing ASDK functionality to platforms such as Swift, Kotlin, Python, and more.

## Building

Debug build:
```bash
cargo build
```

Release build:
```bash
cargo build --release
```

Generating Bindings
```bash
cargo run --bin uniffi-bindgen generate --library ../../target/release/libasdk{.dylib/.so/.dll} --language {kotlin/swift} --out-dir {output dir}
```

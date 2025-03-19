# SDK FFI

This crate provides UniFFI integration for exposing SDK functionality to platforms such as Swift, Kotlin, Python, and more.

## Building

Build the UniFFI binary for your target platform using the commands below.

**Debug build:**
```bash
make debug
```

**Release build:**
```bash
make
```

## Testing

### Kotlin

The Kotlin tests are located in the `kotlin` directory, which is a standard Gradle project with tests under src/test/kotlin.

**Run Kotlin tests:**

In order to run these tests, you will need to have the JDK installed.

```bash
make test
```

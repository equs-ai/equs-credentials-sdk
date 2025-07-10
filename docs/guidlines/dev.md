# Development Guidelines

- [Rust API Guidelines](#rust-api-guidelines)
- [Linting and Formatting](#linting-and-formatting)
- [Error Handling](error_handling.md)
- [Testing](tests-design.md)
- [Logging](logging.md)
- [API Wrappers](wrappers.md)
- [Publish release](release.md)
- [Conformance testing](conformance-tests.md)
- [Protocol Engine](protocol-engine.md)

## Rust API Guidelines

Reference the official Rust API Guidelines: [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/).
These guidelines provide standards for readability, usability and legibility.

## Linting and Formatting

### Use hooks for automated linting & formatting

ASDK uses [lefthook](https://lefthook.dev/intro.html) for hooks.

Ensure you have installed lefthook. Lookup for installation [here](https://lefthook.dev/installation/)

Make sure you install lefthook into git hooks by running

```bash
  lefthook install
```

Done! You now have hooks.

For manual linting, follow the instructions below

### Use `rustfmt` for Consistent Code Formatting

`rustfmt` ensures that code follows Rust's official style guidelines. It is essential for maintaining a uniform
codebase.

- Run `rustfmt` manually:
   ```bash
   cargo fmt --all
   ```
- Automatic Formatting in Rust Rover:
    1. Go to **File > Settings > Rust > Rustfmt**.
    2. Enable the option: **Use Rustfmt instead of the built-in formatter**.

**Note:** Always ensure that your code is properly formatted before submitting a pull request.

### Use `clippy` for Code Linting

`clippy` is a linting tool that helps catch common mistakes and enforce best practices.

- Run `clippy`:
   ```bash
   cargo clippy --workspace --all-targets --all-features
   ```
- Fix the warnings and suggestions provided by `clippy` manually
  or apply Clippy's suggestions automatically using the command below.
  ```bash
  cargo clippy --workspace --all-targets --all-features --fix
  ```

**Note:** Fix all `warnings` and `errors` provided by the linter before submitting a pull request.

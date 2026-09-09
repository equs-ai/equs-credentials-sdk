# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Governing Policy

**All AI work on this repository is governed by [`docs/AI_CONSTITUTION.md`](./docs/AI_CONSTITUTION.md).** Read and apply it at the start of every session. When any instruction in this file conflicts with `AI_CONSTITUTION.md`, the constitution wins. No exceptions.

## Development Workflow

Before any task that implies code changes, ask which flow applies: feature / bugfix / research / code review / tests / quick change. Skip for `/commands`, questions about the repo, or trivial edits.

## Commands

### Build

```bash
cargo build
```

### Test

```bash
# Build (exclude WASM which requires wasm-pack)
cargo build --all-features --workspace --exclude wasm

# Run all tests
cargo test --all-features

# Run a single test by name
cargo test --all-features <test_name>

# Run tests for a specific module (e.g., did::webvh)
cargo test --all-features did::webvh
```

### Lint and Format

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
```

The pre-push hook (lefthook) runs both automatically. Install with `lefthook install`.

## Context System

This repo has a living, multi-level context system. Always use it — do not guess at structure from filenames alone.

- **Start at [`context.claude.md`](context.claude.md)** for the full domain map with links.
- **Each domain** has a summary in `claude/<domain>.md` (e.g. `claude/vc.md`, `claude/didcomm.md`).
- **Each source directory** has a `CLAUDE.md` alongside the `.rs` files.

Before working in any directory, read its `CLAUDE.md` first. Read parent `CLAUDE.md` files too if the directory is new to you.

### Keeping context current (mandatory)

When you change any file, update the context system to match. Follow this chain upward until nothing is stale:

1. **File changed** → update its `//!` doc comment if its role or constraints changed.
2. **Directory affected** → update that directory's `CLAUDE.md` (files table, key types, dependencies).
3. **Parent directory affected** → update the parent's `CLAUDE.md`.
4. **Domain affected** → update `claude/<domain>.md` (bump "Last updated" + add a reason line).
5. **New or deleted domain** → update `context.claude.md`.

A context file is stale if a reader skimming it would get a wrong picture of the current code.

## Architecture

EQUS SDK is a Rust library providing identity protocol building blocks, consumed by four wrapper targets: Node.js (NAPI-RS), WASM, Kotlin (UniFFI), and Swift (UniFFI). Consumers must provide their own implementations of `KmsService`, `VaultService`, and OID4VC endpoint handlers. The `inmem/` module ships reference implementations for testing and demos.

For the full module layout, domain details, and cross-cutting constraints, see [`context.claude.md`](context.claude.md).
For coding conventions — testing, error handling, logging — see [`claude/tests.md`](claude/tests.md) and [`claude/core.md`](claude/core.md).

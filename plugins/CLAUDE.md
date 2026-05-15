# plugins — Context

## Purpose
Optional, feature-gated ASDK plugins that provide alternative backend implementations
for core SDK traits (KMS, vault), currently encompassing the Hyperledger Askar plugin.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| askar/   | Hyperledger Askar-backed KMS and vault plugin, plus its Node.js NAPI-RS wrapper. See [askar/CLAUDE.md](askar/CLAUDE.md). |

## Key types / traits (if applicable)
- Each plugin crate replaces the in-memory defaults (`LocalKms`, `InMemVault`) with durable,
  encrypted alternatives that share the same `Kms` / `Vault` trait interfaces.

## Dependencies
- Depends on: `agent_sdk` (trait definitions), third-party backends (`aries_askar`)
- Used by: host applications and demos that need persistent storage beyond in-memory mocks

## Constraints
- Plugin crates are standalone Cargo workspaces; they are not compiled as part of the main ASDK workspace unless explicitly added to the workspace.
- Non-wasm only (current plugins rely on native OS/database backends).

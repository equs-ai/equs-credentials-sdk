# ios — Context

## Purpose
iOS demo application demonstrating OID4VC flows using the Swift UniFFI wrapper generated from
the ASDK Rust library, packaged as an XCFramework and Swift bindings.

## Files / Sub-areas

| File/Dir | Role |
|----------|------|
| OID4VC/  | Xcode project; contains the iOS application sources, `run.sh` script for simulator build and launch, and `README.md` with prerequisites and instructions. |

## Dependencies
- Depends on: ASDK UniFFI Swift wrapper (XCFramework built from `wrappers/uniffi/`), `demos/oid4vc/` issuer and verifier services
- Used by: developers evaluating ASDK on iOS

## Constraints
- Requires macOS with Xcode and Xcode Command Line Tools installed.
- The XCFramework must be generated following `wrappers/uniffi/README.md` before opening the Xcode project.

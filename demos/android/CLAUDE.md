# android — Context

## Purpose
Android demo application demonstrating OID4VC flows using the Kotlin UniFFI wrapper generated
from the EQUS SDK Rust library, packaged as an Android AAR archive.

## Files / Sub-areas

| File/Dir         | Role |
|------------------|------|
| app/             | Android Gradle project; `MainActivity.kt` and `DemoViewModel.kt` drive the UI; depends on the AAR placed in `app/libs/`. |
| scripts/         | Helper scripts for building or deploying the demo. |
| build.gradle.kts | Root Gradle build configuration. |
| README.md        | Prerequisites, build, and run instructions including ADB port forwarding steps. |

## Dependencies
- Depends on: EQUS SDK UniFFI Kotlin wrapper (`wrappers/uniffi/` built as `android-release.aar`), `demos/oid4vc/` issuer and verifier services running on host
- Used by: developers evaluating EQUS SDK on Android

## Constraints
- The `.aar` must be copied to `app/libs/` before building; see README for the exact `cp` command.
- Requires ADB port forwarding (`adb reverse`) to route emulator traffic to host-side demo services.

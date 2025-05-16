# Android Demo App

This repository contains a demo Android application for demonstrating OID4VC flows using a Kotlin Package based on UniFFI wrappers.

## Prerequisites


1. Generate the Android Archive(aar) by following the instructions in [`wrappers/uniffi/README.md`](../../wrappers/uniffi/README.md#android)
2. Copy generated `arr` file from [`wrappers/kotlin`](../../wrappers/uniffi/kotlin/android/build/outputs/aar) to [`app/libs`](./app/libs)
3. Run issuer and verifier demos by following the instructions in [`demos/oid4vc/README.md`](../oid4vc/README.md)
4. Execute the below commands to map tcp ports of Emulator to the corresponding ports on the host machine
```bash
  adb reverse tcp:8088 tcp:8088
  adb reverse tcp:8080 tcp:8080
  adb reverse tcp:8098 tcp:8098
```
## Build and Run Demo App

To build and run the Android demo app on the emulator, make the following steps
1. Start the emulator by executing the below command. Where `AVD_NAME` is the emulator name, for example `Pixel_3a_API_36`
```bash
emulator -avd <AVD_NAME>
```
2. Run the demo application
  ```bash
  ./gradlew installDebug && adb shell monkey -p org.bci.asdk.demo -c android.intent.category.LAUNCHER 1
  ```


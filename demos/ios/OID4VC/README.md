# iOS Demo App

A demo iOS application showing OID4VC flows through the Swift (UniFFI) wrapper.

## Prerequisites

- **Xcode:** must be installed on your system. You can download it from the Mac App Store. 
Ensure that you have agreed to the Xcode license terms by opening Xcode once before running script.
- **Xcode Command Line Tools:** need to be installed. You can install them by running:
    ```bash
    xcode-select --install
    ```
- Verify that `xcrun`, `xcodebuild`, and `simctl` are available in your terminal.
- Confirm that the simulator specified in the `run.sh` script matches an available simulator on your system.
  You can list available simulators by running:
    ```bash
    xcrun simctl list devices
    ```
- Generate the XCFramework and Swift Bindings: Follow the instructions in [`wrappers/uniffi/README.md`](../../../wrappers/uniffi/README.md#ios)

## Build and Run Demo App

To build and run the iOS demo app on the simulator, execute the following command
```bash
./run.sh
```

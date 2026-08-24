# SDK FFI

This crate provides UniFFI integration for exposing SDK functionality to platforms such as Swift, Kotlin, Python, and
more.

## Building

Build the UniFFI binary for your target platform using the commands below.

**Debug build:**

```bash
  make kotlin-debug-build
```

**Release build:**

```bash
  make kotlin-release-build
```

## Testing

### Kotlin

The Kotlin tests are located in the `kotlin` directory, which is a standard Gradle project with tests under
`src/test/kotlin`.

**Run Kotlin tests:**

In order to run these tests, you will need to have the JDK installed.

```bash
  make kotlin-test
```

# Android

### 1. Setup Android SDK and NDK

Using Command-line:

```bash
  brew install --cask android-commandlinetools
```

```bash
  sdkmanager "ndk;29.0.13599879"
```

### 2. Set Environment Variables

Add these lines to your `~/.zshrc` or `~/.bash_profile`:

```bash
  export ANDROID_HOME=$HOME/Library/Android/sdk
  export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/29.0.13599879  # Use your NDK version instead of '29.0.13599879'
  export PATH=$PATH:$ANDROID_HOME/tools/bin:$ANDROID_HOME/platform-tools
  export PATH=$PATH:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64/bin # Use your platform folder darwin arm64
```

Reload your shell:

```bash
  source ~/.bash_profile  # or ~/.zshrc
```

Check that you are able to see the C libraries for each of the architecture-Android version combinations

```bash
  find $ANDROID_NDK_HOME/toolchains/llvm -name "*-linux-android*-clang" | sort -r
```

You should see the similar output as below:

```
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64/bin/aarch64-linux-android35-clang
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64/bin/aarch64-linux-android34-clang
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-arm64/bin/aarch64-linux-android33-clang
...
```

### 4. Bind linkers to android targets

Open (or create) your main `$HOME/.cargo/config` file. Add each of the target linkers:

```toml
[target.armv7-linux-androideabi]
linker = "armv7a-linux-androideabi24-clang"
ar = "llvm-ar"

[target.x86_64-linux-android]
linker = "x86_64-linux-android24-clang"
ar = "llvm-ar"

[target.aarch64-linux-android]
linker = "aarch64-linux-android24-clang"
ar = "llvm-ar"

[target.i686-linux-android]
linker = "i686-linux-android24-clang"
ar = "llvm-ar"
```

### 5. Install Rust Android Targets

```bash
  rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

### 6. Build Android Archive (`.aar`)

Depending on your need, you should build **dev** or **release** android archives.
Release build lacks some features that are not expected to be used in production code.

#### 6.1. Build dev Android Archive

Run `android-aar-dev` Makefile target:

```bash
  make android-aar
```

On success, `aar`  is saved to `./kotlin/android/build/outputs/aar/android-release.aar`

#### 6.2. Build release Android Archive

Run `android-aar` Makefile target:

```bash
  make android-aar-dev
```

On success, `aar` is saved to `./kotlin/android/build/outputs/aar/android-release.aar`

# iOS

h4: #### IOS builds for IOS@17. This can be configured at [config.toml](./.cargo/config.toml)

### 1. Setup Xcode Command-Line Tools

#### Install XCode

Probably not mandatory. If you are new to install XCode - try to avoid this step. if it is possible to avoid installing
or if it is necessary - update this documentation

You can install XCode [here](https://developer.apple.com/download/all/) (You will be asked to log in into your
account)
For MacOS you can install XCode from AppStore

#### Install XCode Command Line Tools

You can install XCode CLT [here](https://developer.apple.com/download/all/)

Make sure you install compatible versions of XCode & XCode CLT

```bash
  xcode-select --install
  xcodebuild -runFirstLaunch
```

#### Update your paths

Add next line to your shell profile `~/.zshrc` or `~/.bash_profile` or any other

```
  export PATH=$PATH:/Developer/Applications/Xcode.app/Contents/MacOS/
```

Make sure you refresh your profile

```bash
  source ~/.bash_profile  # or ~/.zshrc
```

### 2. Install Rust iOS and macOS Targets

```bash
  rustup target add aarch64-apple-ios x86_64-apple-ios aarch64-apple-ios-sim
```

### 3. Generate the XCFramework and Swift Bindings

```bash
  make ios-generate-xcframework-dev
```

## Testing

The Swift tests are located in the `swift` directory, which is a Swift Package with tests under `Tests/EqusSdkTests/`.

**Run Swift tests:**

In order to run these tests, you will need to have the iOS simulator installed.

```bash
  make ios-test
```



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


# Android
### 1. Setup Android SDK and NDK
Using Command-line:
```bash
brew install --cask android-commandlinetools
```
```bash
sdkmanager "ndk;28.0.13004108"
```
### 2. Set Environment Variables
Add these lines to your `~/.zshrc` or `~/.bash_profile`:
```bash
export ANDROID_HOME=$HOME/Library/Android/sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.0.13004108  # Use your NDK version instead of '28.0.13004108'
export PATH=$PATH:$ANDROID_HOME/tools/bin:$ANDROID_HOME/platform-tools
export PATH=$PATH:$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin # Use your platform folder 'darwin-x86_64'
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
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android35-clang
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android34-clang
$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/x86_64-linux-android33-clang
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

### 6. Run `android-aar` target of Makefile:
```bash
make android-aar
```
On success, `aar` file must be outputted in `./kotlin/android/build/outputs/aar/android-release.aar`
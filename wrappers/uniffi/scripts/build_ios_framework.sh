#!/usr/bin/env bash
# Compiles the generated Swift bindings and the static-library XCFramework into
# a dynamic EqusSdk.xcframework, so consumers need only a binary target.
set -euo pipefail

USAGE="usage: build_ios_framework.sh <static xcframework> <equssdk.swift> <output dir> <min iOS> [version]"
IN="${1:?$USAGE}"
SRC="${2:?$USAGE}"
OUT="${3:?$USAGE}"
MIN_IOS="${4:?$USAGE}"
VERSION="${5:-0.0.0}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The FFI module stays private to the framework, so the generated converters,
# which UniFFI makes public for cross-crate use, must be internal.
sed -E -e 's/^import equssdkFFI$/@_implementationOnly import equssdkFFI/' \
  -e 's/^public ((func|struct|class|enum) FfiConverter)/\1/' "$SRC" >"$work/equssdk.swift"
grep -q '^@_implementationOnly import equssdkFFI$' "$work/equssdk.swift" ||
  { echo "no 'import equssdkFFI' line in $SRC" >&2; exit 1; }
if grep -nE '^public .*FfiConverter' "$work/equssdk.swift" >&2; then
  echo "public FfiConverter declarations left in $SRC" >&2
  exit 1
fi

plist() {
  cat >"$1/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleExecutable</key><string>EqusSdk</string>
  <key>CFBundleIdentifier</key><string>ai.equs.credentials.EqusSdk</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>EqusSdk</string>
  <key>CFBundlePackageType</key><string>FMWK</string>
  <key>CFBundleShortVersionString</key><string>${VERSION%%-*}</string>
  <key>CFBundleVersion</key><string>${VERSION%%-*}</string>
  <key>CFBundleSupportedPlatforms</key><array><string>$2</string></array>
  <key>MinimumOSVersion</key><string>$MIN_IOS</string>
</dict>
</plist>
EOF
}

# slice <static slice id> <sdk> <platform> <triple>...
slice() {
  local id="$1" sdk="$2" platform="$3"
  shift 3
  local dir="$IN/$id" fw="$work/$id/EqusSdk.framework" bins=()
  mkdir -p "$fw/Modules/EqusSdk.swiftmodule"
  for triple in "$@"; do
    local b="$work/$id/$triple" name="${triple/ios$MIN_IOS/ios}"
    mkdir -p "$b"
    xcrun --sdk "$sdk" swiftc -target "$triple" -module-name EqusSdk -parse-as-library \
      -swift-version 5 -O -whole-module-optimization -enable-library-evolution \
      -emit-library -emit-module -emit-module-path "$b/EqusSdk.swiftmodule" \
      -emit-module-interface-path "$fw/Modules/EqusSdk.swiftmodule/$name.swiftinterface" \
      -I "$dir/Headers" -L "$dir" -lequssdk -lz -liconv \
      -Xlinker -install_name -Xlinker @rpath/EqusSdk.framework/EqusSdk \
      -o "$b/EqusSdk" "$work/equssdk.swift"
    bins+=("$b/EqusSdk")
  done
  lipo -create "${bins[@]}" -output "$fw/EqusSdk"
  plist "$fw" "$platform"
}

sim_id=$(basename "$(ls -d "$IN"/ios-*-simulator)")
sim_triples=()
for arch in $(lipo -archs "$IN/$sim_id/libequssdk.a"); do
  sim_triples+=("$arch-apple-ios$MIN_IOS-simulator")
done
slice ios-arm64 iphoneos iPhoneOS "arm64-apple-ios$MIN_IOS"
slice "$sim_id" iphonesimulator iPhoneSimulator "${sim_triples[@]}"

rm -rf "$OUT/EqusSdk.xcframework"
mkdir -p "$OUT"
xcodebuild -create-xcframework \
  -framework "$work/ios-arm64/EqusSdk.framework" \
  -framework "$work/$sim_id/EqusSdk.framework" \
  -output "$OUT/EqusSdk.xcframework"

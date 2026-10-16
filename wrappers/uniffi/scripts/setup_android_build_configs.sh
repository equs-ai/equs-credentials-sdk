#!/usr/bin/env bash
set -euo pipefail

: "${TOOLCHAIN:?TOOLCHAIN is not set}"

AR="llvm-ar"

TARGETS=(
  "aarch64-linux-android"
  "x86_64-linux-android"
  "i686-linux-android"
  "armv7-linux-androideabi"
)

CLANG_PREFIXES=(
  "${TARGETS[0]}24-clang"
  "${TARGETS[1]}24-clang"
  "${TARGETS[2]}24-clang"
  "armv7a-linux-androideabi24-clang"
)

LINK_NAMES=(
  "${TARGETS[0]}-clang"
  "${TARGETS[1]}-clang"
  "${TARGETS[2]}-clang"
  "arm-linux-androideabi-clang"
)

echo "📦 Installing Rust targets and configuring toolchain..."
mkdir -p ~/.cargo
> ~/.cargo/config.toml

for i in "${!TARGETS[@]}"; do
  TARGET="${TARGETS[$i]}"
  CLANG="${CLANG_PREFIXES[$i]}"
  LINK_NAME="${LINK_NAMES[$i]}"

  echo "📦 Adding target $TARGET"
  rustup target add "$TARGET"

  echo "📝 Writing config for $TARGET"
  cat >> ~/.cargo/config.toml <<EOF
[target.${TARGET}]
linker = "${CLANG}"
ar = "${AR}"

EOF

FULL_LINK_PATH=${TOOLCHAIN}/${LINK_NAME}
mkdir -p $TOOLCHAIN

if [[ -n $CLANG ]]; then
  ln -sf "${CLANG}" "${FULL_LINK_PATH}"
  ln -sf "${CLANG}++" "${FULL_LINK_PATH}++"
  echo "🔗 Linked $CLANG → $LINK_NAME"
else
  echo "⚠️ $CLANG not found in PATH"
fi
done

echo "✅ Android Rust toolchain configured successfully."

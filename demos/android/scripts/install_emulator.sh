#!/bin/bash

set -e

AVD_NAME="pixel33"
ANDROID_VERSION="33"
SYSTEM_IMAGE="system-images;android-${ANDROID_VERSION};google_apis;x86_64"
DEVICE_NAME="pixel"

if ! command -v sdkmanager &> /dev/null; then
  echo "sdkmanager not found. Make sure Android SDK is installed & \$PATH is set up"
  exit 1
fi

echo "Installing Android SDK components"
sdkmanager --install "platform-tools" "emulator" "platforms;android-${ANDROID_VERSION}" "${SYSTEM_IMAGE}"

if avdmanager list avd | grep -q "${AVD_NAME}"; then
  echo "Delete existing avd: ${AVD_NAME}"
  avdmanager delete avd --name "${AVD_NAME}"
fi

echo "Creating avd: ${AVD_NAME}"
echo "no" | avdmanager create avd \
  --name "${AVD_NAME}" \
  --package "${SYSTEM_IMAGE}" \
  --device "${DEVICE_NAME}"
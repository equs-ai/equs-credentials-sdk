#!/bin/bash
set -e

SCHEME="OID4VC"
CONFIGURATION="Debug"
SIMULATOR_NAME="iPhone 16"
DESTINATION="platform=iOS Simulator,name=$SIMULATOR_NAME"
DERIVED_DATA_PATH="build"
BUNDLE_ID="com.bci.OID4VC"

echo "Building the project..."
xcrun xcodebuild -scheme "$SCHEME" \
                 -configuration "$CONFIGURATION" \
                 -destination "$DESTINATION" \
                 -derivedDataPath "$DERIVED_DATA_PATH" \
                 build

echo "Booting the simulator ($SIMULATOR_NAME)..."
xcrun simctl boot "$SIMULATOR_NAME" || echo "Simulator $SIMULATOR_NAME may already be booted."

echo "Launching the Simulator application..."
open -a Simulator

APP_PRODUCTS_DIR=$(find "$DERIVED_DATA_PATH/Build/Products" -type d -name "*iphonesimulator*" -print -quit)
if [ -z "$APP_PRODUCTS_DIR" ]; then
  echo "Error: Unable to locate the products directory for the iOS Simulator builds."
  exit 1
fi

APP_BUNDLE=$(find "$APP_PRODUCTS_DIR" -maxdepth 1 -type d -name "*.app" -print -quit)
if [ -z "$APP_BUNDLE" ]; then
  echo "Error: Unable to locate the .app bundle in $APP_PRODUCTS_DIR."
  exit 1
fi
echo "Found app bundle at: $APP_BUNDLE"

echo "Installing the app on the simulator..."
xcrun simctl install booted "$APP_BUNDLE"

echo "Launching the app with bundle identifier: $BUNDLE_ID"
xcrun simctl launch booted "$BUNDLE_ID"

echo "App launched successfully!"
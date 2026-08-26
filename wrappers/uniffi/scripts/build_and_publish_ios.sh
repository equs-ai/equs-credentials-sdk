#!/usr/bin/env bash
set -euo pipefail

DEV_ENV="development"
MAKEFILE_JOB="ios-generate-xcframework"
XCFRAMEWORK_LOCATION="swift/ios/release"

VERSION="1.13.0"
REGISTRY_URL_IOS="${REGISTRY_URL_IOS:?REGISTRY_URL_IOS is required}"

ENVIRONMENT="${ENVIRONMENT:-}"

if [[ "$ENVIRONMENT" == "$DEV_ENV" ]]; then
  VERSION="${CI_COMMIT_TAG:-${VERSION}-dev}"
  MAKEFILE_JOB="${MAKEFILE_JOB}-dev"
  XCFRAMEWORK_LOCATION="swift/ios/debug"
else
  VERSION="${CI_COMMIT_TAG:-${VERSION}}"
fi

ZIP_NAME="equs-sdk.zip"
PACKAGE_NAME="equs-sdk-ios"

make $MAKEFILE_JOB
pwd
zip -r $ZIP_NAME $XCFRAMEWORK_LOCATION
swift package compute-checksum $ZIP_NAME > checksum.txt
echo "Uploading package $PACKAGE_NAME version $VERSION to $REGISTRY_URL_IOS..."

RESPONSE=$(mktemp)
STATUS=$(curl --silent --show-error --http1.1 --output "$RESPONSE" --write-out "%{http_code}" \
  --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  --upload-file "$ZIP_NAME" \
  "${REGISTRY_URL_IOS}/${PACKAGE_NAME}/${VERSION}/${ZIP_NAME}")

if [ "$STATUS" -eq 201 ]; then
  echo "✅ Successfully uploaded package."
else
  echo "❌ Upload failed with status $STATUS"
  echo "Response body:"
  cat "$RESPONSE"
  exit 1
fi

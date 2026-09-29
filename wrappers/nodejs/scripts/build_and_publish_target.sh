#!/bin/bash
set -euo pipefail

if [ -z "${NPM_TOKEN:-}" ]; then
  echo "No NPM_TOKEN"
  exit 1
fi

if [ -z "${REGISTRY_URL_NPM:-}" ]; then
  echo "No REGISTRY_URL_NPM"
  exit 1
fi

if [ -z "${TARGET:-}" ]; then
  echo "No TARGET"
  exit 1
fi

if [ -z "${ALIAS:-}" ]; then
  echo "No ALIAS"
  exit 1
fi

NPM_AUTH="npm_config_//${REGISTRY_URL_NPM#*://}:_authToken=${NPM_TOKEN}"
unset NPM_TOKEN

BINARY_NAME="equs-credentials-sdk.${ALIAS}.node"
VERSION=$(npm pkg get version | tr -d '"')

if [ "${ENVIRONMENT:-}" == "development" ]; then
  TAG="dev"
  BUILD_FLAGS="--features=in-memory"
  PUBLISH_VERSION="${CI_COMMIT_TAG:-${VERSION}-dev}"
else
  TAG="latest"
  BUILD_FLAGS="--release"
  PUBLISH_VERSION="${CI_COMMIT_TAG:-${VERSION}}"
fi

npm version "${PUBLISH_VERSION}" --no-git-tag-version --ignore-scripts --allow-same-version

npm i --ignore-scripts -D

rustup target add $TARGET
npx napi build $BUILD_FLAGS --platform --target $TARGET

npx napi create-npm-dir -t .
mv "$BINARY_NAME" "npm/${ALIAS}/$BINARY_NAME"
npx napi version

cd "npm/${ALIAS}"
TARBALL=$(npm pack --silent)
env "${NPM_AUTH}" npm publish "${TARBALL}" --registry=${REGISTRY_URL_NPM} --tag ${TAG}


cd ../../
npm version "${VERSION}" --no-git-tag-version --ignore-scripts --allow-same-version

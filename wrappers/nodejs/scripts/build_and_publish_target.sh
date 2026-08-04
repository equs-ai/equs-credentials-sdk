#!/bin/bash
set -euo pipefail

if [ -z "${NPM_TOKEN:-}" ]; then
  echo "No NPM_TOKEN"
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

BINARY_NAME="agent-sdk.${ALIAS}.node"
VERSION=$(npm pkg get version | tr -d '"')

if [ "${ENVIRONMENT:-}" == "development" ]; then
  TAG="dev"
  BUILD_FLAGS="--features=in-memory"
  npm version ${VERSION}-dev
else
  TAG="latest"
  BUILD_FLAGS="--release"
fi

npm i --ignore-scripts -D

rustup target add $TARGET
npx napi build $BUILD_FLAGS --platform --target $TARGET

mv "$BINARY_NAME" "npm/${ALIAS}/$BINARY_NAME"
cp .npmrc "npm/${ALIAS}/.npmrc"
npx napi version

cd "npm/${ALIAS}"
NPM_TOKEN=${NPM_TOKEN} npm publish --registry=${REGISTRY_URL_NPM} --tag ${TAG}


if [ "${ENVIRONMENT:-}" == "development" ]; then
  cd ../../
  npm version $VERSION
fi

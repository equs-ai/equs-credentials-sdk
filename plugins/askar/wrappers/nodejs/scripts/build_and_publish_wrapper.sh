#!/bin/bash

REGISTRY_URL="https://git.slock.it/api/v4/projects/1387/packages/npm/"
VERSION=$(npm pkg get version | tr -d '"')

if [ -z "$NPM_TOKEN" ]; then
  echo "No NPM_TOKEN"
  exit 1
fi

if [ "$ENVIRONMENT" == "development" ]; then
  TAG="dev"
  BUILD_SCRIPT="build:debug"
  npm version ${VERSION}-dev
else
  TAG="latest"
  BUILD_SCRIPT="build"
fi

npm i --ignore-scripts
npm i -g typescript @napi-rs/cli
npx npm run $BUILD_SCRIPT
npx napi prepublish --skip-gh-release
NPM_TOKEN=${NPM_TOKEN} npm publish --registry=${REGISTRY_URL} --tag ${TAG}

if [ "$ENVIRONMENT" == "development" ]; then
  npm version $VERSION
fi

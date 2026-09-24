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

printf '%s:_authToken=%s\n' "//${REGISTRY_URL_NPM#*://}" "${NPM_TOKEN}" >> "${HOME}/.npmrc"
chmod 600 "${HOME}/.npmrc"

VERSION=$(npm pkg get version | tr -d '"')

BUILD_SCRIPT="build"

if [ "${ENVIRONMENT:-}" == "development" ]; then
  TAG="dev"
  PUBLISH_VERSION="${CI_COMMIT_TAG:-${VERSION}-dev}"
else
  TAG="latest"
  PUBLISH_VERSION="${CI_COMMIT_TAG:-${VERSION}}"
fi

npm version "${PUBLISH_VERSION}" --no-git-tag-version --ignore-scripts --allow-same-version

npm i --ignore-scripts
npm i -g typescript @napi-rs/cli
npx npm run $BUILD_SCRIPT
npx napi prepublish --skip-gh-release
TARBALL=$(npm pack --silent)
NPM_TOKEN=${NPM_TOKEN} npm publish "${TARBALL}" --registry=${REGISTRY_URL_NPM} --tag ${TAG}

npm version "${VERSION}" --no-git-tag-version --ignore-scripts --allow-same-version

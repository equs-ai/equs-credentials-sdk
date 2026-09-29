#!/bin/bash
set -euo pipefail

if [ -z "${NPM_TOKEN:-}" ] && [ -z "${DRY_RUN:-}" ]; then
  echo "No NPM_TOKEN"
  exit 1
fi

if [ -z "${REGISTRY_URL_NPM:-}" ]; then
  echo "No REGISTRY_URL_NPM"
  exit 1
fi

NPM_AUTH="npm_config_//${REGISTRY_URL_NPM#*://}:_authToken=${NPM_TOKEN}"
unset NPM_TOKEN

VERSION=$(npm pkg get version | tr -d '"')

BUILD_SCRIPT="build"

if [ "${ENVIRONMENT:-}" == "development" ]; then
  TAG="dev"
  PUBLISH_VERSION="${CI_COMMIT_TAG:-${VERSION}-dev}"
else
  TAG="${NPM_DIST_TAG:-latest}"
  PUBLISH_VERSION="${CI_COMMIT_TAG:-${VERSION}}"
fi

npm version "${PUBLISH_VERSION}" --no-git-tag-version --ignore-scripts --allow-same-version

npm i --ignore-scripts
npm i -g typescript @napi-rs/cli
npx npm run $BUILD_SCRIPT
npx napi prepublish --skip-gh-release
TARBALL=$(npm pack --silent)
env "${NPM_AUTH}" npm publish "${TARBALL}" --registry=${REGISTRY_URL_NPM} --tag ${TAG} ${DRY_RUN:+--dry-run}

npm version "${VERSION}" --no-git-tag-version --ignore-scripts --allow-same-version

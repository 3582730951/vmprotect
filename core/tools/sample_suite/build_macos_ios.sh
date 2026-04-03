#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build_macos_ios.sh <output-root>" >&2
  exit 2
fi

OUT_ROOT="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SRC_FILE="${REPO_ROOT}/core/tests/sample_suite/sources/ios/ios_macho_main.c"

IOS_DIR="${OUT_ROOT}/ios_macho"
mkdir -p "${IOS_DIR}"

IOS_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"

xcrun --sdk iphonesimulator clang \
  -target arm64-apple-ios17.0-simulator \
  -isysroot "${IOS_SDK}" \
  -O2 \
  -fvisibility=hidden \
  "${SRC_FILE}" \
  -o "${IOS_DIR}/sample_ios_macho"

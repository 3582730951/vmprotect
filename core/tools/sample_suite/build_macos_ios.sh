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
WRAPPER="${REPO_ROOT}/core/wrapper/eippf_cc.py"

IOS_DIR="${OUT_ROOT}/ios_macho"
PASS_PLUGIN_DIR="${OUT_ROOT}/pass_plugins"
RUNTIME_LIB_DIR="${OUT_ROOT}/runtime_libs"
RUNTIME_BUILD_DIR="${OUT_ROOT}/_runtime_build_macos_ios"
PASS_PLUGIN_PATH="${PASS_PLUGIN_DIR}/eippf_protection_suite_pass.dylib"
RUNTIME_LIB_PATH="${RUNTIME_LIB_DIR}/libeippf_string_token_runtime.a"

for tool in cmake ninja python3 xcrun; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "[FAIL] required tool missing: ${tool}" >&2
    exit 2
  fi
done

if [[ ! -f "${WRAPPER}" ]]; then
  echo "[FAIL] wrapper script is missing: ${WRAPPER}" >&2
  exit 2
fi

LLVM_CMAKE_DIR="${LLVM_DIR:-}"
if [[ -z "${LLVM_CMAKE_DIR}" ]]; then
  if command -v llvm-config-18 >/dev/null 2>&1; then
    LLVM_CMAKE_DIR="$(llvm-config-18 --cmakedir)"
  elif command -v llvm-config >/dev/null 2>&1; then
    LLVM_CMAKE_DIR="$(llvm-config --cmakedir)"
  else
    echo "[FAIL] LLVM_DIR is unset and llvm-config is unavailable" >&2
    exit 2
  fi
fi
if [[ ! -d "${LLVM_CMAKE_DIR}" ]]; then
  echo "[FAIL] LLVM CMake directory not found: ${LLVM_CMAKE_DIR}" >&2
  exit 2
fi

HOST_CLANG="${EIPPF_CLANG:-}"
if [[ -z "${HOST_CLANG}" ]]; then
  LLVM_PREFIX="$(cd "${LLVM_CMAKE_DIR}/../../.." && pwd)"
  if [[ -x "${LLVM_PREFIX}/bin/clang" ]]; then
    HOST_CLANG="${LLVM_PREFIX}/bin/clang"
  elif command -v clang-18 >/dev/null 2>&1; then
    HOST_CLANG="$(command -v clang-18)"
  elif command -v clang >/dev/null 2>&1; then
    HOST_CLANG="$(command -v clang)"
  else
    echo "[FAIL] clang is required" >&2
    exit 2
  fi
fi

HOST_CLANGXX="${EIPPF_CLANGXX:-}"
if [[ -z "${HOST_CLANGXX}" ]]; then
  LLVM_PREFIX="$(cd "${LLVM_CMAKE_DIR}/../../.." && pwd)"
  if [[ -x "${LLVM_PREFIX}/bin/clang++" ]]; then
    HOST_CLANGXX="${LLVM_PREFIX}/bin/clang++"
  elif command -v clang++-18 >/dev/null 2>&1; then
    HOST_CLANGXX="$(command -v clang++-18)"
  elif command -v clang++ >/dev/null 2>&1; then
    HOST_CLANGXX="$(command -v clang++)"
  else
    echo "[FAIL] clang++ is required" >&2
    exit 2
  fi
fi

mkdir -p "${IOS_DIR}" "${PASS_PLUGIN_DIR}" "${RUNTIME_LIB_DIR}" "${RUNTIME_BUILD_DIR}"

cmake -S "${REPO_ROOT}/core" -B "${RUNTIME_BUILD_DIR}" -G Ninja \
  "-DLLVM_DIR=${LLVM_CMAKE_DIR}" \
  "-DCMAKE_C_COMPILER=${HOST_CLANG}" \
  "-DCMAKE_CXX_COMPILER=${HOST_CLANGXX}" \
  "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${PASS_PLUGIN_DIR}" \
  "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=${RUNTIME_LIB_DIR}" \
  -DEIPPF_BUILD_TESTS=OFF \
  -DEIPPF_BUILD_POST_LINK_MUTATOR=OFF \
  -DEIPPF_BUILD_DEX_TOOLCHAIN=OFF \
  -DEIPPF_BUILD_SCRIPT_GUARD=OFF \
  -DEIPPF_BUILD_IP_WEAVER=OFF \
  -DEIPPF_BUILD_IP_WEAVER_IR=OFF \
  -DEIPPF_BUILD_TOOLING=OFF
cmake --build "${RUNTIME_BUILD_DIR}" -j --target eippf_protection_suite_pass eippf_string_token_runtime

if [[ ! -f "${PASS_PLUGIN_PATH}" ]]; then
  echo "[FAIL] pass plugin build output missing: ${PASS_PLUGIN_PATH}" >&2
  exit 2
fi
if [[ ! -f "${RUNTIME_LIB_PATH}" ]]; then
  echo "[FAIL] runtime lib build output missing: ${RUNTIME_LIB_PATH}" >&2
  exit 2
fi

IOS_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
EIPPF_CLANG="${HOST_CLANG}" \
EIPPF_CLANGXX="${HOST_CLANGXX}" \
python3 "${WRAPPER}" --pass-plugin "${PASS_PLUGIN_PATH}" -- \
  -target arm64-apple-ios17.0-simulator \
  -isysroot "${IOS_SDK}" \
  -O2 \
  -fvisibility=hidden \
  "${SRC_FILE}" \
  -o "${IOS_DIR}/sample_ios_macho" \
  "${RUNTIME_LIB_PATH}"

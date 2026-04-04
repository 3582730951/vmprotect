#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "[FAIL] $*" >&2
  exit 2
}

join_argv() {
  local out=""
  local arg
  for arg in "$@"; do
    if [[ -n "${out}" ]]; then
      out+=" "
    fi
    out+="$(printf "%q" "${arg}")"
  done
  printf '%s' "${out}"
}

if [[ $# -ne 1 ]]; then
  echo "usage: build_macos_ios.sh <output-root>" >&2
  exit 2
fi

OUT_ROOT_INPUT="$1"
mkdir -p "${OUT_ROOT_INPUT}"
OUT_ROOT="$(cd "${OUT_ROOT_INPUT}" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SRC_FILE="${REPO_ROOT}/core/tests/sample_suite/sources/ios/ios_macho_main.c"
WRAPPER="${REPO_ROOT}/core/wrapper/eippf_cc.py"

IOS_DIR="${OUT_ROOT}/ios_macho"
PASS_PLUGIN_DIR="${OUT_ROOT}/pass_plugins"
RUNTIME_LIB_DIR="${OUT_ROOT}/runtime_libs"
RUNTIME_BUILD_DIR="${OUT_ROOT}/_runtime_build_macos_ios"
REPORT_DIR="${OUT_ROOT}/toolchain_reports"
COMMANDS_DIR="${REPORT_DIR}/commands"
PASS_PLUGIN_PATH="${PASS_PLUGIN_DIR}/eippf_protection_suite_pass.dylib"
IOS_USER_HELPER_O="${RUNTIME_LIB_DIR}/string_token_runtime.ios.user.o"
IOS_OUTPUT_BIN="${IOS_DIR}/sample_ios_macho"
REPORT_PATH="${REPORT_DIR}/macos_ios.txt"
PLUGIN_COMMAND_PATH="${COMMANDS_DIR}/macos_ios.plugin_build.txt"
IOS_HELPER_COMMAND_PATH="${COMMANDS_DIR}/macos_ios.ios_user_helper_compile.txt"
IOS_LINK_COMMAND_PATH="${COMMANDS_DIR}/macos_ios.ios_link.txt"
IOS_TARGET="arm64-apple-ios17.0-simulator"

for tool in cmake ninja python3 xcrun; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    fail "required tool missing: ${tool}"
  fi
done

if [[ ! -f "${WRAPPER}" ]]; then
  fail "wrapper script is missing: ${WRAPPER}"
fi

if [[ -z "${EIPPF_ALLOWED_LLVM_ROOT:-}" ]]; then
  fail "EIPPF_ALLOWED_LLVM_ROOT is unset"
fi
if [[ -z "${LLVM_DIR:-}" ]]; then
  fail "LLVM_DIR is unset"
fi
if [[ ! -d "${EIPPF_ALLOWED_LLVM_ROOT}" ]]; then
  fail "EIPPF_ALLOWED_LLVM_ROOT directory not found: ${EIPPF_ALLOWED_LLVM_ROOT}"
fi
if [[ ! -d "${LLVM_DIR}" ]]; then
  fail "LLVM_DIR directory not found: ${LLVM_DIR}"
fi

LLVM_PREFIX="$(cd "${EIPPF_ALLOWED_LLVM_ROOT}" && pwd)"
LLVM_CMAKE_DIR="$(cd "${LLVM_DIR}" && pwd)"
EXPECTED_LLVM_CMAKE_DIR="${LLVM_PREFIX}/lib/cmake/llvm"
if [[ "${LLVM_CMAKE_DIR}" != "${EXPECTED_LLVM_CMAKE_DIR}" ]]; then
  fail "LLVM_DIR must equal ${EXPECTED_LLVM_CMAKE_DIR}, got ${LLVM_CMAKE_DIR}"
fi

LLVM_CONFIG_PATH="${LLVM_PREFIX}/lib/cmake/llvm/LLVMConfig.cmake"
PASS_PLUGIN_HEADER_PATH="${LLVM_PREFIX}/include/llvm/Passes/PassPlugin.h"
if [[ ! -f "${LLVM_CONFIG_PATH}" ]]; then
  fail "missing LLVMConfig.cmake: ${LLVM_CONFIG_PATH}"
fi
if [[ ! -f "${PASS_PLUGIN_HEADER_PATH}" ]]; then
  fail "missing PassPlugin.h: ${PASS_PLUGIN_HEADER_PATH}"
fi

HOST_CLANG="${LLVM_PREFIX}/bin/clang"
HOST_CLANGXX="${LLVM_PREFIX}/bin/clang++"
if [[ ! -x "${HOST_CLANG}" ]]; then
  fail "missing host clang: ${HOST_CLANG}"
fi
if [[ ! -x "${HOST_CLANGXX}" ]]; then
  fail "missing host clang++: ${HOST_CLANGXX}"
fi

if ! IOS_TARGET_CLANGXX="$(xcrun --sdk iphonesimulator --find clang++ 2>/dev/null)"; then
  fail "xcrun cannot find iphonesimulator clang++"
fi
if ! IOS_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path 2>/dev/null)"; then
  fail "xcrun cannot resolve iphonesimulator SDK path"
fi
IOS_TARGET_CLANGXX="$(cd "$(dirname "${IOS_TARGET_CLANGXX}")" && pwd)/$(basename "${IOS_TARGET_CLANGXX}")"
IOS_SDK="$(cd "${IOS_SDK}" && pwd)"
if [[ ! -x "${IOS_TARGET_CLANGXX}" ]]; then
  fail "resolved iOS target clang++ is not executable: ${IOS_TARGET_CLANGXX}"
fi
if [[ ! -d "${IOS_SDK}" ]]; then
  fail "resolved iOS SDK path is not a directory: ${IOS_SDK}"
fi

HOST_COMPILER_VERSION_FIRST_LINE="$("${HOST_CLANGXX}" --version | head -n 1)"
if [[ "${HOST_COMPILER_VERSION_FIRST_LINE}" != *"clang version 18"* ]]; then
  fail "host compiler is not clang version 18: ${HOST_COMPILER_VERSION_FIRST_LINE}"
fi
IOS_TARGET_COMPILER_VERSION_FIRST_LINE="$("${IOS_TARGET_CLANGXX}" --version | head -n 1)"

mkdir -p "${IOS_DIR}" "${PASS_PLUGIN_DIR}" "${RUNTIME_LIB_DIR}" "${RUNTIME_BUILD_DIR}" "${REPORT_DIR}" "${COMMANDS_DIR}"

plugin_configure_cmd=(
  cmake
  -S "${REPO_ROOT}/core"
  -B "${RUNTIME_BUILD_DIR}"
  -G Ninja
  "-DLLVM_DIR=${LLVM_CMAKE_DIR}"
  "-DCMAKE_C_COMPILER=${HOST_CLANG}"
  "-DCMAKE_CXX_COMPILER=${HOST_CLANGXX}"
  "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${PASS_PLUGIN_DIR}"
  -DEIPPF_BUILD_TESTS=OFF
  -DEIPPF_BUILD_POST_LINK_MUTATOR=OFF
  -DEIPPF_BUILD_DEX_TOOLCHAIN=OFF
  -DEIPPF_BUILD_SCRIPT_GUARD=OFF
  -DEIPPF_BUILD_IP_WEAVER=OFF
  -DEIPPF_BUILD_IP_WEAVER_IR=OFF
  -DEIPPF_BUILD_TOOLING=OFF
)
plugin_build_cmd=(
  cmake
  --build "${RUNTIME_BUILD_DIR}"
  -j
  --target eippf_protection_suite_pass
)

{
  join_argv "${plugin_configure_cmd[@]}"
  printf '\n'
  join_argv "${plugin_build_cmd[@]}"
  printf '\n'
} > "${PLUGIN_COMMAND_PATH}"

"${plugin_configure_cmd[@]}"
"${plugin_build_cmd[@]}"

if [[ ! -f "${PASS_PLUGIN_PATH}" ]]; then
  fail "pass plugin build output missing: ${PASS_PLUGIN_PATH}"
fi

ios_helper_cmd=(
  "${IOS_TARGET_CLANGXX}"
  -target arm64-apple-ios17.0-simulator
  -isysroot "${IOS_SDK}"
  -std=c++20
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wshadow
  -Wnull-dereference
  -fno-exceptions
  -fno-rtti
  -fPIC
  -c "${REPO_ROOT}/core/runtime/src/string_token_runtime.cpp"
  "-I${REPO_ROOT}/core/include"
  "-I${REPO_ROOT}/core/runtime/include"
  -o "${IOS_USER_HELPER_O}"
)

join_argv "${ios_helper_cmd[@]}" > "${IOS_HELPER_COMMAND_PATH}"
printf '\n' >> "${IOS_HELPER_COMMAND_PATH}"
"${ios_helper_cmd[@]}"

if [[ ! -f "${IOS_USER_HELPER_O}" ]]; then
  fail "iOS helper output missing: ${IOS_USER_HELPER_O}"
fi

ios_link_cmd=(
  python3
  "${WRAPPER}"
  --pass-plugin "${PASS_PLUGIN_PATH}"
  --compiler "${IOS_TARGET_CLANGXX}"
  --
  -target arm64-apple-ios17.0-simulator
  -isysroot "${IOS_SDK}"
  -O2
  -fvisibility=hidden
  "${SRC_FILE}"
  -o "${IOS_OUTPUT_BIN}"
  "${IOS_USER_HELPER_O}"
)

join_argv "${ios_link_cmd[@]}" > "${IOS_LINK_COMMAND_PATH}"
printf '\n' >> "${IOS_LINK_COMMAND_PATH}"
"${ios_link_cmd[@]}"

IOS_LINK_INPUTS="${IOS_USER_HELPER_O}"

{
  printf 'platform=macos_ios\n'
  printf 'ios_target_source=xcrun\n'
  printf 'host_compiler_path=%s\n' "${HOST_CLANGXX}"
  printf 'host_compiler_version_first_line=%s\n' "${HOST_COMPILER_VERSION_FIRST_LINE}"
  printf 'ios_target_compiler_path=%s\n' "${IOS_TARGET_CLANGXX}"
  printf 'ios_target_compiler_version_first_line=%s\n' "${IOS_TARGET_COMPILER_VERSION_FIRST_LINE}"
  printf 'llvm_dir=%s\n' "${LLVM_CMAKE_DIR}"
  printf 'plugin_path=%s\n' "${PASS_PLUGIN_PATH}"
  printf 'ios_user_helper_o=%s\n' "${IOS_USER_HELPER_O}"
  printf 'plugin_build_command=%s\n' "${PLUGIN_COMMAND_PATH}"
  printf 'ios_user_helper_compile_command=%s\n' "${IOS_HELPER_COMMAND_PATH}"
  printf 'ios_link_inputs=%s\n' "${IOS_LINK_INPUTS}"
  printf 'ios_link_command=%s\n' "${IOS_LINK_COMMAND_PATH}"
  printf 'ios_target=%s\n' "${IOS_TARGET}"
  printf 'ios_isysroot=%s\n' "${IOS_SDK}"
} > "${REPORT_PATH}"

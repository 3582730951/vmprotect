#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build_linux_android.sh <output-root>" >&2
  exit 2
fi

OUT_ROOT="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SRC_ROOT="${REPO_ROOT}/core/tests/sample_suite/sources"
WRAPPER="${REPO_ROOT}/core/wrapper/eippf_cc.py"

if [[ -z "${ANDROID_SDK_ROOT:-}" ]]; then
  echo "[FAIL] ANDROID_SDK_ROOT is required" >&2
  exit 2
fi

NDK_VERSION="26.3.11579264"
ANDROID_NDK_ROOT="${ANDROID_SDK_ROOT}/ndk/${NDK_VERSION}"
ANDROID_SYSROOT="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
D8_BIN="${ANDROID_SDK_ROOT}/build-tools/34.0.0/d8"

if [[ ! -f "${WRAPPER}" ]]; then
  echo "[FAIL] wrapper script is missing: ${WRAPPER}" >&2
  exit 2
fi
if [[ ! -d "${ANDROID_SYSROOT}" ]]; then
  echo "[FAIL] Android NDK sysroot is missing: ${ANDROID_SYSROOT}" >&2
  exit 2
fi
if [[ ! -x "${D8_BIN}" ]]; then
  echo "[FAIL] required tool missing: ${D8_BIN}" >&2
  exit 2
fi

HOST_CLANG="${EIPPF_CLANG:-}"
if [[ -z "${HOST_CLANG}" ]]; then
  if command -v clang-18 >/dev/null 2>&1; then
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
  if command -v clang++-18 >/dev/null 2>&1; then
    HOST_CLANGXX="$(command -v clang++-18)"
  elif command -v clang++ >/dev/null 2>&1; then
    HOST_CLANGXX="$(command -v clang++)"
  else
    echo "[FAIL] clang++ is required" >&2
    exit 2
  fi
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

for tool in cmake ninja ld javac python3 "${HOST_CLANG}" "${HOST_CLANGXX}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "[FAIL] required tool missing: ${tool}" >&2
    exit 2
  fi
done

LINUX_ELF_DIR="${OUT_ROOT}/linux_elf"
LINUX_SO_DIR="${OUT_ROOT}/linux_so"
LINUX_KO_DIR="${OUT_ROOT}/linux_ko"
ANDROID_SO_DIR="${OUT_ROOT}/android_so"
ANDROID_DEX_DIR="${OUT_ROOT}/android_dex"
ANDROID_KO_DIR="${OUT_ROOT}/android_ko"
SHELL_DIR="${OUT_ROOT}/shell_script"
PASS_PLUGIN_DIR="${OUT_ROOT}/pass_plugins"
RUNTIME_LIB_DIR="${OUT_ROOT}/runtime_libs"
RUNTIME_BUILD_DIR="${OUT_ROOT}/_runtime_build_linux_android"
PASS_PLUGIN_PATH="${PASS_PLUGIN_DIR}/eippf_protection_suite_pass.so"
RUNTIME_LIB_PATH="${RUNTIME_LIB_DIR}/libeippf_string_token_runtime.a"

mkdir -p \
  "${LINUX_ELF_DIR}" \
  "${LINUX_SO_DIR}" \
  "${LINUX_KO_DIR}" \
  "${ANDROID_SO_DIR}" \
  "${ANDROID_DEX_DIR}" \
  "${ANDROID_KO_DIR}" \
  "${SHELL_DIR}" \
  "${PASS_PLUGIN_DIR}" \
  "${RUNTIME_LIB_DIR}" \
  "${RUNTIME_BUILD_DIR}"

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

run_wrapper_cc() {
  EIPPF_CLANG="${HOST_CLANG}" \
    EIPPF_CLANGXX="${HOST_CLANGXX}" \
    python3 "${WRAPPER}" --pass-plugin "${PASS_PLUGIN_PATH}" -- "$@"
}

run_wrapper_cc -O2 -Wall -Wextra \
  "${SRC_ROOT}/linux/linux_elf_main.c" \
  -o "${LINUX_ELF_DIR}/sample_linux_elf" \
  "${RUNTIME_LIB_PATH}"

run_wrapper_cc -O2 -Wall -Wextra -fPIC -shared \
  "${SRC_ROOT}/linux/linux_so.c" \
  -Wl,-soname,libsample_linux.so \
  -o "${LINUX_SO_DIR}/libsample_linux.so" \
  "${RUNTIME_LIB_PATH}"

run_wrapper_cc -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -c \
  "${SRC_ROOT}/kernel/linux_module.c" \
  -o "${LINUX_KO_DIR}/linux_module.o"
ld -r -o "${LINUX_KO_DIR}/sample_linux_module.ko" "${LINUX_KO_DIR}/linux_module.o" "${RUNTIME_LIB_PATH}"
rm -f "${LINUX_KO_DIR}/linux_module.o"

run_wrapper_cc --target=aarch64-linux-android24 --sysroot="${ANDROID_SYSROOT}" \
  -O2 -Wall -Wextra -fPIC -shared \
  "${SRC_ROOT}/android/android_so.c" \
  -o "${ANDROID_SO_DIR}/libsample_android.so"

mkdir -p "${ANDROID_DEX_DIR}/classes"
javac -source 8 -target 8 \
  -d "${ANDROID_DEX_DIR}/classes" \
  "${SRC_ROOT}/android/SampleMain.java"
mapfile -t CLASS_FILES < <(find "${ANDROID_DEX_DIR}/classes" -type f -name '*.class' | sort)
"${D8_BIN}" --min-api 24 --output "${ANDROID_DEX_DIR}" "${CLASS_FILES[@]}"
rm -rf "${ANDROID_DEX_DIR}/classes"

run_wrapper_cc -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -c \
  "${SRC_ROOT}/kernel/android_module.c" \
  -o "${ANDROID_KO_DIR}/android_module.o"
ld -r -o "${ANDROID_KO_DIR}/sample_android_module.ko" "${ANDROID_KO_DIR}/android_module.o" "${RUNTIME_LIB_PATH}"
rm -f "${ANDROID_KO_DIR}/android_module.o"

cp "${SRC_ROOT}/shell/sample_eval.sh" "${SHELL_DIR}/sample_eval.sh"
chmod +x "${SHELL_DIR}/sample_eval.sh"

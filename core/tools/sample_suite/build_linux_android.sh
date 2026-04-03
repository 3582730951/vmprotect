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

if [[ -z "${ANDROID_SDK_ROOT:-}" ]]; then
  echo "[FAIL] ANDROID_SDK_ROOT is required" >&2
  exit 2
fi

NDK_VERSION="26.3.11579264"
NDK_BIN="${ANDROID_SDK_ROOT}/ndk/${NDK_VERSION}/toolchains/llvm/prebuilt/linux-x86_64/bin"
ANDROID_CLANG="${NDK_BIN}/aarch64-linux-android24-clang"
D8_BIN="${ANDROID_SDK_ROOT}/build-tools/34.0.0/d8"

for tool in gcc ld javac "${ANDROID_CLANG}" "${D8_BIN}"; do
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

mkdir -p \
  "${LINUX_ELF_DIR}" \
  "${LINUX_SO_DIR}" \
  "${LINUX_KO_DIR}" \
  "${ANDROID_SO_DIR}" \
  "${ANDROID_DEX_DIR}" \
  "${ANDROID_KO_DIR}" \
  "${SHELL_DIR}"

gcc -O2 -Wall -Wextra \
  "${SRC_ROOT}/linux/linux_elf_main.c" \
  -o "${LINUX_ELF_DIR}/sample_linux_elf"

gcc -O2 -Wall -Wextra -fPIC -shared \
  "${SRC_ROOT}/linux/linux_so.c" \
  -Wl,-soname,libsample_linux.so \
  -o "${LINUX_SO_DIR}/libsample_linux.so"

gcc -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -c \
  "${SRC_ROOT}/kernel/linux_module.c" \
  -o "${LINUX_KO_DIR}/linux_module.o"
ld -r -o "${LINUX_KO_DIR}/sample_linux_module.ko" "${LINUX_KO_DIR}/linux_module.o"
rm -f "${LINUX_KO_DIR}/linux_module.o"

"${ANDROID_CLANG}" -O2 -Wall -Wextra -fPIC -shared \
  "${SRC_ROOT}/android/android_so.c" \
  -o "${ANDROID_SO_DIR}/libsample_android.so"

mkdir -p "${ANDROID_DEX_DIR}/classes"
javac -source 8 -target 8 \
  -d "${ANDROID_DEX_DIR}/classes" \
  "${SRC_ROOT}/android/SampleMain.java"
mapfile -t CLASS_FILES < <(find "${ANDROID_DEX_DIR}/classes" -type f -name '*.class' | sort)
"${D8_BIN}" --min-api 24 --output "${ANDROID_DEX_DIR}" "${CLASS_FILES[@]}"
rm -rf "${ANDROID_DEX_DIR}/classes"

gcc -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables -c \
  "${SRC_ROOT}/kernel/android_module.c" \
  -o "${ANDROID_KO_DIR}/android_module.o"
ld -r -o "${ANDROID_KO_DIR}/sample_android_module.ko" "${ANDROID_KO_DIR}/android_module.o"
rm -f "${ANDROID_KO_DIR}/android_module.o"

cp "${SRC_ROOT}/shell/sample_eval.sh" "${SHELL_DIR}/sample_eval.sh"
chmod +x "${SHELL_DIR}/sample_eval.sh"

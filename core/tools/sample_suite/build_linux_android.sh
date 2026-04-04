#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build_linux_android.sh <output-root>" >&2
  exit 2
fi

fail() {
  echo "[FAIL] $1" >&2
  exit 2
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    fail "${name} is required"
  fi
}

require_dir() {
  local path="$1"
  local label="$2"
  if [[ ! -d "${path}" ]]; then
    fail "${label} is missing: ${path}"
  fi
}

require_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "${path}" ]]; then
    fail "${label} is missing: ${path}"
  fi
}

require_exe() {
  local path="$1"
  local label="$2"
  if [[ ! -x "${path}" ]]; then
    fail "${label} is missing: ${path}"
  fi
}

resolve_path() {
  local path="$1"
  if [[ -d "${path}" ]]; then
    (cd "${path}" && pwd)
  else
    printf '%s/%s\n' "$(cd "$(dirname "${path}")" && pwd)" "$(basename "${path}")"
  fi
}

command_to_line() {
  local arg
  local escaped=()
  for arg in "$@"; do
    printf -v arg_quoted '%q' "${arg}"
    escaped+=("${arg_quoted}")
  done
  local joined
  joined="${escaped[*]}"
  printf '%s\n' "${joined}"
}

write_command_sidecar() {
  local sidecar="$1"
  shift
  command_to_line "$@" > "${sidecar}"
}

run_and_record() {
  local sidecar="$1"
  shift
  write_command_sidecar "${sidecar}" "$@"
  "$@"
}

run_wrapper_and_record() {
  local sidecar="$1"
  local compiler_path="$2"
  shift 2
  local wrapper_cmd=(
    python3
    "${WRAPPER}"
    --pass-plugin "${PASS_PLUGIN_PATH}"
    --compiler "${compiler_path}"
    --
    "$@"
  )
  write_command_sidecar "${sidecar}" "${wrapper_cmd[@]}"
  "${wrapper_cmd[@]}"
}

OUT_ROOT_INPUT="$1"
mkdir -p "${OUT_ROOT_INPUT}"
OUT_ROOT="$(cd "${OUT_ROOT_INPUT}" && pwd)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
SRC_ROOT="${REPO_ROOT}/core/tests/sample_suite/sources"
HELPER_SOURCE="${REPO_ROOT}/core/runtime/src/string_token_runtime.cpp"
SHARED_INCLUDE="${REPO_ROOT}/core/include"
RUNTIME_INCLUDE="${REPO_ROOT}/core/runtime/include"
WRAPPER="${REPO_ROOT}/core/wrapper/eippf_cc.py"

require_env EIPPF_HOST_LLVM_ROOT
require_env LLVM_DIR
require_env EIPPF_ANDROID_NDK_ROOT
require_env EIPPF_ANDROID_NDK_VERSION
require_env ANDROID_SDK_ROOT

if [[ "${EIPPF_HOST_LLVM_ROOT}" != "/usr/lib/llvm-18" ]]; then
  fail "EIPPF_HOST_LLVM_ROOT mismatch: ${EIPPF_HOST_LLVM_ROOT}"
fi
if [[ "${LLVM_DIR}" != "/usr/lib/llvm-18/lib/cmake/llvm" ]]; then
  fail "LLVM_DIR mismatch: ${LLVM_DIR}"
fi
if [[ "${EIPPF_ANDROID_NDK_VERSION}" != "26.3.11579264" ]]; then
  fail "EIPPF_ANDROID_NDK_VERSION mismatch: ${EIPPF_ANDROID_NDK_VERSION}"
fi

HOST_LLVM_ROOT="${EIPPF_HOST_LLVM_ROOT}"
LLVM_CMAKE_DIR="${LLVM_DIR}"
ANDROID_NDK_ROOT="${EIPPF_ANDROID_NDK_ROOT}"
ANDROID_SYSROOT="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
ANDROID_TARGET_CLANGXX="${ANDROID_NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++"
D8_BIN="${ANDROID_SDK_ROOT}/build-tools/34.0.0/d8"

require_dir "${HOST_LLVM_ROOT}" "EIPPF_HOST_LLVM_ROOT"
require_dir "${LLVM_CMAKE_DIR}" "LLVM_DIR"
require_file "${LLVM_CMAKE_DIR}/LLVMConfig.cmake" "LLVMConfig.cmake"
require_dir "${ANDROID_NDK_ROOT}" "EIPPF_ANDROID_NDK_ROOT"
require_dir "${ANDROID_SYSROOT}" "Android NDK sysroot"
require_exe "${ANDROID_TARGET_CLANGXX}" "aarch64-linux-android24-clang++"
require_file "${WRAPPER}" "wrapper script"
require_exe "${D8_BIN}" "d8"

if [[ -x "${HOST_LLVM_ROOT}/bin/clang++" ]]; then
  HOST_CLANGXX="${HOST_LLVM_ROOT}/bin/clang++"
elif [[ -x "${HOST_LLVM_ROOT}/bin/clang++-18" ]]; then
  HOST_CLANGXX="${HOST_LLVM_ROOT}/bin/clang++-18"
else
  fail "host clang++ is missing under ${HOST_LLVM_ROOT}/bin"
fi

if [[ -x "${HOST_LLVM_ROOT}/bin/clang" ]]; then
  HOST_CLANG="${HOST_LLVM_ROOT}/bin/clang"
elif [[ -x "${HOST_LLVM_ROOT}/bin/clang-18" ]]; then
  HOST_CLANG="${HOST_LLVM_ROOT}/bin/clang-18"
else
  fail "host clang is missing under ${HOST_LLVM_ROOT}/bin"
fi

for tool in cmake ninja python3 javac; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    fail "required tool missing: ${tool}"
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
TOOLCHAIN_REPORT_DIR="${OUT_ROOT}/toolchain_reports"
COMMANDS_DIR="${TOOLCHAIN_REPORT_DIR}/commands"
REPORT_PATH="${TOOLCHAIN_REPORT_DIR}/linux_android.txt"
PASS_PLUGIN_PATH="${PASS_PLUGIN_DIR}/eippf_protection_suite_pass.so"
LINUX_USER_HELPER_O="${RUNTIME_LIB_DIR}/string_token_runtime.linux.user.o"
LINUX_KERNEL_HELPER_O="${RUNTIME_LIB_DIR}/string_token_runtime.linux.ko.o"
ANDROID_USER_HELPER_O="${RUNTIME_LIB_DIR}/string_token_runtime.android.user.o"
ANDROID_KERNEL_HELPER_O="${RUNTIME_LIB_DIR}/string_token_runtime.android.ko.o"

LINUX_ELF_OUTPUT="${LINUX_ELF_DIR}/sample_linux_elf"
LINUX_SO_OUTPUT="${LINUX_SO_DIR}/libsample_linux.so"
LINUX_KO_OUTPUT="${LINUX_KO_DIR}/sample_linux_module.ko"
ANDROID_SO_OUTPUT="${ANDROID_SO_DIR}/libsample_android.so"
ANDROID_KO_OUTPUT="${ANDROID_KO_DIR}/sample_android_module.ko"

PLUGIN_BUILD_SIDECAR="${COMMANDS_DIR}/linux_android.plugin_build.txt"
LINUX_USER_HELPER_SIDECAR="${COMMANDS_DIR}/linux_android.linux_user_helper_compile.txt"
LINUX_KERNEL_HELPER_SIDECAR="${COMMANDS_DIR}/linux_android.linux_kernel_helper_compile.txt"
ANDROID_USER_HELPER_SIDECAR="${COMMANDS_DIR}/linux_android.android_user_helper_compile.txt"
ANDROID_KERNEL_HELPER_SIDECAR="${COMMANDS_DIR}/linux_android.android_kernel_helper_compile.txt"
LINUX_ELF_LINK_SIDECAR="${COMMANDS_DIR}/linux_android.linux_elf_link.txt"
LINUX_SO_LINK_SIDECAR="${COMMANDS_DIR}/linux_android.linux_so_link.txt"
LINUX_KO_LINK_SIDECAR="${COMMANDS_DIR}/linux_android.linux_ko_link.txt"
ANDROID_SO_LINK_SIDECAR="${COMMANDS_DIR}/linux_android.android_so_link.txt"
ANDROID_KO_LINK_SIDECAR="${COMMANDS_DIR}/linux_android.android_ko_link.txt"

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
  "${RUNTIME_BUILD_DIR}" \
  "${TOOLCHAIN_REPORT_DIR}" \
  "${COMMANDS_DIR}"

PLUGIN_CONFIGURE_CMD=(
  cmake
  -S "${REPO_ROOT}/core"
  -B "${RUNTIME_BUILD_DIR}"
  -G Ninja
  "-DLLVM_DIR=${LLVM_CMAKE_DIR}"
  "-DCMAKE_C_COMPILER=${HOST_CLANG}"
  "-DCMAKE_CXX_COMPILER=${HOST_CLANGXX}"
  "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${PASS_PLUGIN_DIR}"
  -DEIPPF_BUILD_TESTS=OFF \
  -DEIPPF_BUILD_POST_LINK_MUTATOR=OFF \
  -DEIPPF_BUILD_DEX_TOOLCHAIN=OFF \
  -DEIPPF_BUILD_SCRIPT_GUARD=OFF \
  -DEIPPF_BUILD_IP_WEAVER=OFF \
  -DEIPPF_BUILD_IP_WEAVER_IR=OFF \
  -DEIPPF_BUILD_TOOLING=OFF
)
run_and_record "${PLUGIN_BUILD_SIDECAR}" "${PLUGIN_CONFIGURE_CMD[@]}"
cmake --build "${RUNTIME_BUILD_DIR}" -j --target eippf_protection_suite_pass

if [[ ! -f "${PASS_PLUGIN_PATH}" ]]; then
  fail "pass plugin build output missing: ${PASS_PLUGIN_PATH}"
fi

LINUX_USER_HELPER_CMD=(
  "${HOST_CLANGXX}"
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
  -c "${HELPER_SOURCE}"
  -I"${SHARED_INCLUDE}"
  -I"${RUNTIME_INCLUDE}"
  -o "${LINUX_USER_HELPER_O}"
)
run_and_record "${LINUX_USER_HELPER_SIDECAR}" "${LINUX_USER_HELPER_CMD[@]}"

LINUX_KERNEL_HELPER_CMD=(
  "${HOST_CLANGXX}"
  -std=c++20
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wshadow
  -Wnull-dereference
  -fno-exceptions
  -fno-rtti
  -ffreestanding
  -fno-builtin
  -fno-stack-protector
  -fno-asynchronous-unwind-tables
  -fvisibility=hidden
  -c "${HELPER_SOURCE}"
  -I"${SHARED_INCLUDE}"
  -I"${RUNTIME_INCLUDE}"
  -o "${LINUX_KERNEL_HELPER_O}"
)
run_and_record "${LINUX_KERNEL_HELPER_SIDECAR}" "${LINUX_KERNEL_HELPER_CMD[@]}"

ANDROID_USER_HELPER_CMD=(
  "${ANDROID_TARGET_CLANGXX}"
  --target=aarch64-linux-android24
  --sysroot="${ANDROID_SYSROOT}"
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
  -c "${HELPER_SOURCE}"
  -I"${SHARED_INCLUDE}"
  -I"${RUNTIME_INCLUDE}"
  -o "${ANDROID_USER_HELPER_O}"
)
run_and_record "${ANDROID_USER_HELPER_SIDECAR}" "${ANDROID_USER_HELPER_CMD[@]}"

ANDROID_KERNEL_HELPER_CMD=(
  "${ANDROID_TARGET_CLANGXX}"
  --target=aarch64-linux-android24
  --sysroot="${ANDROID_SYSROOT}"
  -std=c++20
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wshadow
  -Wnull-dereference
  -fno-exceptions
  -fno-rtti
  -ffreestanding
  -fno-builtin
  -fno-stack-protector
  -fno-asynchronous-unwind-tables
  -fvisibility=hidden
  -c "${HELPER_SOURCE}"
  -I"${SHARED_INCLUDE}"
  -I"${RUNTIME_INCLUDE}"
  -o "${ANDROID_KERNEL_HELPER_O}"
)
run_and_record "${ANDROID_KERNEL_HELPER_SIDECAR}" "${ANDROID_KERNEL_HELPER_CMD[@]}"

LINUX_ELF_LINK_ARGS=(
  -x c
  -O2
  -Wall
  -Wextra
  "${SRC_ROOT}/linux/linux_elf_main.c"
  -o "${LINUX_ELF_OUTPUT}"
  "${LINUX_USER_HELPER_O}"
)
run_wrapper_and_record "${LINUX_ELF_LINK_SIDECAR}" "${HOST_CLANGXX}" "${LINUX_ELF_LINK_ARGS[@]}"

LINUX_SO_LINK_ARGS=(
  -x c
  -O2
  -Wall
  -Wextra
  -fPIC
  -shared
  "${SRC_ROOT}/linux/linux_so.c"
  -Wl,-soname,libsample_linux.so
  -o "${LINUX_SO_OUTPUT}"
  "${LINUX_USER_HELPER_O}"
)
run_wrapper_and_record "${LINUX_SO_LINK_SIDECAR}" "${HOST_CLANGXX}" "${LINUX_SO_LINK_ARGS[@]}"

LINUX_KO_LINK_ARGS=(
  -x c
  -O2
  -ffreestanding
  -fno-builtin
  -fno-stack-protector
  -fno-asynchronous-unwind-tables
  -nostdlib
  -fuse-ld=lld
  -Wl,-r
  "${SRC_ROOT}/kernel/linux_module.c"
  -o "${LINUX_KO_OUTPUT}"
  "${LINUX_KERNEL_HELPER_O}"
)
run_wrapper_and_record "${LINUX_KO_LINK_SIDECAR}" "${HOST_CLANGXX}" "${LINUX_KO_LINK_ARGS[@]}"

ANDROID_SO_LINK_ARGS=(
  --target=aarch64-linux-android24
  --sysroot="${ANDROID_SYSROOT}"
  -x c
  -O2
  -Wall
  -Wextra
  -fPIC
  -shared
  "${SRC_ROOT}/android/android_so.c"
  -o "${ANDROID_SO_OUTPUT}"
  "${ANDROID_USER_HELPER_O}"
)
run_wrapper_and_record "${ANDROID_SO_LINK_SIDECAR}" "${ANDROID_TARGET_CLANGXX}" "${ANDROID_SO_LINK_ARGS[@]}"

mkdir -p "${ANDROID_DEX_DIR}/classes"
javac -source 8 -target 8 \
  -d "${ANDROID_DEX_DIR}/classes" \
  "${SRC_ROOT}/android/SampleMain.java"
mapfile -t CLASS_FILES < <(find "${ANDROID_DEX_DIR}/classes" -type f -name '*.class' | sort)
"${D8_BIN}" --min-api 24 --output "${ANDROID_DEX_DIR}" "${CLASS_FILES[@]}"
rm -rf "${ANDROID_DEX_DIR}/classes"

ANDROID_KO_LINK_ARGS=(
  --target=aarch64-linux-android24
  --sysroot="${ANDROID_SYSROOT}"
  -x c
  -O2
  -ffreestanding
  -fno-builtin
  -fno-stack-protector
  -fno-asynchronous-unwind-tables
  -nostdlib
  -fuse-ld=lld
  -Wl,-r
  "${SRC_ROOT}/kernel/android_module.c"
  -o "${ANDROID_KO_OUTPUT}"
  "${ANDROID_KERNEL_HELPER_O}"
)
run_wrapper_and_record "${ANDROID_KO_LINK_SIDECAR}" "${ANDROID_TARGET_CLANGXX}" "${ANDROID_KO_LINK_ARGS[@]}"

cp "${SRC_ROOT}/shell/sample_eval.sh" "${SHELL_DIR}/sample_eval.sh"
chmod +x "${SHELL_DIR}/sample_eval.sh"

HOST_COMPILER_PATH="$(resolve_path "${HOST_CLANGXX}")"
ANDROID_COMPILER_PATH="$(resolve_path "${ANDROID_TARGET_CLANGXX}")"
HOST_COMPILER_VERSION_FIRST_LINE="$("${HOST_CLANGXX}" --version | head -n 1)"
ANDROID_COMPILER_VERSION_FIRST_LINE="$("${ANDROID_TARGET_CLANGXX}" --version | head -n 1)"

LLVM_DIR_ABS="$(resolve_path "${LLVM_CMAKE_DIR}")"
ANDROID_NDK_ROOT_ABS="$(resolve_path "${ANDROID_NDK_ROOT}")"
PASS_PLUGIN_PATH_ABS="$(resolve_path "${PASS_PLUGIN_PATH}")"
LINUX_USER_HELPER_O_ABS="$(resolve_path "${LINUX_USER_HELPER_O}")"
LINUX_KERNEL_HELPER_O_ABS="$(resolve_path "${LINUX_KERNEL_HELPER_O}")"
ANDROID_USER_HELPER_O_ABS="$(resolve_path "${ANDROID_USER_HELPER_O}")"
ANDROID_KERNEL_HELPER_O_ABS="$(resolve_path "${ANDROID_KERNEL_HELPER_O}")"

PLUGIN_BUILD_SIDECAR_ABS="$(resolve_path "${PLUGIN_BUILD_SIDECAR}")"
LINUX_USER_HELPER_SIDECAR_ABS="$(resolve_path "${LINUX_USER_HELPER_SIDECAR}")"
LINUX_KERNEL_HELPER_SIDECAR_ABS="$(resolve_path "${LINUX_KERNEL_HELPER_SIDECAR}")"
ANDROID_USER_HELPER_SIDECAR_ABS="$(resolve_path "${ANDROID_USER_HELPER_SIDECAR}")"
ANDROID_KERNEL_HELPER_SIDECAR_ABS="$(resolve_path "${ANDROID_KERNEL_HELPER_SIDECAR}")"
LINUX_ELF_LINK_SIDECAR_ABS="$(resolve_path "${LINUX_ELF_LINK_SIDECAR}")"
LINUX_SO_LINK_SIDECAR_ABS="$(resolve_path "${LINUX_SO_LINK_SIDECAR}")"
LINUX_KO_LINK_SIDECAR_ABS="$(resolve_path "${LINUX_KO_LINK_SIDECAR}")"
ANDROID_SO_LINK_SIDECAR_ABS="$(resolve_path "${ANDROID_SO_LINK_SIDECAR}")"
ANDROID_KO_LINK_SIDECAR_ABS="$(resolve_path "${ANDROID_KO_LINK_SIDECAR}")"

cat > "${REPORT_PATH}" <<EOF
platform=linux_android
android_target_source=android_ndk
llvm_dir=${LLVM_DIR_ABS}
android_ndk_root=${ANDROID_NDK_ROOT_ABS}
host_compiler_path=${HOST_COMPILER_PATH}
host_compiler_version_first_line=${HOST_COMPILER_VERSION_FIRST_LINE}
android_target_compiler_path=${ANDROID_COMPILER_PATH}
android_target_compiler_version_first_line=${ANDROID_COMPILER_VERSION_FIRST_LINE}
plugin_path=${PASS_PLUGIN_PATH_ABS}
linux_user_helper_o=${LINUX_USER_HELPER_O_ABS}
linux_kernel_helper_o=${LINUX_KERNEL_HELPER_O_ABS}
android_user_helper_o=${ANDROID_USER_HELPER_O_ABS}
android_kernel_helper_o=${ANDROID_KERNEL_HELPER_O_ABS}
plugin_build_command=${PLUGIN_BUILD_SIDECAR_ABS}
linux_user_helper_compile_command=${LINUX_USER_HELPER_SIDECAR_ABS}
linux_kernel_helper_compile_command=${LINUX_KERNEL_HELPER_SIDECAR_ABS}
android_user_helper_compile_command=${ANDROID_USER_HELPER_SIDECAR_ABS}
android_kernel_helper_compile_command=${ANDROID_KERNEL_HELPER_SIDECAR_ABS}
linux_elf_link_inputs=${LINUX_USER_HELPER_O_ABS}
linux_so_link_inputs=${LINUX_USER_HELPER_O_ABS}
linux_ko_link_inputs=${LINUX_KERNEL_HELPER_O_ABS}
android_so_link_inputs=${ANDROID_USER_HELPER_O_ABS}
android_ko_link_inputs=${ANDROID_KERNEL_HELPER_O_ABS}
linux_elf_link_command=${LINUX_ELF_LINK_SIDECAR_ABS}
linux_so_link_command=${LINUX_SO_LINK_SIDECAR_ABS}
linux_ko_link_command=${LINUX_KO_LINK_SIDECAR_ABS}
android_so_link_command=${ANDROID_SO_LINK_SIDECAR_ABS}
android_ko_link_command=${ANDROID_KO_LINK_SIDECAR_ABS}
android_ko_link_driver_path=${ANDROID_COMPILER_PATH}
android_ko_link_flags=--target=aarch64-linux-android24;-nostdlib;-fuse-ld=lld;-Wl,-r
EOF

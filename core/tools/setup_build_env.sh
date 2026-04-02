#!/usr/bin/env bash
set -euo pipefail

# Provision a clean Ubuntu/Debian CI node for the polyglot zero-trust pipeline.
# Usage:
#   ./setup_build_env.sh [LLVM_MAJOR]
# Env:
#   EIPPF_INSTALL_RUST_TOOLCHAIN (default: stable)
#   EIPPF_INSTALL_LLVM_MAJOR    (overrides positional arg)

LLVM_MAJOR="${1:-}"
if [[ -z "${LLVM_MAJOR}" ]]; then
  LLVM_MAJOR="${EIPPF_INSTALL_LLVM_MAJOR:-18}"
fi
RUST_TOOLCHAIN="${EIPPF_INSTALL_RUST_TOOLCHAIN:-stable}"

if [[ "${EUID}" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

require_apt() {
  if ! have_cmd apt-get; then
    echo "[ERROR] apt-get not found. This script supports Ubuntu/Debian only." >&2
    exit 1
  fi
}

install_apt_packages() {
  local -a packages=("$@")
  "${SUDO}" DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
}

enable_llvm_apt_repo_if_needed() {
  if dpkg -s "clang-${LLVM_MAJOR}" >/dev/null 2>&1; then
    return 0
  fi

  if [[ ! -f "/etc/apt/sources.list.d/llvm.list" ]]; then
    echo "[INFO] Enabling LLVM apt repository for version ${LLVM_MAJOR}"
    local codename
    codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
    if [[ -z "${codename}" ]]; then
      echo "[ERROR] Failed to detect Ubuntu/Debian codename." >&2
      exit 1
    fi

    install_apt_packages ca-certificates curl gnupg lsb-release
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | "${SUDO}" gpg --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg
    cat <<EOF_REPO | "${SUDO}" tee /etc/apt/sources.list.d/llvm.list >/dev/null
deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${LLVM_MAJOR} main
EOF_REPO
    "${SUDO}" apt-get update -y
  fi
}

install_rust() {
  if ! have_cmd rustup; then
    echo "[INFO] Installing rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"
  fi

  # shellcheck disable=SC1091
  source "${HOME}/.cargo/env"
  rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal || true
  rustup default "${RUST_TOOLCHAIN}"
  rustup component add rustfmt clippy
}

print_versions() {
  echo "===== Provisioned toolchain versions ====="
  if have_cmd "clang-${LLVM_MAJOR}"; then
    "clang-${LLVM_MAJOR}" --version | head -n 1
  elif have_cmd clang; then
    clang --version | head -n 1
  fi

  if have_cmd "llvm-config-${LLVM_MAJOR}"; then
    "llvm-config-${LLVM_MAJOR}" --version
  elif have_cmd llvm-config; then
    llvm-config --version
  fi

  if have_cmd rustc; then
    rustc --version
  fi

  if have_cmd cargo; then
    cargo --version
  fi

  if have_cmd cmake; then
    cmake --version | head -n 1
  fi
}

main() {
  require_apt

  echo "[INFO] Updating apt metadata"
  "${SUDO}" apt-get update -y

  echo "[INFO] Installing baseline build dependencies"
  install_apt_packages \
    build-essential \
    pkg-config \
    cmake \
    ninja-build \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    file \
    unzip \
    xz-utils \
    libssl-dev \
    zlib1g-dev \
    libzstd-dev \
    libedit-dev \
    libxml2-dev \
    libncurses-dev

  enable_llvm_apt_repo_if_needed

  echo "[INFO] Installing LLVM/Clang ${LLVM_MAJOR} toolchain and headers"
  install_apt_packages \
    "llvm-${LLVM_MAJOR}" \
    "llvm-${LLVM_MAJOR}-dev" \
    "llvm-${LLVM_MAJOR}-tools" \
    "clang-${LLVM_MAJOR}" \
    "clang-tools-${LLVM_MAJOR}" \
    "clangd-${LLVM_MAJOR}" \
    "libclang-${LLVM_MAJOR}-dev" \
    "lld-${LLVM_MAJOR}"

  if [[ -x "/usr/lib/llvm-${LLVM_MAJOR}/bin/llvm-config" ]]; then
    "${SUDO}" ln -sf "/usr/lib/llvm-${LLVM_MAJOR}/bin/llvm-config" /usr/local/bin/llvm-config || true
    "${SUDO}" ln -sf "/usr/lib/llvm-${LLVM_MAJOR}/bin/clang" /usr/local/bin/clang || true
    "${SUDO}" ln -sf "/usr/lib/llvm-${LLVM_MAJOR}/bin/clang++" /usr/local/bin/clang++ || true
    "${SUDO}" ln -sf "/usr/lib/llvm-${LLVM_MAJOR}/bin/llc" /usr/local/bin/llc || true
  fi

  echo "[INFO] Installing Rust toolchain (${RUST_TOOLCHAIN})"
  install_rust

  print_versions
  echo "[INFO] Build environment provisioning completed."
}

main "$@"

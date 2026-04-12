#include "contracts/protection_contracts.hpp"
#include "runtime/memory_hal.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

extern "C" void eippf_je0(const std::uint8_t*, std::size_t, std::uint8_t) noexcept;
extern "C" const char* eippf_jgc0() noexcept;
extern "C" void eippf_jgr0() noexcept;
extern "C" std::uint32_t eippf_jgf0() noexcept;

#if defined(__x86_64__) || defined(_M_X64)
constexpr std::uint8_t kMinimalRetPayload[] = {0xC3u};
#elif defined(__aarch64__) || defined(_M_ARM64)
constexpr std::uint8_t kMinimalRetPayload[] = {0xC0u, 0x03u, 0x5Fu, 0xD6u};
#else
#error unsupported arch for hardened_target_runtime_kind_test
#endif

const char* safe_gate_code() {
  const char* gate_code = eippf_jgc0();
  return gate_code == nullptr ? "" : gate_code;
}

}  // namespace

int main() {
  const eippf::contracts::ProtectionTargetKind configured =
      eippf::runtime::MemoryHAL::configured_target_kind();
  const bool dynamic_code_allowed = eippf::runtime::MemoryHAL::runtime_dynamic_code_allowed();

#if defined(EIPPF_EXPECT_DESKTOP_NATIVE)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kDesktopNative,
              "hardened target should inject desktop target kind")) {
    return 1;
  }
  if (!expect(dynamic_code_allowed, "desktop target should allow runtime dynamic code")) {
    return 1;
  }
  eippf_jgr0();
  eippf_je0(kMinimalRetPayload, sizeof(kMinimalRetPayload), 0x00u);
  if (!expect(std::strcmp(safe_gate_code(), "") == 0,
              "desktop target should not emit a gate code")) {
    return 1;
  }
  if (!expect((eippf_jgf0() & 0xFu) == 0xFu,
              "desktop target should execute full jit enclave W^X probe path")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_IOS_APPSTORE)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kIosAppStore,
              "hardened target should inject ios target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_WINDOWS_DRIVER)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kWindowsDriver,
              "hardened target should inject windows driver target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_LINUX_KERNEL_MODULE)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kLinuxKernelModule,
              "hardened target should inject linux kernel module target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_ANDROID_KERNEL_MODULE)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kAndroidKernelModule,
              "hardened target should inject android kernel module target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_ANDROID_DEX)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kAndroidDex,
              "hardened target should inject android dex target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_SHELL_EPHEMERAL)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kShellEphemeral,
              "hardened target should inject shell ephemeral target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_UNKNOWN_TARGET)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kUnknown,
              "non-hardened target should remain unknown")) {
    return 1;
  }
#else
  return expect(false, "missing expected runtime target macro") ? 0 : 1;
#endif

#if !defined(EIPPF_EXPECT_DESKTOP_NATIVE)
  if (!expect(!dynamic_code_allowed, "forbidden target should block runtime dynamic code")) {
    return 1;
  }
  eippf_jgr0();
  eippf_je0(kMinimalRetPayload, sizeof(kMinimalRetPayload), 0x00u);
  if (!expect(std::strcmp(safe_gate_code(), "jit_route_forbidden_for_target") == 0,
              "forbidden target should emit jit_route_forbidden_for_target")) {
    return 1;
  }
  if (!expect(eippf_jgf0() == 0x1u,
              "forbidden target should only set precheck probe flag")) {
    return 1;
  }
#endif

  std::cout << "[PASS] hardened_target_runtime_kind_test\n";
  return 0;
}

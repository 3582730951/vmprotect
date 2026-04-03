#include "runtime/dynamic_api_resolver.hpp"
#include "runtime/memory_hal.hpp"

#include <cstdint>
#include <iostream>

namespace {

using Resolver = eippf::runtime::DynamicAPIResolver<64u, 4u>;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_target_is_hardened() {
  using eippf::contracts::ProtectionTargetKind;
  const ProtectionTargetKind configured = eippf::runtime::MemoryHAL::configured_target_kind();

#if defined(EIPPF_EXPECT_IOS_APPSTORE)
  if (!expect(configured == ProtectionTargetKind::kIosAppStore,
              "expected ios app store runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_WINDOWS_DRIVER)
  if (!expect(configured == ProtectionTargetKind::kWindowsDriver,
              "expected windows driver runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_LINUX_KERNEL_MODULE)
  if (!expect(configured == ProtectionTargetKind::kLinuxKernelModule,
              "expected linux kernel module runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_ANDROID_KERNEL_MODULE)
  if (!expect(configured == ProtectionTargetKind::kAndroidKernelModule,
              "expected android kernel module runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_ANDROID_DEX)
  if (!expect(configured == ProtectionTargetKind::kAndroidDex,
              "expected android dex runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_SHELL_EPHEMERAL)
  if (!expect(configured == ProtectionTargetKind::kShellEphemeral,
              "expected shell ephemeral runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_UNKNOWN_TARGET)
  if (!expect(configured == ProtectionTargetKind::kUnknown,
              "expected unknown runtime target")) {
    return false;
  }
#else
  return expect(false, "missing expected runtime target macro");
#endif

  return expect(!eippf::runtime::MemoryHAL::runtime_dynamic_code_allowed(),
                "safe backend should forbid runtime dynamic code");
}

bool test_executable_transition_is_blocked() {
  Resolver resolver;
  eippf::runtime::MemoryHAL::Region region =
      eippf::runtime::MemoryHAL::allocate_rw(resolver, 4096u);
  if (!expect(region.valid(), "allocate_rw should still provide a scratch region")) {
    return false;
  }

  auto* bytes = static_cast<std::uint8_t*>(region.base);
  bytes[0] = 0x11u;
  bytes[1] = 0x22u;

  if (!expect(!eippf::runtime::MemoryHAL::protect_rx(resolver, region),
              "protect_rx must fail closed for safe backends")) {
    eippf::runtime::MemoryHAL::release(resolver, region);
    return false;
  }

  if (!expect(eippf::runtime::MemoryHAL::protect_rw(resolver, region),
              "protect_rw should remain a safe no-op for non-executable regions")) {
    eippf::runtime::MemoryHAL::release(resolver, region);
    return false;
  }

  eippf::runtime::MemoryHAL::release(resolver, region);
  return expect(!region.valid(), "release should invalidate region handle");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_target_is_hardened() && ok;
  ok = test_executable_transition_is_blocked() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] memory_hal_safe_backend_test\n";
  return 0;
}

#include "contracts/protection_contracts.hpp"
#include "runtime/memory_hal.hpp"

#include <iostream>

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

}  // namespace

int main() {
  const eippf::contracts::ProtectionTargetKind configured =
      eippf::runtime::MemoryHAL::configured_target_kind();

#if defined(EIPPF_EXPECT_IOS_APPSTORE)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kIosAppStore,
              "hardened target should inject ios target kind")) {
    return 1;
  }
#elif defined(EIPPF_EXPECT_WINDOWS_DRIVER)
  if (!expect(configured == eippf::contracts::ProtectionTargetKind::kWindowsDriver,
              "hardened target should inject windows driver target kind")) {
    return 1;
  }
#else
  return 1;
#endif

  if (!expect(!eippf::runtime::MemoryHAL::runtime_dynamic_code_allowed(),
              "hardened safe target should block runtime dynamic code")) {
    return 1;
  }

  std::cout << "[PASS] hardened_target_runtime_kind_test\n";
  return 0;
}

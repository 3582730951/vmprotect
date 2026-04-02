#include <iostream>
#include <string>

#include "runtime/backend_policy.hpp"
#include "runtime/backends/backend_registry.hpp"

namespace {

using eippf::contracts::ProtectionTargetKind;
using eippf::contracts::RuntimeBackendKind;
using eippf::runtime::backend::Policy;
using eippf::runtime::backend::PolicyError;

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

}  // namespace

int main() {
  const Policy ios_policy =
      eippf::runtime::backend::default_policy_for_target(ProtectionTargetKind::kIosAppStore);
  if (!expect(eippf::runtime::backend::validate_policy(ios_policy) == PolicyError::kOk,
              "ios policy should validate")) {
    return 1;
  }
  if (!expect(!ios_policy.allow_jit, "ios policy should disable jit")) {
    return 1;
  }

  const auto ios_backend = eippf::runtime::backends::default_backend_for_target(
      ProtectionTargetKind::kIosAppStore);
  const auto* ios_descriptor = eippf::runtime::backends::get_backend_descriptor(ios_backend);
  if (!expect(ios_descriptor != nullptr, "ios backend descriptor should exist")) {
    return 1;
  }
  if (!expect(!ios_descriptor->supports_jit, "ios backend descriptor should forbid jit")) {
    return 1;
  }

  Policy invalid_driver =
      eippf::runtime::backend::default_policy_for_target(ProtectionTargetKind::kWindowsDriver);
  invalid_driver.allow_runtime_executable_pages = true;
  if (!expect(eippf::runtime::backend::validate_policy(invalid_driver) ==
                  PolicyError::kRuntimeExecutablePagesForbidden,
              "kernel-safe driver must reject runtime executable pages")) {
    return 1;
  }

  Policy invalid_mismatch =
      eippf::runtime::backend::default_policy_for_target(ProtectionTargetKind::kAndroidDex);
  invalid_mismatch.backend = RuntimeBackendKind::kDesktopJit;
  if (!expect(eippf::runtime::backend::validate_policy(invalid_mismatch) ==
                  PolicyError::kBackendTargetMismatch,
              "android dex should reject desktop jit backend")) {
    return 1;
  }

  if (!expect(std::string(eippf::runtime::backend::policy_error_name(
                  PolicyError::kPersistentPlaintextForbidden)) ==
                  "PERSISTENT_PLAINTEXT_FORBIDDEN",
              "policy error names should stay stable")) {
    return 1;
  }

  return 0;
}

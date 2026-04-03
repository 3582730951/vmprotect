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

  const Policy dex_policy =
      eippf::runtime::backend::default_policy_for_target(ProtectionTargetKind::kAndroidDex);
  if (!expect(!dex_policy.allow_jit, "android dex policy should disable jit")) {
    return 1;
  }

  const Policy linux_kernel_policy = eippf::runtime::backend::default_policy_for_target(
      ProtectionTargetKind::kLinuxKernelModule);
  if (!expect(eippf::runtime::backend::validate_policy(linux_kernel_policy) == PolicyError::kOk,
              "linux kernel module policy should validate")) {
    return 1;
  }
  if (!expect(!linux_kernel_policy.allow_jit,
              "linux kernel module policy should disable jit")) {
    return 1;
  }
  if (!expect(!linux_kernel_policy.allow_runtime_executable_pages,
              "linux kernel module policy should disable runtime executable pages")) {
    return 1;
  }

  const auto linux_kernel_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kLinuxKernelModule);
  if (!expect(linux_kernel_dispatch.backend == RuntimeBackendKind::kKernelSafeAot,
              "linux kernel module dispatch backend should be kernel_safe_aot")) {
    return 1;
  }
  const auto linux_kernel_backend = eippf::runtime::backends::default_backend_for_target(
      ProtectionTargetKind::kLinuxKernelModule);
  if (!expect(linux_kernel_backend == RuntimeBackendKind::kKernelSafeAot,
              "linux kernel module default backend should be kernel_safe_aot")) {
    return 1;
  }
  if (!expect(eippf::runtime::backend::target_kind_requires_sign_after_mutate(
                  ProtectionTargetKind::kLinuxKernelModule),
              "linux kernel module should require sign-after-mutate")) {
    return 1;
  }

  const Policy android_kernel_policy = eippf::runtime::backend::default_policy_for_target(
      ProtectionTargetKind::kAndroidKernelModule);
  if (!expect(eippf::runtime::backend::validate_policy(android_kernel_policy) == PolicyError::kOk,
              "android kernel module policy should validate")) {
    return 1;
  }
  if (!expect(!android_kernel_policy.allow_jit,
              "android kernel module policy should disable jit")) {
    return 1;
  }
  if (!expect(!android_kernel_policy.allow_runtime_executable_pages,
              "android kernel module policy should disable runtime executable pages")) {
    return 1;
  }

  const auto android_kernel_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kAndroidKernelModule);
  if (!expect(android_kernel_dispatch.backend == RuntimeBackendKind::kKernelSafeAot,
              "android kernel module dispatch backend should be kernel_safe_aot")) {
    return 1;
  }
  const auto android_kernel_backend = eippf::runtime::backends::default_backend_for_target(
      ProtectionTargetKind::kAndroidKernelModule);
  if (!expect(android_kernel_backend == RuntimeBackendKind::kKernelSafeAot,
              "android kernel module default backend should be kernel_safe_aot")) {
    return 1;
  }
  if (!expect(eippf::runtime::backend::target_kind_requires_sign_after_mutate(
                  ProtectionTargetKind::kAndroidKernelModule),
              "android kernel module should require sign-after-mutate")) {
    return 1;
  }

  if (!expect(eippf::runtime::backend::target_forbids_runtime_executable_pages(
                  ProtectionTargetKind::kUnknown),
              "unknown target should forbid runtime executable pages")) {
    return 1;
  }
  if (!expect(!eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kUnknown)
                   .allow_runtime_executable_pages,
              "unknown dispatch must disable runtime executable pages")) {
    return 1;
  }
  if (!expect(!eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kUnknown)
                   .allow_jit,
              "unknown dispatch must disable jit")) {
    return 1;
  }
  if (!expect(eippf::contracts::target_forbids_jit(ProtectionTargetKind::kUnknown),
              "unknown target should forbid jit in contracts")) {
    return 1;
  }
  if (!expect(eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kUnknown)
                      .allow_jit ==
                  !eippf::contracts::target_forbids_jit(ProtectionTargetKind::kUnknown),
              "unknown dispatch jit should match contracts forbid-jit rule")) {
    return 1;
  }

  if (!expect(eippf::runtime::backend::target_kind_supports_desktop_jit(
                  ProtectionTargetKind::kAndroidSo),
              "android so should support desktop jit lane")) {
    return 1;
  }

  if (!expect(eippf::runtime::backend::target_kind_requires_sign_after_mutate(
                  ProtectionTargetKind::kWindowsDriver),
              "windows driver should require sign-after-mutate")) {
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

  Policy invalid_linux_kernel = eippf::runtime::backend::default_policy_for_target(
      ProtectionTargetKind::kLinuxKernelModule);
  invalid_linux_kernel.allow_runtime_executable_pages = true;
  if (!expect(eippf::runtime::backend::validate_policy(invalid_linux_kernel) ==
                  PolicyError::kRuntimeExecutablePagesForbidden,
              "linux kernel module must reject runtime executable pages")) {
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

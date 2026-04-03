#include <iostream>

#include "runtime/backend_policy.hpp"

namespace {

using eippf::contracts::ProtectionTargetKind;
using eippf::contracts::RuntimeBackendKind;
using eippf::contracts::RuntimeLaneKind;
using eippf::runtime::backend::RuntimeBackendDispatch;

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

}  // namespace

int main() {
  const RuntimeBackendDispatch windows_driver_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kWindowsDriver);
  if (!expect(windows_driver_dispatch.lane == RuntimeLaneKind::kKernelSafe,
              "windows_driver lane must be kernel_safe")) {
    return 1;
  }
  if (!expect(windows_driver_dispatch.backend == RuntimeBackendKind::kKernelSafeAot,
              "windows_driver backend must be kernel_safe_aot")) {
    return 1;
  }
  if (!expect(windows_driver_dispatch.requires_sign_after_mutate,
              "windows_driver must require sign_after_mutate")) {
    return 1;
  }
  if (!expect(!windows_driver_dispatch.allow_jit, "windows_driver must disable jit")) {
    return 1;
  }
  if (!expect(!windows_driver_dispatch.allow_runtime_executable_pages,
              "windows_driver must disable runtime executable pages")) {
    return 1;
  }

  const RuntimeBackendDispatch linux_kernel_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kLinuxKernelModule);
  if (!expect(linux_kernel_dispatch.lane == RuntimeLaneKind::kKernelSafe,
              "linux_kernel_module lane must be kernel_safe")) {
    return 1;
  }
  if (!expect(linux_kernel_dispatch.backend == RuntimeBackendKind::kKernelSafeAot,
              "linux_kernel_module backend must be kernel_safe_aot")) {
    return 1;
  }
  if (!expect(linux_kernel_dispatch.requires_sign_after_mutate,
              "linux_kernel_module must require sign_after_mutate")) {
    return 1;
  }
  if (!expect(!linux_kernel_dispatch.allow_jit, "linux_kernel_module must disable jit")) {
    return 1;
  }
  if (!expect(!linux_kernel_dispatch.allow_runtime_executable_pages,
              "linux_kernel_module must disable runtime executable pages")) {
    return 1;
  }

  const RuntimeBackendDispatch android_kernel_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kAndroidKernelModule);
  if (!expect(android_kernel_dispatch.lane == RuntimeLaneKind::kKernelSafe,
              "android_kernel_module lane must be kernel_safe")) {
    return 1;
  }
  if (!expect(android_kernel_dispatch.backend == RuntimeBackendKind::kKernelSafeAot,
              "android_kernel_module backend must be kernel_safe_aot")) {
    return 1;
  }
  if (!expect(android_kernel_dispatch.requires_sign_after_mutate,
              "android_kernel_module must require sign_after_mutate")) {
    return 1;
  }
  if (!expect(!android_kernel_dispatch.allow_jit, "android_kernel_module must disable jit")) {
    return 1;
  }
  if (!expect(!android_kernel_dispatch.allow_runtime_executable_pages,
              "android_kernel_module must disable runtime executable pages")) {
    return 1;
  }

  const RuntimeBackendDispatch ios_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kIosAppStore);
  if (!expect(ios_dispatch.lane == RuntimeLaneKind::kIosSafe,
              "ios_appstore lane must be ios_safe")) {
    return 1;
  }
  if (!expect(!ios_dispatch.allow_jit, "ios_appstore must disable jit")) {
    return 1;
  }
  if (!expect(!ios_dispatch.allow_runtime_executable_pages,
              "ios_appstore must disable runtime executable pages")) {
    return 1;
  }

  const RuntimeBackendDispatch android_so_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kAndroidSo);
  if (!expect(android_so_dispatch.lane == RuntimeLaneKind::kDesktopUserMode,
              "android_so lane must be desktop_user_mode")) {
    return 1;
  }
  if (!expect(eippf::runtime::backend::target_kind_supports_desktop_jit(
                  ProtectionTargetKind::kAndroidSo),
              "android_so must support desktop jit")) {
    return 1;
  }

  const RuntimeBackendDispatch android_dex_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kAndroidDex);
  if (!expect(android_dex_dispatch.lane == RuntimeLaneKind::kDexLoaderVm,
              "android_dex lane must be dex_loader_vm")) {
    return 1;
  }
  if (!expect(!android_dex_dispatch.allow_jit, "android_dex must disable jit")) {
    return 1;
  }
  if (!expect(android_dex_dispatch.allow_jit == false,
              "android_dex dispatch jit flag must be false")) {
    return 1;
  }
  if (!expect(eippf::contracts::target_forbids_jit(ProtectionTargetKind::kAndroidDex),
              "android_dex contracts jit-forbid must be true")) {
    return 1;
  }

  const RuntimeBackendDispatch shell_dispatch =
      eippf::runtime::backend::dispatch_for_target(ProtectionTargetKind::kShellEphemeral);
  if (!expect(shell_dispatch.lane == RuntimeLaneKind::kShellLauncher,
              "shell_ephemeral lane must be shell_launcher")) {
    return 1;
  }
  if (!expect(!shell_dispatch.allow_persistent_plaintext,
              "shell_ephemeral must disable persistent plaintext")) {
    return 1;
  }
  if (!expect(shell_dispatch.allow_jit == false,
              "shell_ephemeral dispatch jit flag must be false")) {
    return 1;
  }
  if (!expect(eippf::contracts::target_forbids_jit(ProtectionTargetKind::kShellEphemeral),
              "shell_ephemeral contracts jit-forbid must be true")) {
    return 1;
  }

  return 0;
}

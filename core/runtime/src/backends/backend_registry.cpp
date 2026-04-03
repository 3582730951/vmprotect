#include "runtime/backends/backend_registry.hpp"
#include "runtime/backends/desktop_user_mode_backend.hpp"
#include "runtime/backends/dex_loader_backend.hpp"
#include "runtime/backends/ios_safe_backend.hpp"
#include "runtime/backends/kernel_safe_backend.hpp"
#include "runtime/backends/shell_launcher_backend.hpp"

namespace eippf::runtime::backends {

namespace {

using contracts::RuntimeBackendKind;
using contracts::RuntimeLaneKind;

constexpr BackendDescriptor kDesktopInterpreterDescriptor{
    RuntimeBackendKind::kDesktopInterpreter,
    RuntimeLaneKind::kDesktopUserMode,
    "desktop_interpreter",
    false,
    false,
    false,
    false,
};

}  // namespace

const BackendDescriptor* get_backend_descriptor(contracts::RuntimeBackendKind kind) noexcept {
  switch (kind) {
    case RuntimeBackendKind::kDesktopInterpreter:
      return &kDesktopInterpreterDescriptor;
    case RuntimeBackendKind::kDesktopJit:
      return &desktop_user_mode_backend_descriptor();
    case RuntimeBackendKind::kIosSafeAot:
      return &ios_safe_backend_descriptor();
    case RuntimeBackendKind::kKernelSafeAot:
      return &kernel_safe_backend_descriptor();
    case RuntimeBackendKind::kDexLoaderVm:
      return &dex_loader_backend_descriptor();
    case RuntimeBackendKind::kShellLauncher:
      return &shell_launcher_backend_descriptor();
    case RuntimeBackendKind::kUnknown:
      return nullptr;
  }
  return nullptr;
}

contracts::RuntimeBackendKind default_backend_for_target(
    contracts::ProtectionTargetKind target) noexcept {
  return contracts::default_backend_for_target(target);
}

bool is_desktop_user_mode_backend(contracts::RuntimeBackendKind kind) noexcept {
  const BackendDescriptor* descriptor = get_backend_descriptor(kind);
  return descriptor != nullptr && descriptor->lane == RuntimeLaneKind::kDesktopUserMode;
}

bool is_kernel_safe_backend(contracts::RuntimeBackendKind kind) noexcept {
  const BackendDescriptor* descriptor = get_backend_descriptor(kind);
  return descriptor != nullptr && descriptor->lane == RuntimeLaneKind::kKernelSafe;
}

bool is_ios_safe_backend(contracts::RuntimeBackendKind kind) noexcept {
  const BackendDescriptor* descriptor = get_backend_descriptor(kind);
  return descriptor != nullptr && descriptor->lane == RuntimeLaneKind::kIosSafe;
}

}  // namespace eippf::runtime::backends

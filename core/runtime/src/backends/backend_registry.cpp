#include "runtime/backends/backend_registry.hpp"

namespace eippf::runtime::backends {

namespace {

using contracts::ProtectionTargetKind;
using contracts::RuntimeBackendKind;

constexpr BackendDescriptor kBackendDescriptors[] = {
    BackendDescriptor{
        RuntimeBackendKind::kDesktopInterpreter,
        "desktop_interpreter",
        false,
        false,
        false,
    },
    BackendDescriptor{
        RuntimeBackendKind::kDesktopJit,
        "desktop_jit",
        true,
        true,
        false,
    },
    BackendDescriptor{
        RuntimeBackendKind::kIosSafeAot,
        "ios_safe_aot",
        false,
        false,
        false,
    },
    BackendDescriptor{
        RuntimeBackendKind::kKernelSafeAot,
        "kernel_safe_aot",
        false,
        false,
        false,
    },
    BackendDescriptor{
        RuntimeBackendKind::kDexLoaderVm,
        "dex_loader_vm",
        false,
        false,
        false,
    },
    BackendDescriptor{
        RuntimeBackendKind::kShellLauncher,
        "shell_launcher",
        false,
        false,
        false,
    },
};

}  // namespace

const BackendDescriptor* get_backend_descriptor(contracts::RuntimeBackendKind kind) noexcept {
  for (const BackendDescriptor& descriptor : kBackendDescriptors) {
    if (descriptor.kind == kind) {
      return &descriptor;
    }
  }
  return nullptr;
}

contracts::RuntimeBackendKind default_backend_for_target(
    contracts::ProtectionTargetKind target) noexcept {
  return contracts::default_backend_for_target(target);
}

}  // namespace eippf::runtime::backends

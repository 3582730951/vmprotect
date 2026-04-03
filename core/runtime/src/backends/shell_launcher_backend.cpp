#include "runtime/backends/shell_launcher_backend.hpp"

namespace eippf::runtime::backends {

const BackendDescriptor& shell_launcher_backend_descriptor() noexcept {
  static constexpr BackendDescriptor kDescriptor{
      contracts::RuntimeBackendKind::kShellLauncher,
      contracts::RuntimeLaneKind::kShellLauncher,
      "shell_launcher",
      false,
      false,
      false,
      false,
  };
  return kDescriptor;
}

}  // namespace eippf::runtime::backends

#include "runtime/backends/desktop_user_mode_backend.hpp"

namespace eippf::runtime::backends {

const BackendDescriptor& desktop_user_mode_backend_descriptor() noexcept {
  static constexpr BackendDescriptor kDescriptor{
      contracts::RuntimeBackendKind::kDesktopJit,
      contracts::RuntimeLaneKind::kDesktopUserMode,
      "desktop_jit",
      true,
      true,
      false,
      false,
  };
  return kDescriptor;
}

}  // namespace eippf::runtime::backends

#include "runtime/backends/kernel_safe_backend.hpp"

namespace eippf::runtime::backends {

const BackendDescriptor& kernel_safe_backend_descriptor() noexcept {
  static constexpr BackendDescriptor kDescriptor{
      contracts::RuntimeBackendKind::kKernelSafeAot,
      contracts::RuntimeLaneKind::kKernelSafe,
      "kernel_safe_aot",
      false,
      false,
      false,
      true,
  };
  return kDescriptor;
}

}  // namespace eippf::runtime::backends

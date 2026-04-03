#include "runtime/backends/ios_safe_backend.hpp"

namespace eippf::runtime::backends {

const BackendDescriptor& ios_safe_backend_descriptor() noexcept {
  static constexpr BackendDescriptor kDescriptor{
      contracts::RuntimeBackendKind::kIosSafeAot,
      contracts::RuntimeLaneKind::kIosSafe,
      "ios_safe_aot",
      false,
      false,
      false,
      false,
  };
  return kDescriptor;
}

}  // namespace eippf::runtime::backends

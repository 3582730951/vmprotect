#include "runtime/backends/dex_loader_backend.hpp"

namespace eippf::runtime::backends {

const BackendDescriptor& dex_loader_backend_descriptor() noexcept {
  static constexpr BackendDescriptor kDescriptor{
      contracts::RuntimeBackendKind::kDexLoaderVm,
      contracts::RuntimeLaneKind::kDexLoaderVm,
      "dex_loader_vm",
      false,
      false,
      false,
      false,
  };
  return kDescriptor;
}

}  // namespace eippf::runtime::backends

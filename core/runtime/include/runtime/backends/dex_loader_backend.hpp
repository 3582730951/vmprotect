#pragma once

#include "runtime/backends/backend_registry.hpp"

namespace eippf::runtime::backends {

[[nodiscard]] const BackendDescriptor& dex_loader_backend_descriptor() noexcept;

}  // namespace eippf::runtime::backends

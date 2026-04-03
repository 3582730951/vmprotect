#pragma once

#include "runtime/backends/backend_registry.hpp"

namespace eippf::runtime::backends {

[[nodiscard]] const BackendDescriptor& kernel_safe_backend_descriptor() noexcept;

}  // namespace eippf::runtime::backends

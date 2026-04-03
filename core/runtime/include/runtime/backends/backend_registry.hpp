#pragma once

#include "contracts/protection_contracts.hpp"

namespace eippf::runtime::backends {

struct BackendDescriptor final {
  contracts::RuntimeBackendKind kind = contracts::RuntimeBackendKind::kUnknown;
  contracts::RuntimeLaneKind lane = contracts::RuntimeLaneKind::kUnknown;
  const char* name = "unknown";
  bool supports_jit = false;
  bool supports_runtime_executable_pages = false;
  bool allows_persistent_plaintext = false;
  bool requires_sign_after_mutate = false;
};

[[nodiscard]] const BackendDescriptor* get_backend_descriptor(
    contracts::RuntimeBackendKind kind) noexcept;

[[nodiscard]] contracts::RuntimeBackendKind default_backend_for_target(
    contracts::ProtectionTargetKind target) noexcept;

[[nodiscard]] bool is_desktop_user_mode_backend(contracts::RuntimeBackendKind kind) noexcept;
[[nodiscard]] bool is_kernel_safe_backend(contracts::RuntimeBackendKind kind) noexcept;
[[nodiscard]] bool is_ios_safe_backend(contracts::RuntimeBackendKind kind) noexcept;

}  // namespace eippf::runtime::backends

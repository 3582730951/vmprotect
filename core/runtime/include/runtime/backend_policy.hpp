#pragma once

#include <cstdint>

#include "contracts/protection_contracts.hpp"

namespace eippf::runtime::backend {

enum class PolicyError : std::uint8_t {
  kOk = 0u,
  kUnknownTarget = 1u,
  kUnknownBackend = 2u,
  kBackendTargetMismatch = 3u,
  kJitForbidden = 4u,
  kRuntimeExecutablePagesForbidden = 5u,
  kPersistentPlaintextForbidden = 6u,
  kFailClosedRequired = 7u,
  kInvalidPlaintextTtl = 8u,
};

struct Policy final {
  contracts::ProtectionTargetKind target = contracts::ProtectionTargetKind::kUnknown;
  contracts::RuntimeBackendKind backend = contracts::RuntimeBackendKind::kUnknown;
  bool allow_jit = false;
  bool allow_runtime_executable_pages = false;
  bool allow_persistent_plaintext = false;
  bool require_fail_closed = true;
  std::uint32_t plaintext_ttl_ms = 0u;
};

[[nodiscard]] Policy default_policy_for_target(
    contracts::ProtectionTargetKind target) noexcept;

[[nodiscard]] PolicyError validate_policy(const Policy& policy) noexcept;

[[nodiscard]] bool target_forbids_jit(contracts::ProtectionTargetKind target) noexcept;
[[nodiscard]] bool target_forbids_runtime_executable_pages(
    contracts::ProtectionTargetKind target) noexcept;
[[nodiscard]] bool target_forbids_persistent_plaintext(
    contracts::ProtectionTargetKind target) noexcept;
[[nodiscard]] bool backend_matches_target(contracts::RuntimeBackendKind backend,
                                          contracts::ProtectionTargetKind target) noexcept;

[[nodiscard]] const char* policy_error_name(PolicyError error) noexcept;

}  // namespace eippf::runtime::backend

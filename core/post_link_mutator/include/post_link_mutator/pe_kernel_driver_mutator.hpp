#pragma once

#include <optional>
#include <vector>

#include "contracts/protection_contracts.hpp"

namespace eippf::post_link_mutator {

[[nodiscard]] std::optional<std::vector<std::uint8_t>> mutate_pe_kernel_driver_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind);

}  // namespace eippf::post_link_mutator

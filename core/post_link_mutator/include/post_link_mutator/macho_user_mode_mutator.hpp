#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include "contracts/protection_contracts.hpp"

namespace eippf::post_link_mutator {

inline constexpr std::string_view kMachOIosSafeMarker = "EIPPF_MACHO_IOSSAFE_V1";

[[nodiscard]] std::optional<std::vector<std::uint8_t>> mutate_macho_user_mode_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind);

}  // namespace eippf::post_link_mutator

#pragma once

#include <optional>
#include <string_view>

#include "contracts/protection_contracts.hpp"

namespace eippf::post_link_mutator {

[[nodiscard]] std::optional<eippf::contracts::ProtectionTargetKind> parse_target_kind_hint(
    std::string_view target_kind);

[[nodiscard]] eippf::contracts::ProtectionTargetKind classify_target_kind(
    std::string_view target_label,
    std::string_view explicit_target_kind,
    eippf::contracts::ArtifactKind base_artifact_kind);

[[nodiscard]] bool target_kind_matches_artifact_kind(
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::ArtifactKind artifact_kind);

[[nodiscard]] eippf::contracts::ArtifactKind classify_artifact_kind(
    eippf::contracts::ArtifactKind base_artifact_kind,
    eippf::contracts::ProtectionTargetKind target_kind);

}  // namespace eippf::post_link_mutator

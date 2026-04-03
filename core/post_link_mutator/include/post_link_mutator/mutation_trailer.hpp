#pragma once

#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include "contracts/protection_contracts.hpp"

namespace eippf::post_link_mutator {

inline constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";

[[nodiscard]] std::uint64_t fnv1a64(const std::vector<std::uint8_t>& data) noexcept;

[[nodiscard]] std::vector<std::uint8_t> build_mutation_trailer(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind);

[[nodiscard]] std::vector<std::uint8_t> mutate_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind);

[[nodiscard]] bool has_valid_mutation_trailer(std::span<const std::uint8_t> artifact);

}  // namespace eippf::post_link_mutator

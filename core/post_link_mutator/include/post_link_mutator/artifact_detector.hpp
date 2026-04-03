#pragma once

#include <filesystem>

#include "contracts/protection_contracts.hpp"

namespace eippf::post_link_mutator {

[[nodiscard]] eippf::contracts::ArtifactKind detect_base_artifact_kind(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_path = {});

}  // namespace eippf::post_link_mutator

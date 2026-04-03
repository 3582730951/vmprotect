#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "contracts/protection_contracts.hpp"

namespace eippf::post_link_mutator {

[[nodiscard]] std::filesystem::path derive_manifest_path(
    const std::filesystem::path& output_path,
    const std::filesystem::path& explicit_manifest_path);

[[nodiscard]] const char* signing_profile_for_target(
    eippf::contracts::ProtectionTargetKind target_kind);

[[nodiscard]] const char* attestation_profile_for_target(
    eippf::contracts::ProtectionTargetKind target_kind);

[[nodiscard]] std::string json_escape(std::string_view text);

[[nodiscard]] bool write_manifest(
    const std::filesystem::path& manifest_path,
    std::string_view target_label,
    std::string_view target_kind_source,
    const eippf::contracts::ProtectionManifestV2& manifest,
    std::uintmax_t input_size_bytes,
    std::uintmax_t output_size_bytes,
    std::string_view mutation_status);

}  // namespace eippf::post_link_mutator

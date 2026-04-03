#include "post_link_mutator/macho_user_mode_mutator.hpp"

#include "post_link_mutator/mutation_trailer.hpp"

namespace eippf::post_link_mutator {
namespace {

[[nodiscard]] bool has_macho_header(const std::vector<std::uint8_t>& input) noexcept {
  if (input.size() < 4u) {
    return false;
  }
  const std::uint32_t magic = (static_cast<std::uint32_t>(input[0u]) << 24u) |
                              (static_cast<std::uint32_t>(input[1u]) << 16u) |
                              (static_cast<std::uint32_t>(input[2u]) << 8u) |
                              static_cast<std::uint32_t>(input[3u]);
  return magic == 0xFEEDFACEu || magic == 0xCEFAEDFEu || magic == 0xFEEDFACFu ||
         magic == 0xCFFAEDFEu || magic == 0xCAFEBABEu || magic == 0xBEBAFECAu ||
         magic == 0xCAFEBABFu || magic == 0xBFBAFECAu;
}

[[nodiscard]] bool backend_supported(eippf::contracts::RuntimeBackendKind backend) noexcept {
  return backend == eippf::contracts::RuntimeBackendKind::kIosSafeAot;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> mutate_macho_user_mode_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  using eippf::contracts::ArtifactKind;
  using eippf::contracts::ProtectionTargetKind;

  if (artifact_kind != ArtifactKind::kMachO || target_kind != ProtectionTargetKind::kIosAppStore ||
      !backend_supported(backend_kind) || !has_macho_header(input)) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> output = input;
  output.insert(output.end(), kMachOIosSafeMarker.begin(), kMachOIosSafeMarker.end());
  const std::vector<std::uint8_t> trailer =
      build_mutation_trailer(output, target_kind, backend_kind, artifact_kind);
  if (trailer.empty()) {
    return std::nullopt;
  }
  output.insert(output.end(), trailer.begin(), trailer.end());
  if (output == input) {
    return std::nullopt;
  }

  return output;
}

}  // namespace eippf::post_link_mutator

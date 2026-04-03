#include "post_link_mutator/pe_user_mode_mutator.hpp"

#include "post_link_mutator/mutation_trailer.hpp"

namespace eippf::post_link_mutator {
namespace {

[[nodiscard]] bool has_pe_header(const std::vector<std::uint8_t>& input) noexcept {
  return input.size() >= 2u && input[0] == static_cast<std::uint8_t>('M') &&
         input[1] == static_cast<std::uint8_t>('Z');
}

[[nodiscard]] bool backend_supported(eippf::contracts::RuntimeBackendKind backend) noexcept {
  return backend == eippf::contracts::RuntimeBackendKind::kDesktopJit ||
         backend == eippf::contracts::RuntimeBackendKind::kDesktopInterpreter;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> mutate_pe_user_mode_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  using eippf::contracts::ArtifactKind;
  using eippf::contracts::ProtectionTargetKind;

  if (artifact_kind != ArtifactKind::kPe || target_kind != ProtectionTargetKind::kDesktopNative ||
      !backend_supported(backend_kind) || !has_pe_header(input)) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> output = input;
  output.insert(output.end(), kPeUserModeMarker.begin(), kPeUserModeMarker.end());
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

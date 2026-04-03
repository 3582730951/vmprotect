#include "post_link_mutator/elf_user_mode_mutator.hpp"

#include "post_link_mutator/mutation_trailer.hpp"

namespace eippf::post_link_mutator {
namespace {

[[nodiscard]] bool has_elf_header(const std::vector<std::uint8_t>& input) noexcept {
  return input.size() >= 4u && input[0] == 0x7Fu &&
         input[1] == static_cast<std::uint8_t>('E') &&
         input[2] == static_cast<std::uint8_t>('L') &&
         input[3] == static_cast<std::uint8_t>('F');
}

[[nodiscard]] bool target_supported(eippf::contracts::ProtectionTargetKind target) noexcept {
  return target == eippf::contracts::ProtectionTargetKind::kDesktopNative ||
         target == eippf::contracts::ProtectionTargetKind::kAndroidSo;
}

[[nodiscard]] bool backend_supported(eippf::contracts::RuntimeBackendKind backend) noexcept {
  return backend == eippf::contracts::RuntimeBackendKind::kDesktopJit ||
         backend == eippf::contracts::RuntimeBackendKind::kDesktopInterpreter;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> mutate_elf_user_mode_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  using eippf::contracts::ArtifactKind;

  if (artifact_kind != ArtifactKind::kElf || !target_supported(target_kind) ||
      !backend_supported(backend_kind) || !has_elf_header(input)) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> output = input;
  output.insert(output.end(), kElfUserModeMarker.begin(), kElfUserModeMarker.end());
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

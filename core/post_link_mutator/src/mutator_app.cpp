#include "post_link_mutator/mutator_app.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <system_error>
#include <vector>

#include "contracts/protection_contracts.hpp"
#include "post_link_mutator/artifact_detector.hpp"
#include "post_link_mutator/binary_io.hpp"
#include "post_link_mutator/cli_options.hpp"
#include "post_link_mutator/elf_user_mode_mutator.hpp"
#include "post_link_mutator/macho_user_mode_mutator.hpp"
#include "post_link_mutator/manifest_writer.hpp"
#include "post_link_mutator/mutation_trailer.hpp"
#include "post_link_mutator/pe_user_mode_mutator.hpp"
#include "post_link_mutator/target_classifier.hpp"

namespace eippf::post_link_mutator {
namespace {

[[nodiscard]] bool is_user_mode_target(eippf::contracts::ProtectionTargetKind target_kind) noexcept {
  using eippf::contracts::ProtectionTargetKind;
  return target_kind == ProtectionTargetKind::kDesktopNative ||
         target_kind == ProtectionTargetKind::kAndroidSo ||
         target_kind == ProtectionTargetKind::kIosAppStore;
}

[[nodiscard]] bool is_user_mode_artifact(eippf::contracts::ArtifactKind artifact_kind) noexcept {
  using eippf::contracts::ArtifactKind;
  return artifact_kind == ArtifactKind::kPe || artifact_kind == ArtifactKind::kElf ||
         artifact_kind == ArtifactKind::kMachO;
}

[[nodiscard]] std::optional<std::vector<std::uint8_t>> mutate_user_mode_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  using eippf::contracts::ArtifactKind;
  if (artifact_kind == ArtifactKind::kPe) {
    return mutate_pe_user_mode_artifact(input, target_kind, backend_kind, artifact_kind);
  }
  if (artifact_kind == ArtifactKind::kElf) {
    return mutate_elf_user_mode_artifact(input, target_kind, backend_kind, artifact_kind);
  }
  if (artifact_kind == ArtifactKind::kMachO) {
    return mutate_macho_user_mode_artifact(input, target_kind, backend_kind, artifact_kind);
  }
  return std::nullopt;
}

[[nodiscard]] const char* kernel_compat_profile_for_target(
    eippf::contracts::ProtectionTargetKind target_kind) noexcept {
  using eippf::contracts::ProtectionTargetKind;
  switch (target_kind) {
    case ProtectionTargetKind::kWindowsDriver:
      return "hvci_profile";
    case ProtectionTargetKind::kLinuxKernelModule:
      return "vermagic_profile";
    case ProtectionTargetKind::kAndroidKernelModule:
      return "gki_kmi_profile";
    default:
      return "";
  }
}

}  // namespace

int run_mutator(int argc, char** argv, std::ostream& out, std::ostream& err) {
  return run_mutator_with_test_fault(argc, argv, out, err, TestFault::kNone);
}

int run_mutator_with_test_fault(int argc,
                                char** argv,
                                std::ostream& out,
                                std::ostream& err,
                                TestFault fault) {
  using eippf::contracts::ArtifactKind;
  using eippf::contracts::ProtectionManifestV2;
  using eippf::contracts::ProtectionTargetKind;
  using eippf::contracts::RuntimeBackendKind;

  const std::optional<CliOptions> parsed = parse_cli(argc, argv);
  if (!parsed.has_value()) {
    err << "Invalid arguments.\n";
    print_usage(out);
    return 2;
  }
  if (parsed->show_help) {
    print_usage(out);
    return 0;
  }

  const CliOptions options = *parsed;
  const std::filesystem::path manifest_path =
      derive_manifest_path(options.output_path, options.manifest_path);
  std::error_code ec;
  if (!std::filesystem::exists(options.input_path, ec) || ec) {
    err << "Input artifact does not exist: " << options.input_path << '\n';
    return 3;
  }

  const ArtifactKind base_artifact_kind =
      detect_base_artifact_kind(options.input_path, options.output_path);
  if (base_artifact_kind == ArtifactKind::kUnknown) {
    err << "Unsupported or unknown artifact kind: " << options.input_path << '\n';
    return 4;
  }

  const ProtectionTargetKind target_kind =
      classify_target_kind(options.target_label, options.target_kind_hint, base_artifact_kind);
  if (target_kind == ProtectionTargetKind::kUnknown) {
    err << "Unable to classify target kind from explicit hint/label: " << options.target_kind_hint
        << " / " << options.target_label << '\n';
    return 5;
  }
  if (!target_kind_matches_artifact_kind(target_kind, base_artifact_kind)) {
    err << "Explicit/derived target kind is incompatible with artifact kind\n";
    return 6;
  }

  std::vector<std::uint8_t> input;
  if (fault == TestFault::kForceReadInputFailure || !read_binary_file(options.input_path, input)) {
    err << "Failed to read input artifact: " << options.input_path << '\n';
    return 7;
  }

  const ArtifactKind manifest_artifact_kind = classify_artifact_kind(base_artifact_kind, target_kind);
  RuntimeBackendKind backend_kind = eippf::contracts::default_backend_for_target(target_kind);
  if (fault == TestFault::kForceBackendUnknown) {
    backend_kind = RuntimeBackendKind::kUnknown;
  }
  if (backend_kind == RuntimeBackendKind::kUnknown) {
    err << "Unable to classify backend kind from target: " << options.target_label << '\n';
    return 8;
  }

  std::vector<std::uint8_t> mutated;
  if (is_user_mode_target(target_kind) && is_user_mode_artifact(manifest_artifact_kind)) {
    const std::optional<std::vector<std::uint8_t>> user_mode_mutated =
        mutate_user_mode_artifact(input, target_kind, backend_kind, manifest_artifact_kind);
    if (!user_mode_mutated.has_value()) {
      err << "User-mode mutator rejected artifact/target combination\n";
      return 9;
    }
    mutated = *user_mode_mutated;
  } else {
    mutated = mutate_artifact(input, target_kind, backend_kind, manifest_artifact_kind);
  }
  if (fault == TestFault::kForceMutationIdentity) {
    mutated = input;
  }
  if (mutated == input) {
    err << "Mutation did not alter artifact output\n";
    return 9;
  }
  if (!write_binary_file(options.output_path, mutated)) {
    err << "Failed to write mutated artifact to: " << options.output_path << '\n';
    return 10;
  }

  ProtectionManifestV2 manifest{};
  manifest.target_kind = target_kind;
  manifest.backend_kind = backend_kind;
  manifest.artifact_kind = manifest_artifact_kind;
  manifest.runtime_lane = eippf::contracts::runtime_lane_for_target(target_kind);
  manifest.mutation_profile =
      eippf::contracts::mutation_profile_for_target_artifact(target_kind, manifest_artifact_kind);
  manifest.signature_policy = eippf::contracts::signature_policy_for_target(target_kind);
  manifest.kernel_compat_profile = kernel_compat_profile_for_target(target_kind);
  manifest.allow_jit = eippf::contracts::target_allows_jit(target_kind);
  manifest.allow_runtime_executable_pages = manifest.allow_jit;
  manifest.allow_persistent_plaintext = false;
  manifest.require_fail_closed = true;
  if (target_kind == ProtectionTargetKind::kWindowsDriver ||
      target_kind == ProtectionTargetKind::kLinuxKernelModule ||
      target_kind == ProtectionTargetKind::kAndroidKernelModule) {
    manifest.allow_jit = false;
    manifest.allow_runtime_executable_pages = false;
    manifest.allow_persistent_plaintext = false;
    manifest.require_fail_closed = true;
  }
  manifest.plaintext_ttl_ms = 0u;
  manifest.signing_profile = signing_profile_for_target(target_kind);
  manifest.attestation_profile = attestation_profile_for_target(target_kind);
  manifest.audit_policy = "lexical_anchor_strict";
  const std::string_view target_kind_source =
      options.target_kind_hint.empty() ? "derived_from_target_label" : "explicit_cli";

  if (!write_manifest(manifest_path,
                      options.target_label,
                      target_kind_source,
                      manifest,
                      input.size(),
                      mutated.size(),
                      "mutated_with_trailer_v1")) {
    err << "Failed to write manifest: " << manifest_path << '\n';
    return 11;
  }

  return 0;
}

}  // namespace eippf::post_link_mutator

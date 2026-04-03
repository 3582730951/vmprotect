#include "post_link_mutator/manifest_writer.hpp"

#include <fstream>
#include <system_error>

namespace eippf::post_link_mutator {
namespace {

[[nodiscard]] bool ensure_parent_exists(const std::filesystem::path& path) {
  const std::filesystem::path parent = path.parent_path();
  if (parent.empty()) {
    return true;
  }
  std::error_code ec;
  std::filesystem::create_directories(parent, ec);
  return !ec;
}

[[nodiscard]] const char* mutation_envelope_kind_for_manifest(
    const eippf::contracts::ProtectionManifestV2& manifest) noexcept {
  using eippf::contracts::ArtifactKind;
  using eippf::contracts::ProtectionTargetKind;

  if (manifest.target_kind == ProtectionTargetKind::kWindowsDriver) {
    return "pe_overlay_trailer_v2";
  }
  if (manifest.target_kind == ProtectionTargetKind::kLinuxKernelModule ||
      manifest.target_kind == ProtectionTargetKind::kAndroidKernelModule) {
    return "elf_note_section_v1";
  }

  switch (manifest.artifact_kind) {
    case ArtifactKind::kPe:
      return "pe_user_mode_trailer_v1";
    case ArtifactKind::kElf:
      return "elf_user_mode_trailer_v1";
    case ArtifactKind::kMachO:
      return "macho_user_mode_trailer_v1";
    case ArtifactKind::kDex:
      return "dex_bundle_trailer_v1";
    case ArtifactKind::kShellBundle:
      return "shell_bundle_trailer_v1";
    case ArtifactKind::kWindowsDriverSys:
      return "pe_overlay_trailer_v2";
    case ArtifactKind::kLinuxKernelModuleKo:
      return "elf_note_section_v1";
    case ArtifactKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

[[nodiscard]] const char* mutation_note_for_envelope_kind(
    std::string_view mutation_envelope_kind) noexcept {
  if (mutation_envelope_kind == "pe_overlay_trailer_v2") {
    return "pe overlay trailer appended";
  }
  if (mutation_envelope_kind == "elf_note_section_v1") {
    return "elf note section injected";
  }
  if (mutation_envelope_kind == "macho_user_mode_trailer_v1" ||
      mutation_envelope_kind == "elf_user_mode_trailer_v1" ||
      mutation_envelope_kind == "pe_user_mode_trailer_v1") {
    return "mutation trailer appended";
  }
  return "mutation envelope applied";
}

}  // namespace

std::filesystem::path derive_manifest_path(const std::filesystem::path& output_path,
                                           const std::filesystem::path& explicit_manifest_path) {
  if (!explicit_manifest_path.empty()) {
    return explicit_manifest_path;
  }
  if (output_path.empty()) {
    return {};
  }
  return std::filesystem::path(output_path.string() + ".manifest.json");
}

const char* signing_profile_for_target(eippf::contracts::ProtectionTargetKind target_kind) {
  using eippf::contracts::ProtectionTargetKind;
  if (target_kind == ProtectionTargetKind::kWindowsDriver) {
    return "windows_driver_sign_after_mutation";
  }
  if (target_kind == ProtectionTargetKind::kLinuxKernelModule ||
      target_kind == ProtectionTargetKind::kAndroidKernelModule) {
    return "kernel_module_sign_after_mutation";
  }
  if (target_kind == ProtectionTargetKind::kIosAppStore) {
    return "ios_codesign_after_mutation";
  }
  return "unsigned_dev_or_sign_after_mutation";
}

const char* attestation_profile_for_target(eippf::contracts::ProtectionTargetKind target_kind) {
  using eippf::contracts::ProtectionTargetKind;
  if (target_kind == ProtectionTargetKind::kWindowsDriver ||
      target_kind == ProtectionTargetKind::kLinuxKernelModule ||
      target_kind == ProtectionTargetKind::kAndroidKernelModule) {
    return "kernel_safe";
  }
  if (target_kind == ProtectionTargetKind::kIosAppStore) {
    return "ios_safe";
  }
  return "default";
}

std::string json_escape(std::string_view text) {
  std::string escaped;
  escaped.reserve(text.size() + 8u);
  for (const char ch : text) {
    switch (ch) {
      case '\\':
        escaped += "\\\\";
        break;
      case '"':
        escaped += "\\\"";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        escaped.push_back(ch);
        break;
    }
  }
  return escaped;
}

bool write_manifest(const std::filesystem::path& manifest_path,
                    std::string_view target_label,
                    std::string_view target_kind_source,
                    const eippf::contracts::ProtectionManifestV2& manifest,
                    std::uintmax_t input_size_bytes,
                    std::uintmax_t output_size_bytes,
                    std::string_view mutation_status) {
  if (!ensure_parent_exists(manifest_path)) {
    return false;
  }

  if (!eippf::contracts::validate_manifest_baseline(manifest)) {
    return false;
  }

  std::ofstream output(manifest_path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }

  const bool sign_after_mutate_required =
      manifest.signature_policy == eippf::contracts::SignaturePolicyKind::kSignAfterMutate;
  const bool requires_resign = eippf::contracts::target_requires_signed_artifact(manifest.target_kind);
  const char* mutation_envelope_kind = mutation_envelope_kind_for_manifest(manifest);
  const char* mutation_note = mutation_note_for_envelope_kind(mutation_envelope_kind);
  const bool hvci_profile = manifest.kernel_compat_profile == "hvci_profile";
  const bool vermagic_profile = manifest.kernel_compat_profile == "vermagic_profile";
  const bool gki_kmi_profile = manifest.kernel_compat_profile == "gki_kmi_profile";

  output << "{\n";
  output << "  \"schema_version\": " << manifest.schema_version << ",\n";
  output << "  \"target_label\": \"" << json_escape(target_label) << "\",\n";
  output << "  \"target_kind_source\": \"" << json_escape(target_kind_source) << "\",\n";
  output << "  \"target_kind\": \"" << eippf::contracts::to_string(manifest.target_kind)
         << "\",\n";
  output << "  \"backend_kind\": \"" << eippf::contracts::to_string(manifest.backend_kind)
         << "\",\n";
  output << "  \"artifact_kind\": \"" << eippf::contracts::to_string(manifest.artifact_kind)
         << "\",\n";
  output << "  \"runtime_lane\": \"" << eippf::contracts::to_string(manifest.runtime_lane)
         << "\",\n";
  output << "  \"mutation_profile\": \""
         << eippf::contracts::to_string(manifest.mutation_profile) << "\",\n";
  output << "  \"signature_policy\": \""
         << eippf::contracts::to_string(manifest.signature_policy) << "\",\n";
  output << "  \"mutation_envelope_kind\": \"" << mutation_envelope_kind << "\",\n";
  output << "  \"requires_resign\": " << (requires_resign ? "true" : "false") << ",\n";
  output << "  \"kernel_compat_profile\": \"" << json_escape(manifest.kernel_compat_profile)
         << "\",\n";
  output << "  \"sign_after_mutate_required\": "
         << (sign_after_mutate_required ? "true" : "false") << ",\n";
  output << "  \"hvci_profile\": " << (hvci_profile ? "true" : "false") << ",\n";
  output << "  \"vermagic_profile\": " << (vermagic_profile ? "true" : "false") << ",\n";
  output << "  \"gki_kmi_profile\": " << (gki_kmi_profile ? "true" : "false") << ",\n";
  output << "  \"allow_jit\": " << (manifest.allow_jit ? "true" : "false") << ",\n";
  output << "  \"allow_runtime_executable_pages\": "
         << (manifest.allow_runtime_executable_pages ? "true" : "false") << ",\n";
  output << "  \"allow_persistent_plaintext\": "
         << (manifest.allow_persistent_plaintext ? "true" : "false") << ",\n";
  output << "  \"require_fail_closed\": "
         << (manifest.require_fail_closed ? "true" : "false") << ",\n";
  output << "  \"plaintext_ttl_ms\": " << manifest.plaintext_ttl_ms << ",\n";
  output << "  \"signing_profile\": \"" << json_escape(manifest.signing_profile) << "\",\n";
  output << "  \"attestation_profile\": \"" << json_escape(manifest.attestation_profile)
         << "\",\n";
  output << "  \"audit_policy\": \"" << json_escape(manifest.audit_policy) << "\",\n";
  if (manifest.target_kind == eippf::contracts::ProtectionTargetKind::kIosAppStore) {
    output << "  \"ios_compliance_profile\": \"app_store_safe\",\n";
  }
  output << "  \"input_size_bytes\": " << input_size_bytes << ",\n";
  output << "  \"output_size_bytes\": " << output_size_bytes << ",\n";
  output << "  \"mutation_status\": \"" << json_escape(mutation_status) << "\",\n";
  output << "  \"notes\": [\"" << json_escape(mutation_note)
         << "\", \"sign after mutation if required\"]\n";
  output << "}\n";
  return static_cast<bool>(output);
}

}  // namespace eippf::post_link_mutator

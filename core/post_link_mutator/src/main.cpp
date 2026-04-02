#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "contracts/protection_contracts.hpp"

namespace {

using eippf::contracts::ArtifactKind;
using eippf::contracts::ProtectionManifestV2;
using eippf::contracts::ProtectionTargetKind;
using eippf::contracts::RuntimeBackendKind;

constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";

struct CliOptions final {
  std::filesystem::path input_path;
  std::filesystem::path output_path;
  std::filesystem::path manifest_path;
  std::string target_label;
  std::string target_kind_hint;
  bool show_help = false;
};

[[nodiscard]] std::string json_escape(std::string_view text) {
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

[[nodiscard]] std::optional<std::string> read_option_value(int& index, int argc, char** argv) {
  if (index + 1 >= argc) {
    return std::nullopt;
  }
  ++index;
  return std::string(argv[index]);
}

[[nodiscard]] std::optional<CliOptions> parse_cli(int argc, char** argv) {
  CliOptions options{};

  for (int i = 1; i < argc; ++i) {
    const std::string_view token(argv[i]);
    if (token == "--help" || token == "-h") {
      options.show_help = true;
      return options;
    }
    if (token.rfind("--input=", 0u) == 0u) {
      options.input_path = std::filesystem::path(std::string(token.substr(8u)));
      continue;
    }
    if (token.rfind("--output=", 0u) == 0u) {
      options.output_path = std::filesystem::path(std::string(token.substr(9u)));
      continue;
    }
    if (token.rfind("--manifest=", 0u) == 0u) {
      options.manifest_path = std::filesystem::path(std::string(token.substr(11u)));
      continue;
    }
    if (token.rfind("--target=", 0u) == 0u) {
      options.target_label = std::string(token.substr(9u));
      continue;
    }
    if (token.rfind("--target-kind=", 0u) == 0u) {
      options.target_kind_hint = std::string(token.substr(14u));
      continue;
    }
    if (token == "--input") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.input_path = std::filesystem::path(*value);
      continue;
    }
    if (token == "--output") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.output_path = std::filesystem::path(*value);
      continue;
    }
    if (token == "--manifest") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.manifest_path = std::filesystem::path(*value);
      continue;
    }
    if (token == "--target") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.target_label = *value;
      continue;
    }
    if (token == "--target-kind") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.target_kind_hint = *value;
      continue;
    }
    return std::nullopt;
  }

  if (options.target_label.empty()) {
    options.target_label = "unspecified";
  }
  if (options.input_path.empty() || options.output_path.empty() || options.manifest_path.empty()) {
    return std::nullopt;
  }
  return options;
}

void print_usage() {
  std::cout
      << "eippf_post_link_mutator --input <file> --output <file> --manifest <file> "
         "--target-kind <kind> [--target <label>]\n";
}

[[nodiscard]] std::string to_lower_ascii(std::string_view text) {
  std::string lowered;
  lowered.reserve(text.size());
  for (const char ch : text) {
    lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return lowered;
}

[[nodiscard]] bool contains_token(std::string_view text, std::string_view token) {
  return text.find(token) != std::string_view::npos;
}

[[nodiscard]] std::array<std::uint8_t, 4u> read_magic(std::ifstream& stream) {
  std::array<std::uint8_t, 4u> magic{0u, 0u, 0u, 0u};
  stream.seekg(0, std::ios::beg);
  stream.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
  return magic;
}

[[nodiscard]] bool is_pe_file(std::ifstream& stream, const std::array<std::uint8_t, 4u>& magic) {
  if (magic[0] != static_cast<std::uint8_t>('M') || magic[1] != static_cast<std::uint8_t>('Z')) {
    return false;
  }

  stream.seekg(0x3c, std::ios::beg);
  std::array<std::uint8_t, 4u> pe_offset_bytes{0u, 0u, 0u, 0u};
  stream.read(reinterpret_cast<char*>(pe_offset_bytes.data()),
              static_cast<std::streamsize>(pe_offset_bytes.size()));
  if (stream.gcount() != 4) {
    return true;
  }

  const std::uint32_t pe_offset = static_cast<std::uint32_t>(pe_offset_bytes[0]) |
                                  (static_cast<std::uint32_t>(pe_offset_bytes[1]) << 8u) |
                                  (static_cast<std::uint32_t>(pe_offset_bytes[2]) << 16u) |
                                  (static_cast<std::uint32_t>(pe_offset_bytes[3]) << 24u);
  stream.seekg(static_cast<std::streamoff>(pe_offset), std::ios::beg);
  std::array<std::uint8_t, 4u> pe_sig{0u, 0u, 0u, 0u};
  stream.read(reinterpret_cast<char*>(pe_sig.data()), static_cast<std::streamsize>(pe_sig.size()));
  if (stream.gcount() != 4) {
    return true;
  }
  return pe_sig[0] == static_cast<std::uint8_t>('P') &&
         pe_sig[1] == static_cast<std::uint8_t>('E') && pe_sig[2] == 0u && pe_sig[3] == 0u;
}

[[nodiscard]] bool is_elf_file(const std::array<std::uint8_t, 4u>& magic) {
  return magic[0] == 0x7fu && magic[1] == static_cast<std::uint8_t>('E') &&
         magic[2] == static_cast<std::uint8_t>('L') && magic[3] == static_cast<std::uint8_t>('F');
}

[[nodiscard]] bool is_macho_magic(std::uint32_t magic) {
  return magic == 0xFEEDFACEu || magic == 0xCEFAEDFEu || magic == 0xFEEDFACFu ||
         magic == 0xCFFAEDFEu || magic == 0xCAFEBABEu || magic == 0xBEBAFECAu ||
         magic == 0xCAFEBABFu || magic == 0xBFBAFECAu;
}

[[nodiscard]] ArtifactKind detect_base_artifact_kind(const std::filesystem::path& input_path) {
  std::ifstream input(input_path, std::ios::binary);
  if (!input) {
    return ArtifactKind::kUnknown;
  }

  const std::array<std::uint8_t, 4u> magic = read_magic(input);
  if (is_elf_file(magic)) {
    return ArtifactKind::kElf;
  }
  if (is_pe_file(input, magic)) {
    return ArtifactKind::kPe;
  }

  const std::uint32_t magic_u32 = static_cast<std::uint32_t>(magic[0]) << 24u |
                                  static_cast<std::uint32_t>(magic[1]) << 16u |
                                  static_cast<std::uint32_t>(magic[2]) << 8u |
                                  static_cast<std::uint32_t>(magic[3]);
  if (is_macho_magic(magic_u32)) {
    return ArtifactKind::kMachO;
  }
  return ArtifactKind::kUnknown;
}

[[nodiscard]] std::optional<ProtectionTargetKind> parse_target_kind_hint(std::string_view target_kind) {
  const std::string lowered = to_lower_ascii(target_kind);
  if (lowered == "desktop_native") {
    return ProtectionTargetKind::kDesktopNative;
  }
  if (lowered == "android_so") {
    return ProtectionTargetKind::kAndroidSo;
  }
  if (lowered == "android_dex" || lowered == "android_dex_research") {
    return ProtectionTargetKind::kAndroidDex;
  }
  if (lowered == "ios_appstore") {
    return ProtectionTargetKind::kIosAppStore;
  }
  if (lowered == "windows_driver") {
    return ProtectionTargetKind::kWindowsDriver;
  }
  if (lowered == "linux_kernel_module") {
    return ProtectionTargetKind::kLinuxKernelModule;
  }
  if (lowered == "android_kernel_module") {
    return ProtectionTargetKind::kAndroidKernelModule;
  }
  if (lowered == "shell_ephemeral") {
    return ProtectionTargetKind::kShellEphemeral;
  }
  return std::nullopt;
}

[[nodiscard]] ProtectionTargetKind classify_target_kind(std::string_view target_label,
                                                        std::string_view explicit_target_kind,
                                                        ArtifactKind base_artifact_kind) {
  if (!explicit_target_kind.empty()) {
    const std::optional<ProtectionTargetKind> parsed = parse_target_kind_hint(explicit_target_kind);
    if (!parsed.has_value()) {
      return ProtectionTargetKind::kUnknown;
    }
    return *parsed;
  }

  const std::string lowered = to_lower_ascii(target_label);
  if (contains_token(lowered, "windows_driver") || contains_token(lowered, "driver_sys") ||
      contains_token(lowered, ".sys")) {
    return ProtectionTargetKind::kWindowsDriver;
  }
  if ((contains_token(lowered, "android") && contains_token(lowered, ".ko")) ||
      contains_token(lowered, "android_kernel_module")) {
    return ProtectionTargetKind::kAndroidKernelModule;
  }
  if (contains_token(lowered, "linux_kernel_module") || contains_token(lowered, "kernel_module") ||
      contains_token(lowered, ".ko")) {
    return ProtectionTargetKind::kLinuxKernelModule;
  }
  if (contains_token(lowered, "ios")) {
    return ProtectionTargetKind::kIosAppStore;
  }
  if (contains_token(lowered, "dex")) {
    return ProtectionTargetKind::kAndroidDex;
  }
  if (contains_token(lowered, "shell") || contains_token(lowered, "script") ||
      contains_token(lowered, ".sh")) {
    return ProtectionTargetKind::kShellEphemeral;
  }
  if (contains_token(lowered, "android")) {
    return ProtectionTargetKind::kAndroidSo;
  }

  switch (base_artifact_kind) {
    case ArtifactKind::kMachO:
      return ProtectionTargetKind::kIosAppStore;
    case ArtifactKind::kPe:
    case ArtifactKind::kElf:
      return ProtectionTargetKind::kDesktopNative;
    case ArtifactKind::kDex:
    case ArtifactKind::kShellBundle:
    case ArtifactKind::kWindowsDriverSys:
    case ArtifactKind::kLinuxKernelModuleKo:
    case ArtifactKind::kUnknown:
      return ProtectionTargetKind::kUnknown;
  }
  return ProtectionTargetKind::kUnknown;
}

[[nodiscard]] bool target_kind_matches_artifact_kind(ProtectionTargetKind target_kind,
                                                     ArtifactKind artifact_kind) {
  switch (target_kind) {
    case ProtectionTargetKind::kDesktopNative:
      return artifact_kind == ArtifactKind::kPe || artifact_kind == ArtifactKind::kElf;
    case ProtectionTargetKind::kAndroidSo:
      return artifact_kind == ArtifactKind::kElf;
    case ProtectionTargetKind::kIosAppStore:
      return artifact_kind == ArtifactKind::kMachO;
    case ProtectionTargetKind::kWindowsDriver:
      return artifact_kind == ArtifactKind::kPe;
    case ProtectionTargetKind::kLinuxKernelModule:
    case ProtectionTargetKind::kAndroidKernelModule:
      return artifact_kind == ArtifactKind::kElf;
    case ProtectionTargetKind::kAndroidDex:
      return artifact_kind == ArtifactKind::kDex;
    case ProtectionTargetKind::kShellEphemeral:
      return artifact_kind == ArtifactKind::kShellBundle;
    case ProtectionTargetKind::kUnknown:
      return false;
  }
  return false;
}

[[nodiscard]] ArtifactKind classify_artifact_kind(ArtifactKind base_artifact_kind,
                                                  ProtectionTargetKind target_kind) {
  if (target_kind == ProtectionTargetKind::kWindowsDriver) {
    return ArtifactKind::kWindowsDriverSys;
  }
  if (target_kind == ProtectionTargetKind::kLinuxKernelModule ||
      target_kind == ProtectionTargetKind::kAndroidKernelModule) {
    return ArtifactKind::kLinuxKernelModuleKo;
  }
  return base_artifact_kind;
}

[[nodiscard]] bool ensure_parent_exists(const std::filesystem::path& path) {
  const std::filesystem::path parent = path.parent_path();
  if (parent.empty()) {
    return true;
  }
  std::error_code ec;
  std::filesystem::create_directories(parent, ec);
  return !ec;
}

[[nodiscard]] bool read_binary_file(const std::filesystem::path& path,
                                    std::vector<std::uint8_t>& data_out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  data_out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  return static_cast<bool>(input) || input.eof();
}

[[nodiscard]] bool write_binary_file(const std::filesystem::path& path,
                                     const std::vector<std::uint8_t>& data) {
  if (!ensure_parent_exists(path)) {
    return false;
  }
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }
  if (!data.empty()) {
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  return static_cast<bool>(output);
}

[[nodiscard]] std::uint64_t fnv1a64(const std::vector<std::uint8_t>& data) noexcept {
  std::uint64_t hash = 14695981039346656037ull;
  for (const std::uint8_t byte : data) {
    hash ^= static_cast<std::uint64_t>(byte);
    hash *= 1099511628211ull;
  }
  return hash;
}

void append_u32_le(std::vector<std::uint8_t>& output, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    output.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(i * 8)) & 0xFFu));
  }
}

void append_u64_le(std::vector<std::uint8_t>& output, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    output.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(i * 8)) & 0xFFu));
  }
}

[[nodiscard]] std::vector<std::uint8_t> build_mutation_trailer(
    const std::vector<std::uint8_t>& input,
    ProtectionTargetKind target_kind,
    RuntimeBackendKind backend_kind,
    ArtifactKind artifact_kind) {
  std::vector<std::uint8_t> trailer;
  trailer.reserve(kMutationTrailerMagic.size() + 24u);

  trailer.insert(trailer.end(), kMutationTrailerMagic.begin(), kMutationTrailerMagic.end());
  trailer.push_back(1u);  // trailer version
  trailer.push_back(static_cast<std::uint8_t>(target_kind));
  trailer.push_back(static_cast<std::uint8_t>(backend_kind));
  trailer.push_back(static_cast<std::uint8_t>(artifact_kind));
  trailer.push_back(0u);  // flags
  append_u32_le(trailer, static_cast<std::uint32_t>(input.size()));
  append_u64_le(trailer, fnv1a64(input));
  append_u64_le(trailer, static_cast<std::uint64_t>(input.size()) ^ 0xE1F0F11ull);
  return trailer;
}

[[nodiscard]] std::vector<std::uint8_t> mutate_artifact(
    const std::vector<std::uint8_t>& input,
    ProtectionTargetKind target_kind,
    RuntimeBackendKind backend_kind,
    ArtifactKind artifact_kind) {
  std::vector<std::uint8_t> output = input;
  const std::vector<std::uint8_t> trailer =
      build_mutation_trailer(input, target_kind, backend_kind, artifact_kind);
  output.insert(output.end(), trailer.begin(), trailer.end());
  return output;
}

[[nodiscard]] const char* signing_profile_for_target(ProtectionTargetKind target_kind) {
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

[[nodiscard]] const char* attestation_profile_for_target(ProtectionTargetKind target_kind) {
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

[[nodiscard]] bool write_manifest(const std::filesystem::path& manifest_path,
                                  std::string_view target_label,
                                  std::string_view target_kind_source,
                                  const ProtectionManifestV2& manifest,
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
  output << "  \"input_size_bytes\": " << input_size_bytes << ",\n";
  output << "  \"output_size_bytes\": " << output_size_bytes << ",\n";
  output << "  \"mutation_status\": \"" << json_escape(mutation_status) << "\",\n";
  output << "  \"notes\": [\"mutation trailer appended\", \"sign after mutation if required\"]\n";
  output << "}\n";
  return static_cast<bool>(output);
}

}  // namespace

int main(int argc, char** argv) {
  const std::optional<CliOptions> parsed = parse_cli(argc, argv);
  if (!parsed.has_value()) {
    std::cerr << "Invalid arguments.\n";
    print_usage();
    return 2;
  }
  if (parsed->show_help) {
    print_usage();
    return 0;
  }

  const CliOptions options = *parsed;
  std::error_code ec;
  if (!std::filesystem::exists(options.input_path, ec) || ec) {
    std::cerr << "Input artifact does not exist: " << options.input_path << '\n';
    return 3;
  }

  const ArtifactKind base_artifact_kind = detect_base_artifact_kind(options.input_path);
  if (base_artifact_kind == ArtifactKind::kUnknown) {
    std::cerr << "Unsupported or unknown artifact kind: " << options.input_path << '\n';
    return 4;
  }

  const ProtectionTargetKind target_kind =
      classify_target_kind(options.target_label, options.target_kind_hint, base_artifact_kind);
  if (target_kind == ProtectionTargetKind::kUnknown) {
    std::cerr << "Unable to classify target kind from explicit hint/label: "
              << options.target_kind_hint << " / " << options.target_label << '\n';
    return 5;
  }
  if (!target_kind_matches_artifact_kind(target_kind, base_artifact_kind)) {
    std::cerr << "Explicit/derived target kind is incompatible with artifact kind\n";
    return 6;
  }

  std::vector<std::uint8_t> input;
  if (!read_binary_file(options.input_path, input)) {
    std::cerr << "Failed to read input artifact: " << options.input_path << '\n';
    return 7;
  }

  const ArtifactKind manifest_artifact_kind = classify_artifact_kind(base_artifact_kind, target_kind);
  const RuntimeBackendKind backend_kind = eippf::contracts::default_backend_for_target(target_kind);
  if (backend_kind == RuntimeBackendKind::kUnknown) {
    std::cerr << "Unable to classify backend kind from target: " << options.target_label << '\n';
    return 8;
  }

  const std::vector<std::uint8_t> mutated =
      mutate_artifact(input, target_kind, backend_kind, manifest_artifact_kind);
  if (mutated == input) {
    std::cerr << "Mutation did not alter artifact output\n";
    return 9;
  }
  if (!write_binary_file(options.output_path, mutated)) {
    std::cerr << "Failed to write mutated artifact to: " << options.output_path << '\n';
    return 10;
  }

  ProtectionManifestV2 manifest{};
  manifest.target_kind = target_kind;
  manifest.backend_kind = backend_kind;
  manifest.artifact_kind = manifest_artifact_kind;
  manifest.allow_jit = eippf::contracts::target_allows_jit(target_kind);
  manifest.allow_runtime_executable_pages = manifest.allow_jit;
  manifest.allow_persistent_plaintext = false;
  manifest.require_fail_closed = true;
  manifest.plaintext_ttl_ms = 0u;
  manifest.signing_profile = signing_profile_for_target(target_kind);
  manifest.attestation_profile = attestation_profile_for_target(target_kind);
  manifest.audit_policy = "lexical_anchor_strict";
  const std::string_view target_kind_source =
      options.target_kind_hint.empty() ? "derived_from_target_label" : "explicit_cli";

  if (!write_manifest(options.manifest_path,
                      options.target_label,
                      target_kind_source,
                      manifest,
                      input.size(),
                      mutated.size(),
                      "mutated_with_trailer_v1")) {
    std::cerr << "Failed to write manifest: " << options.manifest_path << '\n';
    return 11;
  }

  return 0;
}

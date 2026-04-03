#include "dex_toolchain/loader.hpp"

#include "dex_toolchain/bundle_format.hpp"
#include "dex_toolchain/external_key_provider.hpp"
#include "dex_toolchain/manifest_contract.hpp"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace eippf::dex_toolchain {

namespace {

constexpr std::uint8_t kDexBundleFormatVersion = 3u;
constexpr std::size_t kDexBundleHeaderBytesV3 = 26u;
constexpr std::uint8_t kDispatchKindNativeBridge = 1u;
constexpr std::uint16_t kBridgeFlagsFixed = 0u;
constexpr std::string_view kTargetKindAndroidDex = "android_dex";
constexpr std::string_view kTargetKindAndroidDexLegacy = "android_dex_research";
constexpr std::string_view kBackendKindDexLoaderVm = "dex_loader_vm";
constexpr std::string_view kRuntimeLaneDexLoaderVm = "dex_loader_vm";
constexpr std::string_view kReportKind = "android_dex_loader_report";

template <typename T>
inline constexpr bool kDependentFalse = false;

template <typename ManifestT>
constexpr bool kManifestContractFieldsAvailable = requires(ManifestT manifest) {
  manifest.kind;
  manifest.target_kind;
  manifest.backend_kind;
  manifest.runtime_lane;
  manifest.loader_format_version;
  manifest.key_id;
};

template <typename HeaderT>
constexpr bool kBundleHeaderFieldsAvailable = requires(HeaderT header) {
  header.format_version;
  header.key_material_marker;
  header.key_id_len;
  header.bridge_record_count;
  header.bridge_table_len;
  header.payload_len;
};

[[nodiscard]] bool starts_with(std::string_view value, std::string_view prefix) noexcept {
  return value.size() >= prefix.size() && value.substr(0u, prefix.size()) == prefix;
}

void secure_zero(std::vector<std::uint8_t>& data) noexcept {
  volatile std::uint8_t* p = data.data();
  for (std::size_t i = 0u; i < data.size(); ++i) {
    p[i] = 0u;
  }
}

[[nodiscard]] bool read_binary_file(const std::filesystem::path& path,
                                    std::vector<std::uint8_t>& out) noexcept {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }

  input.seekg(0, std::ios::end);
  const std::streamoff file_size = input.tellg();
  if (file_size < 0) {
    return false;
  }
  input.seekg(0, std::ios::beg);

  out.resize(static_cast<std::size_t>(file_size));
  if (out.empty()) {
    return true;
  }
  input.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  return input.good() || input.eof();
}

[[nodiscard]] bool read_text_file(const std::filesystem::path& path,
                                  std::string& out) noexcept {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  return input.good() || input.eof();
}

[[nodiscard]] std::uint64_t read_u64_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  std::uint64_t value = 0u;
  for (std::size_t i = 0u; i < 8u; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + i]) << static_cast<unsigned>(8u * i);
  }
  return value;
}

[[nodiscard]] std::uint32_t read_u32_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  std::uint32_t value = 0u;
  for (std::size_t i = 0u; i < 4u; ++i) {
    value |= static_cast<std::uint32_t>(bytes[offset + i]) << static_cast<unsigned>(8u * i);
  }
  return value;
}

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                    static_cast<std::uint16_t>(bytes[offset + 1u] << 8u));
}

[[nodiscard]] bool parse_bridge_token_hex(std::string_view token_hex,
                                          std::uint64_t& token_out) noexcept {
  if (token_hex.size() != 16u) {
    return false;
  }

  std::uint64_t value = 0u;
  for (char ch : token_hex) {
    value <<= 4u;
    if (ch >= '0' && ch <= '9') {
      value |= static_cast<std::uint64_t>(ch - '0');
      continue;
    }
    if (ch >= 'a' && ch <= 'f') {
      value |= static_cast<std::uint64_t>((ch - 'a') + 10);
      continue;
    }
    return false;
  }

  token_out = value;
  return true;
}

[[nodiscard]] std::string json_escape(std::string_view value) {
  std::string escaped;
  escaped.reserve(value.size() + 8u);
  for (char ch : value) {
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

[[nodiscard]] int loader_error_to_exit_code(LoaderError error) noexcept {
  switch (error) {
    case LoaderError::ok:
      return 0;
    case LoaderError::invalid_cli:
      return 2;
    case LoaderError::manifest_read_failed:
    case LoaderError::manifest_invalid:
    case LoaderError::bundle_read_failed:
    case LoaderError::bundle_invalid:
      return 20;
    case LoaderError::provider_failed:
      return 30;
    case LoaderError::guardrail_blocked:
      return 40;
    case LoaderError::bridge_token_missing:
      return 50;
    case LoaderError::report_write_failed:
      return 60;
  }
  return 1;
}

template <typename ManifestT>
[[nodiscard]] std::string manifest_kind(const ManifestT& manifest) {
  if constexpr (requires { manifest.kind; }) {
    return std::string(manifest.kind);
  }
  return std::string("android_dex_bundle");
}

template <typename ManifestT>
[[nodiscard]] std::string manifest_target_kind(const ManifestT& manifest) {
  if constexpr (requires { manifest.target_kind; }) {
    return std::string(manifest.target_kind);
  }
  return std::string(kTargetKindAndroidDex);
}

template <typename ManifestT>
[[nodiscard]] std::string manifest_backend_kind(const ManifestT& manifest) {
  if constexpr (requires { manifest.backend_kind; }) {
    return std::string(manifest.backend_kind);
  }
  return std::string(kBackendKindDexLoaderVm);
}

template <typename ManifestT>
[[nodiscard]] std::string manifest_runtime_lane(const ManifestT& manifest) {
  if constexpr (requires { manifest.runtime_lane; }) {
    return std::string(manifest.runtime_lane);
  }
  return std::string(kRuntimeLaneDexLoaderVm);
}

template <typename ManifestT>
[[nodiscard]] std::uint64_t manifest_loader_format_version(const ManifestT& manifest) noexcept {
  if constexpr (requires { manifest.loader_format_version; }) {
    return static_cast<std::uint64_t>(manifest.loader_format_version);
  }
  return 0u;
}

template <typename ManifestT>
[[nodiscard]] std::string manifest_key_id(const ManifestT& manifest) {
  if constexpr (requires { manifest.key_id; }) {
    return std::string(manifest.key_id);
  }
  return std::string();
}

template <typename ManifestT>
[[nodiscard]] std::string manifest_provider_endpoint_kind(const ManifestT& manifest) {
  if constexpr (requires { manifest.key_provider_endpoint_kind; }) {
    return std::string(manifest.key_provider_endpoint_kind);
  }
  return std::string("unknown");
}

template <typename HeaderT>
[[nodiscard]] std::uint8_t header_format_version(const HeaderT& header) noexcept {
  if constexpr (requires { header.format_version; }) {
    return static_cast<std::uint8_t>(header.format_version);
  }
  return 0u;
}

template <typename HeaderT>
[[nodiscard]] std::uint8_t header_key_material_marker(const HeaderT& header) noexcept {
  if constexpr (requires { header.key_material_marker; }) {
    return static_cast<std::uint8_t>(header.key_material_marker);
  }
  return 0xFFu;
}

template <typename HeaderT>
[[nodiscard]] std::uint16_t header_key_id_length(const HeaderT& header) noexcept {
  if constexpr (requires { header.key_id_len; }) {
    return static_cast<std::uint16_t>(header.key_id_len);
  }
  if constexpr (requires { header.key_id_length; }) {
    return static_cast<std::uint16_t>(header.key_id_length);
  }
  return 0u;
}

template <typename HeaderT>
[[nodiscard]] std::uint64_t header_bridge_record_count(const HeaderT& header) noexcept {
  if constexpr (requires { header.bridge_record_count; }) {
    return static_cast<std::uint64_t>(header.bridge_record_count);
  }
  return 0u;
}

template <typename HeaderT>
[[nodiscard]] std::uint64_t header_payload_length(const HeaderT& header) noexcept {
  if constexpr (requires { header.bridge_table_len; header.payload_len; }) {
    return static_cast<std::uint64_t>(header.bridge_table_len) +
           static_cast<std::uint64_t>(header.payload_len);
  }
  if constexpr (requires { header.payload_length; }) {
    return static_cast<std::uint64_t>(header.payload_length);
  }
  return 0u;
}

template <typename HeaderT>
[[nodiscard]] std::size_t header_size_bytes(const HeaderT& header) noexcept {
  (void)header;
  if constexpr (requires { header.header_size_bytes; }) {
    return static_cast<std::size_t>(header.header_size_bytes);
  }
  return kDexBundleHeaderBytesV3;
}

template <typename EndpointKindT>
[[nodiscard]] bool endpoint_kind_allowed(EndpointKindT kind) noexcept {
  if constexpr (requires { EndpointKindT::kExecutableAdapter; EndpointKindT::kFifo; EndpointKindT::kUnixSocket; }) {
    return kind == EndpointKindT::kExecutableAdapter ||
           kind == EndpointKindT::kFifo ||
           kind == EndpointKindT::kUnixSocket;
  }
  return true;
}

template <typename EndpointKindT>
[[nodiscard]] std::string endpoint_kind_to_string(EndpointKindT kind) {
  if constexpr (requires { provider_endpoint_kind_name(kind); }) {
    return std::string(provider_endpoint_kind_name(kind));
  } else if constexpr (std::is_enum_v<EndpointKindT>) {
    return std::to_string(static_cast<int>(kind));
  }
  return std::string("unknown");
}

template <typename ManifestT>
[[nodiscard]] bool invoke_load_and_validate_manifest_contract(
    const std::filesystem::path& manifest_path,
    std::string_view expected_key_id,
    ManifestT& manifest_out,
    std::string& validation_error_out) {
  if constexpr (requires {
                  load_and_validate_manifest_contract(
                      manifest_path, expected_key_id, manifest_out, validation_error_out);
                }) {
    return load_and_validate_manifest_contract(
        manifest_path, expected_key_id, manifest_out, validation_error_out);
  } else if constexpr (requires {
                         load_and_validate_manifest_contract(
                             manifest_path, expected_key_id, manifest_out);
                       }) {
    (void)validation_error_out;
    return load_and_validate_manifest_contract(manifest_path, expected_key_id, manifest_out);
  } else {
    static_assert(kDependentFalse<ManifestT>,
                  "Unsupported load_and_validate_manifest_contract signature");
  }
}

template <typename HeaderT>
[[nodiscard]] bool invoke_read_bundle_header_v3(const std::vector<std::uint8_t>& bundle_bytes,
                                                HeaderT& header_out,
                                                std::string& bundle_error_out) {
  if constexpr (requires {
                  read_bundle_header_v3(bundle_bytes, header_out, bundle_error_out);
                }) {
    return read_bundle_header_v3(bundle_bytes, header_out, bundle_error_out);
  } else if constexpr (requires {
                         read_bundle_header_v3(
                             bundle_bytes, header_out, std::declval<std::size_t&>());
                       }) {
    (void)bundle_error_out;
    std::size_t payload_offset_out = 0u;
    return read_bundle_header_v3(bundle_bytes, header_out, payload_offset_out);
  } else if constexpr (requires {
                         read_bundle_header_v3(bundle_bytes, header_out);
                       }) {
    (void)bundle_error_out;
    return read_bundle_header_v3(bundle_bytes, header_out);
  } else {
    static_assert(kDependentFalse<HeaderT>, "Unsupported read_bundle_header_v3 signature");
  }
}

template <typename EndpointKindT>
[[nodiscard]] bool invoke_resolve_external_key_from_endpoint(
    const std::filesystem::path& provider_path,
    std::string_view expected_key_id,
    std::uint8_t& key_out,
    EndpointKindT& endpoint_kind_out,
    bool& endpoint_rejected_out) {
  endpoint_rejected_out = false;
  const std::filesystem::path workspace_root("/workspace");
  std::error_code temp_ec;
  const std::filesystem::path temp_root = std::filesystem::temp_directory_path(temp_ec);
  if (temp_ec) {
    return false;
  }

  if constexpr (requires {
                  resolve_external_key_from_endpoint(
                      provider_path,
                      expected_key_id,
                      workspace_root,
                      temp_root,
                      key_out,
                      endpoint_kind_out);
                }) {
    const auto status = resolve_external_key_from_endpoint(
        provider_path, expected_key_id, workspace_root, temp_root, key_out, endpoint_kind_out);
    if constexpr (std::is_same_v<decltype(status), bool>) {
      return status;
    } else {
      if (static_cast<int>(status) == 0) {
        return true;
      }
      if constexpr (requires { status == KeyProviderError::kUnsupportedEndpoint; }) {
        if (status == KeyProviderError::kUnsupportedEndpoint) {
          endpoint_rejected_out = true;
        }
      }
      if constexpr (requires { status == KeyProviderError::kStaticFileRejected; }) {
        if (status == KeyProviderError::kStaticFileRejected) {
          endpoint_rejected_out = true;
        }
      }
      return false;
    }
  } else if constexpr (requires {
                         resolve_external_key_from_endpoint(
                             provider_path, expected_key_id, key_out, endpoint_kind_out);
                       }) {
    const auto status = resolve_external_key_from_endpoint(
        provider_path, expected_key_id, key_out, endpoint_kind_out);
    if constexpr (std::is_same_v<decltype(status), bool>) {
      return status;
    } else {
      return static_cast<int>(status) == 0;
    }
  } else {
    static_assert(kDependentFalse<EndpointKindT>,
                  "Unsupported resolve_external_key_from_endpoint signature");
  }
}

[[nodiscard]] bool load_bundle_for_probe(const std::filesystem::path& bundle_path,
                                         DexBundleHeaderV3& header_out,
                                         std::string& bundle_key_id_out,
                                         std::vector<std::uint8_t>& encrypted_payload_out,
                                         LoaderError& error_out) noexcept {
  if constexpr (!kBundleHeaderFieldsAvailable<DexBundleHeaderV3>) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }

  std::vector<std::uint8_t> bundle_bytes;
  if (!read_binary_file(bundle_path, bundle_bytes)) {
    error_out = LoaderError::bundle_read_failed;
    return false;
  }

  std::string bundle_error;
  if (!invoke_read_bundle_header_v3(bundle_bytes, header_out, bundle_error)) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }

  const std::size_t header_bytes = header_size_bytes(header_out);
  const std::size_t key_id_len = static_cast<std::size_t>(header_key_id_length(header_out));
  const std::uint64_t payload_len_u64 = header_payload_length(header_out);
  if (payload_len_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  const std::size_t payload_len = static_cast<std::size_t>(payload_len_u64);

  if (header_bytes > bundle_bytes.size()) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  if (key_id_len > (bundle_bytes.size() - header_bytes)) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  const std::size_t payload_offset = header_bytes + key_id_len;
  if (payload_offset > bundle_bytes.size()) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  if (payload_len > (bundle_bytes.size() - payload_offset)) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }

  bundle_key_id_out.assign(
      reinterpret_cast<const char*>(bundle_bytes.data() + static_cast<std::ptrdiff_t>(header_bytes)),
      reinterpret_cast<const char*>(
          bundle_bytes.data() + static_cast<std::ptrdiff_t>(header_bytes + key_id_len)));
  encrypted_payload_out.assign(
      bundle_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
      bundle_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset + payload_len));
  error_out = LoaderError::ok;
  return true;
}

[[nodiscard]] bool validate_manifest_header_and_key(const DexManifestContract& manifest,
                                                    const DexBundleHeaderV3& header,
                                                    std::string_view expected_key_id,
                                                    std::string_view bundle_key_id,
                                                    LoaderError& error_out) noexcept {
  if constexpr (!kManifestContractFieldsAvailable<DexManifestContract>) {
    error_out = LoaderError::manifest_invalid;
    return false;
  }
  if constexpr (!kBundleHeaderFieldsAvailable<DexBundleHeaderV3>) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }

  const std::string target_kind = manifest_target_kind(manifest);
  if (target_kind != kTargetKindAndroidDex &&
      target_kind != kTargetKindAndroidDexLegacy) {
    error_out = LoaderError::manifest_invalid;
    return false;
  }
  if (manifest_backend_kind(manifest) != kBackendKindDexLoaderVm ||
      manifest_runtime_lane(manifest) != kRuntimeLaneDexLoaderVm) {
    error_out = LoaderError::manifest_invalid;
    return false;
  }
  if (manifest_loader_format_version(manifest) != static_cast<std::uint64_t>(kDexBundleFormatVersion)) {
    error_out = LoaderError::manifest_invalid;
    return false;
  }
  if (manifest_key_id(manifest) != expected_key_id) {
    error_out = LoaderError::manifest_invalid;
    return false;
  }

  if (header_format_version(header) != kDexBundleFormatVersion ||
      header_key_material_marker(header) != 0u) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  if (static_cast<std::uint64_t>(header_format_version(header)) != manifest_loader_format_version(manifest)) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  if (bundle_key_id != expected_key_id || bundle_key_id != manifest_key_id(manifest)) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  return true;
}

[[nodiscard]] bool has_valid_dex_magic_and_version(const std::vector<std::uint8_t>& dex_payload) noexcept {
  if (dex_payload.size() < 8u) {
    return false;
  }
  if (dex_payload[0u] != static_cast<std::uint8_t>('d') ||
      dex_payload[1u] != static_cast<std::uint8_t>('e') ||
      dex_payload[2u] != static_cast<std::uint8_t>('x') ||
      dex_payload[3u] != static_cast<std::uint8_t>('\n')) {
    return false;
  }
  if (dex_payload[7u] != 0u) {
    return false;
  }
  for (std::size_t i = 4u; i <= 6u; ++i) {
    if (std::isdigit(static_cast<unsigned char>(dex_payload[i])) == 0) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool parse_loader_options(int argc,
                          char** argv,
                          LoaderOptions& options_out,
                          LoaderError& error_out) noexcept {
  error_out = LoaderError::invalid_cli;
  if (argc < 2) {
    return false;
  }

  LoaderOptions options{};
  bool seen_input_bundle = false;
  bool seen_manifest = false;
  bool seen_key_provider = false;
  bool seen_key_id = false;
  bool seen_bridge_token = false;
  bool seen_report = false;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--help" || arg == "-h") {
      return false;
    }
    if (starts_with(arg, "--input-bundle=")) {
      if (seen_input_bundle) {
        return false;
      }
      options.input_bundle_path = std::filesystem::path(std::string(arg.substr(15u)));
      seen_input_bundle = true;
      continue;
    }
    if (starts_with(arg, "--manifest=")) {
      if (seen_manifest) {
        return false;
      }
      options.manifest_path = std::filesystem::path(std::string(arg.substr(11u)));
      seen_manifest = true;
      continue;
    }
    if (starts_with(arg, "--key-provider=")) {
      if (seen_key_provider) {
        return false;
      }
      options.key_provider_path = std::filesystem::path(std::string(arg.substr(15u)));
      seen_key_provider = true;
      continue;
    }
    if (starts_with(arg, "--key-id=")) {
      if (seen_key_id) {
        return false;
      }
      options.key_id = std::string(arg.substr(9u));
      seen_key_id = true;
      continue;
    }
    if (starts_with(arg, "--bridge-token=")) {
      if (seen_bridge_token) {
        return false;
      }
      options.bridge_token_hex = std::string(arg.substr(15u));
      seen_bridge_token = true;
      continue;
    }
    if (starts_with(arg, "--report=")) {
      if (seen_report) {
        return false;
      }
      options.report_path = std::filesystem::path(std::string(arg.substr(9u)));
      seen_report = true;
      continue;
    }
    return false;
  }

  if (!seen_input_bundle || !seen_manifest || !seen_key_provider || !seen_key_id) {
    return false;
  }
  if (options.input_bundle_path.empty() || options.manifest_path.empty() ||
      options.key_provider_path.empty() || options.key_id.empty()) {
    return false;
  }
  if (seen_bridge_token && options.bridge_token_hex.empty()) {
    return false;
  }
  if (seen_report && options.report_path.empty()) {
    return false;
  }

  options_out = std::move(options);
  error_out = LoaderError::ok;
  return true;
}

bool load_and_validate_android_dex_manifest(const std::filesystem::path& manifest_path,
                                            std::string_view expected_key_id,
                                            DexManifestContract& manifest_out,
                                            LoaderError& error_out) noexcept {
  std::string manifest_probe;
  if (!read_text_file(manifest_path, manifest_probe)) {
    error_out = LoaderError::manifest_read_failed;
    return false;
  }

  std::string manifest_error;
  if (!invoke_load_and_validate_manifest_contract(
          manifest_path, expected_key_id, manifest_out, manifest_error)) {
    error_out = LoaderError::manifest_invalid;
    return false;
  }
  error_out = LoaderError::ok;
  return true;
}

bool materialize_bridge_table(const std::vector<std::uint8_t>& payload_plaintext,
                              std::uint64_t expected_record_count,
                              std::vector<std::uint64_t>& token_allowlist_out,
                              std::size_t& bridge_table_size_out,
                              LoaderError& error_out) noexcept {
  token_allowlist_out.clear();
  bridge_table_size_out = 0u;

  if (expected_record_count >
      static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }

  const std::size_t record_count = static_cast<std::size_t>(expected_record_count);
  token_allowlist_out.reserve(record_count);

  std::size_t offset = 0u;
  for (std::size_t i = 0u; i < record_count; ++i) {
    if (offset > payload_plaintext.size()) {
      error_out = LoaderError::bundle_invalid;
      return false;
    }
    const std::size_t fixed_record_bytes = 17u;
    if (fixed_record_bytes > (payload_plaintext.size() - offset)) {
      error_out = LoaderError::bundle_invalid;
      return false;
    }

    const std::uint64_t token_u64_le = read_u64_le(payload_plaintext, offset);
    const std::uint8_t dispatch_kind_u8 = payload_plaintext[offset + 8u];
    const std::uint32_t method_ordinal_u32_le = read_u32_le(payload_plaintext, offset + 9u);
    const std::uint16_t flags_u16_le = read_u16_le(payload_plaintext, offset + 13u);
    const std::uint16_t opaque_metadata_len_u16_le = read_u16_le(payload_plaintext, offset + 15u);
    (void)method_ordinal_u32_le;

    offset += fixed_record_bytes;
    if (opaque_metadata_len_u16_le > (payload_plaintext.size() - offset)) {
      error_out = LoaderError::bundle_invalid;
      return false;
    }
    if (dispatch_kind_u8 != kDispatchKindNativeBridge || flags_u16_le != kBridgeFlagsFixed) {
      error_out = LoaderError::bundle_invalid;
      return false;
    }

    offset += static_cast<std::size_t>(opaque_metadata_len_u16_le);
    token_allowlist_out.push_back(token_u64_le);
  }

  bridge_table_size_out = offset;
  if (token_allowlist_out.size() != record_count) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  error_out = LoaderError::ok;
  return true;
}

bool decrypt_bundle_payload_to_memory(const LoaderOptions& options,
                                      std::uint8_t external_key,
                                      std::vector<std::uint64_t>& bridge_tokens_out,
                                      std::vector<std::uint8_t>& bridge_plain_out,
                                      std::vector<std::uint8_t>& dex_plain_out,
                                      std::uint64_t& bridge_record_count_out,
                                      LoaderError& error_out) noexcept {
  bridge_tokens_out.clear();
  bridge_plain_out.clear();
  dex_plain_out.clear();
  bridge_record_count_out = 0u;

  DexBundleHeaderV3 header{};
  std::string bundle_key_id;
  std::vector<std::uint8_t> encrypted_payload;
  if (!load_bundle_for_probe(
          options.input_bundle_path, header, bundle_key_id, encrypted_payload, error_out)) {
    return false;
  }

  bridge_record_count_out = header_bridge_record_count(header);
  std::vector<std::uint8_t> combined_plaintext = encrypted_payload;
  encrypt_in_place(combined_plaintext, external_key);

  std::size_t bridge_table_size = 0u;
  if (!materialize_bridge_table(combined_plaintext,
                                bridge_record_count_out,
                                bridge_tokens_out,
                                bridge_table_size,
                                error_out)) {
    secure_zero(combined_plaintext);
    combined_plaintext.clear();
    return false;
  }
  if (bridge_table_size > combined_plaintext.size() ||
      bridge_table_size > encrypted_payload.size()) {
    error_out = LoaderError::bundle_invalid;
    secure_zero(combined_plaintext);
    combined_plaintext.clear();
    return false;
  }

  bridge_plain_out.assign(
      combined_plaintext.begin(),
      combined_plaintext.begin() + static_cast<std::ptrdiff_t>(bridge_table_size));

  const std::size_t dex_cipher_offset = bridge_table_size;
  std::vector<std::uint8_t> dex_candidate_reset(
      encrypted_payload.begin() + static_cast<std::ptrdiff_t>(dex_cipher_offset),
      encrypted_payload.end());
  std::vector<std::uint8_t> dex_candidate_continued(
      encrypted_payload.begin() + static_cast<std::ptrdiff_t>(dex_cipher_offset),
      encrypted_payload.end());

  encrypt_in_place(dex_candidate_reset, external_key);
  for (std::size_t i = 0u; i < dex_candidate_continued.size(); ++i) {
    dex_candidate_continued[i] = static_cast<std::uint8_t>(
        dex_candidate_continued[i] ^
        stream_mask(external_key, dex_cipher_offset + i));
  }

  const bool reset_valid = has_valid_dex_magic_and_version(dex_candidate_reset);
  const bool continued_valid = has_valid_dex_magic_and_version(dex_candidate_continued);

  if (reset_valid && !continued_valid) {
    dex_plain_out = std::move(dex_candidate_reset);
  } else if (!reset_valid && continued_valid) {
    dex_plain_out = std::move(dex_candidate_continued);
    secure_zero(dex_candidate_reset);
    dex_candidate_reset.clear();
  } else {
    dex_plain_out = std::move(dex_candidate_reset);
    secure_zero(dex_candidate_continued);
    dex_candidate_continued.clear();
  }

  secure_zero(combined_plaintext);
  combined_plaintext.clear();
  error_out = LoaderError::ok;
  return true;
}

bool parse_minimal_dex_tables(const std::vector<std::uint8_t>& dex_payload,
                              LoaderError& error_out) noexcept {
  if (!has_valid_dex_magic_and_version(dex_payload)) {
    error_out = LoaderError::bundle_invalid;
    return false;
  }
  error_out = LoaderError::ok;
  return true;
}

bool evaluate_guardrail_probe(std::string& guardrail_status_out) noexcept {
  static constexpr const char* kGuardrailVars[] = {
      "EIPPF_SIMULATE_JDWP",
      "EIPPF_SIMULATE_FRIDA",
      "EIPPF_SIMULATE_XPOSED",
      "EIPPF_SIMULATE_CLASSLOADER_DUMP",
      "EIPPF_SIMULATE_DEX_DUMP",
  };

  for (const char* var_name : kGuardrailVars) {
    const char* value = std::getenv(var_name);
    if (value != nullptr && std::string_view(value) == "1") {
      guardrail_status_out = "blocked";
      return false;
    }
  }

  guardrail_status_out = "pass";
  return true;
}

bool write_loader_report(const LoaderOptions& options,
                         const DexManifestContract& manifest,
                         std::uint64_t bridge_record_count,
                         bool bridge_token_checked,
                         std::string_view bridge_token_status,
                         std::string_view guardrail_status,
                         std::string_view provider_endpoint_kind,
                         std::string_view result,
                         LoaderError& error_out) noexcept {
  if (options.report_path.empty()) {
    error_out = LoaderError::ok;
    return true;
  }

  std::error_code mk_ec;
  const std::filesystem::path parent = options.report_path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, mk_ec);
    if (mk_ec) {
      error_out = LoaderError::report_write_failed;
      return false;
    }
  }

  std::ofstream report(options.report_path, std::ios::binary | std::ios::trunc);
  if (!report.is_open()) {
    error_out = LoaderError::report_write_failed;
    return false;
  }

  report << "{\n";
  report << "  \"schema_version\":1,\n";
  report << "  \"kind\":\"" << json_escape(kReportKind) << "\",\n";
  report << "  \"target_kind\":\"" << json_escape(manifest_target_kind(manifest)) << "\",\n";
  report << "  \"backend_kind\":\"" << json_escape(manifest_backend_kind(manifest)) << "\",\n";
  report << "  \"runtime_lane\":\"" << json_escape(manifest_runtime_lane(manifest)) << "\",\n";
  report << "  \"loader_format_version\":" << manifest_loader_format_version(manifest) << ",\n";
  report << "  \"bridge_record_count\":" << bridge_record_count << ",\n";
  report << "  \"bridge_token_checked\":" << (bridge_token_checked ? "true" : "false") << ",\n";
  report << "  \"bridge_token_status\":\"" << json_escape(bridge_token_status) << "\",\n";
  report << "  \"guardrail_status\":\"" << json_escape(guardrail_status) << "\",\n";
  report << "  \"provider_endpoint_kind\":\"" << json_escape(provider_endpoint_kind) << "\",\n";
  report << "  \"result\":\"" << json_escape(result) << "\"\n";
  report << "}\n";

  if (!report.good()) {
    error_out = LoaderError::report_write_failed;
    return false;
  }
  error_out = LoaderError::ok;
  return true;
}

int run_loader_session(const LoaderOptions& options,
                       LoaderError& error_out) noexcept {
  error_out = LoaderError::ok;

  DexManifestContract manifest{};
  std::vector<std::uint8_t> bridge_plaintext;
  std::vector<std::uint8_t> dex_plaintext;
  std::vector<std::uint64_t> bridge_tokens;

  std::string provider_endpoint_kind_value = "unknown";
  std::string guardrail_status = "not_evaluated";
  bool bridge_token_checked = !options.bridge_token_hex.empty();
  std::string bridge_token_status = bridge_token_checked ? "pending" : "not_checked";
  std::uint64_t bridge_record_count = 0u;

  auto wipe_plain_buffers = [&]() noexcept {
    secure_zero(bridge_plaintext);
    bridge_plaintext.clear();
    secure_zero(dex_plaintext);
    dex_plaintext.clear();
  };

  auto fail_closed = [&](LoaderError failure_error) noexcept -> int {
    error_out = failure_error;
    LoaderError report_error = LoaderError::ok;
    if (!write_loader_report(options,
                             manifest,
                             bridge_record_count,
                             bridge_token_checked,
                             bridge_token_status,
                             guardrail_status,
                             provider_endpoint_kind_value,
                             loader_error_message(failure_error),
                             report_error)) {
      error_out = report_error;
    }
    wipe_plain_buffers();
    return loader_error_to_exit_code(error_out);
  };

  // 1) Read/validate manifest.
  if (!load_and_validate_android_dex_manifest(
          options.manifest_path, options.key_id, manifest, error_out)) {
    return fail_closed(error_out);
  }

  // 2) Read bundle header.
  DexBundleHeaderV3 probe_header{};
  std::string bundle_key_id;
  std::vector<std::uint8_t> encrypted_payload_probe;
  if (!load_bundle_for_probe(
          options.input_bundle_path,
          probe_header,
          bundle_key_id,
          encrypted_payload_probe,
          error_out)) {
    return fail_closed(error_out);
  }

  // 3) Validate manifest/header/key-id coherence.
  if (!validate_manifest_header_and_key(
          manifest, probe_header, options.key_id, bundle_key_id, error_out)) {
    return fail_closed(error_out);
  }
  bridge_record_count = header_bridge_record_count(probe_header);
  provider_endpoint_kind_value = manifest_provider_endpoint_kind(manifest);

  // 4) Resolve external key provider.
  std::uint8_t external_key = 0u;
  bool endpoint_rejected = false;
  ProviderEndpointKind endpoint_kind = ProviderEndpointKind::kInvalid;
  if (!invoke_resolve_external_key_from_endpoint(
          options.key_provider_path,
          options.key_id,
          external_key,
          endpoint_kind,
          endpoint_rejected)) {
    (void)endpoint_rejected;
    return fail_closed(LoaderError::provider_failed);
  }
  if (!endpoint_kind_allowed(endpoint_kind)) {
    return fail_closed(LoaderError::provider_failed);
  }
  provider_endpoint_kind_value = endpoint_kind_to_string(endpoint_kind);

  // 5) Guardrail preflight.
  if (!evaluate_guardrail_probe(guardrail_status)) {
    bridge_token_status = bridge_token_checked ? "not_checked" : "not_checked";
    return fail_closed(LoaderError::guardrail_blocked);
  }

  // 6) Decrypt bridge table and dex payload in memory.
  if (!decrypt_bundle_payload_to_memory(options,
                                        external_key,
                                        bridge_tokens,
                                        bridge_plaintext,
                                        dex_plaintext,
                                        bridge_record_count,
                                        error_out)) {
    return fail_closed(error_out);
  }

  // 7) Validate dex magic/version.
  if (!parse_minimal_dex_tables(dex_plaintext, error_out)) {
    return fail_closed(error_out);
  }

  // 8) Optional bridge token allowlist check.
  if (bridge_token_checked) {
    std::uint64_t requested_token = 0u;
    if (!parse_bridge_token_hex(options.bridge_token_hex, requested_token)) {
      bridge_token_status = "invalid_format";
      return fail_closed(LoaderError::invalid_cli);
    }
    bool token_found = false;
    for (std::uint64_t token : bridge_tokens) {
      if (token == requested_token) {
        token_found = true;
        break;
      }
    }
    if (!token_found) {
      bridge_token_status = "missing";
      return fail_closed(LoaderError::bridge_token_missing);
    }
    bridge_token_status = "matched";
  } else {
    bridge_token_status = "not_checked";
  }

  // 9) Write report.
  if (!write_loader_report(options,
                           manifest,
                           bridge_record_count,
                           bridge_token_checked,
                           bridge_token_status,
                           guardrail_status,
                           provider_endpoint_kind_value,
                           "success",
                           error_out)) {
    return fail_closed(LoaderError::report_write_failed);
  }

  // 10) Success stdout contract.
  std::cout << "token_count=" << bridge_record_count << '\n';
  std::cout << "gate_status=" << guardrail_status << '\n';
  if (!options.report_path.empty()) {
    std::cout << "report_path=" << options.report_path.string() << '\n';
  }

  wipe_plain_buffers();
  error_out = LoaderError::ok;
  return 0;
}

const char* loader_error_message(LoaderError error) noexcept {
  switch (error) {
    case LoaderError::ok:
      return "ok";
    case LoaderError::invalid_cli:
      return "invalid_cli";
    case LoaderError::manifest_read_failed:
      return "manifest_read_failed";
    case LoaderError::manifest_invalid:
      return "manifest_invalid";
    case LoaderError::bundle_read_failed:
      return "bundle_read_failed";
    case LoaderError::bundle_invalid:
      return "bundle_invalid";
    case LoaderError::provider_failed:
      return "provider_failed";
    case LoaderError::guardrail_blocked:
      return "guardrail_blocked";
    case LoaderError::bridge_token_missing:
      return "bridge_token_missing";
    case LoaderError::report_write_failed:
      return "report_write_failed";
  }
  return "unknown";
}

}  // namespace eippf::dex_toolchain

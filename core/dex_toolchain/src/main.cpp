#include "dex_toolchain/bundle_format.hpp"
#include "dex_toolchain/external_key_provider.hpp"
#include "dex_toolchain/manifest_contract.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace eippf::dex_toolchain {
namespace {

struct Options final {
  std::filesystem::path input_path;
  std::filesystem::path output_bundle_path;
  std::filesystem::path manifest_path;
  std::filesystem::path key_provider_path;
  std::string key_id;
};

[[nodiscard]] bool starts_with(std::string_view value, std::string_view prefix) noexcept {
  return value.size() >= prefix.size() && value.substr(0u, prefix.size()) == prefix;
}

void print_usage(const char* argv0) {
  std::cerr << "Usage: " << argv0
            << " --input=<classes.dex> --output-bundle=<path> --manifest=<path>"
            << " --key-provider=<path> --key-id=<id>\n";
}

[[nodiscard]] bool parse_options(int argc, char** argv, Options& options_out) {
  if (argc < 2) {
    return false;
  }

  Options options{};
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--help" || arg == "-h") {
      return false;
    }
    if (starts_with(arg, "--input=")) {
      options.input_path = std::filesystem::path(std::string(arg.substr(8u)));
      continue;
    }
    if (starts_with(arg, "--output-bundle=")) {
      options.output_bundle_path = std::filesystem::path(std::string(arg.substr(16u)));
      continue;
    }
    if (starts_with(arg, "--manifest=")) {
      options.manifest_path = std::filesystem::path(std::string(arg.substr(11u)));
      continue;
    }
    if (starts_with(arg, "--key-provider=")) {
      options.key_provider_path = std::filesystem::path(std::string(arg.substr(15u)));
      continue;
    }
    if (starts_with(arg, "--key-id=")) {
      options.key_id = std::string(arg.substr(9u));
      continue;
    }
    return false;
  }

  if (options.input_path.empty() || options.output_bundle_path.empty() || options.manifest_path.empty() ||
      options.key_provider_path.empty() || options.key_id.empty()) {
    return false;
  }
  options_out = std::move(options);
  return true;
}

[[nodiscard]] bool read_binary_file(const std::filesystem::path& path,
                                    std::vector<std::uint8_t>& data_out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }

  input.seekg(0, std::ios::end);
  const std::streamoff end_pos = input.tellg();
  if (end_pos < 0) {
    return false;
  }
  input.seekg(0, std::ios::beg);
  data_out.resize(static_cast<std::size_t>(end_pos));
  if (data_out.empty()) {
    return true;
  }
  input.read(reinterpret_cast<char*>(data_out.data()), static_cast<std::streamsize>(data_out.size()));
  return input.good() || input.eof();
}

[[nodiscard]] bool write_binary_file(const std::filesystem::path& path,
                                     const std::vector<std::uint8_t>& data) {
  std::error_code ec;
  const std::filesystem::path parent = path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return false;
    }
  }
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }
  if (!data.empty()) {
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  return output.good();
}

[[nodiscard]] bool write_text_file(const std::filesystem::path& path, std::string_view text) {
  std::error_code ec;
  const std::filesystem::path parent = path.parent_path();
  if (!parent.empty()) {
    std::filesystem::create_directories(parent, ec);
    if (ec) {
      return false;
    }
  }
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }
  output << text;
  return output.good();
}

[[nodiscard]] bool is_valid_dex_magic(const std::vector<std::uint8_t>& dex_data,
                                      std::array<char, 3u>& version_out) noexcept {
  if (dex_data.size() < 8u) {
    return false;
  }
  if (dex_data[0] != static_cast<std::uint8_t>('d') ||
      dex_data[1] != static_cast<std::uint8_t>('e') ||
      dex_data[2] != static_cast<std::uint8_t>('x') ||
      dex_data[3] != static_cast<std::uint8_t>('\n')) {
    return false;
  }
  if (dex_data[7] != 0u) {
    return false;
  }
  for (std::size_t i = 0; i < version_out.size(); ++i) {
    const unsigned char ch = dex_data[4u + i];
    if (std::isdigit(ch) == 0) {
      return false;
    }
    version_out[i] = static_cast<char>(ch);
  }
  return true;
}

void secure_zero(std::vector<std::uint8_t>& data) noexcept {
  volatile std::uint8_t* p = data.data();
  for (std::size_t i = 0; i < data.size(); ++i) {
    p[i] = 0u;
  }
}

void append_u16_le(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (std::size_t i = 0; i < 8u; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(8u * i)) & 0xFFu));
  }
}

[[nodiscard]] bool write_outputs_atomically(const std::filesystem::path& bundle_path,
                                            const std::vector<std::uint8_t>& bundle_bytes,
                                            const std::filesystem::path& manifest_path,
                                            std::string_view manifest_text) {
  const std::filesystem::path bundle_tmp = bundle_path.string() + ".tmp";
  const std::filesystem::path manifest_tmp = manifest_path.string() + ".tmp";

  auto cleanup = [&]() noexcept {
    std::error_code ignored;
    std::filesystem::remove(bundle_tmp, ignored);
    std::filesystem::remove(manifest_tmp, ignored);
  };

  if (!write_binary_file(bundle_tmp, bundle_bytes) || !write_text_file(manifest_tmp, manifest_text)) {
    cleanup();
    return false;
  }

  std::error_code ec;
  std::filesystem::remove(bundle_path, ec);
  ec.clear();
  std::filesystem::remove(manifest_path, ec);
  ec.clear();

  std::filesystem::rename(bundle_tmp, bundle_path, ec);
  if (ec) {
    cleanup();
    return false;
  }

  ec.clear();
  std::filesystem::rename(manifest_tmp, manifest_path, ec);
  if (ec) {
    std::error_code ignored;
    std::filesystem::remove(bundle_path, ignored);
    cleanup();
    return false;
  }
  return true;
}

[[nodiscard]] int key_provider_exit_code(KeyProviderError error) noexcept {
  switch (error) {
    case KeyProviderError::kOk:
      return 0;
    case KeyProviderError::kMalformed:
      return 8;
    case KeyProviderError::kProviderRejected:
      return 9;
    case KeyProviderError::kKeyIdMismatch:
      return 10;
    case KeyProviderError::kReadFailed:
    case KeyProviderError::kUnsupportedEndpoint:
    case KeyProviderError::kStaticFileRejected:
    case KeyProviderError::kExecutionFailed:
      return 7;
  }
  return 7;
}

}  // namespace

int tool_main(int argc, char** argv) {
  Options options{};
  if (!parse_options(argc, argv, options)) {
    print_usage(argv[0]);
    return 2;
  }

  std::vector<std::uint8_t> dex_data;
  if (!read_binary_file(options.input_path, dex_data)) {
    std::cerr << "[dex_toolchain] failed to read input dex\n";
    return 3;
  }

  std::array<char, 3u> dex_version_ascii{};
  if (!is_valid_dex_magic(dex_data, dex_version_ascii)) {
    std::cerr << "[dex_toolchain] input is not a valid dex stream\n";
    return 4;
  }

  std::uint8_t external_key = 0u;
  ProviderEndpointKind endpoint_kind = ProviderEndpointKind::kInvalid;
  std::error_code ec;
  const std::filesystem::path workspace_root = std::filesystem::current_path(ec);
  ec.clear();
  const std::filesystem::path temp_root = std::filesystem::temp_directory_path(ec);
  const KeyProviderError key_error = resolve_external_key_from_endpoint(
      options.key_provider_path,
      options.key_id,
      workspace_root,
      temp_root,
      external_key,
      endpoint_kind);
  if (key_error != KeyProviderError::kOk) {
    std::cerr << "[dex_toolchain] external key resolution failed\n";
    return key_provider_exit_code(key_error);
  }

  const std::string token_input =
      options.key_id + "\x1f" + "0" + "\x1f" + "0" + "\x1f" + "eippf.dex.bridge.v1";
  const std::uint64_t token = fnv1a64(token_input);

  std::vector<std::uint8_t> bridge_table;
  bridge_table.reserve(17u);
  append_u64_le(bridge_table, token);
  bridge_table.push_back(1u);
  append_u32_le(bridge_table, 0u);
  append_u16_le(bridge_table, 0u);
  append_u16_le(bridge_table, 0u);

  std::vector<std::uint8_t> encrypted_bridge_table = bridge_table;
  encrypt_in_place(encrypted_bridge_table, external_key);
  secure_zero(bridge_table);

  std::vector<std::uint8_t> encrypted_payload = dex_data;
  encrypt_in_place(encrypted_payload, external_key);
  secure_zero(dex_data);

  if (options.key_id.size() > std::numeric_limits<std::uint16_t>::max() ||
      encrypted_bridge_table.size() > std::numeric_limits<std::uint32_t>::max()) {
    std::cerr << "[dex_toolchain] input exceeds bundle limits\n";
    secure_zero(encrypted_bridge_table);
    secure_zero(encrypted_payload);
    return 8;
  }

  DexBundleHeaderV3 header{};
  header.format_version = 3u;
  header.flags = 0x03u;
  header.dex_version_ascii = dex_version_ascii;
  header.key_material_marker = 0u;
  header.key_id_len = static_cast<std::uint16_t>(options.key_id.size());
  header.bridge_record_count = 1u;
  header.bridge_table_len = static_cast<std::uint32_t>(encrypted_bridge_table.size());
  header.payload_len = static_cast<std::uint64_t>(encrypted_payload.size());

  const std::vector<std::uint8_t> bundle_bytes =
      write_bundle_v3(header, options.key_id, encrypted_bridge_table, encrypted_payload);
  secure_zero(encrypted_bridge_table);
  secure_zero(encrypted_payload);

  DexManifestContract manifest{};
  manifest.key_id = options.key_id;
  manifest.key_provider_endpoint_kind = std::string(provider_endpoint_kind_name(endpoint_kind));
  const std::string manifest_text = build_android_dex_manifest_v2_json(manifest);

  if (!write_outputs_atomically(
          options.output_bundle_path,
          bundle_bytes,
          options.manifest_path,
          manifest_text)) {
    std::cerr << "[dex_toolchain] failed to write output artifacts\n";
    return 9;
  }

  return 0;
}

}  // namespace eippf::dex_toolchain

int main(int argc, char** argv) {
  return eippf::dex_toolchain::tool_main(argc, argv);
}

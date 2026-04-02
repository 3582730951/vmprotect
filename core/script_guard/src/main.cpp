#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kKeyProviderProtocol = "eippf.external_key.v1";

struct Options final {
  std::filesystem::path input_script_path;
  std::filesystem::path output_bundle_path;
  std::filesystem::path manifest_path;
  std::filesystem::path key_provider_path;
  std::string key_id;
};

enum class KeyProviderError : std::uint8_t {
  kOk = 0u,
  kReadFailed = 1u,
  kMalformed = 2u,
  kProviderRejected = 3u,
  kKeyIdMismatch = 4u,
};

[[nodiscard]] bool starts_with(std::string_view value, std::string_view prefix) noexcept {
  return value.size() >= prefix.size() && value.substr(0u, prefix.size()) == prefix;
}

void print_usage(const char* argv0) {
  std::cerr << "Usage: " << argv0
            << " --input-script=<path> --output-bundle=<path> --manifest=<path>"
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
    if (starts_with(arg, "--input-script=")) {
      options.input_script_path = std::filesystem::path(std::string(arg.substr(15u)));
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

  if (options.input_script_path.empty() || options.output_bundle_path.empty() ||
      options.manifest_path.empty() || options.key_provider_path.empty() || options.key_id.empty()) {
    return false;
  }

  options_out = options;
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

[[nodiscard]] bool write_text_file(const std::filesystem::path& path, const std::string& text) {
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

[[nodiscard]] std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 29u) + (index >> 1u) + 0x31u) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

void encrypt_in_place(std::vector<std::uint8_t>& data, std::uint8_t key) noexcept {
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(data[i] ^ stream_mask(key, i));
  }
}

void append_u64_le(std::vector<std::uint8_t>& output, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    output.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(i * 8)) & 0xFFu));
  }
}

void append_u16_le(std::vector<std::uint8_t>& output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  output.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

[[nodiscard]] bool has_shebang(const std::vector<std::uint8_t>& script_data) noexcept {
  return script_data.size() >= 2u && script_data[0] == static_cast<std::uint8_t>('#') &&
         script_data[1] == static_cast<std::uint8_t>('!');
}

[[nodiscard]] std::string build_manifest_json(std::size_t input_size,
                                              std::size_t bundle_size,
                                              bool external_key_required,
                                              bool shebang_present,
                                              std::string_view key_id) {
  std::string json;
  json.reserve(512u);
  json += "{\n";
  json += "  \"schema_version\":1,\n";
  json += "  \"kind\":\"shell_script_bundle\",\n";
  json += "  \"target_kind\":\"shell_ephemeral\",\n";
  json += "  \"backend_kind\":\"shell_launcher\",\n";
  json += "  \"format\":\"eippf.script.bundle.v2\",\n";
  json += "  \"encryption\":\"xor_stream_v1\",\n";
  json += "  \"key_material\":\"external_binding_required\",\n";
  json += "  \"key_provider_protocol\":\"";
  json += kKeyProviderProtocol;
  json += "\",\n";
  json += "  \"key_id\":\"";
  json += std::string(key_id);
  json += "\",\n";
  json += "  \"key_material_embedded\":false,\n";
  json += "  \"input_size_bytes\":";
  json += std::to_string(input_size);
  json += ",\n";
  json += "  \"bundle_size_bytes\":";
  json += std::to_string(bundle_size);
  json += ",\n";
  json += "  \"no_persistent_plaintext_goal\":true,\n";
  json += "  \"external_key_required\":";
  json += external_key_required ? "true" : "false";
  json += ",\n";
  json += "  \"execution_model\":\"ephemeral_decrypt_execute\",\n";
  json += "  \"contains_shebang\":";
  json += shebang_present ? "true" : "false";
  json += ",\n";
  json += "  \"plaintext_output\":false\n";
  json += "}\n";
  return json;
}

void secure_zero(std::vector<std::uint8_t>& data) noexcept {
  for (std::uint8_t& byte : data) {
    byte = 0u;
  }
}

void secure_zero(std::string& text) noexcept {
  for (char& byte : text) {
    byte = '\0';
  }
}

[[nodiscard]] bool read_text_file(const std::filesystem::path& path, std::string& out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  return input.good() || input.eof();
}

[[nodiscard]] std::string trim_ascii(std::string_view text) {
  std::size_t begin = 0u;
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
    ++begin;
  }
  std::size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1u])) != 0) {
    --end;
  }
  return std::string(text.substr(begin, end - begin));
}

[[nodiscard]] bool parse_u8(std::string_view text, std::uint8_t& value_out) noexcept {
  if (text.empty()) {
    return false;
  }
  std::string owned(text);
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(owned.c_str(), &end, 0);
  if (errno != 0 || end == nullptr || *end != '\0' || parsed > 0xFFul) {
    return false;
  }
  value_out = static_cast<std::uint8_t>(parsed);
  return true;
}

[[nodiscard]] KeyProviderError resolve_external_key(const std::filesystem::path& provider_path,
                                                    std::string_view expected_key_id,
                                                    std::uint8_t& key_out) {
  std::string provider_text;
  if (!read_text_file(provider_path, provider_text)) {
    return KeyProviderError::kReadFailed;
  }

  std::string provider_protocol;
  std::string provider_status;
  std::string provider_key_id;
  std::string key_u8_text;
  bool seen_protocol = false;
  bool seen_status = false;
  bool seen_key_id = false;
  bool seen_key_u8 = false;

  const auto finish = [&](KeyProviderError error) noexcept -> KeyProviderError {
    secure_zero(provider_text);
    secure_zero(provider_protocol);
    secure_zero(provider_status);
    secure_zero(provider_key_id);
    secure_zero(key_u8_text);
    return error;
  };

  std::size_t cursor = 0u;
  while (cursor <= provider_text.size()) {
    const std::size_t next = provider_text.find('\n', cursor);
    const std::size_t end = next == std::string::npos ? provider_text.size() : next;
    std::string line = trim_ascii(std::string_view(provider_text).substr(cursor, end - cursor));
    cursor = next == std::string::npos ? provider_text.size() + 1u : next + 1u;

    if (line.empty() || line[0] == '#') {
      continue;
    }

    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) {
      return KeyProviderError::kMalformed;
    }
    const std::string key = trim_ascii(std::string_view(line).substr(0u, eq));
    const std::string value = trim_ascii(std::string_view(line).substr(eq + 1u));
    if (key.empty()) {
      return finish(KeyProviderError::kMalformed);
    }
    if (key == "protocol") {
      if (seen_protocol) {
        return finish(KeyProviderError::kMalformed);
      }
      provider_protocol = value;
      seen_protocol = true;
    } else if (key == "status") {
      if (seen_status) {
        return finish(KeyProviderError::kMalformed);
      }
      provider_status = value;
      seen_status = true;
    } else if (key == "key_id") {
      if (seen_key_id) {
        return finish(KeyProviderError::kMalformed);
      }
      provider_key_id = value;
      seen_key_id = true;
    } else if (key == "key_u8") {
      if (seen_key_u8) {
        return finish(KeyProviderError::kMalformed);
      }
      key_u8_text = value;
      seen_key_u8 = true;
    } else {
      return finish(KeyProviderError::kMalformed);
    }
  }

  if (!seen_protocol || provider_protocol != kKeyProviderProtocol) {
    return finish(KeyProviderError::kMalformed);
  }
  if (!seen_status || !seen_key_id || !seen_key_u8) {
    return finish(KeyProviderError::kMalformed);
  }
  if (provider_status != "ok") {
    return finish(KeyProviderError::kProviderRejected);
  }
  if (provider_key_id != expected_key_id) {
    return finish(KeyProviderError::kKeyIdMismatch);
  }

  std::uint8_t parsed_key = 0u;
  if (!parse_u8(key_u8_text, parsed_key)) {
    return finish(KeyProviderError::kMalformed);
  }
  key_out = parsed_key;
  return finish(KeyProviderError::kOk);
}

}  // namespace

int main(int argc, char** argv) {
  Options options{};
  if (!parse_options(argc, argv, options)) {
    print_usage(argv[0]);
    return 2;
  }

  std::vector<std::uint8_t> script_data;
  if (!read_binary_file(options.input_script_path, script_data)) {
    std::cerr << "[script_guard] failed to read input script: " << options.input_script_path << '\n';
    return 3;
  }
  if (script_data.empty()) {
    std::cerr << "[script_guard] input script is empty\n";
    return 4;
  }

  const bool shebang_present = has_shebang(script_data);
  std::uint8_t external_key = 0u;
  const KeyProviderError key_error =
      resolve_external_key(options.key_provider_path, options.key_id, external_key);
  if (key_error != KeyProviderError::kOk) {
    switch (key_error) {
      case KeyProviderError::kReadFailed:
        std::cerr << "[script_guard] key provider read failed: " << options.key_provider_path << '\n';
        return 7;
      case KeyProviderError::kMalformed:
        std::cerr << "[script_guard] key provider is malformed\n";
        return 8;
      case KeyProviderError::kProviderRejected:
        std::cerr << "[script_guard] key provider reported failure\n";
        return 9;
      case KeyProviderError::kKeyIdMismatch:
        std::cerr << "[script_guard] key id mismatch for external provider\n";
        return 10;
      case KeyProviderError::kOk:
        break;
    }
  }

  std::vector<std::uint8_t> encrypted = script_data;
  encrypt_in_place(encrypted, external_key);
  secure_zero(script_data);

  std::vector<std::uint8_t> bundle;
  bundle.reserve(22u + options.key_id.size() + encrypted.size());
  bundle.push_back(static_cast<std::uint8_t>('E'));
  bundle.push_back(static_cast<std::uint8_t>('S'));
  bundle.push_back(static_cast<std::uint8_t>('H'));
  bundle.push_back(static_cast<std::uint8_t>('B'));
  bundle.push_back(2u);           // format version
  bundle.push_back(0u);           // key material is external, no embedded marker
  bundle.push_back(shebang_present ? 1u : 0u);
  bundle.push_back(0u);  // reserved
  append_u16_le(bundle, static_cast<std::uint16_t>(options.key_id.size()));
  append_u16_le(bundle, 1u);  // key binding schema version
  append_u64_le(bundle, static_cast<std::uint64_t>(encrypted.size()));
  bundle.insert(bundle.end(), options.key_id.begin(), options.key_id.end());
  bundle.insert(bundle.end(), encrypted.begin(), encrypted.end());
  secure_zero(encrypted);

  if (!write_binary_file(options.output_bundle_path, bundle)) {
    std::cerr << "[script_guard] failed to write bundle: " << options.output_bundle_path << '\n';
    return 5;
  }

  const std::string manifest = build_manifest_json(
      script_data.size(), bundle.size(), true, shebang_present, options.key_id);
  if (!write_text_file(options.manifest_path, manifest)) {
    std::cerr << "[script_guard] failed to write manifest: " << options.manifest_path << '\n';
    return 6;
  }

  return 0;
}

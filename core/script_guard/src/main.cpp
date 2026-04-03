#include "script_guard/bundle_format.hpp"
#include "script_guard/external_key_provider.hpp"
#include "script_guard/unsafe_shell_scan.hpp"

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view kWorkspaceRoot = "/workspace";

struct Options final {
  std::filesystem::path input_script_path;
  std::filesystem::path output_bundle_path;
  std::filesystem::path manifest_path;
  std::filesystem::path key_provider_path;
  std::string key_id;
};

[[nodiscard]] bool starts_with(std::string_view value, std::string_view prefix) noexcept {
  return value.size() >= prefix.size() && value.substr(0u, prefix.size()) == prefix;
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
  for (int index = 1; index < argc; ++index) {
    const std::string_view arg(argv[index]);
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
  if (!data_out.empty()) {
    input.read(reinterpret_cast<char*>(data_out.data()), static_cast<std::streamsize>(data_out.size()));
  }
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

void secure_zero(std::vector<std::uint8_t>& data) noexcept {
  for (std::uint8_t& byte : data) {
    byte = 0u;
  }
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

[[nodiscard]] std::string basename_of(std::string_view path) {
  if (path.empty()) {
    return {};
  }
  const std::size_t slash = path.find_last_of('/');
  if (slash == std::string_view::npos) {
    return std::string(path);
  }
  return std::string(path.substr(slash + 1u));
}

[[nodiscard]] bool detect_interpreter_tag_from_shebang(const std::vector<std::uint8_t>& script_data,
                                                       std::string& interpreter_tag_out,
                                                       bool& shebang_present_out) {
  shebang_present_out = script_data.size() >= 2u && script_data[0u] == static_cast<std::uint8_t>('#') &&
                        script_data[1u] == static_cast<std::uint8_t>('!');
  if (!shebang_present_out) {
    interpreter_tag_out = "sh";
    return true;
  }

  std::size_t line_end = 2u;
  while (line_end < script_data.size() && script_data[line_end] != static_cast<std::uint8_t>('\n') &&
         script_data[line_end] != static_cast<std::uint8_t>('\r')) {
    ++line_end;
  }

  const std::string shebang_line(
      reinterpret_cast<const char*>(script_data.data() + 2u),
      reinterpret_cast<const char*>(script_data.data() + line_end));
  const std::string trimmed = trim_ascii(shebang_line);
  if (trimmed.empty()) {
    return false;
  }

  std::string token = trimmed;
  if (starts_with(trimmed, "/usr/bin/env ")) {
    const std::string env_tail = trim_ascii(std::string_view(trimmed).substr(13u));
    const std::size_t space = env_tail.find_first_of(" \t");
    token = space == std::string::npos ? env_tail : env_tail.substr(0u, space);
  } else {
    const std::size_t space = trimmed.find_first_of(" \t");
    token = space == std::string::npos ? trimmed : trimmed.substr(0u, space);
  }

  const std::string base = basename_of(token);
  if (base == "sh" || base == "bash" || base == "dash") {
    interpreter_tag_out = base;
    return true;
  }
  return false;
}

[[nodiscard]] std::string build_shell_manifest_v2_json(std::size_t input_size,
                                                        std::size_t bundle_size,
                                                        std::string_view key_id,
                                                        std::string_view provider_endpoint_kind,
                                                        std::string_view interpreter_tag,
                                                        bool shebang_present) {
  std::string json;
  json.reserve(1024u);
  json += "{\n";
  json += "  \"schema_version\":2,\n";
  json += "  \"kind\":\"shell_script_bundle\",\n";
  json += "  \"target_kind\":\"shell_ephemeral\",\n";
  json += "  \"backend_kind\":\"shell_launcher\",\n";
  json += "  \"runtime_lane\":\"shell_launcher\",\n";
  json += "  \"mutation_profile\":\"shell_bundle\",\n";
  json += "  \"signature_policy\":\"required_verifier\",\n";
  json += "  \"artifact_kind\":\"shell_bundle\",\n";
  json += "  \"allow_jit\":false,\n";
  json += "  \"allow_runtime_executable_pages\":false,\n";
  json += "  \"allow_persistent_plaintext\":false,\n";
  json += "  \"require_fail_closed\":true,\n";
  json += "  \"plaintext_ttl_ms\":0,\n";
  json += "  \"loader_format_version\":3,\n";
  json += "  \"key_provider_protocol\":\"eippf.external_key.v1\",\n";
  json += "  \"key_provider_endpoint_kind\":\"";
  json += std::string(provider_endpoint_kind);
  json += "\",\n";
  json += "  \"key_provider_static_file\":false,\n";
  json += "  \"key_id\":\"";
  json += std::string(key_id);
  json += "\",\n";
  json += "  \"key_material_embedded\":false,\n";
  json += "  \"execution_model\":\"pipe_stdin_exec\",\n";
  json += "  \"launcher_host\":\"linux_posix\",\n";
  json += "  \"interpreter_tag\":\"";
  json += std::string(interpreter_tag);
  json += "\",\n";
  json += "  \"contains_shebang\":";
  json += shebang_present ? "true" : "false";
  json += ",\n";
  json += "  \"trace_env_scrubbed\":true,\n";
  json += "  \"source_policy\":\"self_contained_only\",\n";
  json += "  \"unsafe_shell_features\":[],\n";
  json += "  \"plaintext_output\":false,\n";
  json += "  \"no_persistent_plaintext_goal\":true,\n";
  json += "  \"input_size_bytes\":";
  json += std::to_string(input_size);
  json += ",\n";
  json += "  \"bundle_size_bytes\":";
  json += std::to_string(bundle_size);
  json += "\n";
  json += "}\n";
  return json;
}

[[nodiscard]] bool reject_if_unsafe_shell_features_present(const std::vector<std::uint8_t>& script_data) {
  const std::string script_text(reinterpret_cast<const char*>(script_data.data()), script_data.size());
  const std::vector<std::string> unsafe = eippf::script_guard::scan_unsafe_shell_features(script_text);
  if (unsafe.empty()) {
    return false;
  }
  std::cerr << "[script_guard] rejected unsafe shell features:";
  for (const std::string& feature : unsafe) {
    std::cerr << ' ' << feature;
  }
  std::cerr << '\n';
  return true;
}

[[nodiscard]] int provider_error_to_exit_code(eippf::script_guard::KeyProviderError error) noexcept {
  using eippf::script_guard::KeyProviderError;
  switch (error) {
    case KeyProviderError::kReadFailed:
      return 7;
    case KeyProviderError::kMalformed:
      return 8;
    case KeyProviderError::kProviderRejected:
      return 9;
    case KeyProviderError::kKeyIdMismatch:
      return 10;
    case KeyProviderError::kUnsupportedEndpoint:
      return 11;
    case KeyProviderError::kStaticFileRejected:
      return 12;
    case KeyProviderError::kExecutionFailed:
      return 13;
    case KeyProviderError::kOk:
      break;
  }
  return 14;
}

void print_provider_error(eippf::script_guard::KeyProviderError error,
                          const std::filesystem::path& provider_path) {
  using eippf::script_guard::KeyProviderError;
  switch (error) {
    case KeyProviderError::kReadFailed:
      std::cerr << "[script_guard] key provider read failed: " << provider_path << '\n';
      return;
    case KeyProviderError::kMalformed:
      std::cerr << "[script_guard] key provider response is malformed\n";
      return;
    case KeyProviderError::kProviderRejected:
      std::cerr << "[script_guard] key provider reported failure\n";
      return;
    case KeyProviderError::kKeyIdMismatch:
      std::cerr << "[script_guard] key id mismatch for external provider\n";
      return;
    case KeyProviderError::kUnsupportedEndpoint:
      std::cerr << "[script_guard] provider endpoint kind is unsupported\n";
      return;
    case KeyProviderError::kStaticFileRejected:
      std::cerr << "[script_guard] static key file providers are forbidden\n";
      return;
    case KeyProviderError::kExecutionFailed:
      std::cerr << "[script_guard] executable key provider failed\n";
      return;
    case KeyProviderError::kOk:
      return;
  }
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

  std::string interpreter_tag;
  bool shebang_present = false;
  if (!detect_interpreter_tag_from_shebang(script_data, interpreter_tag, shebang_present)) {
    std::cerr << "[script_guard] unsupported shebang interpreter; only sh|bash|dash are allowed\n";
    return 15;
  }

  if (reject_if_unsafe_shell_features_present(script_data)) {
    return 16;
  }

  std::uint8_t external_key = 0u;
  eippf::script_guard::ProviderEndpointKind endpoint_kind =
      eippf::script_guard::ProviderEndpointKind::kInvalid;
  const eippf::script_guard::KeyProviderError provider_error =
      eippf::script_guard::resolve_external_key_from_endpoint(
          options.key_provider_path,
          options.key_id,
          std::filesystem::path(kWorkspaceRoot),
          options.input_script_path.parent_path(),
          external_key,
          endpoint_kind);
  if (provider_error != eippf::script_guard::KeyProviderError::kOk) {
    print_provider_error(provider_error, options.key_provider_path);
    return provider_error_to_exit_code(provider_error);
  }

  std::vector<std::uint8_t> encrypted_payload = script_data;
  encrypt_in_place(encrypted_payload, external_key);
  const std::size_t input_size = script_data.size();
  secure_zero(script_data);

  std::vector<std::uint8_t> bundle;
  std::string bundle_error;
  if (!eippf::script_guard::write_bundle_v3(
          options.key_id, interpreter_tag, shebang_present, encrypted_payload, bundle, bundle_error)) {
    std::cerr << "[script_guard] failed to build bundle: " << bundle_error << '\n';
    secure_zero(encrypted_payload);
    return 17;
  }
  secure_zero(encrypted_payload);

  eippf::script_guard::BundleHeader header{};
  std::string header_error;
  if (!eippf::script_guard::read_bundle_header(bundle, header, header_error)) {
    std::cerr << "[script_guard] internal bundle verification failed: " << header_error << '\n';
    return 18;
  }

  const std::string manifest = build_shell_manifest_v2_json(
      input_size,
      bundle.size(),
      options.key_id,
      eippf::script_guard::provider_endpoint_kind_name(endpoint_kind),
      header.interpreter_tag,
      shebang_present);

  if (!write_binary_file(options.output_bundle_path, bundle)) {
    std::cerr << "[script_guard] failed to write bundle: " << options.output_bundle_path << '\n';
    return 5;
  }
  if (!write_text_file(options.manifest_path, manifest)) {
    std::cerr << "[script_guard] failed to write manifest: " << options.manifest_path << '\n';
    return 6;
  }

  return 0;
}

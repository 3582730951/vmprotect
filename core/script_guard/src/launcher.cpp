#include "script_guard/launcher.hpp"

#include "script_guard/bundle_format.hpp"
#include "script_guard/external_key_provider.hpp"
#include "script_guard/unsafe_shell_scan.hpp"

#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace eippf::script_guard {
namespace {

constexpr std::string_view kExecutionModelPipeStdinExec = "pipe_stdin_exec";
constexpr std::uint64_t kManifestSchemaVersion = 2u;
constexpr std::string_view kManifestKindShellScriptBundle = "shell_script_bundle";
constexpr std::string_view kManifestArtifactKindShellBundle = "shell_bundle";
constexpr std::uint64_t kManifestPlaintextTtlMs = 0u;
constexpr std::string_view kManifestKeyProviderProtocolV1 = "eippf.external_key.v1";
constexpr std::string_view kManifestLauncherHostLinuxPosix = "linux_posix";

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

[[nodiscard]] bool read_text_file(const std::filesystem::path& path, std::string& out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  return input.good() || input.eof();
}

[[nodiscard]] bool read_binary_file(const std::filesystem::path& path,
                                    std::vector<std::uint8_t>& out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  input.seekg(0, std::ios::end);
  const std::streamoff size = input.tellg();
  if (size < 0) {
    return false;
  }
  input.seekg(0, std::ios::beg);
  out.resize(static_cast<std::size_t>(size));
  if (out.empty()) {
    return true;
  }
  input.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  return input.good() || input.eof();
}

void secure_zero(std::vector<std::uint8_t>& data) noexcept {
  volatile std::uint8_t* p = data.data();
  for (std::size_t i = 0; i < data.size(); ++i) {
    p[i] = 0u;
  }
}

[[nodiscard]] bool parse_string_field(std::string_view json,
                                      std::string_view key,
                                      std::string& out) {
  const std::string needle = "\"" + std::string(key) + "\"";
  const std::size_t key_pos = json.find(needle);
  if (key_pos == std::string_view::npos) {
    return false;
  }
  const std::size_t colon_pos = json.find(':', key_pos + needle.size());
  if (colon_pos == std::string_view::npos) {
    return false;
  }
  std::size_t value_start = colon_pos + 1u;
  while (value_start < json.size() &&
         std::isspace(static_cast<unsigned char>(json[value_start])) != 0) {
    ++value_start;
  }
  if (value_start >= json.size() || json[value_start] != '"') {
    return false;
  }
  ++value_start;
  const std::size_t value_end = json.find('"', value_start);
  if (value_end == std::string_view::npos) {
    return false;
  }
  out = std::string(json.substr(value_start, value_end - value_start));
  return true;
}

[[nodiscard]] bool parse_bool_field(std::string_view json,
                                    std::string_view key,
                                    bool& out) {
  const std::string needle = "\"" + std::string(key) + "\"";
  const std::size_t key_pos = json.find(needle);
  if (key_pos == std::string_view::npos) {
    return false;
  }
  const std::size_t colon_pos = json.find(':', key_pos + needle.size());
  if (colon_pos == std::string_view::npos) {
    return false;
  }
  std::size_t value_start = colon_pos + 1u;
  while (value_start < json.size() &&
         std::isspace(static_cast<unsigned char>(json[value_start])) != 0) {
    ++value_start;
  }
  if (starts_with(json.substr(value_start), "true")) {
    out = true;
    return true;
  }
  if (starts_with(json.substr(value_start), "false")) {
    out = false;
    return true;
  }
  return false;
}

[[nodiscard]] bool parse_uint_field(std::string_view json,
                                    std::string_view key,
                                    std::uint64_t& out) {
  const std::string needle = "\"" + std::string(key) + "\"";
  const std::size_t key_pos = json.find(needle);
  if (key_pos == std::string_view::npos) {
    return false;
  }
  const std::size_t colon_pos = json.find(':', key_pos + needle.size());
  if (colon_pos == std::string_view::npos) {
    return false;
  }
  std::size_t value_start = colon_pos + 1u;
  while (value_start < json.size() &&
         std::isspace(static_cast<unsigned char>(json[value_start])) != 0) {
    ++value_start;
  }
  if (value_start >= json.size() ||
      std::isdigit(static_cast<unsigned char>(json[value_start])) == 0) {
    return false;
  }

  std::uint64_t value = 0u;
  while (value_start < json.size() &&
         std::isdigit(static_cast<unsigned char>(json[value_start])) != 0) {
    const std::uint64_t digit = static_cast<std::uint64_t>(json[value_start] - '0');
    if (value > ((std::numeric_limits<std::uint64_t>::max() - digit) / 10u)) {
      return false;
    }
    value = (value * 10u) + digit;
    ++value_start;
  }

  if (value_start < json.size()) {
    const char tail = json[value_start];
    if (tail != ',' && tail != '}' &&
        std::isspace(static_cast<unsigned char>(tail)) == 0) {
      return false;
    }
  }

  out = value;
  return true;
}

[[nodiscard]] bool parse_explicit_empty_array_field(std::string_view json,
                                                    std::string_view key,
                                                    std::vector<std::string>& out) {
  const std::string needle = "\"" + std::string(key) + "\"";
  const std::size_t key_pos = json.find(needle);
  if (key_pos == std::string_view::npos) {
    return false;
  }
  const std::size_t colon_pos = json.find(':', key_pos + needle.size());
  if (colon_pos == std::string_view::npos) {
    return false;
  }
  std::size_t value_start = colon_pos + 1u;
  while (value_start < json.size() &&
         std::isspace(static_cast<unsigned char>(json[value_start])) != 0) {
    ++value_start;
  }
  if (value_start >= json.size() || json[value_start] != '[') {
    return false;
  }
  ++value_start;
  while (value_start < json.size() &&
         std::isspace(static_cast<unsigned char>(json[value_start])) != 0) {
    ++value_start;
  }
  if (value_start >= json.size() || json[value_start] != ']') {
    return false;
  }
  ++value_start;
  if (value_start < json.size()) {
    const char tail = json[value_start];
    if (tail != ',' && tail != '}' &&
        std::isspace(static_cast<unsigned char>(tail)) == 0) {
      return false;
    }
  }
  out.clear();
  return true;
}

[[nodiscard]] bool is_allowed_interpreter(std::string_view tag) noexcept {
  return tag == "sh" || tag == "bash" || tag == "dash";
}

[[nodiscard]] const char* interpreter_path_for_tag(std::string_view tag) noexcept {
  if (tag == "sh") {
    return "/bin/sh";
  }
  if (tag == "bash") {
    return "/bin/bash";
  }
  if (tag == "dash") {
    return "/bin/dash";
  }
  return nullptr;
}

[[nodiscard]] std::string endpoint_kind_to_string(ProviderEndpointKind kind) {
  return std::string(provider_endpoint_kind_name(kind));
}

[[nodiscard]] bool endpoint_kind_allowed(ProviderEndpointKind kind) noexcept {
  return kind == ProviderEndpointKind::kExecutableAdapter || kind == ProviderEndpointKind::kFifo ||
         kind == ProviderEndpointKind::kUnixSocket;
}

[[nodiscard]] std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 29u) + (index >> 1u) + 0x31u) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

void decrypt_in_place(std::vector<std::uint8_t>& data, std::uint8_t key) noexcept {
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(data[i] ^ stream_mask(key, i));
  }
}

[[nodiscard]] bool has_runtime_unsafe_shell_features(
    const std::vector<std::uint8_t>& plaintext_script) {
  if (plaintext_script.empty()) {
    return false;
  }
  const std::string script_text(reinterpret_cast<const char*>(plaintext_script.data()),
                                plaintext_script.size());
  return !scan_unsafe_shell_features(script_text).empty();
}

[[nodiscard]] int launcher_error_to_exit_code(LauncherError error) noexcept {
  switch (error) {
    case LauncherError::kOk:
      return 0;
    case LauncherError::kInvalidCli:
      return 2;
    case LauncherError::kManifestReadFailed:
      return 3;
    case LauncherError::kManifestInvalid:
      return 4;
    case LauncherError::kBundleReadFailed:
      return 5;
    case LauncherError::kBundleInvalid:
      return 6;
    case LauncherError::kKeyProviderFailed:
      return 7;
    case LauncherError::kKeyProviderEndpointRejected:
      return 8;
    case LauncherError::kUnsupportedInterpreter:
      return 9;
    case LauncherError::kPipeFailed:
      return 10;
    case LauncherError::kForkFailed:
      return 11;
    case LauncherError::kWritePipeFailed:
      return 12;
    case LauncherError::kWaitFailed:
      return 13;
    case LauncherError::kEnvSanitizeFailed:
      return 14;
    case LauncherError::kExecFailed:
      return 15;
  }
  return 1;
}

}  // namespace

bool parse_launcher_options(int argc, char** argv, LauncherOptions& options_out) noexcept {
  if (argc < 2) {
    return false;
  }

  LauncherOptions options{};
  bool parsing_flags = true;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (parsing_flags && arg == "--") {
      parsing_flags = false;
      continue;
    }
    if (!parsing_flags) {
      options.script_args.emplace_back(argv[i]);
      continue;
    }
    if (arg == "--help" || arg == "-h") {
      return false;
    }
    if (starts_with(arg, "--input-bundle=")) {
      options.input_bundle_path = std::filesystem::path(std::string(arg.substr(15u)));
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

  if (options.input_bundle_path.empty() || options.manifest_path.empty() ||
      options.key_provider_path.empty() || options.key_id.empty()) {
    return false;
  }
  options_out = std::move(options);
  return true;
}

bool load_and_validate_shell_manifest(const std::filesystem::path& manifest_path,
                                      std::string_view expected_key_id,
                                      ManifestContract& manifest_out,
                                      LauncherError& error_out) noexcept {
  std::string manifest_text;
  if (!read_text_file(manifest_path, manifest_text)) {
    error_out = LauncherError::kManifestReadFailed;
    return false;
  }

  ManifestContract contract{};
  if (!parse_uint_field(manifest_text, "schema_version", contract.schema_version) ||
      !parse_string_field(manifest_text, "kind", contract.kind) ||
      !parse_string_field(manifest_text, "target_kind", contract.target_kind) ||
      !parse_string_field(manifest_text, "backend_kind", contract.backend_kind) ||
      !parse_string_field(manifest_text, "runtime_lane", contract.runtime_lane) ||
      !parse_string_field(manifest_text, "mutation_profile", contract.mutation_profile) ||
      !parse_string_field(manifest_text, "signature_policy", contract.signature_policy) ||
      !parse_string_field(manifest_text, "artifact_kind", contract.artifact_kind) ||
      !parse_string_field(manifest_text, "execution_model", contract.execution_model) ||
      !parse_string_field(manifest_text, "interpreter_tag", contract.interpreter_tag) ||
      !parse_string_field(manifest_text, "source_policy", contract.source_policy) ||
      !parse_uint_field(manifest_text, "plaintext_ttl_ms", contract.plaintext_ttl_ms) ||
      !parse_uint_field(manifest_text, "loader_format_version", contract.loader_format_version) ||
      !parse_string_field(manifest_text, "key_provider_protocol",
                          contract.key_provider_protocol) ||
      !parse_string_field(manifest_text, "launcher_host", contract.launcher_host) ||
      !parse_string_field(manifest_text, "key_provider_endpoint_kind",
                          contract.key_provider_endpoint_kind) ||
      !parse_string_field(manifest_text, "key_id", contract.key_id) ||
      !parse_explicit_empty_array_field(manifest_text,
                                        "unsafe_shell_features",
                                        contract.unsafe_shell_features) ||
      !parse_bool_field(manifest_text, "allow_jit", contract.allow_jit) ||
      !parse_bool_field(manifest_text, "allow_runtime_executable_pages",
                        contract.allow_runtime_executable_pages) ||
      !parse_bool_field(manifest_text, "allow_persistent_plaintext",
                        contract.allow_persistent_plaintext) ||
      !parse_bool_field(manifest_text, "require_fail_closed", contract.require_fail_closed) ||
      !parse_bool_field(manifest_text, "trace_env_scrubbed", contract.trace_env_scrubbed) ||
      !parse_bool_field(manifest_text, "key_material_embedded", contract.key_material_embedded) ||
      !parse_bool_field(manifest_text, "key_provider_static_file",
                        contract.key_provider_static_file) ||
      !parse_bool_field(manifest_text, "plaintext_output", contract.plaintext_output) ||
      !parse_bool_field(manifest_text, "no_persistent_plaintext_goal",
                        contract.no_persistent_plaintext_goal)) {
    error_out = LauncherError::kManifestInvalid;
    return false;
  }

  if (contract.schema_version != kManifestSchemaVersion ||
      contract.kind != kManifestKindShellScriptBundle ||
      contract.target_kind != "shell_ephemeral" || contract.backend_kind != "shell_launcher" ||
      contract.runtime_lane != "shell_launcher" || contract.mutation_profile != "shell_bundle" ||
      contract.signature_policy != "required_verifier" ||
      contract.artifact_kind != kManifestArtifactKindShellBundle ||
      contract.execution_model != kExecutionModelPipeStdinExec ||
      contract.source_policy != "self_contained_only" ||
      contract.plaintext_ttl_ms != kManifestPlaintextTtlMs ||
      contract.loader_format_version != static_cast<std::uint64_t>(kShellBundleFormatVersion) ||
      contract.key_provider_protocol != kManifestKeyProviderProtocolV1 ||
      contract.launcher_host != kManifestLauncherHostLinuxPosix ||
      !contract.unsafe_shell_features.empty() || contract.allow_jit ||
      contract.allow_runtime_executable_pages || contract.allow_persistent_plaintext ||
      !contract.require_fail_closed || !contract.trace_env_scrubbed ||
      contract.key_material_embedded || contract.key_provider_static_file ||
      contract.plaintext_output || !contract.no_persistent_plaintext_goal ||
      contract.key_id != expected_key_id || !is_allowed_interpreter(contract.interpreter_tag)) {
    error_out = LauncherError::kManifestInvalid;
    return false;
  }

  if (contract.key_provider_endpoint_kind != "executable_adapter" &&
      contract.key_provider_endpoint_kind != "fifo" &&
      contract.key_provider_endpoint_kind != "unix_socket") {
    error_out = LauncherError::kManifestInvalid;
    return false;
  }

  manifest_out = std::move(contract);
  error_out = LauncherError::kOk;
  return true;
}

bool decrypt_bundle_payload(const std::filesystem::path& bundle_path,
                            const std::filesystem::path& key_provider_path,
                            std::string_view expected_key_id,
                            const ManifestContract& manifest,
                            std::vector<std::uint8_t>& plaintext_out,
                            LauncherError& error_out) noexcept {
  std::vector<std::uint8_t> bundle_bytes;
  if (!read_binary_file(bundle_path, bundle_bytes)) {
    error_out = LauncherError::kBundleReadFailed;
    return false;
  }

  BundleHeader bundle_header{};
  std::string bundle_error;
  if (!read_bundle_header(bundle_bytes, bundle_header, bundle_error)) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  if (bundle_header.format_version != kShellBundleFormatVersion ||
      bundle_header.format_version != static_cast<std::uint8_t>(manifest.loader_format_version) ||
      bundle_header.key_material_marker != 0u ||
      bundle_header.key_binding_schema_version != kShellKeyBindingSchemaVersion ||
      !is_supported_interpreter_tag(bundle_header.interpreter_tag) ||
      bundle_header.interpreter_tag != manifest.interpreter_tag ||
      bundle_header.key_id_length == 0u) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  if (expected_key_id.size() > std::numeric_limits<std::uint16_t>::max() ||
      bundle_header.key_id_length != static_cast<std::uint16_t>(expected_key_id.size()) ||
      bundle_header.key_id_length != static_cast<std::uint16_t>(manifest.key_id.size())) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  if (bundle_header.header_size_bytes > bundle_bytes.size()) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }
  const std::size_t key_id_offset = bundle_header.header_size_bytes;
  if (key_id_offset > bundle_bytes.size()) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }
  if (bundle_header.key_id_length > (bundle_bytes.size() - key_id_offset)) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  const std::size_t payload_offset = key_id_offset + static_cast<std::size_t>(bundle_header.key_id_length);
  if (payload_offset > bundle_bytes.size()) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }
  if (bundle_header.payload_length > static_cast<std::uint64_t>(bundle_bytes.size() - payload_offset)) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  const std::string bundle_key_id(
      reinterpret_cast<const char*>(bundle_bytes.data() + static_cast<std::ptrdiff_t>(key_id_offset)),
      reinterpret_cast<const char*>(
          bundle_bytes.data() + static_cast<std::ptrdiff_t>(key_id_offset) +
          static_cast<std::ptrdiff_t>(bundle_header.key_id_length)));
  if (bundle_key_id != expected_key_id || bundle_key_id != manifest.key_id) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  const std::uint64_t payload_length = bundle_header.payload_length;
  if (payload_length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    error_out = LauncherError::kBundleInvalid;
    return false;
  }

  std::uint8_t key = 0u;
  ProviderEndpointKind endpoint_kind = ProviderEndpointKind::kInvalid;
  const std::filesystem::path workspace_root("/workspace");
  std::error_code temp_ec;
  const std::filesystem::path temp_root = std::filesystem::temp_directory_path(temp_ec);
  if (temp_ec) {
    error_out = LauncherError::kKeyProviderEndpointRejected;
    return false;
  }
  const KeyProviderError key_error = resolve_external_key_from_endpoint(
      key_provider_path, expected_key_id, workspace_root, temp_root, key, endpoint_kind);
  if (key_error != KeyProviderError::kOk) {
    if (key_error == KeyProviderError::kUnsupportedEndpoint ||
        key_error == KeyProviderError::kStaticFileRejected) {
      error_out = LauncherError::kKeyProviderEndpointRejected;
    } else {
      error_out = LauncherError::kKeyProviderFailed;
    }
    return false;
  }
  if (!endpoint_kind_allowed(endpoint_kind)) {
    error_out = LauncherError::kKeyProviderEndpointRejected;
    return false;
  }
  if (endpoint_kind_to_string(endpoint_kind) != manifest.key_provider_endpoint_kind) {
    error_out = LauncherError::kKeyProviderEndpointRejected;
    return false;
  }

  plaintext_out.assign(bundle_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
                       bundle_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset) +
                           static_cast<std::ptrdiff_t>(payload_length));
  decrypt_in_place(plaintext_out, key);
  error_out = LauncherError::kOk;
  return true;
}

bool sanitize_child_environment(LauncherError& error_out) noexcept {
  static constexpr const char* kKeepVars[] = {
      "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "PWD", "TERM"};
  static constexpr const char* kForceEmptyVars[] = {
      "BASH_ENV",
      "ENV",
      "PS4",
      "BASH_XTRACEFD",
  };
  static constexpr const char* kDropVars[] = {
      "PROMPT_COMMAND",
      "SHELLOPTS",
      "LD_PRELOAD",
      "LD_LIBRARY_PATH",
      "DYLD_INSERT_LIBRARIES",
      "DYLD_LIBRARY_PATH",
  };

  std::vector<std::pair<std::string, std::string>> kept_values;
  kept_values.reserve(sizeof(kKeepVars) / sizeof(kKeepVars[0]));
  for (const char* name : kKeepVars) {
    const char* value = std::getenv(name);
    if (value != nullptr) {
      kept_values.emplace_back(name, value);
    }
  }

  if (clearenv() != 0) {
    error_out = LauncherError::kEnvSanitizeFailed;
    return false;
  }
  for (const auto& item : kept_values) {
    if (setenv(item.first.c_str(), item.second.c_str(), 1) != 0) {
      error_out = LauncherError::kEnvSanitizeFailed;
      return false;
    }
  }

  // Ensure these shell-sensitive variables are visible as empty, not inherited defaults.
  for (const char* name : kForceEmptyVars) {
    if (setenv(name, "", 1) != 0) {
      error_out = LauncherError::kEnvSanitizeFailed;
      return false;
    }
  }

  for (const char* name : kDropVars) {
    unsetenv(name);
  }

  error_out = LauncherError::kOk;
  return true;
}

int exec_interpreter_from_stdin(const ManifestContract& manifest,
                                const std::vector<std::string>& script_args,
                                std::vector<std::uint8_t>& plaintext_script,
                                LauncherError& error_out) noexcept {
  if (manifest.execution_model != kExecutionModelPipeStdinExec) {
    error_out = LauncherError::kUnsupportedInterpreter;
    return launcher_error_to_exit_code(error_out);
  }

  const char* interpreter_path = interpreter_path_for_tag(manifest.interpreter_tag);
  if (interpreter_path == nullptr) {
    error_out = LauncherError::kUnsupportedInterpreter;
    return launcher_error_to_exit_code(error_out);
  }

  int pipe_fds[2] = {-1, -1};
  if (pipe(pipe_fds) != 0) {
    error_out = LauncherError::kPipeFailed;
    return launcher_error_to_exit_code(error_out);
  }

  const pid_t pid = fork();
  if (pid < 0) {
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    error_out = LauncherError::kForkFailed;
    return launcher_error_to_exit_code(error_out);
  }

  if (pid == 0) {
    close(pipe_fds[1]);
    LauncherError child_error = LauncherError::kOk;
    if (!sanitize_child_environment(child_error)) {
      _exit(241);
    }
    if (dup2(pipe_fds[0], STDIN_FILENO) < 0) {
      _exit(242);
    }
    close(pipe_fds[0]);

    std::vector<std::string> argv_owned;
    argv_owned.reserve(3u + script_args.size());
    argv_owned.emplace_back(manifest.interpreter_tag);
    argv_owned.emplace_back("-s");
    argv_owned.emplace_back("--");
    for (const std::string& arg : script_args) {
      argv_owned.push_back(arg);
    }

    std::vector<char*> argv_raw;
    argv_raw.reserve(argv_owned.size() + 1u);
    for (std::string& arg : argv_owned) {
      argv_raw.push_back(arg.data());
    }
    argv_raw.push_back(nullptr);

    execv(interpreter_path, argv_raw.data());
    _exit(243);
  }

  close(pipe_fds[0]);
  std::size_t offset = 0u;
  while (offset < plaintext_script.size()) {
    const std::size_t remaining = plaintext_script.size() - offset;
    const ssize_t written = write(pipe_fds[1], plaintext_script.data() + offset, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      close(pipe_fds[1]);
      secure_zero(plaintext_script);
      plaintext_script.clear();
      int status = 0;
      waitpid(pid, &status, 0);
      error_out = LauncherError::kWritePipeFailed;
      return launcher_error_to_exit_code(error_out);
    }
    offset += static_cast<std::size_t>(written);
  }
  close(pipe_fds[1]);
  secure_zero(plaintext_script);
  plaintext_script.clear();

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    error_out = LauncherError::kWaitFailed;
    return launcher_error_to_exit_code(error_out);
  }
  error_out = LauncherError::kOk;
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

int launch_bundle_via_pipe(const LauncherOptions& options, LauncherError& error_out) noexcept {
  ManifestContract manifest{};
  if (!load_and_validate_shell_manifest(options.manifest_path, options.key_id, manifest, error_out)) {
    return launcher_error_to_exit_code(error_out);
  }

  std::vector<std::uint8_t> plaintext_script;
  if (!decrypt_bundle_payload(options.input_bundle_path,
                              options.key_provider_path,
                              options.key_id,
                              manifest,
                              plaintext_script,
                              error_out)) {
    return launcher_error_to_exit_code(error_out);
  }
  if (has_runtime_unsafe_shell_features(plaintext_script)) {
    secure_zero(plaintext_script);
    plaintext_script.clear();
    error_out = LauncherError::kManifestInvalid;
    return launcher_error_to_exit_code(error_out);
  }

  return exec_interpreter_from_stdin(manifest, options.script_args, plaintext_script, error_out);
}

const char* launcher_error_message(LauncherError error) noexcept {
  switch (error) {
    case LauncherError::kOk:
      return "ok";
    case LauncherError::kInvalidCli:
      return "invalid_cli";
    case LauncherError::kManifestReadFailed:
      return "manifest_read_failed";
    case LauncherError::kManifestInvalid:
      return "manifest_invalid";
    case LauncherError::kBundleReadFailed:
      return "bundle_read_failed";
    case LauncherError::kBundleInvalid:
      return "bundle_invalid";
    case LauncherError::kKeyProviderFailed:
      return "key_provider_failed";
    case LauncherError::kKeyProviderEndpointRejected:
      return "key_provider_endpoint_rejected";
    case LauncherError::kUnsupportedInterpreter:
      return "unsupported_interpreter";
    case LauncherError::kPipeFailed:
      return "pipe_failed";
    case LauncherError::kForkFailed:
      return "fork_failed";
    case LauncherError::kWritePipeFailed:
      return "write_pipe_failed";
    case LauncherError::kWaitFailed:
      return "wait_failed";
    case LauncherError::kEnvSanitizeFailed:
      return "env_sanitize_failed";
    case LauncherError::kExecFailed:
      return "exec_failed";
  }
  return "unknown";
}

}  // namespace eippf::script_guard

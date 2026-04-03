#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace eippf::script_guard {

struct LauncherOptions final {
  std::filesystem::path input_bundle_path;
  std::filesystem::path manifest_path;
  std::filesystem::path key_provider_path;
  std::string key_id;
  std::vector<std::string> script_args;
};

struct ManifestContract final {
  std::uint64_t schema_version = 0u;
  std::string kind;
  std::string target_kind;
  std::string backend_kind;
  std::string runtime_lane;
  std::string mutation_profile;
  std::string signature_policy;
  std::string artifact_kind;
  std::string execution_model;
  std::string interpreter_tag;
  std::string source_policy;
  std::uint64_t plaintext_ttl_ms = 0u;
  std::uint64_t loader_format_version = 0u;
  std::string key_provider_protocol;
  std::string launcher_host;
  std::string key_provider_endpoint_kind;
  std::string key_id;
  std::vector<std::string> unsafe_shell_features;

  bool allow_jit = false;
  bool allow_runtime_executable_pages = false;
  bool allow_persistent_plaintext = false;
  bool require_fail_closed = false;
  bool trace_env_scrubbed = false;
  bool key_material_embedded = true;
  bool key_provider_static_file = true;
  bool plaintext_output = true;
  bool no_persistent_plaintext_goal = false;
};

enum class LauncherError : std::uint8_t {
  kOk = 0u,
  kInvalidCli = 1u,
  kManifestReadFailed = 2u,
  kManifestInvalid = 3u,
  kBundleReadFailed = 4u,
  kBundleInvalid = 5u,
  kKeyProviderFailed = 6u,
  kKeyProviderEndpointRejected = 7u,
  kUnsupportedInterpreter = 8u,
  kPipeFailed = 9u,
  kForkFailed = 10u,
  kWritePipeFailed = 11u,
  kWaitFailed = 12u,
  kEnvSanitizeFailed = 13u,
  kExecFailed = 14u,
};

[[nodiscard]] bool parse_launcher_options(int argc,
                                          char** argv,
                                          LauncherOptions& options_out) noexcept;

[[nodiscard]] bool load_and_validate_shell_manifest(const std::filesystem::path& manifest_path,
                                                    std::string_view expected_key_id,
                                                    ManifestContract& manifest_out,
                                                    LauncherError& error_out) noexcept;

[[nodiscard]] bool decrypt_bundle_payload(const std::filesystem::path& bundle_path,
                                          const std::filesystem::path& key_provider_path,
                                          std::string_view expected_key_id,
                                          const ManifestContract& manifest,
                                          std::vector<std::uint8_t>& plaintext_out,
                                          LauncherError& error_out) noexcept;

[[nodiscard]] bool sanitize_child_environment(LauncherError& error_out) noexcept;

[[nodiscard]] int exec_interpreter_from_stdin(const ManifestContract& manifest,
                                              const std::vector<std::string>& script_args,
                                              std::vector<std::uint8_t>& plaintext_script,
                                              LauncherError& error_out) noexcept;

[[nodiscard]] int launch_bundle_via_pipe(const LauncherOptions& options,
                                         LauncherError& error_out) noexcept;

[[nodiscard]] const char* launcher_error_message(LauncherError error) noexcept;

}  // namespace eippf::script_guard

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/stat.h>
#include <sys/wait.h>
#endif

#ifndef EIPPF_SCRIPT_GUARD_PATH
#error "EIPPF_SCRIPT_GUARD_PATH must be defined"
#endif

#ifndef EIPPF_SCRIPT_LAUNCHER_PATH
#error "EIPPF_SCRIPT_LAUNCHER_PATH must be defined"
#endif

namespace {

constexpr std::string_view kProviderProtocol = "eippf.external_key.v1";

[[nodiscard]] std::string quote_arg(const std::string& value) {
  std::string out = "\"";
  out.reserve(value.size() + 2u);
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

[[nodiscard]] int normalize_status(int status) {
#if defined(__unix__) || defined(__APPLE__)
  if (status == -1) {
    return -1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return status;
#else
  return status;
#endif
}

bool write_text(const std::filesystem::path& path, std::string_view text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_script_launcher_failure_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

[[nodiscard]] std::string provider_text(std::string_view status,
                                        std::string_view key_id,
                                        std::string_view key_u8) {
  std::string out;
  out.reserve(96u);
  out += "protocol=";
  out += kProviderProtocol;
  out += "\nstatus=";
  out += status;
  out += "\nkey_id=";
  out += key_id;
  out += "\nkey_u8=";
  out += key_u8;
  out += "\n";
  return out;
}

bool create_fifo_endpoint(const std::filesystem::path& path) {
#if defined(__unix__) || defined(__APPLE__)
  std::error_code ec;
  std::filesystem::remove(path, ec);
  if (::mkfifo(path.c_str(), 0600) != 0) {
    return false;
  }
  return true;
#else
  (void)path;
  return false;
#endif
}

[[nodiscard]] std::string wrap_command_with_fifo_provider(const std::string& command,
                                                          const std::filesystem::path& provider_path,
                                                          std::string_view provider_payload) {
  std::string wrapped = "( { cat > ";
  wrapped += quote_arg(provider_path.string());
  wrapped += " <<'__EIPPF_PROVIDER_EOF__'\n";
  wrapped += std::string(provider_payload);
  if (provider_payload.empty() || provider_payload.back() != '\n') {
    wrapped += '\n';
  }
  wrapped += "__EIPPF_PROVIDER_EOF__\n";
  wrapped += "} & writer_pid=$!; ";
  wrapped += command;
  wrapped += "; command_status=$?; ";
  wrapped += "kill \"$writer_pid\" 2>/dev/null || true; ";
  wrapped += "wait \"$writer_pid\" 2>/dev/null || true; ";
  wrapped += "exit \"$command_status\"; )";
  return wrapped;
}

[[nodiscard]] std::string guard_command(const std::filesystem::path& script_path,
                                        const std::filesystem::path& bundle_path,
                                        const std::filesystem::path& manifest_path,
                                        const std::filesystem::path& provider_path,
                                        std::string_view key_id) {
  return std::string(EIPPF_SCRIPT_GUARD_PATH) + " --input-script=" + quote_arg(script_path.string()) +
         " --output-bundle=" + quote_arg(bundle_path.string()) + " --manifest=" +
         quote_arg(manifest_path.string()) + " --key-provider=" + quote_arg(provider_path.string()) +
         " --key-id=" + std::string(key_id);
}

[[nodiscard]] std::string launcher_command(const std::filesystem::path& bundle_path,
                                           const std::filesystem::path& manifest_path,
                                           const std::filesystem::path& provider_path,
                                           std::string_view key_id,
                                           const std::filesystem::path& output_path) {
  return std::string(EIPPF_SCRIPT_LAUNCHER_PATH) + " --input-bundle=" + quote_arg(bundle_path.string()) +
         " --manifest=" + quote_arg(manifest_path.string()) + " --key-provider=" +
         quote_arg(provider_path.string()) + " --key-id=" + std::string(key_id) +
         " -- alpha beta > " + quote_arg(output_path.string()) + " 2>&1";
}

bool expect_status(std::string_view label, const std::string& command, int expected_status) {
  const int status = normalize_status(std::system(command.c_str()));
  if (status == expected_status) {
    return true;
  }
  std::cerr << "[FAIL] " << label << " returned " << status << ", expected " << expected_status << '\n';
  return false;
}

bool expect_nonzero(std::string_view label, const std::string& command) {
  const int status = normalize_status(std::system(command.c_str()));
  if (status != 0) {
    return true;
  }
  std::cerr << "[FAIL] " << label << " unexpectedly returned success\n";
  return false;
}

bool expect_launcher_nonzero_pre_exec(std::string_view label,
                                      const std::string& command,
                                      const std::filesystem::path& output_path) {
  std::error_code ec;
  std::filesystem::remove(output_path, ec);
  const int status = normalize_status(std::system(command.c_str()));
  if (status == 0) {
    std::cerr << "[FAIL] " << label << " unexpectedly returned success\n";
    return false;
  }

  const std::string output = read_text(output_path);
  if (output.find("SECRET_ANCHOR") != std::string::npos ||
      output.find("ARGS:alpha:beta") != std::string::npos) {
    std::cerr << "[FAIL] " << label << " executed script payload unexpectedly\n";
    return false;
  }
  return true;
}

bool write_single_field_manifest_mutation(const std::filesystem::path& source_manifest_path,
                                          const std::filesystem::path& output_manifest_path,
                                          std::string_view marker,
                                          std::string_view replacement,
                                          std::string_view field_name) {
  std::string manifest_text = read_text(source_manifest_path);
  if (manifest_text.empty()) {
    std::cerr << "[FAIL] cannot read source manifest for " << field_name << '\n';
    return false;
  }
  const std::size_t marker_pos = manifest_text.find(marker);
  if (marker_pos == std::string::npos) {
    std::cerr << "[FAIL] cannot locate marker for " << field_name << '\n';
    return false;
  }
  manifest_text.replace(marker_pos, marker.size(), replacement);
  if (!write_text(output_manifest_path, manifest_text)) {
    std::cerr << "[FAIL] cannot write mutated manifest for " << field_name << '\n';
    return false;
  }
  return true;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  const std::filesystem::path script_path = temp_dir / "launcher_failure.sh";
  const std::filesystem::path bundle_path = temp_dir / "launcher_failure.eippf";
  const std::filesystem::path manifest_path = temp_dir / "launcher_failure.manifest.json";
  const std::filesystem::path output_path = temp_dir / "launcher_failure.out";

  const std::filesystem::path provider_ok = temp_dir / "provider_ok";
  const std::filesystem::path provider_malformed = temp_dir / "provider_malformed";
  const std::filesystem::path provider_rejected = temp_dir / "provider_rejected";
  const std::filesystem::path provider_mismatch = temp_dir / "provider_mismatch";
  const std::filesystem::path provider_missing = temp_dir / "provider_missing";
  const std::filesystem::path provider_static_file = temp_dir / "provider_static_file";
  const std::filesystem::path provider_symlink = temp_dir / "provider_symlink";

  const std::string script =
      "#!/bin/sh\n"
      "echo SECRET_ANCHOR\n"
      "printf 'ARGS:%s:%s\\n' \"$1\" \"$2\"\n";
  const std::string provider_ok_payload = provider_text("ok", "launcher-failure", "99");
  const std::string provider_malformed_payload =
      "protocol=wrong\nstatus=ok\nkey_id=launcher-failure\nkey_u8=99\n";
  const std::string provider_rejected_payload = provider_text("deny", "launcher-failure", "99");
  const std::string provider_mismatch_payload = provider_text("ok", "other-key", "99");

  if (!write_text(script_path, script)) {
    std::cerr << "[FAIL] cannot write script fixture\n";
    return 1;
  }
  if (!create_fifo_endpoint(provider_ok) ||
      !create_fifo_endpoint(provider_malformed) ||
      !create_fifo_endpoint(provider_rejected) ||
      !create_fifo_endpoint(provider_mismatch) ||
      !write_text(provider_static_file, provider_text("ok", "launcher-failure", "99"))) {
    std::cerr << "[FAIL] cannot write provider fixtures\n";
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove(provider_symlink, ec);
  ec.clear();
  std::filesystem::create_symlink(provider_static_file, provider_symlink, ec);
  if (ec) {
    std::cerr << "[FAIL] cannot create symlink provider fixture\n";
    return 1;
  }

  if (!expect_status("bundle generation",
                     wrap_command_with_fifo_provider(
                         guard_command(script_path, bundle_path, manifest_path, provider_ok, "launcher-failure"),
                         provider_ok,
                         provider_ok_payload),
                     0)) {
    return 1;
  }

  if (!expect_nonzero("missing provider",
                      launcher_command(bundle_path, manifest_path, provider_missing, "launcher-failure", output_path))) {
    return 1;
  }
  if (!expect_nonzero("malformed provider",
                      wrap_command_with_fifo_provider(
                          launcher_command(bundle_path,
                                           manifest_path,
                                           provider_malformed,
                                           "launcher-failure",
                                           output_path),
                          provider_malformed,
                          provider_malformed_payload))) {
    return 1;
  }
  if (!expect_nonzero("rejected provider",
                      wrap_command_with_fifo_provider(
                          launcher_command(bundle_path,
                                           manifest_path,
                                           provider_rejected,
                                           "launcher-failure",
                                           output_path),
                          provider_rejected,
                          provider_rejected_payload))) {
    return 1;
  }
  if (!expect_nonzero("key id mismatch",
                      wrap_command_with_fifo_provider(
                          launcher_command(bundle_path,
                                           manifest_path,
                                           provider_mismatch,
                                           "launcher-failure",
                                           output_path),
                          provider_mismatch,
                          provider_mismatch_payload))) {
    return 1;
  }
  if (!expect_nonzero("static key file provider",
                      launcher_command(bundle_path, manifest_path, provider_static_file, "launcher-failure", output_path))) {
    return 1;
  }
  if (!expect_nonzero("symlink key file provider",
                      launcher_command(bundle_path, manifest_path, provider_symlink, "launcher-failure", output_path))) {
    return 1;
  }

  struct ManifestMutationCase final {
    std::string_view field_name;
    std::string_view marker;
    std::string_view replacement;
  };
  const std::vector<ManifestMutationCase> manifest_mutation_cases = {
      {"schema_version", "\"schema_version\":2", "\"schema_version\":99"},
      {"kind",
       "\"kind\":\"shell_script_bundle\"",
       "\"kind\":\"tampered_shell_script_bundle\""},
      {"target_kind", "\"target_kind\":\"shell_ephemeral\"", "\"target_kind\":\"shell_persistent\""},
      {"backend_kind", "\"backend_kind\":\"shell_launcher\"", "\"backend_kind\":\"shell_runtime\""},
      {"runtime_lane", "\"runtime_lane\":\"shell_launcher\"", "\"runtime_lane\":\"shell_runtime\""},
      {"mutation_profile",
       "\"mutation_profile\":\"shell_bundle\"",
       "\"mutation_profile\":\"shell_runtime\""},
      {"signature_policy",
       "\"signature_policy\":\"required_verifier\"",
       "\"signature_policy\":\"optional\""},
      {"artifact_kind", "\"artifact_kind\":\"shell_bundle\"", "\"artifact_kind\":\"shell_plaintext\""},
      {"allow_jit", "\"allow_jit\":false", "\"allow_jit\":true"},
      {"allow_runtime_executable_pages",
       "\"allow_runtime_executable_pages\":false",
       "\"allow_runtime_executable_pages\":true"},
      {"allow_persistent_plaintext",
       "\"allow_persistent_plaintext\":false",
       "\"allow_persistent_plaintext\":true"},
      {"require_fail_closed", "\"require_fail_closed\":true", "\"require_fail_closed\":false"},
      {"plaintext_ttl_ms", "\"plaintext_ttl_ms\":0", "\"plaintext_ttl_ms\":60000"},
      {"loader_format_version", "\"loader_format_version\":3", "\"loader_format_version\":7"},
      {"key_provider_protocol",
       "\"key_provider_protocol\":\"eippf.external_key.v1\"",
       "\"key_provider_protocol\":\"eippf.external_key.v2\""},
      {"key_provider_endpoint_kind",
       "\"key_provider_endpoint_kind\":\"fifo\"",
       "\"key_provider_endpoint_kind\":\"static_file\""},
      {"key_provider_static_file", "\"key_provider_static_file\":false", "\"key_provider_static_file\":true"},
      {"key_id", "\"key_id\":\"launcher-failure\"", "\"key_id\":\"launcher-failure-mutated\""},
      {"key_material_embedded", "\"key_material_embedded\":false", "\"key_material_embedded\":true"},
      {"execution_model", "\"execution_model\":\"pipe_stdin_exec\"", "\"execution_model\":\"temp_script_exec\""},
      {"launcher_host", "\"launcher_host\":\"linux_posix\"", "\"launcher_host\":\"windows_nt\""},
      {"interpreter_tag", "\"interpreter_tag\":\"sh\"", "\"interpreter_tag\":\"python\""},
      {"trace_env_scrubbed", "\"trace_env_scrubbed\":true", "\"trace_env_scrubbed\":false"},
      {"source_policy", "\"source_policy\":\"self_contained_only\"", "\"source_policy\":\"allow_source\""},
      {"unsafe_shell_features",
       "\"unsafe_shell_features\":[]",
       "\"unsafe_shell_features\":[\"set -o xtrace\"]"},
      {"plaintext_output", "\"plaintext_output\":false", "\"plaintext_output\":true"},
      {"no_persistent_plaintext_goal",
       "\"no_persistent_plaintext_goal\":true",
       "\"no_persistent_plaintext_goal\":false"},
  };

  for (const ManifestMutationCase& mutation : manifest_mutation_cases) {
    const std::filesystem::path mutated_manifest_path =
        temp_dir / ("manifest_mutation_" + std::string(mutation.field_name) + ".json");
    if (!write_single_field_manifest_mutation(manifest_path,
                                              mutated_manifest_path,
                                              mutation.marker,
                                              mutation.replacement,
                                              mutation.field_name)) {
      return 1;
    }
    const std::string label = "manifest frozen field mutation " + std::string(mutation.field_name);
    if (!expect_launcher_nonzero_pre_exec(
            label,
            wrap_command_with_fifo_provider(
                launcher_command(bundle_path,
                                 mutated_manifest_path,
                                 provider_ok,
                                 "launcher-failure",
                                 output_path),
                provider_ok,
                provider_ok_payload),
            output_path)) {
      return 1;
    }
  }

  const std::filesystem::path manifest_missing_field_path = temp_dir / "manifest_missing_field.json";
  std::string manifest_text = read_text(manifest_path);
  const std::string key_marker = "\"key_id\":\"launcher-failure\",";
  const std::size_t key_pos = manifest_text.find(key_marker);
  if (key_pos == std::string::npos) {
    std::cerr << "[FAIL] cannot locate key_id marker in manifest fixture\n";
    return 1;
  }
  manifest_text.erase(key_pos, key_marker.size());
  if (!write_text(manifest_missing_field_path, manifest_text)) {
    std::cerr << "[FAIL] cannot write missing-field manifest\n";
    return 1;
  }
  if (!expect_launcher_nonzero_pre_exec("manifest missing required field",
                                        launcher_command(bundle_path,
                                                         manifest_missing_field_path,
                                                         provider_ok,
                                                         "launcher-failure",
                                                         output_path),
                                        output_path)) {
    return 1;
  }

  const std::filesystem::path bundle_bad_version_path = temp_dir / "bundle_bad_version.eippf";
  std::vector<std::uint8_t> bundle_bytes = read_bytes(bundle_path);
  if (bundle_bytes.size() < 5u) {
    std::cerr << "[FAIL] bundle fixture too small\n";
    return 1;
  }
  bundle_bytes[4] = 2u;
  if (!write_bytes(bundle_bad_version_path, bundle_bytes)) {
    std::cerr << "[FAIL] cannot write bad-version bundle\n";
    return 1;
  }
  if (!expect_launcher_nonzero_pre_exec("bundle version mismatch",
                                        launcher_command(bundle_bad_version_path,
                                                         manifest_path,
                                                         provider_ok,
                                                         "launcher-failure",
                                                         output_path),
                                        output_path)) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

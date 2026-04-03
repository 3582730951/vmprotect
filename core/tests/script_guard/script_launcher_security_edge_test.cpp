#include <chrono>
#include <cstdint>
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

[[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_script_launcher_edge_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

[[nodiscard]] bool contains_bytes(const std::vector<std::uint8_t>& haystack, std::string_view needle) {
  if (needle.empty() || haystack.size() < needle.size()) {
    return false;
  }
  for (std::size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
    bool match = true;
    for (std::size_t j = 0; j < needle.size(); ++j) {
      if (haystack[i + j] != static_cast<std::uint8_t>(needle[j])) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                    static_cast<std::uint16_t>(bytes[offset + 1u] << 8u));
}

[[nodiscard]] std::uint64_t read_u64_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) {
  std::uint64_t value = 0u;
  for (std::size_t i = 0u; i < 8u; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + i]) << static_cast<unsigned>(8u * i);
  }
  return value;
}

void write_u64_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
  for (std::size_t i = 0u; i < 8u; ++i) {
    bytes[offset + i] = static_cast<std::uint8_t>((value >> static_cast<unsigned>(i * 8u)) & 0xFFu);
  }
}

[[nodiscard]] std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 29u) + (index >> 1u) + 0x31u) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

void xor_with_stream_mask(std::vector<std::uint8_t>& data, std::uint8_t key) noexcept {
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(data[i] ^ stream_mask(key, i));
  }
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
                                           const std::filesystem::path& output_path,
                                           bool inject_env) {
  std::string command;
  if (inject_env) {
    command += "BASH_ENV=forbidden ENV=forbidden PS4=forbidden BASH_XTRACEFD=7 ";
  }
  command += std::string(EIPPF_SCRIPT_LAUNCHER_PATH) + " --input-bundle=" + quote_arg(bundle_path.string()) +
             " --manifest=" + quote_arg(manifest_path.string()) + " --key-provider=" +
             quote_arg(provider_path.string()) + " --key-id=" + std::string(key_id) +
             " -- > " + quote_arg(output_path.string()) + " 2>&1";
  return command;
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
                                      const std::filesystem::path& output_path,
                                      std::string_view probe_execution_marker) {
  std::error_code ec;
  std::filesystem::remove(output_path, ec);
  const int status = normalize_status(std::system(command.c_str()));
  if (status == 0) {
    std::cerr << "[FAIL] " << label << " unexpectedly returned success\n";
    return false;
  }

  const std::string output = read_text(output_path);
  if (output.find("SECRET_ANCHOR") != std::string::npos ||
      output.find("ENV_CLEAN") != std::string::npos ||
      output.find("ARGS:alpha:beta") != std::string::npos) {
    std::cerr << "[FAIL] " << label << " executed safe script payload unexpectedly\n";
    return false;
  }
  if (!probe_execution_marker.empty() &&
      output.find(probe_execution_marker) != std::string::npos) {
    std::cerr << "[FAIL] " << label << " executed tampered script payload unexpectedly\n";
    return false;
  }
  return true;
}

bool write_single_field_manifest_mutation(const std::filesystem::path& source_manifest_path,
                                          const std::filesystem::path& output_manifest_path,
                                          std::string_view marker,
                                          std::string_view replacement,
                                          std::string_view label) {
  std::string manifest_text = read_text(source_manifest_path);
  if (manifest_text.empty()) {
    std::cerr << "[FAIL] cannot read source manifest for " << label << '\n';
    return false;
  }
  const std::size_t marker_pos = manifest_text.find(marker);
  if (marker_pos == std::string::npos) {
    std::cerr << "[FAIL] cannot locate marker for " << label << '\n';
    return false;
  }
  manifest_text.replace(marker_pos, marker.size(), replacement);
  if (!write_text(output_manifest_path, manifest_text)) {
    std::cerr << "[FAIL] cannot write mutated manifest for " << label << '\n';
    return false;
  }
  return true;
}

bool write_tampered_bundle_payload(const std::filesystem::path& source_bundle_path,
                                   const std::filesystem::path& output_bundle_path,
                                   std::uint8_t key_u8,
                                   std::string_view tampered_plaintext,
                                   std::string_view label) {
  std::vector<std::uint8_t> bundle_bytes = read_bytes(source_bundle_path);
  if (bundle_bytes.size() < 21u) {
    std::cerr << "[FAIL] bundle fixture too small for " << label << '\n';
    return false;
  }
  if (bundle_bytes[0u] != static_cast<std::uint8_t>('E') ||
      bundle_bytes[1u] != static_cast<std::uint8_t>('S') ||
      bundle_bytes[2u] != static_cast<std::uint8_t>('H') ||
      bundle_bytes[3u] != static_cast<std::uint8_t>('B') ||
      bundle_bytes[4u] != 3u || bundle_bytes[5u] != 0u) {
    std::cerr << "[FAIL] bundle header mismatch for " << label << '\n';
    return false;
  }

  const std::size_t header_size = 21u + static_cast<std::size_t>(bundle_bytes[7u]);
  if (header_size > bundle_bytes.size()) {
    std::cerr << "[FAIL] bundle header overflow for " << label << '\n';
    return false;
  }

  const std::size_t key_id_length = static_cast<std::size_t>(read_u16_le(bundle_bytes, 9u));
  const std::size_t payload_offset = header_size + key_id_length;
  if (payload_offset > bundle_bytes.size()) {
    std::cerr << "[FAIL] bundle key id range overflow for " << label << '\n';
    return false;
  }

  const std::uint64_t payload_length_u64 = read_u64_le(bundle_bytes, 13u);
  const std::size_t available_payload_bytes = bundle_bytes.size() - payload_offset;
  if (payload_length_u64 > static_cast<std::uint64_t>(available_payload_bytes)) {
    std::cerr << "[FAIL] bundle payload range overflow for " << label << '\n';
    return false;
  }
  const std::size_t payload_length = static_cast<std::size_t>(payload_length_u64);

  std::vector<std::uint8_t> decrypted_payload(
      bundle_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset),
      bundle_bytes.begin() + static_cast<std::ptrdiff_t>(payload_offset) +
          static_cast<std::ptrdiff_t>(payload_length));
  xor_with_stream_mask(decrypted_payload, key_u8);
  if (!contains_bytes(decrypted_payload, "SECRET_ANCHOR")) {
    std::cerr << "[FAIL] baseline payload missing anchor for " << label << '\n';
    return false;
  }

  std::vector<std::uint8_t> encrypted_tampered_payload(tampered_plaintext.begin(),
                                                       tampered_plaintext.end());
  xor_with_stream_mask(encrypted_tampered_payload, key_u8);

  write_u64_le(bundle_bytes,
               13u,
               static_cast<std::uint64_t>(encrypted_tampered_payload.size()));
  bundle_bytes.resize(payload_offset);
  bundle_bytes.insert(bundle_bytes.end(),
                      encrypted_tampered_payload.begin(),
                      encrypted_tampered_payload.end());
  if (!write_bytes(output_bundle_path, bundle_bytes)) {
    std::cerr << "[FAIL] cannot write tampered bundle for " << label << '\n';
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

  const std::filesystem::path script_xtrace = temp_dir / "xtrace.sh";
  const std::filesystem::path script_source = temp_dir / "source.sh";
  const std::filesystem::path script_safe = temp_dir / "safe.sh";
  const std::filesystem::path bundled = temp_dir / "edge.eippf";
  const std::filesystem::path manifest = temp_dir / "edge.manifest.json";
  const std::filesystem::path output = temp_dir / "edge.out";

  const std::filesystem::path provider_ok = temp_dir / "provider_ok";
  const std::filesystem::path provider_static = temp_dir / "provider_static";
  const std::filesystem::path provider_symlink = temp_dir / "provider_symlink";
  const std::string provider_ok_payload = provider_text("ok", "launcher-edge", "55");

  if (!write_text(script_xtrace, "#!/bin/sh\nset -x\necho BAD\n") ||
      !write_text(script_source, "#!/bin/sh\nsource ./other.sh\n") ||
      !write_text(script_safe,
                  "#!/bin/sh\n"
                  "if [ -n \"${BASH_ENV:-}\" ] || [ -n \"${ENV:-}\" ] || [ -n \"${PS4:-}\" ] || [ -n \"${BASH_XTRACEFD:-}\" ]; then\n"
                  "  echo LEAK\n"
                  "  exit 91\n"
                  "fi\n"
                  "echo SECRET_ANCHOR\n"
                  "echo ENV_CLEAN\n") ||
      !create_fifo_endpoint(provider_ok) ||
      !write_text(provider_static, provider_text("ok", "launcher-edge", "55"))) {
    std::cerr << "[FAIL] cannot write fixtures\n";
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove(provider_symlink, ec);
  ec.clear();
  std::filesystem::create_symlink(provider_static, provider_symlink, ec);
  if (ec) {
    std::cerr << "[FAIL] cannot create symlink provider fixture\n";
    return 1;
  }

  if (!expect_nonzero("xtrace redlight",
                      guard_command(script_xtrace, bundled, manifest, provider_ok, "launcher-edge"))) {
    return 1;
  }
  if (!expect_nonzero("source redlight",
                      guard_command(script_source, bundled, manifest, provider_ok, "launcher-edge"))) {
    return 1;
  }
  if (!expect_nonzero("static provider redlight",
                      guard_command(script_safe, bundled, manifest, provider_static, "launcher-edge"))) {
    return 1;
  }
  if (!expect_nonzero("symlink provider redlight",
                      guard_command(script_safe, bundled, manifest, provider_symlink, "launcher-edge"))) {
    return 1;
  }

  if (!expect_status("safe bundle generation",
                     wrap_command_with_fifo_provider(
                         guard_command(script_safe, bundled, manifest, provider_ok, "launcher-edge"),
                         provider_ok,
                         provider_ok_payload),
                     0)) {
    return 1;
  }

  const std::vector<std::uint8_t> bundle_bytes = read_bytes(bundled);
  if (contains_bytes(bundle_bytes, "SECRET_ANCHOR")) {
    std::cerr << "[FAIL] bundle should not expose plaintext anchor\n";
    return 1;
  }

  struct BundleTamperCase final {
    std::string_view label;
    std::string_view marker;
    std::string_view script_payload;
  };
  const std::vector<BundleTamperCase> bundle_tamper_cases = {
      {"xtrace_runtime_probe",
       "TAMPER_EXECUTED_XTRACE",
       "#!/bin/sh\nset -o xtrace\necho TAMPER_EXECUTED_XTRACE\n"},
      {"dot_source_runtime_probe",
       "TAMPER_EXECUTED_DOT_SOURCE",
       "#!/bin/sh\n. /dev/null\necho TAMPER_EXECUTED_DOT_SOURCE\n"},
      {"dollar_zero_runtime_probe",
       "TAMPER_EXECUTED_DOLLAR_ZERO",
       "#!/bin/sh\necho \"$0\"\necho TAMPER_EXECUTED_DOLLAR_ZERO\n"},
      {"bash_source_runtime_probe",
       "TAMPER_EXECUTED_BASH_SOURCE",
       "#!/bin/sh\necho \"${BASH_SOURCE}\"\necho TAMPER_EXECUTED_BASH_SOURCE\n"},
  };
  for (const BundleTamperCase& tamper_case : bundle_tamper_cases) {
    const std::filesystem::path tampered_bundle = temp_dir / ("edge_tamper_" +
                                                              std::string(tamper_case.label) +
                                                              ".eippf");
    if (!write_tampered_bundle_payload(
            bundled, tampered_bundle, 55u, tamper_case.script_payload, tamper_case.label)) {
      return 1;
    }
    const std::string failure_label = "runtime tamper probe " + std::string(tamper_case.label);
    if (!expect_launcher_nonzero_pre_exec(
            failure_label,
            wrap_command_with_fifo_provider(
                launcher_command(tampered_bundle, manifest, provider_ok, "launcher-edge", output, false),
                provider_ok,
                provider_ok_payload),
            output,
            tamper_case.marker)) {
      return 1;
    }
  }

  const std::filesystem::path manifest_unsafe_nonempty = temp_dir / "edge_manifest_unsafe_nonempty.json";
  if (!write_single_field_manifest_mutation(manifest,
                                            manifest_unsafe_nonempty,
                                            "\"unsafe_shell_features\":[]",
                                            "\"unsafe_shell_features\":[\"set -o xtrace\"]",
                                            "unsafe_shell_features_nonempty")) {
    return 1;
  }
  if (!expect_launcher_nonzero_pre_exec(
          "manifest tamper unsafe_shell_features non-empty",
          wrap_command_with_fifo_provider(
              launcher_command(bundled,
                               manifest_unsafe_nonempty,
                               provider_ok,
                               "launcher-edge",
                               output,
                               false),
              provider_ok,
              provider_ok_payload),
          output,
          "")) {
    return 1;
  }

  const std::filesystem::path manifest_unsafe_invalid_type =
      temp_dir / "edge_manifest_unsafe_invalid_type.json";
  if (!write_single_field_manifest_mutation(manifest,
                                            manifest_unsafe_invalid_type,
                                            "\"unsafe_shell_features\":[]",
                                            "\"unsafe_shell_features\":{}",
                                            "unsafe_shell_features_invalid_type")) {
    return 1;
  }
  if (!expect_launcher_nonzero_pre_exec(
          "manifest tamper unsafe_shell_features invalid type",
          wrap_command_with_fifo_provider(
              launcher_command(bundled,
                               manifest_unsafe_invalid_type,
                               provider_ok,
                               "launcher-edge",
                               output,
                               false),
              provider_ok,
              provider_ok_payload),
          output,
          "")) {
    return 1;
  }

  if (!expect_status("launcher env scrub",
                     wrap_command_with_fifo_provider(
                         launcher_command(bundled, manifest, provider_ok, "launcher-edge", output, true),
                         provider_ok,
                         provider_ok_payload),
                     0)) {
    return 1;
  }

  const std::string launcher_output = read_text(output);
  if (launcher_output.find("LEAK") != std::string::npos) {
    std::cerr << "[FAIL] launcher did not scrub env variables\n";
    return 1;
  }
  if (launcher_output.find("ENV_CLEAN") == std::string::npos) {
    std::cerr << "[FAIL] launcher missing clean env marker\n";
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

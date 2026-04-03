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
#include <sys/wait.h>
#endif

#ifndef EIPPF_DEX_TOOLCHAIN_PATH
#error "EIPPF_DEX_TOOLCHAIN_PATH must be defined"
#endif

#ifndef EIPPF_DEX_LOADER_PATH
#error "EIPPF_DEX_LOADER_PATH must be defined"
#endif

namespace {

constexpr std::string_view kProviderProtocol = "eippf.external_key.v1";
constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;

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

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

bool write_executable_script(const std::filesystem::path& path, std::string_view content) {
  if (!write_text(path, content)) {
    return false;
  }
  std::error_code ec;
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
          std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
          std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
          std::filesystem::perms::others_exec,
      std::filesystem::perm_options::replace,
      ec);
  return !ec;
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
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("eippf_android_dex_security_edge_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

[[nodiscard]] std::string provider_payload(std::string_view status,
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

[[nodiscard]] std::string build_provider_script(std::string_view payload) {
  std::string script;
  script.reserve(payload.size() + 64u);
  script += "#!/bin/sh\n";
  script += "cat <<'__EIPPF_PROVIDER_EOF__'\n";
  script += std::string(payload);
  if (payload.empty() || payload.back() != '\n') {
    script.push_back('\n');
  }
  script += "__EIPPF_PROVIDER_EOF__\n";
  return script;
}

[[nodiscard]] std::string build_bundle_command(const std::filesystem::path& input_path,
                                               const std::filesystem::path& bundle_path,
                                               const std::filesystem::path& manifest_path,
                                               const std::filesystem::path& provider_path,
                                               std::string_view key_id) {
  return std::string(EIPPF_DEX_TOOLCHAIN_PATH) + " --input=" + quote_arg(input_path.string()) +
         " --output-bundle=" + quote_arg(bundle_path.string()) + " --manifest=" +
         quote_arg(manifest_path.string()) + " --key-provider=" + quote_arg(provider_path.string()) +
         " --key-id=" + std::string(key_id);
}

[[nodiscard]] std::string build_loader_command(const std::filesystem::path& bundle_path,
                                               const std::filesystem::path& manifest_path,
                                               const std::filesystem::path& provider_path,
                                               std::string_view key_id,
                                               std::string_view bridge_token,
                                               const std::filesystem::path& report_path,
                                               bool with_bridge_token) {
  std::string command = std::string(EIPPF_DEX_LOADER_PATH) + " --input-bundle=" +
                        quote_arg(bundle_path.string()) + " --manifest=" +
                        quote_arg(manifest_path.string()) + " --key-provider=" +
                        quote_arg(provider_path.string()) + " --key-id=" + std::string(key_id) +
                        " --report=" + quote_arg(report_path.string());
  if (with_bridge_token) {
    command += " --bridge-token=";
    command += std::string(bridge_token);
  }
  return command;
}

[[nodiscard]] std::uint64_t fnv1a64(std::string_view text) noexcept {
  std::uint64_t hash = kFnvOffset;
  for (const char ch : text) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= kFnvPrime;
  }
  return hash;
}

[[nodiscard]] std::string to_hex_u64(std::uint64_t value) {
  std::string out(16u, '0');
  for (std::size_t i = 0u; i < out.size(); ++i) {
    const std::size_t index = out.size() - 1u - i;
    const std::uint8_t nibble = static_cast<std::uint8_t>(value & 0x0Fu);
    out[index] = static_cast<char>(nibble < 10u ? ('0' + nibble) : ('a' + (nibble - 10u)));
    value >>= 4u;
  }
  return out;
}

[[nodiscard]] std::string make_bridge_token(std::string_view key_id) {
  std::string bridge_material(key_id);
  bridge_material += '\x1f';
  bridge_material += '0';
  bridge_material += '\x1f';
  bridge_material += '0';
  bridge_material += '\x1f';
  bridge_material += "eippf.dex.bridge.v1";
  return to_hex_u64(fnv1a64(bridge_material));
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

bool expect_contains(std::string_view label, std::string_view haystack, std::string_view needle) {
  if (haystack.find(needle) != std::string::npos) {
    return true;
  }
  std::cerr << "[FAIL] " << label << " missing marker: " << needle << '\n';
  return false;
}

[[nodiscard]] bool has_disallowed_sidecar(const std::filesystem::path& dir,
                                          std::string& offending_file) {
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    std::string ext = entry.path().extension().string();
    for (char& ch : ext) {
      if (ch >= 'A' && ch <= 'Z') {
        ch = static_cast<char>(ch - 'A' + 'a');
      }
    }
    if (ext == ".dex" || ext == ".jar" || ext == ".tmp" || ext == ".plain" || ext == ".dec") {
      offending_file = entry.path().filename().string();
      return true;
    }
  }
  return false;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  constexpr std::string_view kKeyId = "dex-security-edge";
  const std::filesystem::path input_path = temp_dir / "classes.input";
  const std::filesystem::path bundle_path = temp_dir / "classes.eippf";
  const std::filesystem::path manifest_path = temp_dir / "classes.manifest.json";
  const std::filesystem::path provider_path = temp_dir / "provider_ok.sh";
  const std::filesystem::path guardrail_report_path = temp_dir / "loader.guardrail.report.json";
  const std::filesystem::path invalid_token_report_path = temp_dir / "loader.invalid_token.report.json";

  const std::vector<std::uint8_t> dex_bytes = {
      static_cast<std::uint8_t>('d'), static_cast<std::uint8_t>('e'),
      static_cast<std::uint8_t>('x'), static_cast<std::uint8_t>('\n'),
      static_cast<std::uint8_t>('0'), static_cast<std::uint8_t>('3'),
      static_cast<std::uint8_t>('5'), 0u,
      static_cast<std::uint8_t>('S'), static_cast<std::uint8_t>('E'),
      static_cast<std::uint8_t>('C'), static_cast<std::uint8_t>('U'),
      static_cast<std::uint8_t>('R'), static_cast<std::uint8_t>('E'),
      static_cast<std::uint8_t>('D'),
  };

  if (!write_bytes(input_path, dex_bytes) ||
      !write_executable_script(
      provider_path,
          build_provider_script(provider_payload("ok", kKeyId, "90")))) {
    std::cerr << "[FAIL] cannot write fixtures\n";
    return 1;
  }

  if (!expect_status("bundle generation",
                     build_bundle_command(input_path, bundle_path, manifest_path, provider_path, kKeyId),
                     0)) {
    return 1;
  }

  const std::string guardrail_command =
      "EIPPF_SIMULATE_FRIDA=1 " +
      build_loader_command(
          bundle_path, manifest_path, provider_path, kKeyId, "", guardrail_report_path, false);
  if (!expect_nonzero("guardrail blocked", guardrail_command)) {
    return 1;
  }

  const std::string guardrail_report = read_text(guardrail_report_path);
  if (!expect_contains("guardrail report", guardrail_report, "\"guardrail_status\":\"blocked\"") ||
      !expect_contains("guardrail report", guardrail_report, "\"result\":\"guardrail_blocked\"") ||
      !expect_contains(
          "guardrail report", guardrail_report, "\"provider_endpoint_kind\":\"executable_adapter\"")) {
    return 1;
  }

  const std::string invalid_token_command = build_loader_command(bundle_path,
                                                                 manifest_path,
                                                                 provider_path,
                                                                 kKeyId,
                                                                 "invalid-token",
                                                                 invalid_token_report_path,
                                                                 true);
  if (!expect_nonzero("invalid bridge token format", invalid_token_command)) {
    return 1;
  }

  const std::string invalid_token_report = read_text(invalid_token_report_path);
  if (!expect_contains(
          "invalid token report", invalid_token_report, "\"bridge_token_status\":\"invalid_format\"") ||
      !expect_contains(
          "invalid token report", invalid_token_report, "\"result\":\"invalid_cli\"")) {
    return 1;
  }

  const std::filesystem::path success_report_path = temp_dir / "loader.success.report.json";
  const std::string success_command =
      build_loader_command(bundle_path,
                           manifest_path,
                           provider_path,
                           kKeyId,
                           make_bridge_token(kKeyId),
                           success_report_path,
                           true);
  if (!expect_status("loader success with valid token", success_command, 0)) {
    return 1;
  }

  std::string offending_file;
  if (has_disallowed_sidecar(temp_dir, offending_file)) {
    std::cerr << "[FAIL] plaintext sidecar detected: " << offending_file << '\n';
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

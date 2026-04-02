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
#include <sys/wait.h>
#endif

#ifndef EIPPF_SCRIPT_GUARD_PATH
#error "EIPPF_SCRIPT_GUARD_PATH must be defined"
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

[[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] bool contains_bytes(const std::vector<std::uint8_t>& haystack,
                                  std::string_view needle) {
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

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_script_guard_test_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

[[nodiscard]] std::string build_command(const std::filesystem::path& input_path,
                                        const std::filesystem::path& bundle_path,
                                        const std::filesystem::path& manifest_path,
                                        const std::filesystem::path& provider_path,
                                        std::string_view key_id) {
  return std::string(EIPPF_SCRIPT_GUARD_PATH) + " --input-script=" + quote_arg(input_path.string()) +
         " --output-bundle=" + quote_arg(bundle_path.string()) + " --manifest=" +
         quote_arg(manifest_path.string()) + " --key-provider=" + quote_arg(provider_path.string()) +
         " --key-id=" + std::string(key_id);
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

bool expect_status(std::string_view label, const std::string& command, int expected_status) {
  const int status = normalize_status(std::system(command.c_str()));
  if (status == expected_status) {
    return true;
  }
  std::cerr << "[FAIL] " << label << " returned " << status << ", expected " << expected_status << '\n';
  return false;
}

bool expect_absent(std::string_view label, const std::filesystem::path& path) {
  if (!std::filesystem::exists(path)) {
    return true;
  }
  std::cerr << "[FAIL] " << label << " should not exist: " << path << '\n';
  return false;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  const std::filesystem::path input_path = temp_dir / "guard.sh";
  const std::filesystem::path bundle_path = temp_dir / "guard.eippf";
  const std::filesystem::path manifest_path = temp_dir / "guard.manifest.json";
  const std::filesystem::path key_provider_path = temp_dir / "script.key_provider";
  const std::filesystem::path rejected_provider_path = temp_dir / "script.rejected_provider";
  const std::filesystem::path malformed_provider_path = temp_dir / "script.malformed_provider";
  const std::filesystem::path mismatch_provider_path = temp_dir / "script.mismatch_provider";
  const std::filesystem::path missing_provider_path = temp_dir / "script.missing_provider";
  const std::string script = "#!/bin/sh\necho SECRET_ANCHOR\n";

  if (!write_text(input_path, script)) {
    std::cerr << "[FAIL] cannot write script input\n";
    return 1;
  }
  if (!write_text(key_provider_path, provider_text("ok", "script-smoke", "93")) ||
      !write_text(rejected_provider_path, provider_text("deny", "script-smoke", "93")) ||
      !write_text(malformed_provider_path,
                  "protocol=wrong\nstatus=ok\nkey_id=script-smoke\nkey_u8=93\n") ||
      !write_text(mismatch_provider_path, provider_text("ok", "other-key", "93"))) {
    std::cerr << "[FAIL] cannot write key provider fixtures\n";
    return 1;
  }

  if (!expect_status("happy path",
                     build_command(input_path, bundle_path, manifest_path, key_provider_path, "script-smoke"),
                     0)) {
    return 1;
  }

  const std::vector<std::uint8_t> bundle = read_bytes(bundle_path);
  if (bundle.size() <= script.size()) {
    std::cerr << "[FAIL] bundle should be larger than plaintext script\n";
    return 1;
  }
  if (bundle.size() < 4u || bundle[0] != static_cast<std::uint8_t>('E') ||
      bundle[1] != static_cast<std::uint8_t>('S') ||
      bundle[2] != static_cast<std::uint8_t>('H') ||
      bundle[3] != static_cast<std::uint8_t>('B')) {
    std::cerr << "[FAIL] bundle header mismatch\n";
    return 1;
  }
  if (contains_bytes(bundle, "SECRET_ANCHOR")) {
    std::cerr << "[FAIL] encrypted bundle must not expose plaintext anchor\n";
    return 1;
  }

  const std::string manifest = read_text_file(manifest_path);
  if (manifest.find("\"kind\":\"shell_script_bundle\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest kind mismatch\n";
    return 1;
  }
  if (manifest.find("\"execution_model\":\"ephemeral_decrypt_execute\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest execution model mismatch\n";
    return 1;
  }
  if (manifest.find("\"key_provider_protocol\":\"eippf.external_key.v1\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest key provider protocol mismatch\n";
    return 1;
  }
  if (manifest.find("\"key_id\":\"script-smoke\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest key id mismatch\n";
    return 1;
  }
  if (manifest.find("\"key_material_embedded\":false") == std::string::npos) {
    std::cerr << "[FAIL] manifest should require external key material\n";
    return 1;
  }
  if (manifest.find("encryption_key") != std::string::npos ||
      manifest.find("input_hash_fnv1a64") != std::string::npos) {
    std::cerr << "[FAIL] manifest must not leak key or plaintext fingerprint\n";
    return 1;
  }
  if (manifest.find("\"contains_shebang\":true") == std::string::npos) {
    std::cerr << "[FAIL] manifest should preserve shebang metadata\n";
    return 1;
  }
  if (manifest.find("\"plaintext_output\":false") == std::string::npos) {
    std::cerr << "[FAIL] manifest plaintext guarantee missing\n";
    return 1;
  }
  if (!contains_bytes(bundle, "script-smoke")) {
    std::cerr << "[FAIL] bundle should carry key binding id metadata\n";
    return 1;
  }

  const std::filesystem::path missing_bundle_path = temp_dir / "missing.eippf";
  const std::filesystem::path missing_manifest_out = temp_dir / "missing.manifest.json";
  if (!expect_status("missing provider",
                     build_command(input_path,
                                   missing_bundle_path,
                                   missing_manifest_out,
                                   missing_provider_path,
                                   "script-smoke"),
                     7) ||
      !expect_absent("missing provider bundle", missing_bundle_path) ||
      !expect_absent("missing provider manifest", missing_manifest_out)) {
    return 1;
  }

  const std::filesystem::path rejected_bundle_path = temp_dir / "rejected.eippf";
  const std::filesystem::path rejected_manifest_out = temp_dir / "rejected.manifest.json";
  if (!expect_status("rejected provider",
                     build_command(input_path,
                                   rejected_bundle_path,
                                   rejected_manifest_out,
                                   rejected_provider_path,
                                   "script-smoke"),
                     9) ||
      !expect_absent("rejected provider bundle", rejected_bundle_path) ||
      !expect_absent("rejected provider manifest", rejected_manifest_out)) {
    return 1;
  }

  const std::filesystem::path malformed_bundle_path = temp_dir / "malformed.eippf";
  const std::filesystem::path malformed_manifest_out = temp_dir / "malformed.manifest.json";
  if (!expect_status("malformed provider",
                     build_command(input_path,
                                   malformed_bundle_path,
                                   malformed_manifest_out,
                                   malformed_provider_path,
                                   "script-smoke"),
                     8) ||
      !expect_absent("malformed provider bundle", malformed_bundle_path) ||
      !expect_absent("malformed provider manifest", malformed_manifest_out)) {
    return 1;
  }

  const std::filesystem::path mismatch_bundle_path = temp_dir / "mismatch.eippf";
  const std::filesystem::path mismatch_manifest_out = temp_dir / "mismatch.manifest.json";
  if (!expect_status("key id mismatch",
                     build_command(input_path,
                                   mismatch_bundle_path,
                                   mismatch_manifest_out,
                                   mismatch_provider_path,
                                   "script-smoke"),
                     10) ||
      !expect_absent("mismatch provider bundle", mismatch_bundle_path) ||
      !expect_absent("mismatch provider manifest", mismatch_manifest_out)) {
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

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

#ifndef EIPPF_DEX_TOOLCHAIN_PATH
#error "EIPPF_DEX_TOOLCHAIN_PATH must be defined"
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

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
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

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
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
                                         ("eippf_dex_toolchain_test_" +
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
  return std::string(EIPPF_DEX_TOOLCHAIN_PATH) + " --input=" + quote_arg(input_path.string()) +
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

  const std::filesystem::path input_path = temp_dir / "classes.dex";
  const std::filesystem::path bundle_path = temp_dir / "classes.eippf";
  const std::filesystem::path manifest_path = temp_dir / "classes.manifest.json";
  const std::filesystem::path key_provider_path = temp_dir / "dex.key_provider";
  const std::filesystem::path rejected_provider_path = temp_dir / "dex.rejected_provider";
  const std::filesystem::path malformed_provider_path = temp_dir / "dex.malformed_provider";
  const std::filesystem::path mismatch_provider_path = temp_dir / "dex.mismatch_provider";
  const std::filesystem::path missing_provider_path = temp_dir / "dex.missing_provider";

  const std::vector<std::uint8_t> dex_bytes = {
      static_cast<std::uint8_t>('d'), static_cast<std::uint8_t>('e'),
      static_cast<std::uint8_t>('x'), static_cast<std::uint8_t>('\n'),
      static_cast<std::uint8_t>('0'), static_cast<std::uint8_t>('3'),
      static_cast<std::uint8_t>('5'), 0u,
      static_cast<std::uint8_t>('S'), static_cast<std::uint8_t>('E'),
      static_cast<std::uint8_t>('C'), static_cast<std::uint8_t>('R'),
      static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('T'),
      static_cast<std::uint8_t>('_'), static_cast<std::uint8_t>('A'),
      static_cast<std::uint8_t>('N'), static_cast<std::uint8_t>('C'),
      static_cast<std::uint8_t>('H'), static_cast<std::uint8_t>('O'),
      static_cast<std::uint8_t>('R'),
  };

  if (!write_bytes(input_path, dex_bytes)) {
    std::cerr << "[FAIL] cannot write dex input\n";
    return 1;
  }
  if (!write_text(key_provider_path, provider_text("ok", "dex-smoke", "42")) ||
      !write_text(rejected_provider_path, provider_text("deny", "dex-smoke", "42")) ||
      !write_text(malformed_provider_path,
                  "protocol=wrong\nstatus=ok\nkey_id=dex-smoke\nkey_u8=42\n") ||
      !write_text(mismatch_provider_path, provider_text("ok", "other-key", "42"))) {
    std::cerr << "[FAIL] cannot write key provider fixtures\n";
    return 1;
  }

  if (!expect_status("happy path",
                     build_command(input_path, bundle_path, manifest_path, key_provider_path, "dex-smoke"),
                     0)) {
    return 1;
  }

  const std::vector<std::uint8_t> bundle = read_bytes(bundle_path);
  if (bundle.size() <= dex_bytes.size()) {
    std::cerr << "[FAIL] bundle should be larger than input dex\n";
    return 1;
  }
  if (bundle.size() < 4u || bundle[0] != static_cast<std::uint8_t>('E') ||
      bundle[1] != static_cast<std::uint8_t>('D') ||
      bundle[2] != static_cast<std::uint8_t>('X') ||
      bundle[3] != static_cast<std::uint8_t>('B')) {
    std::cerr << "[FAIL] bundle header mismatch\n";
    return 1;
  }
  if (contains_bytes(bundle, "SECRET_ANCHOR")) {
    std::cerr << "[FAIL] encrypted bundle must not expose plaintext anchor\n";
    return 1;
  }

  const std::string manifest = read_text(manifest_path);
  if (manifest.find("\"kind\":\"android_dex_bundle\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest kind mismatch\n";
    return 1;
  }
  if (manifest.find("\"target_kind\":\"android_dex_research\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest target kind mismatch\n";
    return 1;
  }
  if (manifest.find("\"key_provider_protocol\":\"eippf.external_key.v1\"") == std::string::npos) {
    std::cerr << "[FAIL] manifest key provider protocol mismatch\n";
    return 1;
  }
  if (manifest.find("\"key_id\":\"dex-smoke\"") == std::string::npos) {
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
  if (manifest.find("\"plaintext_output\":false") == std::string::npos) {
    std::cerr << "[FAIL] manifest plaintext guarantee missing\n";
    return 1;
  }
  if (!contains_bytes(bundle, "dex-smoke")) {
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
                                   "dex-smoke"),
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
                                   "dex-smoke"),
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
                                   "dex-smoke"),
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
                                   "dex-smoke"),
                     10) ||
      !expect_absent("mismatch provider bundle", mismatch_bundle_path) ||
      !expect_absent("mismatch provider manifest", mismatch_manifest_out)) {
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

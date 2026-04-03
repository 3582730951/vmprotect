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
                                         ("eippf_android_dex_failure_" +
                                          std::to_string(static_cast<long long>(stamp)));
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
                                               bool with_bridge_token) {
  std::string command = std::string(EIPPF_DEX_LOADER_PATH) + " --input-bundle=" +
                        quote_arg(bundle_path.string()) + " --manifest=" +
                        quote_arg(manifest_path.string()) + " --key-provider=" +
                        quote_arg(provider_path.string()) + " --key-id=" + std::string(key_id);
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

bool write_manifest_missing_required_field(const std::filesystem::path& source_manifest,
                                           const std::filesystem::path& output_manifest) {
  std::string manifest = read_text(source_manifest);
  if (manifest.empty()) {
    return false;
  }

  const std::vector<std::string> markers = {
      "\"loader_format_version\"",
      "\"runtime_lane\"",
      "\"backend_kind\"",
      "\"target_kind\"",
  };

  for (const std::string& marker : markers) {
    const std::size_t pos = manifest.find(marker);
    if (pos == std::string::npos) {
      continue;
    }
    const std::size_t line_begin = [&]() -> std::size_t {
      const std::size_t begin = manifest.rfind('\n', pos);
      return begin == std::string::npos ? 0u : begin + 1u;
    }();
    const std::size_t line_end = [&]() -> std::size_t {
      const std::size_t end = manifest.find('\n', pos);
      return end == std::string::npos ? manifest.size() : end + 1u;
    }();
    manifest.erase(line_begin, line_end - line_begin);
    return write_text(output_manifest, manifest);
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

  constexpr std::string_view kKeyId = "dex-failure";
  const std::filesystem::path input_path = temp_dir / "classes.input";
  const std::filesystem::path bundle_path = temp_dir / "classes.eippf";
  const std::filesystem::path manifest_path = temp_dir / "classes.manifest.json";
  const std::filesystem::path missing_manifest_path = temp_dir / "classes.missing.manifest.json";
  const std::filesystem::path bad_bundle_path = temp_dir / "classes.bad.eippf";

  const std::filesystem::path provider_ok = temp_dir / "provider_ok.sh";
  const std::filesystem::path provider_malformed = temp_dir / "provider_malformed.sh";
  const std::filesystem::path provider_rejected = temp_dir / "provider_rejected.sh";
  const std::filesystem::path provider_mismatch = temp_dir / "provider_mismatch.sh";
  const std::filesystem::path provider_regular = temp_dir / "provider_regular.txt";
  const std::filesystem::path provider_symlink = temp_dir / "provider_symlink.sh";
  const std::filesystem::path provider_missing = temp_dir / "provider_missing.sh";

  const std::vector<std::uint8_t> dex_bytes = {
      static_cast<std::uint8_t>('d'), static_cast<std::uint8_t>('e'),
      static_cast<std::uint8_t>('x'), static_cast<std::uint8_t>('\n'),
      static_cast<std::uint8_t>('0'), static_cast<std::uint8_t>('3'),
      static_cast<std::uint8_t>('5'), 0u,
      static_cast<std::uint8_t>('F'), static_cast<std::uint8_t>('A'),
      static_cast<std::uint8_t>('I'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('U'), static_cast<std::uint8_t>('R'),
      static_cast<std::uint8_t>('E'),
  };
  if (!write_bytes(input_path, dex_bytes)) {
    std::cerr << "[FAIL] cannot write dex fixture\n";
    return 1;
  }

  if (!write_executable_script(
          provider_ok,
          build_provider_script(provider_payload("ok", kKeyId, "61"))) ||
      !write_executable_script(
          provider_malformed,
          build_provider_script("protocol=invalid\nstatus=ok\nkey_id=dex-failure\nkey_u8=61\n")) ||
      !write_executable_script(
          provider_rejected,
          build_provider_script(provider_payload("deny", kKeyId, "61"))) ||
      !write_executable_script(
          provider_mismatch,
          build_provider_script(provider_payload("ok", "wrong-key-id", "61"))) ||
      !write_text(provider_regular, provider_payload("ok", kKeyId, "61"))) {
    std::cerr << "[FAIL] cannot create provider fixtures\n";
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove(provider_symlink, ec);
  ec.clear();
  std::filesystem::create_symlink(provider_regular, provider_symlink, ec);
  if (ec) {
    std::cerr << "[FAIL] cannot create symlink provider fixture\n";
    return 1;
  }

  if (!expect_status("bundle generation",
                     build_bundle_command(input_path, bundle_path, manifest_path, provider_ok, kKeyId),
                     0)) {
    return 1;
  }

  const std::string bridge_token = make_bridge_token(kKeyId);

  if (!expect_nonzero(
          "missing provider",
          build_loader_command(bundle_path, manifest_path, provider_missing, kKeyId, bridge_token, true)) ||
      !expect_nonzero(
          "provider malformed",
          build_loader_command(bundle_path, manifest_path, provider_malformed, kKeyId, bridge_token, true)) ||
      !expect_nonzero(
          "provider rejected",
          build_loader_command(bundle_path, manifest_path, provider_rejected, kKeyId, bridge_token, true)) ||
      !expect_nonzero(
          "key_id mismatch",
          build_loader_command(bundle_path, manifest_path, provider_mismatch, kKeyId, bridge_token, true)) ||
      !expect_nonzero(
          "regular file provider",
          build_loader_command(bundle_path, manifest_path, provider_regular, kKeyId, bridge_token, true)) ||
      !expect_nonzero(
          "symlink regular-file provider",
          build_loader_command(bundle_path, manifest_path, provider_symlink, kKeyId, bridge_token, true))) {
    return 1;
  }

  if (!write_manifest_missing_required_field(manifest_path, missing_manifest_path)) {
    std::cerr << "[FAIL] cannot create missing-field manifest\n";
    return 1;
  }
  if (!expect_nonzero(
          "manifest missing required field",
          build_loader_command(bundle_path, missing_manifest_path, provider_ok, kKeyId, bridge_token, true))) {
    return 1;
  }

  std::vector<std::uint8_t> bundle_bytes = read_bytes(bundle_path);
  if (bundle_bytes.size() < 5u) {
    std::cerr << "[FAIL] bundle too small for header mutation\n";
    return 1;
  }
  bundle_bytes[4] = 0x7Fu;
  if (!write_bytes(bad_bundle_path, bundle_bytes)) {
    std::cerr << "[FAIL] cannot write bad-version bundle\n";
    return 1;
  }
  if (!expect_nonzero(
          "bundle header version mismatch",
          build_loader_command(bad_bundle_path, manifest_path, provider_ok, kKeyId, bridge_token, true))) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

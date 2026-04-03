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
                                         ("eippf_script_launcher_success_" +
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

[[nodiscard]] std::string build_guard_command(const std::filesystem::path& input_path,
                                              const std::filesystem::path& bundle_path,
                                              const std::filesystem::path& manifest_path,
                                              const std::filesystem::path& provider_path,
                                              std::string_view key_id) {
  return std::string(EIPPF_SCRIPT_GUARD_PATH) + " --input-script=" + quote_arg(input_path.string()) +
         " --output-bundle=" + quote_arg(bundle_path.string()) + " --manifest=" +
         quote_arg(manifest_path.string()) + " --key-provider=" + quote_arg(provider_path.string()) +
         " --key-id=" + std::string(key_id);
}

[[nodiscard]] std::string build_launcher_command(const std::filesystem::path& bundle_path,
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

bool has_plaintext_sidecar(const std::filesystem::path& dir) {
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    const std::string ext = entry.path().extension().string();
    if (ext == ".plain" || ext == ".tmp" || ext == ".dec") {
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

  const std::filesystem::path script_path = temp_dir / "launcher_success.sh";
  const std::filesystem::path bundle_path = temp_dir / "launcher_success.eippf";
  const std::filesystem::path manifest_path = temp_dir / "launcher_success.manifest.json";
  const std::filesystem::path provider_path = temp_dir / "launcher_success.provider.sh";
  const std::filesystem::path output_path = temp_dir / "launcher_success.out";

  const std::string script =
      "#!/bin/sh\n"
      "echo SECRET_ANCHOR\n"
      "printf 'ARGS:%s:%s\\n' \"$1\" \"$2\"\n";
  const std::string provider_payload = provider_text("ok", "launcher-success", "77");
  std::string provider_script;
  provider_script.reserve(provider_payload.size() + 48u);
  provider_script += "#!/bin/sh\n";
  provider_script += "cat <<'__EIPPF_PROVIDER_EOF__'\n";
  provider_script += provider_payload;
  provider_script += "__EIPPF_PROVIDER_EOF__\n";

  if (!write_text(script_path, script)) {
    std::cerr << "[FAIL] cannot write script fixture\n";
    return 1;
  }
  if (!write_executable_script(provider_path, provider_script)) {
    std::cerr << "[FAIL] cannot write provider adapter\n";
    return 1;
  }

  if (!expect_status("bundle generation",
                     build_guard_command(script_path,
                                         bundle_path,
                                         manifest_path,
                                         provider_path,
                                         "launcher-success"),
                     0)) {
    return 1;
  }

  if (!expect_status("launcher execution",
                     build_launcher_command(bundle_path,
                                            manifest_path,
                                            provider_path,
                                            "launcher-success",
                                            output_path),
                     0)) {
    return 1;
  }

  const std::string output = read_text(output_path);
  if (output.find("SECRET_ANCHOR") == std::string::npos) {
    std::cerr << "[FAIL] launcher output missing script payload\n";
    return 1;
  }
  if (output.find("ARGS:alpha:beta") == std::string::npos) {
    std::cerr << "[FAIL] launcher output missing argv passthrough\n";
    return 1;
  }

  const std::vector<std::uint8_t> bundle = read_bytes(bundle_path);
  if (contains_bytes(bundle, "SECRET_ANCHOR")) {
    std::cerr << "[FAIL] bundle should not expose plaintext anchor\n";
    return 1;
  }

  if (has_plaintext_sidecar(temp_dir)) {
    std::cerr << "[FAIL] launcher should not create .plain/.tmp/.dec sidecar\n";
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

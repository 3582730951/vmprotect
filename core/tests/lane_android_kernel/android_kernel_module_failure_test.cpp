#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

#ifndef EIPPF_ARTIFACT_AUDIT_PATH
#error "EIPPF_ARTIFACT_AUDIT_PATH must be defined"
#endif

#ifndef EIPPF_LEXICAL_DENYLIST_PATH
#error "EIPPF_LEXICAL_DENYLIST_PATH must be defined"
#endif

#ifndef EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH
#error "EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH must be defined"
#endif

#ifndef EIPPF_SIGNATURE_VERIFIER_WORK_DIR
#error "EIPPF_SIGNATURE_VERIFIER_WORK_DIR must be defined"
#endif

namespace {

[[nodiscard]] std::string quote_arg(const std::string& value) {
  std::string out = "\"";
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
#endif
  return status;
}

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
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

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::vector<std::uint8_t> build_signed_elf_fixture() {
  std::vector<std::uint8_t> bytes(0x40 + 0x38, 0u);
  bytes[0] = 0x7f;
  bytes[1] = static_cast<std::uint8_t>('E');
  bytes[2] = static_cast<std::uint8_t>('L');
  bytes[3] = static_cast<std::uint8_t>('F');
  bytes[4] = 2;
  bytes[5] = 1;
  bytes[0x20] = 0x40;
  bytes[0x36] = 0x38;
  bytes[0x38] = 1;
  bytes[0x40] = 1;

  const std::string signer = "ci";
  const std::string key_id = "keyid";
  const std::vector<std::uint8_t> signature = {0x30u, 0x82u, 0x01u, 0x0Au};
  bytes.insert(bytes.end(), signer.begin(), signer.end());
  bytes.insert(bytes.end(), key_id.begin(), key_id.end());
  bytes.insert(bytes.end(), signature.begin(), signature.end());

  std::vector<std::uint8_t> footer(12u, 0u);
  footer[0] = 1u;
  footer[1] = 1u;
  footer[2] = 2u;
  footer[3] = static_cast<std::uint8_t>(signer.size());
  footer[4] = static_cast<std::uint8_t>(key_id.size());
  const std::uint32_t sig_len = static_cast<std::uint32_t>(signature.size());
  footer[8] = static_cast<std::uint8_t>((sig_len >> 24u) & 0xFFu);
  footer[9] = static_cast<std::uint8_t>((sig_len >> 16u) & 0xFFu);
  footer[10] = static_cast<std::uint8_t>((sig_len >> 8u) & 0xFFu);
  footer[11] = static_cast<std::uint8_t>(sig_len & 0xFFu);
  bytes.insert(bytes.end(), footer.begin(), footer.end());
  const char magic[] = "~Module signature appended~\n";
  bytes.insert(bytes.end(), magic, magic + sizeof(magic) - 1);
  return bytes;
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

[[nodiscard]] std::filesystem::path make_verifier_wrapper(const std::filesystem::path& dir) {
  const std::filesystem::path wrapper = dir / "signature_verifier_success.sh";
  const std::string script = std::string("#!/usr/bin/env bash\nexec python3 ") +
                             quote_arg(EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH) +
                             " --mode success \"$@\"\n";
  if (!write_executable_script(wrapper, script)) {
    return {};
  }
  return wrapper;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     ("eippf_android_kernel_failure_" +
                                      std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    return {};
  }
  return path;
}

[[nodiscard]] int run_audit(const std::filesystem::path& artifact,
                            const std::filesystem::path& report,
                            const std::filesystem::path& manifest,
                            const std::filesystem::path& verifier) {
  std::string command = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) +
                        " --input " + quote_arg(artifact.string()) + " --denylist " +
                        quote_arg(EIPPF_LEXICAL_DENYLIST_PATH) + " --output " +
                        quote_arg(report.string()) + " --manifest " + quote_arg(manifest.string()) +
                        " --signature-verifier " + quote_arg(verifier.string()) + " --strict";
  return normalize_status(std::system(command.c_str()));
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp dir")) {
    return 1;
  }

  const std::filesystem::path trusted_dir = EIPPF_SIGNATURE_VERIFIER_WORK_DIR;
  std::error_code ec;
  std::filesystem::create_directories(trusted_dir, ec);
  if (!expect(!ec, "failed to create trusted verifier dir")) {
    return 1;
  }
  const std::filesystem::path verifier = make_verifier_wrapper(trusted_dir);
  if (!expect(!verifier.empty(), "failed to create verifier wrapper")) {
    return 1;
  }

  const std::filesystem::path artifact_path = temp_dir / "module.ko";
  const std::filesystem::path manifest_path = temp_dir / "module_bad.manifest.json";
  const std::filesystem::path report_path = temp_dir / "module.audit.json";
  const std::string bad_manifest =
      "{\"target_kind\":\"android_kernel_module\",\"artifact_kind\":\"linux_kernel_module_ko\","
      "\"runtime_lane\":\"kernel_safe\",\"mutation_profile\":\"kernel_module\","
      "\"signature_policy\":\"sign_after_mutate\",\"sign_after_mutate_required\":true,"
      "\"allow_jit\":false,\"allow_runtime_executable_pages\":false,"
      "\"allow_persistent_plaintext\":false,\"require_fail_closed\":true,"
      "\"kernel_compat_profile\":\"gki_kmi_profile\",\"hvci_profile\":false,"
      "\"vermagic_profile\":false,\"gki_kmi_profile\":false}\n";

  if (!write_bytes(artifact_path, build_signed_elf_fixture()) || !write_text(manifest_path, bad_manifest)) {
    std::cerr << "[FAIL] cannot write fixtures\n";
    return 1;
  }

  if (!expect(run_audit(artifact_path, report_path, manifest_path, verifier) != 0,
              "android kernel failure lane should fail")) {
    return 1;
  }
  const std::string report = read_text(report_path);
  if (!expect(report.find("gki_kmi_mismatch") != std::string::npos,
              "report missing gki_kmi_mismatch")) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

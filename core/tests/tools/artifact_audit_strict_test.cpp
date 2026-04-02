#include <algorithm>
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

struct PeFixtureOptions final {
  std::uint32_t text_characteristics = 0x60000020u;
  std::string payload = "clean_payload";
  std::string import_dll;
  std::string import_symbol;
  bool with_signature = false;
};

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

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_artifact_audit_test_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void write_u16_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
}

void write_u32_be(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 2] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 3] = static_cast<std::uint8_t>(value & 0xFFu);
}

[[nodiscard]] std::vector<std::uint8_t> build_pe_fixture(const PeFixtureOptions& options) {
  constexpr std::size_t kPeOffset = 0x80u;
  constexpr std::size_t kOptionalHeaderSize = 0xE0u;
  const bool has_import = !options.import_dll.empty() && !options.import_symbol.empty();
  const std::size_t section_count = has_import ? 2u : 1u;
  const std::size_t section_table_offset = kPeOffset + 4u + 20u + kOptionalHeaderSize;
  const std::size_t text_raw_offset = section_table_offset + (section_count * 40u);
  const std::size_t text_raw_size = std::max<std::size_t>(options.payload.size(), 1u);
  const std::size_t idata_raw_offset = text_raw_offset + text_raw_size;
  const std::size_t idata_raw_size = has_import ? 0x80u : 0u;
  const std::size_t cert_offset = idata_raw_offset + idata_raw_size;
  const std::size_t cert_size = options.with_signature ? 8u : 0u;

  std::vector<std::uint8_t> bytes(cert_offset + cert_size, 0u);
  bytes[0] = static_cast<std::uint8_t>('M');
  bytes[1] = static_cast<std::uint8_t>('Z');
  write_u32_le(bytes, 0x3Cu, static_cast<std::uint32_t>(kPeOffset));
  bytes[kPeOffset + 0u] = static_cast<std::uint8_t>('P');
  bytes[kPeOffset + 1u] = static_cast<std::uint8_t>('E');
  write_u16_le(bytes, kPeOffset + 4u, 0x014Cu);
  write_u16_le(bytes, kPeOffset + 6u, static_cast<std::uint16_t>(section_count));
  write_u16_le(bytes, kPeOffset + 20u, static_cast<std::uint16_t>(kOptionalHeaderSize));

  const std::size_t optional_offset = kPeOffset + 24u;
  write_u16_le(bytes, optional_offset + 0u, 0x10Bu);
  write_u32_le(bytes, optional_offset + 92u, 16u);

  const std::size_t text_section_offset = section_table_offset;
  bytes[text_section_offset + 0u] = static_cast<std::uint8_t>('.');
  bytes[text_section_offset + 1u] = static_cast<std::uint8_t>('t');
  bytes[text_section_offset + 2u] = static_cast<std::uint8_t>('e');
  bytes[text_section_offset + 3u] = static_cast<std::uint8_t>('x');
  bytes[text_section_offset + 4u] = static_cast<std::uint8_t>('t');
  write_u32_le(bytes, text_section_offset + 8u, static_cast<std::uint32_t>(text_raw_size));
  write_u32_le(bytes, text_section_offset + 12u, 0x1000u);
  write_u32_le(bytes, text_section_offset + 16u, static_cast<std::uint32_t>(text_raw_size));
  write_u32_le(bytes, text_section_offset + 20u, static_cast<std::uint32_t>(text_raw_offset));
  write_u32_le(bytes, text_section_offset + 36u, options.text_characteristics);

  for (std::size_t i = 0; i < options.payload.size(); ++i) {
    bytes[text_raw_offset + i] = static_cast<std::uint8_t>(options.payload[i]);
  }

  if (has_import) {
    const std::size_t idata_section_offset = text_section_offset + 40u;
    constexpr std::uint32_t kIdataVa = 0x2000u;
    bytes[idata_section_offset + 0u] = static_cast<std::uint8_t>('.');
    bytes[idata_section_offset + 1u] = static_cast<std::uint8_t>('i');
    bytes[idata_section_offset + 2u] = static_cast<std::uint8_t>('d');
    bytes[idata_section_offset + 3u] = static_cast<std::uint8_t>('a');
    bytes[idata_section_offset + 4u] = static_cast<std::uint8_t>('t');
    bytes[idata_section_offset + 5u] = static_cast<std::uint8_t>('a');
    write_u32_le(bytes, idata_section_offset + 8u, static_cast<std::uint32_t>(idata_raw_size));
    write_u32_le(bytes, idata_section_offset + 12u, kIdataVa);
    write_u32_le(bytes, idata_section_offset + 16u, static_cast<std::uint32_t>(idata_raw_size));
    write_u32_le(bytes, idata_section_offset + 20u, static_cast<std::uint32_t>(idata_raw_offset));
    write_u32_le(bytes, idata_section_offset + 36u, 0x40000040u);

    const std::string dll_name = options.import_dll + '\0';
    const std::string symbol_name = options.import_symbol + '\0';
    const std::size_t symbol_name_offset = idata_raw_offset + 0x3Au;
    const std::size_t dll_name_offset = symbol_name_offset + symbol_name.size();

    write_u32_le(bytes, optional_offset + 104u, kIdataVa);
    write_u32_le(bytes, optional_offset + 108u, 40u);

    write_u32_le(bytes, idata_raw_offset + 0u, kIdataVa + 0x28u);
    write_u32_le(bytes, idata_raw_offset + 12u,
                 kIdataVa + static_cast<std::uint32_t>(dll_name_offset - idata_raw_offset));
    write_u32_le(bytes, idata_raw_offset + 16u, kIdataVa + 0x30u);

    write_u32_le(bytes, idata_raw_offset + 0x28u, kIdataVa + 0x38u);
    write_u32_le(bytes, idata_raw_offset + 0x30u, kIdataVa + 0x38u);
    write_u16_le(bytes, idata_raw_offset + 0x38u, 0u);
    for (std::size_t i = 0; i < symbol_name.size(); ++i) {
      bytes[symbol_name_offset + i] = static_cast<std::uint8_t>(symbol_name[i]);
    }
    for (std::size_t i = 0; i < dll_name.size(); ++i) {
      bytes[dll_name_offset + i] = static_cast<std::uint8_t>(dll_name[i]);
    }
  }

  if (options.with_signature) {
    write_u32_le(bytes, optional_offset + 128u, static_cast<std::uint32_t>(cert_offset));
    write_u32_le(bytes, optional_offset + 132u, static_cast<std::uint32_t>(cert_size));
    write_u32_le(bytes, cert_offset + 0u, 8u);
    write_u16_le(bytes, cert_offset + 4u, 0x0200u);
    write_u16_le(bytes, cert_offset + 6u, 0x0002u);
  }

  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> build_elf64_fixture(bool add_signature_trailer) {
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
  const std::size_t ph = 0x40;
  bytes[ph + 0] = 1;
  bytes[ph + 4] = 0;
  if (add_signature_trailer) {
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
  }
  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> build_macho32_fixture(bool with_codesig_command) {
  std::vector<std::uint8_t> bytes(28u, 0u);
  bytes[0] = 0xCE;
  bytes[1] = 0xFA;
  bytes[2] = 0xED;
  bytes[3] = 0xFE;
  const std::uint32_t ncmds = with_codesig_command ? 1u : 0u;
  write_u32_le(bytes, 16u, ncmds);
  write_u32_le(bytes, 20u, with_codesig_command ? 16u : 0u);
  if (!with_codesig_command) {
    return bytes;
  }
  const std::size_t cmd_offset = 28u;
  const std::size_t blob_offset = cmd_offset + 16u;
  const std::size_t blob_size = 16u;
  bytes.resize(blob_offset + blob_size, 0u);
  write_u32_le(bytes, cmd_offset + 0u, 0x1Du);
  write_u32_le(bytes, cmd_offset + 4u, 16u);
  write_u32_le(bytes, cmd_offset + 8u, static_cast<std::uint32_t>(blob_offset));
  write_u32_le(bytes, cmd_offset + 12u, static_cast<std::uint32_t>(blob_size));
  write_u32_be(bytes, blob_offset + 0u, 0xFADE0CC0u);
  write_u32_be(bytes, blob_offset + 4u, static_cast<std::uint32_t>(blob_size));
  return bytes;
}

[[nodiscard]] int run_audit(const std::filesystem::path& artifact,
                            const std::filesystem::path& report,
                            const std::filesystem::path& denylist,
                            bool strict,
                            const std::vector<std::string>& extra_args = {}) {
  std::string cmd = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) + " --input " +
                    quote_arg(artifact.string()) + " --denylist " + quote_arg(denylist.string()) +
                    " --output " + quote_arg(report.string());
  for (const std::string& arg : extra_args) {
    cmd += " " + quote_arg(arg);
  }
  if (strict) {
    cmd += " --strict";
  }
  return normalize_status(std::system(cmd.c_str()));
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

[[nodiscard]] std::filesystem::path make_verifier_wrapper(const std::filesystem::path& output_dir,
                                                          std::string_view name,
                                                          std::string_view mode) {
  const std::filesystem::path wrapper_path = output_dir / (std::string(name) + ".sh");
  const std::string content = std::string("#!/usr/bin/env bash\nexec python3 ") +
                              quote_arg(EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH) + " --mode " +
                              quote_arg(std::string(mode)) + " \"$@\"\n";
  if (!write_executable_script(wrapper_path, content)) {
    return {};
  }
  return wrapper_path;
}

[[nodiscard]] bool report_has(const std::string& report, std::string_view needle) {
  return report.find(std::string(needle)) != std::string::npos;
}

bool expect_report_contains(const std::string& report, std::string_view needle, const char* message) {
  return expect(report_has(report, needle), message);
}

bool expect_report_not_contains(const std::string& report, std::string_view needle, const char* message) {
  return expect(!report_has(report, needle), message);
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp dir\n";
    return 1;
  }

  const std::filesystem::path trusted_verifier_dir = EIPPF_SIGNATURE_VERIFIER_WORK_DIR;
  std::error_code ec;
  std::filesystem::create_directories(trusted_verifier_dir, ec);
  if (ec) {
    std::cerr << "[FAIL] cannot create trusted verifier dir\n";
    return 1;
  }

  const std::filesystem::path clean_artifact = temp_dir / "clean.exe";
  const std::filesystem::path dirty_artifact = temp_dir / "dirty.exe";
  const std::filesystem::path rwx_artifact = temp_dir / "rwx.exe";
  const std::filesystem::path suspicious_import_artifact = temp_dir / "analysis_surface.exe";
  const std::filesystem::path unsigned_driver_artifact = temp_dir / "driver_unsigned.sys";
  const std::filesystem::path signed_driver_artifact = temp_dir / "driver_signed.sys";
  const std::filesystem::path manifest_driver_unsigned_artifact = temp_dir / "driver_by_manifest.exe";
  const std::filesystem::path manifest_driver_signed_artifact = temp_dir / "driver_signed_by_manifest.exe";
  const std::filesystem::path signed_ko_artifact = temp_dir / "signed_module.ko";
  const std::filesystem::path signed_macho_artifact = temp_dir / "signed_ios.bin";
  const std::filesystem::path ko_manifest_path = temp_dir / "ko.manifest.json";
  const std::filesystem::path ios_manifest_path = temp_dir / "ios.manifest.json";
  const std::filesystem::path win_driver_manifest_path = temp_dir / "win_driver.manifest.json";
  const std::filesystem::path report_path = temp_dir / "artifact.audit.json";
  const std::filesystem::path missing_denylist = temp_dir / "missing_denylist.txt";

  const std::vector<std::uint8_t> clean_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> dirty_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "SECRET_ANCHOR",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> rwx_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0xE0000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> suspicious_import_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "dbghelp.dll",
                                        .import_symbol = "SymInitialize"});
  const std::vector<std::uint8_t> signed_driver_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = "",
                                        .with_signature = true});
  const std::vector<std::uint8_t> unsigned_driver_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> signed_ko_bytes = build_elf64_fixture(true);
  const std::vector<std::uint8_t> signed_macho_bytes = build_macho32_fixture(true);

  if (!write_bytes(clean_artifact, clean_bytes) || !write_bytes(dirty_artifact, dirty_bytes) ||
      !write_bytes(rwx_artifact, rwx_bytes) ||
      !write_bytes(suspicious_import_artifact, suspicious_import_bytes) ||
      !write_bytes(unsigned_driver_artifact, unsigned_driver_bytes) ||
      !write_bytes(signed_driver_artifact, signed_driver_bytes) ||
      !write_bytes(manifest_driver_unsigned_artifact, unsigned_driver_bytes) ||
      !write_bytes(manifest_driver_signed_artifact, signed_driver_bytes) ||
      !write_bytes(signed_ko_artifact, signed_ko_bytes) ||
      !write_bytes(signed_macho_artifact, signed_macho_bytes)) {
    std::cerr << "[FAIL] cannot write test artifacts\n";
    return 1;
  }

  if (!write_text(ko_manifest_path,
                  "{\"target_kind\":\"linux_kernel_module\",\"artifact_kind\":\"linux_kernel_module_ko\"}\n") ||
      !write_text(ios_manifest_path, "{\"target_kind\":\"ios_appstore\",\"artifact_kind\":\"macho\"}\n") ||
      !write_text(win_driver_manifest_path,
                  "{\"target_kind\":\"windows_driver\",\"artifact_kind\":\"windows_driver_sys\"}\n")) {
    std::cerr << "[FAIL] cannot write manifest fixtures\n";
    return 1;
  }

  const std::filesystem::path verifier_success =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_success", "success");
  const std::filesystem::path verifier_reject =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_reject", "reject");
  const std::filesystem::path verifier_invalid_json =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_invalid_json", "invalid-json");
  const std::filesystem::path verifier_bad_schema =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_bad_schema", "bad-schema");
  const std::filesystem::path verifier_digest_mismatch =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_digest_mismatch", "digest-mismatch");
  const std::filesystem::path verifier_nonzero =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_nonzero", "nonzero");
  const std::filesystem::path verifier_empty =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_empty", "empty");
  const std::filesystem::path verifier_timeout =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_timeout", "timeout");
  const std::filesystem::path untrusted_verifier =
      make_verifier_wrapper(temp_dir, "signature_verifier_untrusted", "success");

  if (verifier_success.empty() || verifier_reject.empty() || verifier_invalid_json.empty() ||
      verifier_bad_schema.empty() || verifier_digest_mismatch.empty() || verifier_nonzero.empty() ||
      verifier_empty.empty() || verifier_timeout.empty() || untrusted_verifier.empty()) {
    std::cerr << "[FAIL] cannot write verifier wrappers\n";
    return 1;
  }

  const std::filesystem::path relative_verifier_path =
      std::filesystem::relative(verifier_success, std::filesystem::current_path(), ec);
  if (ec || relative_verifier_path.empty()) {
    std::cerr << "[FAIL] cannot build relative verifier path\n";
    return 1;
  }

  if (!expect(run_audit(clean_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) == 0,
              "strict audit should pass clean artifact")) {
    return 1;
  }
  const std::string clean_report = read_text(report_path);
  if (!expect_report_contains(clean_report, "\"validation_mode\": \"not_required\"",
                              "clean artifact should report not_required")) {
    return 1;
  }
  if (!expect_report_contains(clean_report, "\"signature_state_passed\": true",
                              "clean artifact should pass signature state")) {
    return 1;
  }
  if (!expect_report_contains(clean_report, "\"verifier_invoked\": false",
                              "clean artifact should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(clean_report, "\"verifier_error\": null",
                              "clean artifact should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--signature-verifier", verifier_success.string()}) == 0,
              "non-required artifact should ignore success verifier")) {
    return 1;
  }
  const std::string optional_success_report = read_text(report_path);
  if (!expect_report_contains(optional_success_report, "\"validation_mode\": \"optional_verifier_ignored\"",
                              "non-required artifact should ignore verifier")) {
    return 1;
  }
  if (!expect_report_contains(optional_success_report, "\"verifier_invoked\": false",
                              "non-required artifact should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(optional_success_report, "\"verifier_error\": null",
                              "ignored verifier should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(optional_success_report, "\"signature_state_passed\": true",
                              "ignored verifier should keep signature state passing")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--signature-verifier", verifier_nonzero.string()}) == 0,
              "non-required artifact should ignore failing verifier")) {
    return 1;
  }
  const std::string optional_nonzero_report = read_text(report_path);
  if (!expect_report_contains(optional_nonzero_report, "\"validation_mode\": \"optional_verifier_ignored\"",
                              "non-required artifact should ignore failing verifier")) {
    return 1;
  }
  if (!expect_report_contains(optional_nonzero_report, "\"verifier_invoked\": false",
                              "ignored failing verifier should not be invoked")) {
    return 1;
  }
  if (!expect_report_contains(optional_nonzero_report, "\"verifier_error\": null",
                              "ignored failing verifier should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(optional_nonzero_report, "\"signature_state_passed\": true",
                              "ignored failing verifier should keep signature state passing")) {
    return 1;
  }

  if (!expect(run_audit(dirty_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) != 0,
              "strict audit should fail artifact containing denylisted anchor")) {
    return 1;
  }

  if (!expect(run_audit(rwx_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) != 0,
              "strict audit should fail PE with writable executable section")) {
    return 1;
  }

  if (!expect(run_audit(suspicious_import_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) != 0,
              "strict audit should fail PE importing analysis-surface libraries")) {
    return 1;
  }

  if (!expect(run_audit(unsigned_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver"}) != 0,
              "unsigned driver should fail required_missing")) {
    return 1;
  }
  const std::string unsigned_driver_report = read_text(report_path);
  if (!expect_report_contains(unsigned_driver_report, "\"validation_mode\": \"required_missing\"",
                              "unsigned driver should report required_missing")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "\"signature_state_passed\": false",
                              "unsigned driver should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "\"verifier_invoked\": false",
                              "unsigned driver should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "\"verifier_error\": null",
                              "unsigned driver should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "signature_missing",
                              "unsigned driver should fail missing signature")) {
    return 1;
  }

  if (!expect(run_audit(manifest_driver_unsigned_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", win_driver_manifest_path.string()}) != 0,
              "manifest-driven unsigned driver should fail missing signature")) {
    return 1;
  }
  const std::string required_missing_report = read_text(report_path);
  if (!expect_report_contains(required_missing_report, "\"validation_mode\": \"required_missing\"",
                              "manifest-driven unsigned driver should report required_missing")) {
    return 1;
  }
  if (!expect_report_contains(required_missing_report, "signature_missing",
                              "manifest-driven unsigned driver should fail missing signature")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver"}) != 0,
              "required signed driver without verifier should fail authenticity")) {
    return 1;
  }
  const std::string required_no_verifier_report = read_text(report_path);
  if (!expect_report_contains(required_no_verifier_report,
                              "\"validation_mode\": \"required_authenticity_missing\"",
                              "required signed driver should require authenticity verifier")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "\"signature_state_passed\": false",
                              "required signed driver without verifier should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "\"verifier_invoked\": false",
                              "required signed driver without verifier should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "\"verifier_error\": null",
                              "required signed driver without verifier should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "signature_authenticity_missing",
                              "required signed driver should fail missing authenticity")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--signature-verifier", verifier_success.string()}) == 0,
              "required signed driver with success verifier should pass")) {
    return 1;
  }
  const std::string verifier_success_report = read_text(report_path);
  if (!expect_report_contains(verifier_success_report, "\"validation_mode\": \"external_verifier\"",
                              "success verifier should report external_verifier")) {
    return 1;
  }
  if (!expect_report_contains(verifier_success_report, "\"signature_state_passed\": true",
                              "success verifier should pass signature state")) {
    return 1;
  }
  if (!expect_report_contains(verifier_success_report, "\"verifier_invoked\": true",
                              "success verifier should be invoked")) {
    return 1;
  }
  if (!expect_report_contains(verifier_success_report, "\"verifier_error\": null",
                              "success verifier should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--signature-verifier", verifier_reject.string()}) != 0,
              "reject verifier should fail required signed driver")) {
    return 1;
  }
  const std::string verifier_reject_report = read_text(report_path);
  if (!expect_report_contains(verifier_reject_report, "\"validation_mode\": \"external_verifier\"",
                              "reject verifier should stay in external_verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report, "\"signature_state_passed\": false",
                              "reject verifier should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report, "\"verifier_invoked\": true",
                              "reject verifier should be invoked")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report,
                              "\"verifier_error\": \"signature_authenticity_rejected\"",
                              "reject verifier should report signature_authenticity_rejected")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report, "signature_authenticity_rejected",
                              "reject verifier should fail with authenticity rejected")) {
    return 1;
  }
  if (!expect_report_not_contains(verifier_reject_report, "signature_verifier_failed",
                                  "reject verifier should not report transport failure")) {
    return 1;
  }

  const std::vector<std::pair<std::filesystem::path, std::string>> verifier_failure_cases = {
      {verifier_nonzero, "signature_verifier_failed"},
      {verifier_invalid_json, "signature_verifier_failed"},
      {verifier_bad_schema, "signature_verifier_failed"},
      {verifier_empty, "signature_verifier_failed"},
      {verifier_timeout, "signature_verifier_failed"},
      {verifier_digest_mismatch, "signature_verifier_digest_mismatch"},
  };
  for (const auto& [verifier_path, expected_failure] : verifier_failure_cases) {
    if (!expect(run_audit(signed_driver_artifact,
                          report_path,
                          EIPPF_LEXICAL_DENYLIST_PATH,
                          true,
                          {"--target-kind", "windows_driver",
                           "--signature-verifier", verifier_path.string()}) != 0,
                "failing verifier should fail required signed driver")) {
      return 1;
    }
    const std::string failure_report = read_text(report_path);
    if (!expect_report_contains(failure_report, "\"validation_mode\": \"external_verifier\"",
                                "failing verifier should stay in external_verifier mode")) {
      return 1;
    }
    if (!expect_report_contains(failure_report, "\"signature_state_passed\": false",
                                "failing verifier should fail signature state")) {
      return 1;
    }
    if (!expect_report_contains(failure_report, expected_failure,
                                "failing verifier should report precise failure code")) {
      return 1;
    }
    if (!expect_report_contains(failure_report, "\"verifier_invoked\": true",
                                "failing verifier should be invoked when trusted")) {
      return 1;
    }
    if (!expect_report_contains(failure_report,
                                std::string("\"verifier_error\": \"") + expected_failure + "\"",
                                "failing verifier should expose verifier_error")) {
      return 1;
    }
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--signature-verifier", verifier_success.string()}) != 0,
              "suffix-only signed driver should fail policy resolution")) {
    return 1;
  }
  const std::string suffix_only_report = read_text(report_path);
  if (!expect_report_contains(suffix_only_report, "\"validation_mode\": \"policy_unresolved\"",
                              "suffix-only signed driver should report policy_unresolved")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "\"signature_state_passed\": false",
                              "suffix-only signed driver should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "\"verifier_invoked\": false",
                              "suffix-only signed driver should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "\"verifier_error\": null",
                              "suffix-only signed driver should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "signature_policy_unresolved",
                              "suffix-only signed driver should fail policy resolution")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--signature-verifier", relative_verifier_path.string()}) != 0,
              "relative verifier path should be rejected")) {
    return 1;
  }
  const std::string relative_verifier_report = read_text(report_path);
  if (!expect_report_contains(relative_verifier_report, "\"validation_mode\": \"external_verifier\"",
                              "relative verifier path should still report external_verifier")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report, "\"signature_state_passed\": false",
                              "relative verifier path should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report, "signature_verifier_untrusted",
                              "relative verifier path should be untrusted")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report, "\"verifier_invoked\": false",
                              "relative verifier path should not be invoked")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report,
                              "\"verifier_error\": \"signature_verifier_untrusted\"",
                              "relative verifier path should expose untrusted verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--signature-verifier", untrusted_verifier.string()}) != 0,
              "temp verifier path should be rejected")) {
    return 1;
  }
  const std::string untrusted_verifier_report = read_text(report_path);
  if (!expect_report_contains(untrusted_verifier_report, "signature_verifier_untrusted",
                              "temp verifier path should be untrusted")) {
    return 1;
  }
  if (!expect_report_contains(untrusted_verifier_report, "\"signature_state_passed\": false",
                              "temp verifier path should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(untrusted_verifier_report, "\"verifier_invoked\": false",
                              "temp verifier path should not be invoked")) {
    return 1;
  }
  if (!expect_report_contains(untrusted_verifier_report,
                              "\"verifier_error\": \"signature_verifier_untrusted\"",
                              "temp verifier path should expose untrusted verifier error")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "ios_appstore",
                         "--signature-verifier", verifier_success.string()}) != 0,
              "mismatched target kind should fail policy resolution")) {
    return 1;
  }
  const std::string mismatch_report = read_text(report_path);
  if (!expect_report_contains(mismatch_report, "\"validation_mode\": \"policy_unresolved\"",
                              "mismatched target kind should report policy_unresolved")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "\"signature_state_passed\": false",
                              "mismatched target kind should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "\"verifier_invoked\": false",
                              "mismatched target kind should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "\"verifier_error\": null",
                              "mismatched target kind should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "signature_policy_unresolved",
                              "mismatched target kind should fail policy resolution")) {
    return 1;
  }

  if (!expect(run_audit(manifest_driver_signed_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", win_driver_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "manifest-driven signed driver with verifier should pass")) {
    return 1;
  }
  const std::string manifest_driver_report = read_text(report_path);
  if (!expect_report_contains(manifest_driver_report,
                              "\"requirement_source\": \"manifest_target_kind\"",
                              "manifest-driven signed driver should prefer manifest target kind")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"validation_mode\": \"external_verifier\"",
                              "manifest-driven signed driver should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"signature_state_passed\": true",
                              "manifest-driven signed driver should pass signature state")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"verifier_invoked\": true",
                              "manifest-driven signed driver should invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"verifier_error\": null",
                              "manifest-driven signed driver should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ko_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "signed .ko with verifier should pass")) {
    return 1;
  }
  const std::string signed_ko_report = read_text(report_path);
  if (!expect_report_contains(signed_ko_report, "\"validation_mode\": \"external_verifier\"",
                              "signed .ko should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"signature_state_passed\": true",
                              "signed .ko should pass signature gate")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"verifier_invoked\": true",
                              "signed .ko should invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"verifier_error\": null",
                              "signed .ko should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_macho_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ios_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "signed Mach-O with verifier should pass")) {
    return 1;
  }
  const std::string signed_macho_report = read_text(report_path);
  if (!expect_report_contains(signed_macho_report, "\"validation_mode\": \"external_verifier\"",
                              "signed Mach-O should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"signature_state_passed\": true",
                              "signed Mach-O should pass signature gate")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"verifier_invoked\": true",
                              "signed Mach-O should invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"verifier_error\": null",
                              "signed Mach-O should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact, report_path, missing_denylist, true) != 0,
              "strict audit should fail when denylist is unavailable")) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

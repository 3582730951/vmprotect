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

[[nodiscard]] std::vector<std::uint8_t> build_signed_pe_fixture() {
  constexpr std::size_t kPeOffset = 0x80u;
  constexpr std::size_t kOptionalHeaderSize = 0xE0u;
  constexpr std::size_t kSectionCount = 1u;
  const std::size_t section_table_offset = kPeOffset + 4u + 20u + kOptionalHeaderSize;
  const std::size_t text_raw_offset = section_table_offset + (kSectionCount * 40u);
  const std::size_t text_raw_size = 32u;
  const std::size_t cert_offset = text_raw_offset + text_raw_size;
  const std::size_t cert_size = 8u;

  std::vector<std::uint8_t> bytes(cert_offset + cert_size, 0u);
  bytes[0] = static_cast<std::uint8_t>('M');
  bytes[1] = static_cast<std::uint8_t>('Z');
  write_u32_le(bytes, 0x3Cu, static_cast<std::uint32_t>(kPeOffset));
  bytes[kPeOffset + 0u] = static_cast<std::uint8_t>('P');
  bytes[kPeOffset + 1u] = static_cast<std::uint8_t>('E');
  write_u16_le(bytes, kPeOffset + 4u, 0x014Cu);
  write_u16_le(bytes, kPeOffset + 6u, static_cast<std::uint16_t>(kSectionCount));
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
  write_u32_le(bytes, text_section_offset + 36u, 0x60000020u);
  write_u32_le(bytes, optional_offset + 128u, static_cast<std::uint32_t>(cert_offset));
  write_u32_le(bytes, optional_offset + 132u, static_cast<std::uint32_t>(cert_size));
  write_u32_le(bytes, cert_offset + 0u, 8u);
  write_u16_le(bytes, cert_offset + 4u, 0x0200u);
  write_u16_le(bytes, cert_offset + 6u, 0x0002u);
  return bytes;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     ("eippf_windows_driver_failure_" +
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
                            const std::filesystem::path& manifest) {
  std::string command = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) +
                        " --input " + quote_arg(artifact.string()) + " --denylist " +
                        quote_arg(EIPPF_LEXICAL_DENYLIST_PATH) + " --output " +
                        quote_arg(report.string()) + " --manifest " + quote_arg(manifest.string()) +
                        " --strict";
  return normalize_status(std::system(command.c_str()));
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp dir")) {
    return 1;
  }

  const std::filesystem::path artifact_path = temp_dir / "driver_signed.sys";
  const std::filesystem::path manifest_path = temp_dir / "driver.manifest.json";
  const std::filesystem::path report_path = temp_dir / "driver.audit.json";

  const std::string manifest =
      "{\"target_kind\":\"windows_driver\",\"artifact_kind\":\"windows_driver_sys\","
      "\"runtime_lane\":\"kernel_safe\",\"mutation_profile\":\"kernel_module\","
      "\"signature_policy\":\"sign_after_mutate\",\"sign_after_mutate_required\":true,"
      "\"allow_jit\":false,\"allow_runtime_executable_pages\":false,"
      "\"allow_persistent_plaintext\":false,\"require_fail_closed\":true,"
      "\"kernel_compat_profile\":\"hvci_profile\",\"hvci_profile\":true,"
      "\"vermagic_profile\":false,\"gki_kmi_profile\":false}\n";
  if (!write_bytes(artifact_path, build_signed_pe_fixture()) || !write_text(manifest_path, manifest)) {
    std::cerr << "[FAIL] cannot write fixtures\n";
    return 1;
  }

  if (!expect(run_audit(artifact_path, report_path, manifest_path) != 0,
              "windows driver failure lane should fail without verifier")) {
    return 1;
  }
  const std::string report = read_text(report_path);
  const bool has_expected_failure =
      report.find("signature_authenticity_missing") != std::string::npos ||
      report.find("signature_verifier_failed") != std::string::npos ||
      report.find("signature_verifier_untrusted") != std::string::npos ||
      report.find("signature_verifier_digest_mismatch") != std::string::npos ||
      report.find("signature_authenticity_rejected") != std::string::npos;
  if (!expect(has_expected_failure, "report missing expected signature failure")) {
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

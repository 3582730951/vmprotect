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

namespace {

constexpr std::string_view kPeUserModeMarker = "EIPPF_PE_USERMODE_V1";
constexpr std::string_view kElfUserModeMarker = "EIPPF_ELF_USERMODE_V1";

struct PeFixtureOptions final {
  std::uint32_t text_characteristics = 0x60000020u;
  std::string payload = "clean_payload";
  std::string import_dll;
  std::string import_symbol;
};

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

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

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("eippf_artifact_audit_user_mode_test_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
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

  std::vector<std::uint8_t> bytes(idata_raw_offset + idata_raw_size, 0u);
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

  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> build_elf64_fixture() {
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
  return bytes;
}

void append_marker(std::vector<std::uint8_t>& bytes, std::string_view marker) {
  bytes.insert(bytes.end(), marker.begin(), marker.end());
}

[[nodiscard]] int run_audit(const std::filesystem::path& artifact,
                            const std::filesystem::path& report,
                            const std::filesystem::path& denylist,
                            std::string_view target_kind) {
  const std::string cmd = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) + " --input " +
                          quote_arg(artifact.string()) + " --denylist " + quote_arg(denylist.string()) +
                          " --output " + quote_arg(report.string()) + " --target-kind " +
                          quote_arg(std::string(target_kind)) + " --strict";
  return normalize_status(std::system(cmd.c_str()));
}

[[nodiscard]] bool report_contains(const std::string& report, std::string_view needle) {
  return report.find(std::string(needle)) != std::string::npos;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::filesystem::path report_path = temp_dir / "audit.report.json";
  const std::filesystem::path denylist_path = temp_dir / "denylist.txt";
  if (!write_text(denylist_path, "TRAINING_ANCHOR\n")) {
    std::cerr << "[FAIL] failed to write denylist\n";
    return 1;
  }

  std::vector<std::uint8_t> pe_marked = build_pe_fixture(PeFixtureOptions{});
  append_marker(pe_marked, kPeUserModeMarker);
  std::vector<std::uint8_t> elf_marked = build_elf64_fixture();
  append_marker(elf_marked, kElfUserModeMarker);
  std::vector<std::uint8_t> pe_import_residual = build_pe_fixture(
      PeFixtureOptions{.text_characteristics = 0x60000020u,
                       .payload = "clean_payload",
                       .import_dll = "dbghelp.dll",
                       .import_symbol = "SymInitialize"});
  append_marker(pe_import_residual, kPeUserModeMarker);
  std::vector<std::uint8_t> pe_string_residual = build_pe_fixture(
      PeFixtureOptions{.text_characteristics = 0x60000020u, .payload = "TRAINING_ANCHOR"});
  append_marker(pe_string_residual, kPeUserModeMarker);

  const std::filesystem::path pe_marked_path = temp_dir / "pe_marked.exe";
  const std::filesystem::path elf_marked_path = temp_dir / "elf_marked.so";
  const std::filesystem::path pe_import_residual_path = temp_dir / "pe_import_residual.exe";
  const std::filesystem::path pe_string_residual_path = temp_dir / "pe_string_residual.exe";
  if (!write_bytes(pe_marked_path, pe_marked) || !write_bytes(elf_marked_path, elf_marked) ||
      !write_bytes(pe_import_residual_path, pe_import_residual) ||
      !write_bytes(pe_string_residual_path, pe_string_residual)) {
    std::cerr << "[FAIL] failed to write artifacts\n";
    return 1;
  }

  if (!expect(run_audit(pe_marked_path, report_path, denylist_path, "desktop_native") == 0,
              "PE user-mode marker case must pass strict audit")) {
    return 1;
  }
  const std::string pe_report = read_text(report_path);
  if (!expect(report_contains(pe_report, "\"expected_marker\": \"EIPPF_PE_USERMODE_V1\""),
              "PE report should contain expected marker name") ||
      !expect(report_contains(pe_report, "\"marker_present\": true"),
              "PE report should show marker_present=true") ||
      !expect(report_contains(pe_report, "\"user_mode_marker_check_passed\": true"),
              "PE report should pass user_mode marker check")) {
    return 1;
  }

  if (!expect(run_audit(elf_marked_path, report_path, denylist_path, "android_so") == 0,
              "ELF user-mode marker case must pass strict audit")) {
    return 1;
  }
  const std::string elf_report = read_text(report_path);
  if (!expect(report_contains(elf_report, "\"expected_marker\": \"EIPPF_ELF_USERMODE_V1\""),
              "ELF report should contain expected marker name") ||
      !expect(report_contains(elf_report, "\"marker_present\": true"),
              "ELF report should show marker_present=true") ||
      !expect(report_contains(elf_report, "\"user_mode_marker_check_passed\": true"),
              "ELF report should pass user_mode marker check")) {
    return 1;
  }

  if (!expect(run_audit(pe_import_residual_path, report_path, denylist_path, "desktop_native") != 0,
              "imports residual should fail strict audit")) {
    return 1;
  }
  const std::string import_report = read_text(report_path);
  if (!expect(report_contains(import_report, "imports_policy_failed"),
              "imports residual must still trigger imports_policy_failed")) {
    return 1;
  }

  if (!expect(run_audit(pe_string_residual_path, report_path, denylist_path, "desktop_native") != 0,
              "strings residual should fail strict audit")) {
    return 1;
  }
  const std::string string_report = read_text(report_path);
  if (!expect(report_contains(string_report, "denylisted_strings_present"),
              "string residual must still trigger denylisted_strings_present")) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir);
  return 0;
}

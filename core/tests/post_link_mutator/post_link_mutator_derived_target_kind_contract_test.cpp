#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

#ifndef EIPPF_POST_LINK_MUTATOR_BIN
#error "EIPPF_POST_LINK_MUTATOR_BIN must be defined"
#endif

namespace {
constexpr std::size_t kElfHeader64Size = 64u;
constexpr std::size_t kElfSectionHeader64Size = 64u;
constexpr std::size_t kPeOffsetField = 0x3Cu;
constexpr std::size_t kCoffHeaderSize = 20u;

struct DerivedCase final {
  std::string case_name;
  std::string target_label;
  std::vector<std::uint8_t> input_bytes;
  std::string expected_target_kind;
  std::string expected_artifact_kind;
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

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     ("eippf_post_link_mutator_derived_contract_" +
                                      std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    return {};
  }
  return path;
}

void write_u16_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
}

void write_u64_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint64_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  bytes[offset + 4u] = static_cast<std::uint8_t>((value >> 32u) & 0xFFu);
  bytes[offset + 5u] = static_cast<std::uint8_t>((value >> 40u) & 0xFFu);
  bytes[offset + 6u] = static_cast<std::uint8_t>((value >> 48u) & 0xFFu);
  bytes[offset + 7u] = static_cast<std::uint8_t>((value >> 56u) & 0xFFu);
}

[[nodiscard]] std::size_t align_up(std::size_t value, std::size_t alignment) {
  const std::size_t remainder = value % alignment;
  return remainder == 0u ? value : (value + (alignment - remainder));
}

[[nodiscard]] std::vector<std::uint8_t> make_windows_driver_pe_fixture() {
  std::vector<std::uint8_t> bytes(0x240u, 0u);
  bytes[0] = static_cast<std::uint8_t>('M');
  bytes[1] = static_cast<std::uint8_t>('Z');
  write_u32_le(bytes, kPeOffsetField, 0x80u);

  const std::size_t pe_offset = 0x80u;
  bytes[pe_offset] = static_cast<std::uint8_t>('P');
  bytes[pe_offset + 1u] = static_cast<std::uint8_t>('E');
  bytes[pe_offset + 2u] = 0u;
  bytes[pe_offset + 3u] = 0u;

  const std::size_t coff_offset = pe_offset + 4u;
  write_u16_le(bytes, coff_offset + 0u, 0x8664u);
  write_u16_le(bytes, coff_offset + 2u, 1u);
  write_u16_le(bytes, coff_offset + 16u, 0xF0u);
  write_u16_le(bytes, coff_offset + 18u, 0x2022u);

  const std::size_t optional_header_offset = coff_offset + kCoffHeaderSize;
  write_u16_le(bytes, optional_header_offset + 0u, 0x20Bu);
  write_u32_le(bytes, optional_header_offset + 56u, 0x1000u);
  write_u32_le(bytes, optional_header_offset + 60u, 0x200u);

  const std::size_t section_offset = optional_header_offset + 0xF0u;
  bytes[section_offset + 0u] = static_cast<std::uint8_t>('.');
  bytes[section_offset + 1u] = static_cast<std::uint8_t>('t');
  bytes[section_offset + 2u] = static_cast<std::uint8_t>('e');
  bytes[section_offset + 3u] = static_cast<std::uint8_t>('x');
  bytes[section_offset + 4u] = static_cast<std::uint8_t>('t');
  write_u32_le(bytes, section_offset + 8u, 0x20u);
  write_u32_le(bytes, section_offset + 12u, 0x1000u);
  write_u32_le(bytes, section_offset + 16u, 0x20u);
  write_u32_le(bytes, section_offset + 20u, 0x200u);
  write_u32_le(bytes, section_offset + 36u, 0x60000020u);

  const std::size_t raw_start = 0x200u;
  const std::vector<std::uint8_t> payload{
      0x48u, 0x31u, 0xC0u, 0xC3u, 0x90u, 0x90u, 0x90u, 0x90u};
  std::copy(payload.begin(),
            payload.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(raw_start));
  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> make_elf_fixture() {
  return {
      0x7fu, static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('F'), 0x02u, 0x01u, 0x01u, 0x00u};
}

[[nodiscard]] std::vector<std::uint8_t> make_kernel_et_rel_fixture() {
  std::vector<std::uint8_t> bytes(kElfHeader64Size, 0u);
  bytes[0] = 0x7Fu;
  bytes[1] = static_cast<std::uint8_t>('E');
  bytes[2] = static_cast<std::uint8_t>('L');
  bytes[3] = static_cast<std::uint8_t>('F');
  bytes[4] = 2u;
  bytes[5] = 1u;
  bytes[6] = 1u;

  write_u16_le(bytes, 16u, 1u);
  write_u16_le(bytes, 18u, 0x3Eu);
  write_u32_le(bytes, 20u, 1u);
  write_u16_le(bytes, 52u, static_cast<std::uint16_t>(kElfHeader64Size));
  write_u16_le(bytes, 58u, static_cast<std::uint16_t>(kElfSectionHeader64Size));
  write_u16_le(bytes, 60u, 3u);
  write_u16_le(bytes, 62u, 1u);

  const std::vector<std::uint8_t> text_payload{
      0x90u, 0x90u, 0xC3u, 0x00u};
  const std::vector<std::uint8_t> shstrtab{
      0x00u,
      static_cast<std::uint8_t>('.'),
      static_cast<std::uint8_t>('s'),
      static_cast<std::uint8_t>('h'),
      static_cast<std::uint8_t>('s'),
      static_cast<std::uint8_t>('t'),
      static_cast<std::uint8_t>('r'),
      static_cast<std::uint8_t>('t'),
      static_cast<std::uint8_t>('a'),
      static_cast<std::uint8_t>('b'),
      0x00u,
      static_cast<std::uint8_t>('.'),
      static_cast<std::uint8_t>('t'),
      static_cast<std::uint8_t>('e'),
      static_cast<std::uint8_t>('x'),
      static_cast<std::uint8_t>('t'),
      0x00u};

  const std::size_t text_offset = align_up(kElfHeader64Size, 4u);
  const std::size_t shstrtab_offset = align_up(text_offset + text_payload.size(), 4u);
  const std::size_t section_header_offset = align_up(shstrtab_offset + shstrtab.size(), 4u);
  const std::size_t total_size = section_header_offset + (3u * kElfSectionHeader64Size);
  bytes.resize(total_size, 0u);

  std::copy(text_payload.begin(),
            text_payload.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(text_offset));
  std::copy(shstrtab.begin(),
            shstrtab.end(),
            bytes.begin() + static_cast<std::ptrdiff_t>(shstrtab_offset));

  write_u64_le(bytes, 40u, static_cast<std::uint64_t>(section_header_offset));

  const std::size_t shstrtab_entry_offset = section_header_offset + kElfSectionHeader64Size;
  write_u32_le(bytes, shstrtab_entry_offset + 0u, 1u);
  write_u32_le(bytes, shstrtab_entry_offset + 4u, 3u);
  write_u64_le(bytes, shstrtab_entry_offset + 24u, static_cast<std::uint64_t>(shstrtab_offset));
  write_u64_le(bytes, shstrtab_entry_offset + 32u, static_cast<std::uint64_t>(shstrtab.size()));
  write_u64_le(bytes, shstrtab_entry_offset + 48u, 1u);

  const std::size_t text_entry_offset = shstrtab_entry_offset + kElfSectionHeader64Size;
  write_u32_le(bytes, text_entry_offset + 0u, 11u);
  write_u32_le(bytes, text_entry_offset + 4u, 1u);
  write_u64_le(bytes, text_entry_offset + 24u, static_cast<std::uint64_t>(text_offset));
  write_u64_le(bytes, text_entry_offset + 32u, static_cast<std::uint64_t>(text_payload.size()));
  write_u64_le(bytes, text_entry_offset + 48u, 4u);

  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> make_macho_fixture() {
  return {
      0xFEu, 0xEDu, 0xFAu, 0xCFu, 0x00u, 0x00u, 0x00u, 0x00u};
}

[[nodiscard]] std::vector<std::uint8_t> make_shell_fixture() {
  const std::string shebang = "#!/bin/sh\nexit 0\n";
  return std::vector<std::uint8_t>(shebang.begin(), shebang.end());
}

bool run_success_case(const std::filesystem::path& temp_dir, const DerivedCase& test_case) {
  const bool is_shell_case = test_case.expected_target_kind == "shell_ephemeral";
  const std::string input_suffix = is_shell_case ? ".in.sh" : ".in.bin";
  const std::string output_suffix = is_shell_case ? ".out.sh" : ".out.bin";
  const std::filesystem::path input = temp_dir / (test_case.case_name + input_suffix);
  const std::filesystem::path output = temp_dir / (test_case.case_name + output_suffix);
  const std::filesystem::path manifest = temp_dir / (test_case.case_name + ".manifest.json");

  if (!write_bytes(input, test_case.input_bytes)) {
    std::cerr << "[FAIL] cannot write input fixture for " << test_case.case_name << '\n';
    return false;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg(test_case.target_label);
  const int status = normalize_status(std::system(command.c_str()));
  if (!expect(status == 0, "derived contract success case must succeed")) {
    std::cerr << "[INFO] case=" << test_case.case_name << " status=" << status << '\n';
    return false;
  }

  const std::string manifest_text = read_text_file(manifest);
  return expect(manifest_text.find("\"target_kind_source\": \"derived_from_target_label\"") !=
                    std::string::npos,
                "manifest target_kind_source must be derived_from_target_label") &&
         expect(manifest_text.find("\"target_kind_source\": \"explicit_cli\"") == std::string::npos,
                "success manifest must not contain explicit_cli target_kind_source") &&
         expect(manifest_text.find("\"target_kind\": \"" + test_case.expected_target_kind + "\"") !=
                    std::string::npos,
                "manifest target_kind mismatch for derived case") &&
         expect(manifest_text.find("\"artifact_kind\": \"" + test_case.expected_artifact_kind + "\"") !=
                    std::string::npos,
                "manifest artifact_kind mismatch for derived case");
}

bool run_failure_case_target_artifact_mismatch(const std::filesystem::path& temp_dir,
                                               const std::vector<std::uint8_t>& input_bytes) {
  const std::filesystem::path input = temp_dir / "mismatch.in.bin";
  const std::filesystem::path output = temp_dir / "mismatch.out.bin";
  const std::filesystem::path manifest = temp_dir / "mismatch.manifest.json";
  if (!write_bytes(input, input_bytes)) {
    std::cerr << "[FAIL] cannot write mismatch input fixture\n";
    return false;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg("bootstrap.sh");
  const int status = normalize_status(std::system(command.c_str()));
  return expect(status == 6, "target/artifact mismatch must return exit code 6");
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::vector<DerivedCase> cases{
      {"derived_exe", "desktop_app.exe", make_windows_driver_pe_fixture(), "desktop_native", "pe"},
      {"derived_dll", "desktop_plugin.dll", make_windows_driver_pe_fixture(), "desktop_native", "pe"},
      {"derived_sys",
       "driver_entry.sys",
       make_windows_driver_pe_fixture(),
       "windows_driver",
       "windows_driver_sys"},
      {"derived_elf", "desktop_payload.elf", make_elf_fixture(), "desktop_native", "elf"},
      {"derived_so", "android_native.so", make_elf_fixture(), "android_so", "elf"},
      {"derived_ko",
       "android_kernel_module.ko",
       make_kernel_et_rel_fixture(),
       "android_kernel_module",
       "linux_kernel_module_ko"},
      {"derived_dylib", "ios_runtime.dylib", make_macho_fixture(), "ios_appstore", "macho"},
      {"derived_sh", "bootstrap.sh", make_shell_fixture(), "shell_ephemeral", "shell_bundle"},
  };

  for (const DerivedCase& test_case : cases) {
    if (!run_success_case(temp_dir, test_case)) {
      std::filesystem::remove_all(temp_dir);
      return 1;
    }
  }

  if (!run_failure_case_target_artifact_mismatch(temp_dir, make_elf_fixture())) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  std::filesystem::remove_all(temp_dir);
  return 0;
}

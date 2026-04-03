#include <algorithm>
#include <array>
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

constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";
constexpr std::string_view kExpectedNoteSectionName = ".note.eippf";
constexpr std::size_t kElfHeader64Size = 64u;
constexpr std::size_t kElfSectionHeader64Size = 64u;
constexpr std::size_t kPeOffsetField = 0x3Cu;
constexpr std::size_t kCoffHeaderSize = 20u;

struct ExpectedManifest final {
  std::string artifact_kind;
  std::string target_kind;
  std::string backend_kind;
  std::string runtime_lane;
  std::string mutation_profile;
  std::string signature_policy;
  std::string kernel_compat_profile;
  std::string signing_profile;
  std::string attestation_profile;
  bool sign_after_mutate_required = false;
  bool allow_jit = false;
  bool allow_runtime_executable_pages = false;
  bool allow_persistent_plaintext = false;
  bool require_fail_closed = true;
  bool hvci_profile = false;
  bool vermagic_profile = false;
  bool gki_kmi_profile = false;
  std::string mutation_envelope_kind;
  bool requires_resign = false;
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

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
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
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  const std::filesystem::path dir =
      base / ("eippf_post_link_mutator_smoke_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return {};
  }
  return dir;
}

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

bool expect_manifest_fields(const std::filesystem::path& manifest_path,
                            std::string_view target_label,
                            std::string_view target_kind_source,
                            const ExpectedManifest& expected) {
  const std::string manifest = read_text_file(manifest_path);
  const std::string sign_after_mutate_required =
      expected.sign_after_mutate_required ? "true" : "false";
  const std::string allow_jit = expected.allow_jit ? "true" : "false";
  const std::string allow_runtime_executable_pages =
      expected.allow_runtime_executable_pages ? "true" : "false";
  const std::string allow_persistent_plaintext =
      expected.allow_persistent_plaintext ? "true" : "false";
  const std::string require_fail_closed = expected.require_fail_closed ? "true" : "false";
  const std::string hvci_profile = expected.hvci_profile ? "true" : "false";
  const std::string vermagic_profile = expected.vermagic_profile ? "true" : "false";
  const std::string gki_kmi_profile = expected.gki_kmi_profile ? "true" : "false";
  const std::string requires_resign = expected.requires_resign ? "true" : "false";

  return expect(manifest.find("\"schema_version\": 2") != std::string::npos,
                "manifest schema version mismatch") &&
         expect(manifest.find("\"mutation_status\": \"mutated_with_trailer_v1\"") != std::string::npos,
                "manifest mutation status mismatch") &&
         expect(manifest.find("\"target_label\": \"" + std::string(target_label) + "\"") !=
                    std::string::npos,
                "manifest target label mismatch") &&
         expect(manifest.find("\"target_kind_source\": \"" + std::string(target_kind_source) + "\"") !=
                    std::string::npos,
                "manifest target kind source mismatch") &&
         expect(manifest.find("\"artifact_kind\": \"" + expected.artifact_kind + "\"") !=
                    std::string::npos,
                "manifest artifact kind mismatch") &&
         expect(manifest.find("\"target_kind\": \"" + expected.target_kind + "\"") !=
                    std::string::npos,
                "manifest target kind mismatch") &&
         expect(manifest.find("\"backend_kind\": \"" + expected.backend_kind + "\"") !=
                    std::string::npos,
                "manifest backend kind mismatch") &&
         expect(manifest.find("\"runtime_lane\": \"" + expected.runtime_lane + "\"") !=
                    std::string::npos,
                "manifest runtime lane mismatch") &&
         expect(manifest.find("\"mutation_profile\": \"" + expected.mutation_profile + "\"") !=
                    std::string::npos,
                "manifest mutation profile mismatch") &&
         expect(manifest.find("\"signature_policy\": \"" + expected.signature_policy + "\"") !=
                    std::string::npos,
                "manifest signature policy mismatch") &&
         expect(manifest.find("\"mutation_envelope_kind\": \"" + expected.mutation_envelope_kind +
                                  "\"") != std::string::npos,
                "manifest mutation envelope kind mismatch") &&
         expect(manifest.find("\"requires_resign\": " + requires_resign) != std::string::npos,
                "manifest requires_resign mismatch") &&
         expect(manifest.find("\"kernel_compat_profile\": \"" + expected.kernel_compat_profile + "\"") !=
                    std::string::npos,
                "manifest kernel compat profile mismatch") &&
         expect(manifest.find("\"signing_profile\": \"" + expected.signing_profile + "\"") !=
                    std::string::npos,
                "manifest signing profile mismatch") &&
         expect(manifest.find("\"attestation_profile\": \"" + expected.attestation_profile + "\"") !=
                    std::string::npos,
                "manifest attestation profile mismatch") &&
         expect(manifest.find("\"sign_after_mutate_required\": " + sign_after_mutate_required) !=
                    std::string::npos,
                "manifest sign-after-mutate mismatch") &&
         expect(manifest.find("\"allow_jit\": " + allow_jit) != std::string::npos,
                "manifest allow_jit mismatch") &&
         expect(manifest.find("\"allow_runtime_executable_pages\": " + allow_runtime_executable_pages) !=
                    std::string::npos,
                "manifest allow_runtime_executable_pages mismatch") &&
         expect(manifest.find("\"allow_persistent_plaintext\": " + allow_persistent_plaintext) !=
                    std::string::npos,
                "manifest allow_persistent_plaintext mismatch") &&
         expect(manifest.find("\"require_fail_closed\": " + require_fail_closed) !=
                    std::string::npos,
                "manifest require_fail_closed mismatch") &&
         expect(manifest.find("\"hvci_profile\": " + hvci_profile) != std::string::npos,
                "manifest hvci_profile mismatch") &&
         expect(manifest.find("\"vermagic_profile\": " + vermagic_profile) != std::string::npos,
                "manifest vermagic_profile mismatch") &&
         expect(manifest.find("\"gki_kmi_profile\": " + gki_kmi_profile) != std::string::npos,
                "manifest gki_kmi_profile mismatch");
}

bool expect_trailer_magic_and_version(const std::vector<std::uint8_t>& original,
                                      const std::vector<std::uint8_t>& mutated) {
  const auto trailer_begin = mutated.begin() + static_cast<std::ptrdiff_t>(original.size());
  const auto magic_begin = std::search(trailer_begin,
                                       mutated.end(),
                                       kMutationTrailerMagic.begin(),
                                       kMutationTrailerMagic.end());
  if (!expect(magic_begin != mutated.end(), "mutation trailer magic missing from appended bytes")) {
    return false;
  }
  const auto version_it =
      magic_begin + static_cast<std::ptrdiff_t>(kMutationTrailerMagic.size());
  if (!expect(version_it != mutated.end(), "mutation trailer version byte missing")) {
    return false;
  }
  return expect(*version_it == 1u, "mutation trailer version mismatch");
}

bool expect_kernel_note_semantics(const std::vector<std::uint8_t>& mutated) {
  if (!expect(mutated.size() >= 4u, "kernel mutated output should have ELF header")) {
    return false;
  }
  if (!expect(mutated[0] == 0x7Fu && mutated[1] == static_cast<std::uint8_t>('E') &&
                  mutated[2] == static_cast<std::uint8_t>('L') &&
                  mutated[3] == static_cast<std::uint8_t>('F'),
              "kernel mutated output should remain ELF")) {
    return false;
  }
  const auto note_begin = std::search(mutated.begin(),
                                      mutated.end(),
                                      kExpectedNoteSectionName.begin(),
                                      kExpectedNoteSectionName.end());
  return expect(note_begin != mutated.end(), "kernel mutated output missing .note.eippf");
}

int run_success_case(const std::filesystem::path& temp_dir,
                     std::string_view label,
                     std::string_view target_label,
                     const std::vector<std::uint8_t>& input_content,
                     const ExpectedManifest& expected,
                     bool in_place_output,
                     bool expect_kernel_note,
                     bool expect_prefix_preserved) {
  const std::filesystem::path input = temp_dir / (std::string(label) + ".in.bin");
  const std::filesystem::path output = in_place_output
                                           ? input
                                           : temp_dir / (std::string(label) + ".out.bin");
  const std::filesystem::path manifest = temp_dir / (std::string(label) + ".manifest.json");

  if (!write_bytes(input, input_content)) {
    std::cerr << "[FAIL] cannot write input for case " << label << '\n';
    return 1;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg(std::string(target_label)) + " --target-kind " +
                              quote_arg(expected.target_kind);
  const int status = normalize_status(std::system(command.c_str()));
  if (status != 0) {
    std::cerr << "[FAIL] mutator returned " << status << " for case " << label << '\n';
    return 1;
  }

  const std::vector<std::uint8_t> got = read_file_bytes(output);
  if (!expect(got.size() > input_content.size(), "mutated output should grow after trailer append")) {
    return 1;
  }
  if (expect_prefix_preserved &&
      !expect(std::equal(input_content.begin(), input_content.end(), got.begin()),
              "mutated output should preserve original prefix")) {
    return 1;
  }
  if (!expect(got != input_content, "mutated output must differ from input")) {
    return 1;
  }
  if (expect_kernel_note) {
    if (!expect_kernel_note_semantics(got)) {
      return 1;
    }
  } else {
    if (!expect_trailer_magic_and_version(input_content, got)) {
      return 1;
    }
  }

  if (!expect_manifest_fields(manifest, target_label, "explicit_cli", expected)) {
    return 1;
  }
  return 0;
}

int run_failure_case(const std::filesystem::path& temp_dir,
                     std::string_view label,
                     std::string_view target_kind,
                     const std::vector<std::uint8_t>& input_content) {
  const std::filesystem::path input = temp_dir / (std::string(label) + ".bad.bin");
  const std::filesystem::path output = temp_dir / (std::string(label) + ".bad.out");
  const std::filesystem::path manifest = temp_dir / (std::string(label) + ".bad.manifest.json");

  if (!write_bytes(input, input_content)) {
    std::cerr << "[FAIL] cannot write negative input for case " << label << '\n';
    return 1;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg("unknown_target") + " --target-kind " +
                              quote_arg(std::string(target_kind));
  const int status = normalize_status(std::system(command.c_str()));
  if (!expect(status != 0, "invalid target/artifact pairing should fail closed")) {
    return 1;
  }
  return 0;
}

int run_fail_closed_spoof_cases(const std::filesystem::path& temp_dir,
                                const std::vector<std::uint8_t>& random_bytes) {
  struct SpoofCase final {
    const char* label;
    const char* input_name;
    const char* output_name;
    const char* target_label;
    const char* target_kind;
  };

  const std::array<SpoofCase, 4u> cases{{
      {"spoof_output_shell",
       "spoof_output_shell.bin",
       "spoof_output_shell.sh",
       "bootstrap.sh",
       "shell_ephemeral"},
      {"spoof_output_dex",
       "spoof_output_dex.bin",
       "spoof_output_dex.dex",
       "classes.dex",
       "android_dex"},
      {"spoof_input_shell",
       "fake_input_shell.sh",
       "fake_input_shell.out",
       "bootstrap.sh",
       "shell_ephemeral"},
      {"spoof_input_dex",
       "fake_input_dex.dex",
       "fake_input_dex.out",
       "classes.dex",
       "android_dex"},
  }};

  for (const SpoofCase& test_case : cases) {
    const std::filesystem::path input = temp_dir / test_case.input_name;
    const std::filesystem::path output = temp_dir / test_case.output_name;
    const std::filesystem::path manifest =
        temp_dir / (std::string(test_case.label) + ".manifest.json");
    if (!write_bytes(input, random_bytes)) {
      std::cerr << "[FAIL] cannot write spoof input for case " << test_case.label << '\n';
      return 1;
    }

    const std::string command =
        std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " + quote_arg(input.string()) +
        " --output " + quote_arg(output.string()) + " --manifest " + quote_arg(manifest.string()) +
        " --target " + quote_arg(test_case.target_label) + " --target-kind " +
        quote_arg(test_case.target_kind);
    const int status = normalize_status(std::system(command.c_str()));
    if (!expect(status != 0, "spoofed dex/shell path must fail closed")) {
      std::cerr << "[INFO] spoof_case=" << test_case.label << " status=" << status << '\n';
      return 1;
    }
  }

  return 0;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  const std::vector<std::uint8_t> pe = make_windows_driver_pe_fixture();

  const std::vector<std::uint8_t> elf{
      0x7fu, static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('F'), 0x02u, 0x01u, 0x01u, 0x00u};
  const std::vector<std::uint8_t> kernel_elf = make_kernel_et_rel_fixture();

  const std::vector<std::uint8_t> macho{
      0xFEu, 0xEDu, 0xFAu, 0xCFu, 0x00u, 0x00u, 0x00u, 0x00u};

  const std::vector<std::uint8_t> unknown{
      0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u};

  if (run_success_case(
          temp_dir,
          "desktop_pe",
          "target_pe",
          pe,
          ExpectedManifest{"pe",
                           "desktop_native",
                           "desktop_jit",
                           "desktop_user_mode",
                           "pe_user_mode",
                           "optional_verifier",
                           "",
                           "unsigned_dev_or_sign_after_mutation",
                           "default",
                           false,
                           true,
                           true,
                           false,
                           true,
                           false,
                           false,
                           false,
                           "pe_user_mode_trailer_v1",
                           false},
          false,
          false,
          true) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "desktop_elf",
          "target_elf",
          elf,
          ExpectedManifest{"elf",
                           "desktop_native",
                           "desktop_jit",
                           "desktop_user_mode",
                           "elf_user_mode",
                           "optional_verifier",
                           "",
                           "unsigned_dev_or_sign_after_mutation",
                           "default",
                           false,
                           true,
                           true,
                           false,
                           true,
                           false,
                           false,
                           false,
                           "elf_user_mode_trailer_v1",
                           false},
          false,
          false,
          true) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "ios_macho",
          "ios_target_macho",
          macho,
          ExpectedManifest{"macho",
                           "ios_appstore",
                           "ios_safe_aot",
                           "ios_safe",
                           "ios_macho",
                           "required_verifier",
                           "",
                           "ios_codesign_after_mutation",
                           "ios_safe",
                           false,
                           false,
                           false,
                           false,
                           true,
                           false,
                           false,
                           false,
                           "macho_user_mode_trailer_v1",
                           true},
          false,
          false,
          true) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "windows_driver",
          "windows_driver_sys",
          pe,
          ExpectedManifest{"windows_driver_sys",
                           "windows_driver",
                           "kernel_safe_aot",
                           "kernel_safe",
                           "kernel_module",
                           "sign_after_mutate",
                           "hvci_profile",
                           "windows_driver_sign_after_mutation",
                           "kernel_safe",
                           true,
                           false,
                           false,
                           false,
                           true,
                           true,
                           false,
                           false,
                           "pe_overlay_trailer_v2",
                           true},
          false,
          false,
          true) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "linux_ko",
          "linux_kernel_module.ko",
          kernel_elf,
          ExpectedManifest{"linux_kernel_module_ko",
                           "linux_kernel_module",
                           "kernel_safe_aot",
                           "kernel_safe",
                           "kernel_module",
                           "sign_after_mutate",
                           "vermagic_profile",
                           "kernel_module_sign_after_mutation",
                           "kernel_safe",
                           true,
                           false,
                           false,
                           false,
                           true,
                           false,
                           true,
                           false,
                           "elf_note_section_v1",
                           true},
          true,
          true,
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "android_ko",
          "android_kernel_module.ko",
          kernel_elf,
          ExpectedManifest{"linux_kernel_module_ko",
                           "android_kernel_module",
                           "kernel_safe_aot",
                           "kernel_safe",
                           "kernel_module",
                           "sign_after_mutate",
                           "gki_kmi_profile",
                           "kernel_module_sign_after_mutation",
                           "kernel_safe",
                           true,
                           false,
                           false,
                           false,
                           true,
                           false,
                           false,
                           true,
                           "elf_note_section_v1",
                           true},
          true,
          true,
          false) != 0) {
    return 1;
  }
  if (run_failure_case(temp_dir, "unknown", "desktop_native", unknown) != 0) {
    return 1;
  }
  if (run_failure_case(temp_dir, "elf_as_driver", "windows_driver", elf) != 0) {
    return 1;
  }
  if (run_fail_closed_spoof_cases(temp_dir, unknown) != 0) {
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

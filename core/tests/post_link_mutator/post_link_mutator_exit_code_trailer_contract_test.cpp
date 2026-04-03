#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "post_link_mutator/mutator_app.hpp"

namespace {

constexpr std::string_view kExpectedNoteSectionName = ".note.eippf";
constexpr std::size_t kElfHeader64Size = 64u;
constexpr std::size_t kElfSectionHeader64Size = 64u;

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

class ArgvBuilder final {
 public:
  explicit ArgvBuilder(std::vector<std::string> args) : args_(std::move(args)) {
    argv_.reserve(args_.size());
    for (std::string& arg : args_) {
      argv_.push_back(arg.data());
    }
  }

  [[nodiscard]] int argc() const { return static_cast<int>(argv_.size()); }

  [[nodiscard]] char** argv() { return argv_.data(); }

 private:
  std::vector<std::string> args_;
  std::vector<char*> argv_;
};

struct RunResult final {
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
};

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     ("eippf_post_link_mutator_exit_contract_" +
                                      std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    return {};
  }
  return path;
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::vector<std::uint8_t> read_binary(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>());
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] bool contains_kernel_note_section(const std::vector<std::uint8_t>& bytes) {
  const auto note_begin = std::search(bytes.begin(),
                                      bytes.end(),
                                      kExpectedNoteSectionName.begin(),
                                      kExpectedNoteSectionName.end());
  return note_begin != bytes.end();
}

void cleanup_temp_dir(const std::filesystem::path& temp_dir) {
  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
}

[[nodiscard]] RunResult run_without_fault(const std::vector<std::string>& args) {
  ArgvBuilder argv(args);
  std::ostringstream out;
  std::ostringstream err;
  RunResult result{};
  result.exit_code = eippf::post_link_mutator::run_mutator(argv.argc(), argv.argv(), out, err);
  result.stdout_text = out.str();
  result.stderr_text = err.str();
  return result;
}

[[nodiscard]] RunResult run_with_fault(const std::vector<std::string>& args,
                                       eippf::post_link_mutator::TestFault fault) {
  ArgvBuilder argv(args);
  std::ostringstream out;
  std::ostringstream err;
  RunResult result{};
  result.exit_code = eippf::post_link_mutator::run_mutator_with_test_fault(
      argv.argc(), argv.argv(), out, err, fault);
  result.stdout_text = out.str();
  result.stderr_text = err.str();
  return result;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::filesystem::path input_path = temp_dir / "input.elf";
  const std::filesystem::path success_output = temp_dir / "success.out";
  const std::filesystem::path success_manifest = temp_dir / "success.manifest.json";
  const std::filesystem::path identity_output = temp_dir / "identity.out";
  const std::filesystem::path identity_manifest = temp_dir / "identity.manifest.json";

  const std::vector<std::uint8_t> elf_bytes = make_kernel_et_rel_fixture();

  if (!expect(write_bytes(input_path, elf_bytes), "failed to write input fixture")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::vector<std::string> success_args{
      "post_link_mutator_exit_contract",
      "--input",
      input_path.string(),
      "--output",
      success_output.string(),
      "--manifest",
      success_manifest.string(),
      "--target",
      "linux_kernel_module.ko",
      "--target-kind",
      "linux_kernel_module",
  };

  const RunResult success = run_without_fault(success_args);
  if (!expect(success.exit_code == 0, "success path should return exit code 0")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::vector<std::uint8_t> success_bytes = read_binary(success_output);
  if (!expect(success_bytes.size() > elf_bytes.size(), "success path should mutate kernel payload")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }
  if (!expect(contains_kernel_note_section(success_bytes),
              "success path output must contain .note.eippf section name")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::string success_manifest_text = read_text_file(success_manifest);
  if (!expect(success_manifest_text.find("\"mutation_envelope_kind\": \"elf_note_section_v1\"") !=
                  std::string::npos,
              "success manifest must use elf_note_section_v1 envelope")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }
  if (!expect(success_manifest_text.find("\"requires_resign\": true") != std::string::npos,
              "success manifest must require resign")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::vector<std::string> identity_args{
      "post_link_mutator_exit_contract",
      "--input",
      input_path.string(),
      "--output",
      identity_output.string(),
      "--manifest",
      identity_manifest.string(),
      "--target",
      "linux_kernel_module.ko",
      "--target-kind",
      "linux_kernel_module",
  };

  const RunResult identity = run_with_fault(
      identity_args, eippf::post_link_mutator::TestFault::kForceMutationIdentity);
  if (!expect(identity.exit_code == 9,
              "forced mutation identity fault must return existing failure code 9")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  if (std::filesystem::exists(identity_output)) {
    const std::vector<std::uint8_t> identity_bytes = read_binary(identity_output);
    if (!expect(!contains_kernel_note_section(identity_bytes),
                "forced mutation identity fault output must not contain kernel note")) {
      cleanup_temp_dir(temp_dir);
      return 1;
    }
  }

  cleanup_temp_dir(temp_dir);
  return 0;
}

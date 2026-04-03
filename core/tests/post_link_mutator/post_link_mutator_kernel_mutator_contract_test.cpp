#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

#include "contracts/protection_contracts.hpp"
#include "post_link_mutator/elf_kernel_module_mutator.hpp"
#include "post_link_mutator/pe_kernel_driver_mutator.hpp"

namespace {

constexpr std::size_t kElfHeader64Size = 64u;
constexpr std::size_t kElfSectionHeader64Size = 64u;
constexpr std::size_t kPeOffsetField = 0x3Cu;
constexpr std::size_t kCoffHeaderSize = 20u;
constexpr std::size_t kSectionHeaderSize = 40u;
constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";
constexpr std::string_view kExpectedNoteSectionName = ".note.eippf";

[[nodiscard]] bool checked_add(std::size_t lhs, std::size_t rhs, std::size_t& out) {
  if (lhs > (std::numeric_limits<std::size_t>::max() - rhs)) {
    return false;
  }
  out = lhs + rhs;
  return true;
}

[[nodiscard]] bool checked_mul(std::size_t lhs, std::size_t rhs, std::size_t& out) {
  if (lhs == 0u || rhs == 0u) {
    out = 0u;
    return true;
  }
  if (lhs > (std::numeric_limits<std::size_t>::max() / rhs)) {
    return false;
  }
  out = lhs * rhs;
  return true;
}

[[nodiscard]] bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
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

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  return static_cast<std::uint16_t>(bytes[offset]) |
         static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1u]) << 8u);
}

[[nodiscard]] std::uint32_t read_u32_le(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
         (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
         (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u);
}

[[nodiscard]] std::uint64_t read_u64_le(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  return static_cast<std::uint64_t>(bytes[offset]) |
         (static_cast<std::uint64_t>(bytes[offset + 1u]) << 8u) |
         (static_cast<std::uint64_t>(bytes[offset + 2u]) << 16u) |
         (static_cast<std::uint64_t>(bytes[offset + 3u]) << 24u) |
         (static_cast<std::uint64_t>(bytes[offset + 4u]) << 32u) |
         (static_cast<std::uint64_t>(bytes[offset + 5u]) << 40u) |
         (static_cast<std::uint64_t>(bytes[offset + 6u]) << 48u) |
         (static_cast<std::uint64_t>(bytes[offset + 7u]) << 56u);
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

[[nodiscard]] bool parse_pe_section_table_range(const std::vector<std::uint8_t>& bytes,
                                                std::size_t& section_table_offset,
                                                std::size_t& section_table_size) {
  if (bytes.size() < 64u) {
    return false;
  }
  if (bytes[0] != static_cast<std::uint8_t>('M') || bytes[1] != static_cast<std::uint8_t>('Z')) {
    return false;
  }

  const std::uint32_t pe_offset_raw = read_u32_le(bytes, kPeOffsetField);
  if (pe_offset_raw > static_cast<std::uint32_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }
  const std::size_t pe_offset = static_cast<std::size_t>(pe_offset_raw);

  std::size_t signature_end = 0u;
  if (!checked_add(pe_offset, 4u, signature_end) || signature_end > bytes.size()) {
    return false;
  }
  if (bytes[pe_offset] != static_cast<std::uint8_t>('P') ||
      bytes[pe_offset + 1u] != static_cast<std::uint8_t>('E') || bytes[pe_offset + 2u] != 0u ||
      bytes[pe_offset + 3u] != 0u) {
    return false;
  }

  std::size_t coff_offset = 0u;
  if (!checked_add(pe_offset, 4u, coff_offset)) {
    return false;
  }
  std::size_t coff_end = 0u;
  if (!checked_add(coff_offset, kCoffHeaderSize, coff_end) || coff_end > bytes.size()) {
    return false;
  }

  const std::uint16_t section_count = read_u16_le(bytes, coff_offset + 2u);
  const std::uint16_t optional_header_size = read_u16_le(bytes, coff_offset + 16u);
  if (section_count == 0u) {
    return false;
  }

  std::size_t optional_header_offset = 0u;
  if (!checked_add(coff_offset, kCoffHeaderSize, optional_header_offset)) {
    return false;
  }
  if (!checked_add(optional_header_offset,
                   static_cast<std::size_t>(optional_header_size),
                   section_table_offset)) {
    return false;
  }
  if (!checked_mul(static_cast<std::size_t>(section_count), kSectionHeaderSize, section_table_size)) {
    return false;
  }
  std::size_t section_table_end = 0u;
  if (!checked_add(section_table_offset, section_table_size, section_table_end) ||
      section_table_end > bytes.size()) {
    return false;
  }
  return true;
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

[[nodiscard]] bool run_et_rel_success_case() {
  const std::vector<std::uint8_t> input = make_kernel_et_rel_fixture();
  const std::size_t original_shoff = static_cast<std::size_t>(read_u64_le(input, 40u));
  const std::size_t text_offset = static_cast<std::size_t>(read_u64_le(input, original_shoff + 128u + 24u));
  const std::size_t text_size = static_cast<std::size_t>(read_u64_le(input, original_shoff + 128u + 32u));
  const std::vector<std::uint8_t> original_text(
      input.begin() + static_cast<std::ptrdiff_t>(text_offset),
      input.begin() + static_cast<std::ptrdiff_t>(text_offset + text_size));

  const auto mutated = eippf::post_link_mutator::mutate_elf_kernel_module_artifact(
      input,
      eippf::contracts::ProtectionTargetKind::kLinuxKernelModule,
      eippf::contracts::RuntimeBackendKind::kKernelSafeAot,
      eippf::contracts::ArtifactKind::kLinuxKernelModuleKo);
  if (!expect(mutated.has_value(), "ET_REL kernel module should mutate successfully")) {
    return false;
  }
  const std::vector<std::uint8_t>& output = *mutated;
  if (!expect(output.size() > input.size(), "mutated ET_REL should grow in size")) {
    return false;
  }
  if (!expect(output[0] == 0x7Fu && output[1] == static_cast<std::uint8_t>('E') &&
                  output[2] == static_cast<std::uint8_t>('L') &&
                  output[3] == static_cast<std::uint8_t>('F'),
              "mutated output should remain ELF")) {
    return false;
  }
  if (!expect(read_u16_le(output, 16u) == 1u, "mutated ELF should remain ET_REL")) {
    return false;
  }

  const std::uint16_t new_shnum = read_u16_le(output, 60u);
  const std::uint16_t shstrndx = read_u16_le(output, 62u);
  if (!expect(new_shnum == 4u, "section count should increase by one for .note.eippf")) {
    return false;
  }
  if (!expect(shstrndx == 1u, "shstrtab index should remain stable")) {
    return false;
  }

  const std::size_t new_shoff = static_cast<std::size_t>(read_u64_le(output, 40u));
  std::size_t new_section_table_size = 0u;
  if (!checked_mul(static_cast<std::size_t>(new_shnum), kElfSectionHeader64Size, new_section_table_size)) {
    return false;
  }
  std::size_t new_section_table_end = 0u;
  if (!checked_add(new_shoff, new_section_table_size, new_section_table_end)) {
    return false;
  }
  if (!expect(new_shoff > original_shoff && new_section_table_end <= output.size(),
              "rebuilt section header table should be in-bounds and moved")) {
    return false;
  }

  const std::size_t shstrtab_entry_offset =
      new_shoff + static_cast<std::size_t>(shstrndx) * kElfSectionHeader64Size;
  const std::size_t shstrtab_offset = static_cast<std::size_t>(read_u64_le(output, shstrtab_entry_offset + 24u));
  const std::size_t shstrtab_size = static_cast<std::size_t>(read_u64_le(output, shstrtab_entry_offset + 32u));
  std::size_t shstrtab_end = 0u;
  if (!checked_add(shstrtab_offset, shstrtab_size, shstrtab_end) || shstrtab_end > output.size()) {
    return false;
  }
  const std::vector<std::uint8_t> shstrtab(
      output.begin() + static_cast<std::ptrdiff_t>(shstrtab_offset),
      output.begin() + static_cast<std::ptrdiff_t>(shstrtab_end));
  const auto note_name_it = std::search(
      shstrtab.begin(),
      shstrtab.end(),
      kExpectedNoteSectionName.begin(),
      kExpectedNoteSectionName.end());
  if (!expect(note_name_it != shstrtab.end(), "shstrtab should include .note.eippf")) {
    return false;
  }
  const std::uint32_t note_name_offset =
      static_cast<std::uint32_t>(std::distance(shstrtab.begin(), note_name_it));

  bool note_section_found = false;
  for (std::size_t i = 0u; i < static_cast<std::size_t>(new_shnum); ++i) {
    const std::size_t entry_offset = new_shoff + (i * kElfSectionHeader64Size);
    const std::uint32_t sh_name = read_u32_le(output, entry_offset + 0u);
    const std::uint32_t sh_type = read_u32_le(output, entry_offset + 4u);
    if (sh_name == note_name_offset && sh_type == 7u) {
      const std::size_t note_offset = static_cast<std::size_t>(read_u64_le(output, entry_offset + 24u));
      const std::size_t note_size = static_cast<std::size_t>(read_u64_le(output, entry_offset + 32u));
      std::size_t note_end = 0u;
      if (!checked_add(note_offset, note_size, note_end) || note_end > output.size()) {
        return false;
      }
      if (!expect((note_offset % 4u) == 0u, "note payload must be 4-byte aligned")) {
        return false;
      }
      if (!expect(note_size > 0u, "note payload should be non-empty")) {
        return false;
      }
      note_section_found = true;
      break;
    }
  }
  if (!expect(note_section_found, "rebuilt section table must contain .note.eippf/SHT_NOTE")) {
    return false;
  }

  const std::vector<std::uint8_t> mutated_text(
      output.begin() + static_cast<std::ptrdiff_t>(text_offset),
      output.begin() + static_cast<std::ptrdiff_t>(text_offset + text_size));
  return expect(mutated_text == original_text, "original section payload must stay unchanged");
}

[[nodiscard]] bool run_non_et_rel_fail_closed_case() {
  std::vector<std::uint8_t> input = make_kernel_et_rel_fixture();
  write_u16_le(input, 16u, 2u);
  const auto mutated = eippf::post_link_mutator::mutate_elf_kernel_module_artifact(
      input,
      eippf::contracts::ProtectionTargetKind::kLinuxKernelModule,
      eippf::contracts::RuntimeBackendKind::kKernelSafeAot,
      eippf::contracts::ArtifactKind::kLinuxKernelModuleKo);
  return expect(!mutated.has_value(), "non-ET_REL ELF should fail closed");
}

[[nodiscard]] bool run_no_section_table_fail_closed_case() {
  std::vector<std::uint8_t> input = make_kernel_et_rel_fixture();
  write_u64_le(input, 40u, 0u);
  write_u16_le(input, 60u, 0u);
  write_u16_le(input, 62u, 0u);
  const auto mutated = eippf::post_link_mutator::mutate_elf_kernel_module_artifact(
      input,
      eippf::contracts::ProtectionTargetKind::kLinuxKernelModule,
      eippf::contracts::RuntimeBackendKind::kKernelSafeAot,
      eippf::contracts::ArtifactKind::kLinuxKernelModuleKo);
  return expect(!mutated.has_value(), "kernel ELF without section headers should fail closed");
}

[[nodiscard]] bool run_windows_driver_overlay_case() {
  const std::vector<std::uint8_t> input = make_windows_driver_pe_fixture();
  std::size_t section_table_offset = 0u;
  std::size_t section_table_size = 0u;
  if (!expect(parse_pe_section_table_range(input, section_table_offset, section_table_size),
              "PE fixture should expose a valid section table")) {
    return false;
  }

  const std::vector<std::uint8_t> original_section_table(
      input.begin() + static_cast<std::ptrdiff_t>(section_table_offset),
      input.begin() + static_cast<std::ptrdiff_t>(section_table_offset + section_table_size));

  const auto mutated = eippf::post_link_mutator::mutate_pe_kernel_driver_artifact(
      input,
      eippf::contracts::ProtectionTargetKind::kWindowsDriver,
      eippf::contracts::RuntimeBackendKind::kKernelSafeAot,
      eippf::contracts::ArtifactKind::kWindowsDriverSys);
  if (!expect(mutated.has_value(), "windows_driver PE should mutate through overlay")) {
    return false;
  }

  const std::vector<std::uint8_t>& output = *mutated;
  if (!expect(output.size() > input.size(), "driver mutation should append overlay bytes")) {
    return false;
  }
  if (!expect(std::equal(input.begin(), input.end(), output.begin()),
              "overlay mutation must keep original image bytes untouched")) {
    return false;
  }

  std::size_t mutated_section_table_offset = 0u;
  std::size_t mutated_section_table_size = 0u;
  if (!expect(parse_pe_section_table_range(output, mutated_section_table_offset, mutated_section_table_size),
              "mutated driver output should keep parseable PE headers")) {
    return false;
  }
  if (!expect(mutated_section_table_offset == section_table_offset &&
                  mutated_section_table_size == section_table_size,
              "section table location/size should not move for overlay mutation")) {
    return false;
  }

  const std::vector<std::uint8_t> mutated_section_table(
      output.begin() + static_cast<std::ptrdiff_t>(mutated_section_table_offset),
      output.begin() + static_cast<std::ptrdiff_t>(mutated_section_table_offset + mutated_section_table_size));
  if (!expect(mutated_section_table == original_section_table,
              "section table bytes must remain unchanged")) {
    return false;
  }

  const auto overlay_magic = std::search(output.begin() + static_cast<std::ptrdiff_t>(input.size()),
                                         output.end(),
                                         kMutationTrailerMagic.begin(),
                                         kMutationTrailerMagic.end());
  return expect(overlay_magic != output.end(), "driver overlay should include mutation trailer magic");
}

}  // namespace

int main() {
  bool ok = true;
  ok = run_et_rel_success_case() && ok;
  ok = run_non_et_rel_fail_closed_case() && ok;
  ok = run_no_section_table_fail_closed_case() && ok;
  ok = run_windows_driver_overlay_case() && ok;
  return ok ? 0 : 1;
}

#include "post_link_mutator/elf_kernel_module_mutator.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <vector>

namespace eippf::post_link_mutator {
namespace {

constexpr std::size_t kElfIdentSize = 16u;
constexpr std::size_t kElfHeader32Size = 52u;
constexpr std::size_t kElfHeader64Size = 64u;
constexpr std::size_t kSectionHeader32Size = 40u;
constexpr std::size_t kSectionHeader64Size = 64u;
constexpr std::uint8_t kElfClass32 = 1u;
constexpr std::uint8_t kElfClass64 = 2u;
constexpr std::uint8_t kElfDataLittleEndian = 1u;
constexpr std::uint16_t kEtRel = 1u;
constexpr std::uint16_t kShnXIndex = 0xFFFFu;
constexpr std::uint32_t kShtStrTab = 3u;
constexpr std::uint32_t kShtNote = 7u;
constexpr std::uint32_t kShtNoBits = 8u;
constexpr std::uint32_t kNoteTypeMutation = 1u;
constexpr std::string_view kNoteSectionName = ".note.eippf";
constexpr std::string_view kNoteName = "EIPPF";
constexpr std::string_view kNoteDescriptor = "kernel_module_mutation_v1";

struct ElfLayout final {
  bool is_64 = false;
  std::size_t header_size = 0u;
  std::size_t section_header_size = 0u;
  std::size_t e_type_offset = 0u;
  std::size_t e_shoff_offset = 0u;
  std::size_t e_shentsize_offset = 0u;
  std::size_t e_shnum_offset = 0u;
  std::size_t e_shstrndx_offset = 0u;
};

struct SectionHeaderView final {
  std::uint32_t name = 0u;
  std::uint32_t type = 0u;
  std::uint64_t flags = 0u;
  std::uint64_t address = 0u;
  std::uint64_t offset = 0u;
  std::uint64_t size = 0u;
  std::uint32_t link = 0u;
  std::uint32_t info = 0u;
  std::uint64_t alignment = 0u;
  std::uint64_t entry_size = 0u;
};

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

[[nodiscard]] bool checked_add_u64(std::uint64_t lhs, std::uint64_t rhs, std::uint64_t& out) {
  if (lhs > (std::numeric_limits<std::uint64_t>::max() - rhs)) {
    return false;
  }
  out = lhs + rhs;
  return true;
}

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) {
  return static_cast<std::uint16_t>(bytes[offset]) |
         static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1u]) << 8u);
}

[[nodiscard]] std::uint32_t read_u32_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
         (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
         (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u);
}

[[nodiscard]] std::uint64_t read_u64_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) {
  return static_cast<std::uint64_t>(bytes[offset]) |
         (static_cast<std::uint64_t>(bytes[offset + 1u]) << 8u) |
         (static_cast<std::uint64_t>(bytes[offset + 2u]) << 16u) |
         (static_cast<std::uint64_t>(bytes[offset + 3u]) << 24u) |
         (static_cast<std::uint64_t>(bytes[offset + 4u]) << 32u) |
         (static_cast<std::uint64_t>(bytes[offset + 5u]) << 40u) |
         (static_cast<std::uint64_t>(bytes[offset + 6u]) << 48u) |
         (static_cast<std::uint64_t>(bytes[offset + 7u]) << 56u);
}

[[nodiscard]] bool write_u16_le(std::vector<std::uint8_t>& bytes,
                                std::size_t offset,
                                std::uint16_t value) {
  std::size_t end_offset = 0u;
  if (!checked_add(offset, 2u, end_offset) || end_offset > bytes.size()) {
    return false;
  }
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  return true;
}

[[nodiscard]] bool write_u32_le(std::vector<std::uint8_t>& bytes,
                                std::size_t offset,
                                std::uint32_t value) {
  std::size_t end_offset = 0u;
  if (!checked_add(offset, 4u, end_offset) || end_offset > bytes.size()) {
    return false;
  }
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  return true;
}

[[nodiscard]] bool write_u64_le(std::vector<std::uint8_t>& bytes,
                                std::size_t offset,
                                std::uint64_t value) {
  std::size_t end_offset = 0u;
  if (!checked_add(offset, 8u, end_offset) || end_offset > bytes.size()) {
    return false;
  }
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  bytes[offset + 4u] = static_cast<std::uint8_t>((value >> 32u) & 0xFFu);
  bytes[offset + 5u] = static_cast<std::uint8_t>((value >> 40u) & 0xFFu);
  bytes[offset + 6u] = static_cast<std::uint8_t>((value >> 48u) & 0xFFu);
  bytes[offset + 7u] = static_cast<std::uint8_t>((value >> 56u) & 0xFFu);
  return true;
}

void append_u32_le(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
  bytes.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 32u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 40u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 48u) & 0xFFu));
  bytes.push_back(static_cast<std::uint8_t>((value >> 56u) & 0xFFu));
}

[[nodiscard]] std::optional<ElfLayout> parse_layout(const std::vector<std::uint8_t>& input) {
  if (input.size() < kElfIdentSize) {
    return std::nullopt;
  }
  if (input[0] != 0x7Fu || input[1] != static_cast<std::uint8_t>('E') ||
      input[2] != static_cast<std::uint8_t>('L') || input[3] != static_cast<std::uint8_t>('F')) {
    return std::nullopt;
  }
  if (input[5] != kElfDataLittleEndian) {
    return std::nullopt;
  }

  ElfLayout layout{};
  if (input[4] == kElfClass32) {
    layout.is_64 = false;
    layout.header_size = kElfHeader32Size;
    layout.section_header_size = kSectionHeader32Size;
    layout.e_type_offset = 16u;
    layout.e_shoff_offset = 32u;
    layout.e_shentsize_offset = 46u;
    layout.e_shnum_offset = 48u;
    layout.e_shstrndx_offset = 50u;
  } else if (input[4] == kElfClass64) {
    layout.is_64 = true;
    layout.header_size = kElfHeader64Size;
    layout.section_header_size = kSectionHeader64Size;
    layout.e_type_offset = 16u;
    layout.e_shoff_offset = 40u;
    layout.e_shentsize_offset = 58u;
    layout.e_shnum_offset = 60u;
    layout.e_shstrndx_offset = 62u;
  } else {
    return std::nullopt;
  }

  return input.size() >= layout.header_size ? std::optional<ElfLayout>(layout) : std::nullopt;
}

[[nodiscard]] bool append_alignment(std::vector<std::uint8_t>& bytes, std::size_t align_to) {
  if (align_to == 0u) {
    return false;
  }
  const std::size_t misalignment = bytes.size() % align_to;
  if (misalignment == 0u) {
    return true;
  }
  const std::size_t pad = align_to - misalignment;
  std::size_t after = 0u;
  if (!checked_add(bytes.size(), pad, after)) {
    return false;
  }
  bytes.resize(after, 0u);
  return true;
}

[[nodiscard]] bool read_section_header(const std::vector<std::uint8_t>& input,
                                       const ElfLayout& layout,
                                       std::size_t section_table_offset,
                                       std::size_t index,
                                       SectionHeaderView& out) {
  std::size_t index_offset = 0u;
  if (!checked_mul(index, layout.section_header_size, index_offset)) {
    return false;
  }
  std::size_t entry_offset = 0u;
  if (!checked_add(section_table_offset, index_offset, entry_offset)) {
    return false;
  }
  std::size_t entry_end = 0u;
  if (!checked_add(entry_offset, layout.section_header_size, entry_end) || entry_end > input.size()) {
    return false;
  }

  out.name = read_u32_le(input, entry_offset);
  out.type = read_u32_le(input, entry_offset + 4u);
  if (layout.is_64) {
    out.flags = read_u64_le(input, entry_offset + 8u);
    out.address = read_u64_le(input, entry_offset + 16u);
    out.offset = read_u64_le(input, entry_offset + 24u);
    out.size = read_u64_le(input, entry_offset + 32u);
    out.link = read_u32_le(input, entry_offset + 40u);
    out.info = read_u32_le(input, entry_offset + 44u);
    out.alignment = read_u64_le(input, entry_offset + 48u);
    out.entry_size = read_u64_le(input, entry_offset + 56u);
  } else {
    out.flags = static_cast<std::uint64_t>(read_u32_le(input, entry_offset + 8u));
    out.address = static_cast<std::uint64_t>(read_u32_le(input, entry_offset + 12u));
    out.offset = static_cast<std::uint64_t>(read_u32_le(input, entry_offset + 16u));
    out.size = static_cast<std::uint64_t>(read_u32_le(input, entry_offset + 20u));
    out.link = read_u32_le(input, entry_offset + 24u);
    out.info = read_u32_le(input, entry_offset + 28u);
    out.alignment = static_cast<std::uint64_t>(read_u32_le(input, entry_offset + 32u));
    out.entry_size = static_cast<std::uint64_t>(read_u32_le(input, entry_offset + 36u));
  }

  return true;
}

[[nodiscard]] bool append_section_header(std::vector<std::uint8_t>& bytes,
                                         const ElfLayout& layout,
                                         const SectionHeaderView& section) {
  if (layout.is_64) {
    append_u32_le(bytes, section.name);
    append_u32_le(bytes, section.type);
    append_u64_le(bytes, section.flags);
    append_u64_le(bytes, section.address);
    append_u64_le(bytes, section.offset);
    append_u64_le(bytes, section.size);
    append_u32_le(bytes, section.link);
    append_u32_le(bytes, section.info);
    append_u64_le(bytes, section.alignment);
    append_u64_le(bytes, section.entry_size);
    return true;
  }

  if (section.flags > std::numeric_limits<std::uint32_t>::max() ||
      section.address > std::numeric_limits<std::uint32_t>::max() ||
      section.offset > std::numeric_limits<std::uint32_t>::max() ||
      section.size > std::numeric_limits<std::uint32_t>::max() ||
      section.alignment > std::numeric_limits<std::uint32_t>::max() ||
      section.entry_size > std::numeric_limits<std::uint32_t>::max()) {
    return false;
  }

  append_u32_le(bytes, section.name);
  append_u32_le(bytes, section.type);
  append_u32_le(bytes, static_cast<std::uint32_t>(section.flags));
  append_u32_le(bytes, static_cast<std::uint32_t>(section.address));
  append_u32_le(bytes, static_cast<std::uint32_t>(section.offset));
  append_u32_le(bytes, static_cast<std::uint32_t>(section.size));
  append_u32_le(bytes, section.link);
  append_u32_le(bytes, section.info);
  append_u32_le(bytes, static_cast<std::uint32_t>(section.alignment));
  append_u32_le(bytes, static_cast<std::uint32_t>(section.entry_size));
  return true;
}

[[nodiscard]] std::vector<std::uint8_t> build_note_payload() {
  const std::uint32_t name_size = static_cast<std::uint32_t>(kNoteName.size() + 1u);
  const std::uint32_t desc_size = static_cast<std::uint32_t>(kNoteDescriptor.size());

  std::vector<std::uint8_t> payload;
  payload.reserve(12u + name_size + desc_size + 8u);
  append_u32_le(payload, name_size);
  append_u32_le(payload, desc_size);
  append_u32_le(payload, kNoteTypeMutation);

  payload.insert(payload.end(), kNoteName.begin(), kNoteName.end());
  payload.push_back(0u);
  while ((payload.size() % 4u) != 0u) {
    payload.push_back(0u);
  }

  payload.insert(payload.end(), kNoteDescriptor.begin(), kNoteDescriptor.end());
  while ((payload.size() % 4u) != 0u) {
    payload.push_back(0u);
  }
  return payload;
}

[[nodiscard]] bool target_supported(eippf::contracts::ProtectionTargetKind target_kind) noexcept {
  using eippf::contracts::ProtectionTargetKind;
  return target_kind == ProtectionTargetKind::kLinuxKernelModule ||
         target_kind == ProtectionTargetKind::kAndroidKernelModule;
}

[[nodiscard]] bool backend_supported(eippf::contracts::RuntimeBackendKind backend_kind) noexcept {
  return backend_kind == eippf::contracts::RuntimeBackendKind::kKernelSafeAot;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> mutate_elf_kernel_module_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  using eippf::contracts::ArtifactKind;

  if (artifact_kind != ArtifactKind::kLinuxKernelModuleKo || !target_supported(target_kind) ||
      !backend_supported(backend_kind)) {
    return std::nullopt;
  }

  const std::optional<ElfLayout> layout = parse_layout(input);
  if (!layout.has_value()) {
    return std::nullopt;
  }
  const ElfLayout elf = *layout;

  if (read_u16_le(input, elf.e_type_offset) != kEtRel) {
    return std::nullopt;
  }

  const std::uint16_t section_header_entry_size = read_u16_le(input, elf.e_shentsize_offset);
  const std::uint16_t section_count = read_u16_le(input, elf.e_shnum_offset);
  const std::uint16_t section_name_index = read_u16_le(input, elf.e_shstrndx_offset);
  if (section_header_entry_size != static_cast<std::uint16_t>(elf.section_header_size) ||
      section_count == 0u || section_name_index == 0u ||
      section_name_index == kShnXIndex ||
      section_name_index >= section_count) {
    return std::nullopt;
  }

  const std::uint64_t raw_section_table_offset =
      elf.is_64 ? read_u64_le(input, elf.e_shoff_offset)
                : static_cast<std::uint64_t>(read_u32_le(input, elf.e_shoff_offset));
  if (raw_section_table_offset == 0u ||
      raw_section_table_offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return std::nullopt;
  }
  const std::size_t section_table_offset = static_cast<std::size_t>(raw_section_table_offset);
  std::size_t section_table_size = 0u;
  if (!checked_mul(static_cast<std::size_t>(section_count), elf.section_header_size, section_table_size)) {
    return std::nullopt;
  }
  std::size_t section_table_end = 0u;
  if (!checked_add(section_table_offset, section_table_size, section_table_end) ||
      section_table_end > input.size()) {
    return std::nullopt;
  }

  std::vector<SectionHeaderView> sections;
  sections.resize(static_cast<std::size_t>(section_count));
  for (std::size_t index = 0u; index < sections.size(); ++index) {
    SectionHeaderView section{};
    if (!read_section_header(input, elf, section_table_offset, index, section)) {
      return std::nullopt;
    }
    if (section.type != kShtNoBits && section.size > 0u) {
      std::uint64_t section_end = 0u;
      if (!checked_add_u64(section.offset, section.size, section_end) ||
          section_end > static_cast<std::uint64_t>(input.size())) {
        return std::nullopt;
      }
    }
    sections[index] = section;
  }

  SectionHeaderView shstrtab = sections[static_cast<std::size_t>(section_name_index)];
  if (shstrtab.type != kShtStrTab || shstrtab.size == 0u ||
      shstrtab.offset > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
      shstrtab.size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return std::nullopt;
  }
  const std::size_t shstrtab_offset = static_cast<std::size_t>(shstrtab.offset);
  const std::size_t shstrtab_size = static_cast<std::size_t>(shstrtab.size);
  std::size_t shstrtab_end = 0u;
  if (!checked_add(shstrtab_offset, shstrtab_size, shstrtab_end) || shstrtab_end > input.size()) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> updated_shstrtab(input.begin() + static_cast<std::ptrdiff_t>(shstrtab_offset),
                                             input.begin() + static_cast<std::ptrdiff_t>(shstrtab_end));
  const std::size_t note_name_offset = updated_shstrtab.size();
  const std::size_t note_name_size_with_null = kNoteSectionName.size() + 1u;
  std::size_t updated_shstrtab_size = 0u;
  if (!checked_add(note_name_offset, note_name_size_with_null, updated_shstrtab_size) ||
      updated_shstrtab_size > std::numeric_limits<std::uint32_t>::max()) {
    return std::nullopt;
  }
  updated_shstrtab.insert(updated_shstrtab.end(), kNoteSectionName.begin(), kNoteSectionName.end());
  updated_shstrtab.push_back(0u);

  const std::vector<std::uint8_t> note_payload = build_note_payload();
  if (note_payload.empty()) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> output = input;
  if (!append_alignment(output, 4u)) {
    return std::nullopt;
  }

  const std::size_t new_shstrtab_offset = output.size();
  output.insert(output.end(), updated_shstrtab.begin(), updated_shstrtab.end());
  if (!append_alignment(output, 4u)) {
    return std::nullopt;
  }

  const std::size_t note_offset = output.size();
  output.insert(output.end(), note_payload.begin(), note_payload.end());
  if (!append_alignment(output, 4u)) {
    return std::nullopt;
  }
  if ((note_offset % 4u) != 0u || (output.size() % 4u) != 0u) {
    return std::nullopt;
  }

  const std::size_t new_section_table_offset = output.size();
  std::uint16_t new_section_count = 0u;
  if (section_count >= std::numeric_limits<std::uint16_t>::max()) {
    return std::nullopt;
  }
  new_section_count = static_cast<std::uint16_t>(section_count + 1u);

  sections[static_cast<std::size_t>(section_name_index)].offset =
      static_cast<std::uint64_t>(new_shstrtab_offset);
  sections[static_cast<std::size_t>(section_name_index)].size =
      static_cast<std::uint64_t>(updated_shstrtab.size());

  SectionHeaderView note_section{};
  note_section.name = static_cast<std::uint32_t>(note_name_offset);
  note_section.type = kShtNote;
  note_section.flags = 0u;
  note_section.address = 0u;
  note_section.offset = static_cast<std::uint64_t>(note_offset);
  note_section.size = static_cast<std::uint64_t>(note_payload.size());
  note_section.link = 0u;
  note_section.info = 0u;
  note_section.alignment = 4u;
  note_section.entry_size = 0u;

  for (const SectionHeaderView& section : sections) {
    if (!append_section_header(output, elf, section)) {
      return std::nullopt;
    }
  }
  if (!append_section_header(output, elf, note_section)) {
    return std::nullopt;
  }

  if (!elf.is_64) {
    if (new_section_table_offset > std::numeric_limits<std::uint32_t>::max()) {
      return std::nullopt;
    }
    if (!write_u32_le(output, elf.e_shoff_offset, static_cast<std::uint32_t>(new_section_table_offset))) {
      return std::nullopt;
    }
  } else {
    if (!write_u64_le(output, elf.e_shoff_offset,
                      static_cast<std::uint64_t>(new_section_table_offset))) {
      return std::nullopt;
    }
  }

  if (!write_u16_le(output, elf.e_shnum_offset, new_section_count)) {
    return std::nullopt;
  }

  return output == input ? std::nullopt : std::optional<std::vector<std::uint8_t>>(output);
}

}  // namespace eippf::post_link_mutator

#include "post_link_mutator/pe_kernel_driver_mutator.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

#include "post_link_mutator/mutation_trailer.hpp"

namespace eippf::post_link_mutator {
namespace {

constexpr std::size_t kPeOffsetField = 0x3Cu;
constexpr std::size_t kCoffHeaderSize = 20u;
constexpr std::size_t kSectionHeaderSize = 40u;

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

[[nodiscard]] bool has_valid_driver_pe_layout(const std::vector<std::uint8_t>& input) {
  if (input.size() < 64u) {
    return false;
  }
  if (input[0] != static_cast<std::uint8_t>('M') || input[1] != static_cast<std::uint8_t>('Z')) {
    return false;
  }

  const std::uint32_t pe_offset_raw = read_u32_le(input, kPeOffsetField);
  if (pe_offset_raw > static_cast<std::uint32_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }
  const std::size_t pe_offset = static_cast<std::size_t>(pe_offset_raw);

  std::size_t pe_signature_end = 0u;
  if (!checked_add(pe_offset, 4u, pe_signature_end) || pe_signature_end > input.size()) {
    return false;
  }
  if (input[pe_offset] != static_cast<std::uint8_t>('P') ||
      input[pe_offset + 1u] != static_cast<std::uint8_t>('E') ||
      input[pe_offset + 2u] != 0u || input[pe_offset + 3u] != 0u) {
    return false;
  }

  std::size_t coff_offset = 0u;
  if (!checked_add(pe_offset, 4u, coff_offset)) {
    return false;
  }
  std::size_t coff_end = 0u;
  if (!checked_add(coff_offset, kCoffHeaderSize, coff_end) || coff_end > input.size()) {
    return false;
  }

  const std::uint16_t section_count = read_u16_le(input, coff_offset + 2u);
  const std::uint16_t optional_header_size = read_u16_le(input, coff_offset + 16u);
  if (section_count == 0u) {
    return false;
  }

  std::size_t optional_header_offset = 0u;
  if (!checked_add(coff_offset, kCoffHeaderSize, optional_header_offset)) {
    return false;
  }
  std::size_t section_table_offset = 0u;
  if (!checked_add(optional_header_offset, static_cast<std::size_t>(optional_header_size),
                   section_table_offset)) {
    return false;
  }

  std::size_t section_table_size = 0u;
  if (!checked_mul(static_cast<std::size_t>(section_count), kSectionHeaderSize, section_table_size)) {
    return false;
  }
  std::size_t section_table_end = 0u;
  if (!checked_add(section_table_offset, section_table_size, section_table_end) ||
      section_table_end > input.size()) {
    return false;
  }

  return true;
}

[[nodiscard]] bool target_supported(eippf::contracts::ProtectionTargetKind target_kind) noexcept {
  return target_kind == eippf::contracts::ProtectionTargetKind::kWindowsDriver;
}

[[nodiscard]] bool backend_supported(eippf::contracts::RuntimeBackendKind backend_kind) noexcept {
  return backend_kind == eippf::contracts::RuntimeBackendKind::kKernelSafeAot;
}

}  // namespace

std::optional<std::vector<std::uint8_t>> mutate_pe_kernel_driver_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  using eippf::contracts::ArtifactKind;

  if (artifact_kind != ArtifactKind::kWindowsDriverSys || !target_supported(target_kind) ||
      !backend_supported(backend_kind) || !has_valid_driver_pe_layout(input)) {
    return std::nullopt;
  }

  const std::vector<std::uint8_t> trailer =
      build_mutation_trailer(input, target_kind, backend_kind, artifact_kind);
  if (trailer.empty()) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> output = input;
  output.insert(output.end(), trailer.begin(), trailer.end());
  if (output.size() <= input.size()) {
    return std::nullopt;
  }
  if (!std::equal(input.begin(), input.end(), output.begin())) {
    return std::nullopt;
  }
  return output;
}

}  // namespace eippf::post_link_mutator

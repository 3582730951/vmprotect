#include "post_link_mutator/mutation_trailer.hpp"

#include <algorithm>
#include <cstddef>

namespace eippf::post_link_mutator {
namespace {

constexpr std::uint8_t kMutationTrailerVersion = 1u;
constexpr std::uint8_t kMutationTrailerFlags = 0u;
constexpr std::uint64_t kMutationTrailerSeed = 0xE1F0F11ull;
constexpr std::size_t kMutationTrailerSize = 33u;

void append_u32_le(std::vector<std::uint8_t>& output, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    const auto shift = static_cast<unsigned>(i * 8);
    output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

void append_u64_le(std::vector<std::uint8_t>& output, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    const auto shift = static_cast<unsigned>(i * 8);
    output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFFu));
  }
}

[[nodiscard]] std::uint32_t read_u32_le(std::span<const std::uint8_t> data, std::size_t offset) {
  return static_cast<std::uint32_t>(data[offset]) |
         (static_cast<std::uint32_t>(data[offset + 1u]) << 8u) |
         (static_cast<std::uint32_t>(data[offset + 2u]) << 16u) |
         (static_cast<std::uint32_t>(data[offset + 3u]) << 24u);
}

[[nodiscard]] std::uint64_t read_u64_le(std::span<const std::uint8_t> data, std::size_t offset) {
  return static_cast<std::uint64_t>(data[offset]) |
         (static_cast<std::uint64_t>(data[offset + 1u]) << 8u) |
         (static_cast<std::uint64_t>(data[offset + 2u]) << 16u) |
         (static_cast<std::uint64_t>(data[offset + 3u]) << 24u) |
         (static_cast<std::uint64_t>(data[offset + 4u]) << 32u) |
         (static_cast<std::uint64_t>(data[offset + 5u]) << 40u) |
         (static_cast<std::uint64_t>(data[offset + 6u]) << 48u) |
         (static_cast<std::uint64_t>(data[offset + 7u]) << 56u);
}

[[nodiscard]] std::uint64_t fnv1a64_span(std::span<const std::uint8_t> data) noexcept {
  std::uint64_t hash = 14695981039346656037ull;
  for (const std::uint8_t byte : data) {
    hash ^= static_cast<std::uint64_t>(byte);
    hash *= 1099511628211ull;
  }
  return hash;
}

}  // namespace

std::uint64_t fnv1a64(const std::vector<std::uint8_t>& data) noexcept {
  return fnv1a64_span(std::span<const std::uint8_t>(data.data(), data.size()));
}

std::vector<std::uint8_t> build_mutation_trailer(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  std::vector<std::uint8_t> trailer;
  trailer.reserve(kMutationTrailerMagic.size() + 24u);

  trailer.insert(trailer.end(), kMutationTrailerMagic.begin(), kMutationTrailerMagic.end());
  trailer.push_back(kMutationTrailerVersion);
  trailer.push_back(static_cast<std::uint8_t>(target_kind));
  trailer.push_back(static_cast<std::uint8_t>(backend_kind));
  trailer.push_back(static_cast<std::uint8_t>(artifact_kind));
  trailer.push_back(kMutationTrailerFlags);
  append_u32_le(trailer, static_cast<std::uint32_t>(input.size()));
  append_u64_le(trailer, fnv1a64(input));
  append_u64_le(trailer, static_cast<std::uint64_t>(input.size()) ^ kMutationTrailerSeed);
  return trailer;
}

std::vector<std::uint8_t> mutate_artifact(
    const std::vector<std::uint8_t>& input,
    eippf::contracts::ProtectionTargetKind target_kind,
    eippf::contracts::RuntimeBackendKind backend_kind,
    eippf::contracts::ArtifactKind artifact_kind) {
  std::vector<std::uint8_t> output = input;
  const std::vector<std::uint8_t> trailer =
      build_mutation_trailer(input, target_kind, backend_kind, artifact_kind);
  output.insert(output.end(), trailer.begin(), trailer.end());
  return output;
}

bool has_valid_mutation_trailer(std::span<const std::uint8_t> artifact) {
  if (artifact.size() < kMutationTrailerSize) {
    return false;
  }

  const std::size_t trailer_offset = artifact.size() - kMutationTrailerSize;
  const auto trailer_magic_begin = artifact.begin() + static_cast<std::ptrdiff_t>(trailer_offset);
  if (!std::equal(kMutationTrailerMagic.begin(), kMutationTrailerMagic.end(), trailer_magic_begin)) {
    return false;
  }

  const std::size_t version_offset = trailer_offset + kMutationTrailerMagic.size();
  if (artifact[version_offset] != kMutationTrailerVersion) {
    return false;
  }

  const std::size_t encoded_size_offset = trailer_offset + 13u;
  const std::size_t encoded_hash_offset = trailer_offset + 17u;
  const std::size_t encoded_guard_offset = trailer_offset + 25u;

  const std::uint32_t encoded_input_size = read_u32_le(artifact, encoded_size_offset);
  if (static_cast<std::size_t>(encoded_input_size) != trailer_offset) {
    return false;
  }

  const std::uint64_t encoded_hash = read_u64_le(artifact, encoded_hash_offset);
  const std::uint64_t encoded_guard = read_u64_le(artifact, encoded_guard_offset);

  const std::span<const std::uint8_t> original = artifact.first(trailer_offset);
  if (fnv1a64_span(original) != encoded_hash) {
    return false;
  }

  const std::uint64_t expected_guard =
      static_cast<std::uint64_t>(encoded_input_size) ^ kMutationTrailerSeed;
  return expected_guard == encoded_guard;
}

}  // namespace eippf::post_link_mutator

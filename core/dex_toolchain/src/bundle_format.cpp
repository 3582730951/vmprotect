#include "dex_toolchain/bundle_format.hpp"

#include <limits>

namespace eippf::dex_toolchain {
namespace {

constexpr std::size_t kBundleHeaderBytesV3 = 26u;
constexpr std::uint64_t kFnv1a64Offset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1a64Prime = 1099511628211ull;

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(
      static_cast<std::uint16_t>(bytes[offset]) |
      static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset + 1u]) << 8u));
}

[[nodiscard]] std::uint32_t read_u32_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  return static_cast<std::uint32_t>(
      static_cast<std::uint32_t>(bytes[offset]) |
      (static_cast<std::uint32_t>(bytes[offset + 1u]) << 8u) |
      (static_cast<std::uint32_t>(bytes[offset + 2u]) << 16u) |
      (static_cast<std::uint32_t>(bytes[offset + 3u]) << 24u));
}

[[nodiscard]] std::uint64_t read_u64_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  std::uint64_t value = 0u;
  for (std::size_t i = 0u; i < 8u; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + i]) << static_cast<unsigned>(8u * i);
  }
  return value;
}

void append_u16_le(std::vector<std::uint8_t>& output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  output.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

void append_u32_le(std::vector<std::uint8_t>& output, std::uint32_t value) {
  output.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  output.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
  output.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
  output.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& output, std::uint64_t value) {
  for (std::size_t i = 0u; i < 8u; ++i) {
    output.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(8u * i)) & 0xFFu));
  }
}

}  // namespace

std::uint64_t fnv1a64(std::string_view value) noexcept {
  std::uint64_t hash = kFnv1a64Offset;
  for (const char ch : value) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= kFnv1a64Prime;
  }
  return hash;
}

std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 37u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

void encrypt_in_place(std::vector<std::uint8_t>& data, std::uint8_t key) noexcept {
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] = static_cast<std::uint8_t>(data[i] ^ stream_mask(key, i));
  }
}

bool read_bundle_header_v3(const std::vector<std::uint8_t>& bundle,
                           DexBundleHeaderV3& header_out,
                           std::size_t& payload_offset_out) noexcept {
  if (bundle.size() < kBundleHeaderBytesV3 || kDexBundleMagic.size() != 4u) {
    return false;
  }

  if (bundle[0u] != static_cast<std::uint8_t>(kDexBundleMagic[0u]) ||
      bundle[1u] != static_cast<std::uint8_t>(kDexBundleMagic[1u]) ||
      bundle[2u] != static_cast<std::uint8_t>(kDexBundleMagic[2u]) ||
      bundle[3u] != static_cast<std::uint8_t>(kDexBundleMagic[3u])) {
    return false;
  }

  DexBundleHeaderV3 parsed{};
  parsed.format_version = bundle[4u];
  parsed.flags = bundle[5u];
  parsed.dex_version_ascii = {
      static_cast<char>(bundle[6u]),
      static_cast<char>(bundle[7u]),
      static_cast<char>(bundle[8u]),
  };
  parsed.key_material_marker = bundle[9u];
  parsed.key_id_len = read_u16_le(bundle, 10u);
  parsed.bridge_record_count = read_u16_le(bundle, 12u);
  parsed.bridge_table_len = read_u32_le(bundle, 14u);
  parsed.payload_len = read_u64_le(bundle, 18u);

  if (parsed.format_version != 3u || parsed.key_material_marker != 0u) {
    return false;
  }

  const std::size_t key_id_len = static_cast<std::size_t>(parsed.key_id_len);
  const std::size_t bridge_table_len = static_cast<std::size_t>(parsed.bridge_table_len);
  const std::size_t payload_len = static_cast<std::size_t>(parsed.payload_len);
  if (parsed.payload_len > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
    return false;
  }

  if (kBundleHeaderBytesV3 > bundle.size() || key_id_len > (bundle.size() - kBundleHeaderBytesV3)) {
    return false;
  }
  const std::size_t bridge_offset = kBundleHeaderBytesV3 + key_id_len;
  if (bridge_table_len > (bundle.size() - bridge_offset)) {
    return false;
  }
  const std::size_t payload_offset = bridge_offset + bridge_table_len;
  if (payload_len > (bundle.size() - payload_offset)) {
    return false;
  }
  if (payload_offset + payload_len != bundle.size()) {
    return false;
  }

  header_out = parsed;
  payload_offset_out = payload_offset;
  return true;
}

std::vector<std::uint8_t> write_bundle_v3(const DexBundleHeaderV3& header,
                                          std::string_view key_id,
                                          const std::vector<std::uint8_t>& encrypted_bridge_table,
                                          const std::vector<std::uint8_t>& encrypted_payload) {
  if (kDexBundleMagic.size() != 4u ||
      key_id.size() > static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) ||
      encrypted_bridge_table.size() >
          static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
    return {};
  }

  const std::size_t reserved_size =
      kBundleHeaderBytesV3 + key_id.size() + encrypted_bridge_table.size() + encrypted_payload.size();
  std::vector<std::uint8_t> bundle;
  bundle.reserve(reserved_size);

  bundle.push_back(static_cast<std::uint8_t>(kDexBundleMagic[0u]));
  bundle.push_back(static_cast<std::uint8_t>(kDexBundleMagic[1u]));
  bundle.push_back(static_cast<std::uint8_t>(kDexBundleMagic[2u]));
  bundle.push_back(static_cast<std::uint8_t>(kDexBundleMagic[3u]));
  bundle.push_back(header.format_version);
  bundle.push_back(header.flags);
  bundle.push_back(static_cast<std::uint8_t>(header.dex_version_ascii[0u]));
  bundle.push_back(static_cast<std::uint8_t>(header.dex_version_ascii[1u]));
  bundle.push_back(static_cast<std::uint8_t>(header.dex_version_ascii[2u]));
  bundle.push_back(0u);  // key_material_marker fixed to external-only
  append_u16_le(bundle, static_cast<std::uint16_t>(key_id.size()));
  append_u16_le(bundle, header.bridge_record_count);
  append_u32_le(bundle, static_cast<std::uint32_t>(encrypted_bridge_table.size()));
  append_u64_le(bundle, static_cast<std::uint64_t>(encrypted_payload.size()));

  bundle.insert(bundle.end(), key_id.begin(), key_id.end());
  bundle.insert(bundle.end(), encrypted_bridge_table.begin(), encrypted_bridge_table.end());
  bundle.insert(bundle.end(), encrypted_payload.begin(), encrypted_payload.end());
  return bundle;
}

}  // namespace eippf::dex_toolchain

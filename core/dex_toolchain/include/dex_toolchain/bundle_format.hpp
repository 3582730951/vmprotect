#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace eippf::dex_toolchain {

constexpr std::string_view kDexBundleMagic = "EDXB";

struct DexBundleHeaderV3 final {
  std::uint8_t format_version = 3u;
  std::uint8_t flags = 0u;
  std::array<char, 3u> dex_version_ascii{{'0', '0', '0'}};
  std::uint8_t key_material_marker = 0u;
  std::uint16_t key_id_len = 0u;
  std::uint16_t bridge_record_count = 0u;
  std::uint64_t payload_len = 0u;
  std::uint32_t bridge_table_len = 0u;
};

[[nodiscard]] std::uint64_t fnv1a64(std::string_view value) noexcept;

[[nodiscard]] std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept;

void encrypt_in_place(std::vector<std::uint8_t>& data, std::uint8_t key) noexcept;

[[nodiscard]] bool read_bundle_header_v3(const std::vector<std::uint8_t>& bundle,
                                         DexBundleHeaderV3& header_out,
                                         std::size_t& payload_offset_out) noexcept;

[[nodiscard]] std::vector<std::uint8_t> write_bundle_v3(
    const DexBundleHeaderV3& header,
    std::string_view key_id,
    const std::vector<std::uint8_t>& encrypted_bridge_table,
    const std::vector<std::uint8_t>& encrypted_payload);

}  // namespace eippf::dex_toolchain

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace eippf::script_guard {

constexpr std::uint8_t kShellBundleFormatVersion = 3u;
constexpr std::uint16_t kShellKeyBindingSchemaVersion = 1u;

struct BundleHeader final {
  std::uint8_t format_version = 0u;
  std::uint8_t key_material_marker = 0u;
  bool shebang_present = false;
  std::string interpreter_tag;
  std::uint16_t key_id_length = 0u;
  std::uint16_t key_binding_schema_version = 0u;
  std::uint64_t payload_length = 0u;
  std::size_t header_size_bytes = 0u;
};

[[nodiscard]] bool is_supported_interpreter_tag(std::string_view tag) noexcept;

[[nodiscard]] bool read_bundle_header(const std::vector<std::uint8_t>& bundle,
                                      BundleHeader& header_out,
                                      std::string& error_out);

[[nodiscard]] bool write_bundle_v3(std::string_view key_id,
                                   std::string_view interpreter_tag,
                                   bool shebang_present,
                                   const std::vector<std::uint8_t>& encrypted_payload,
                                   std::vector<std::uint8_t>& bundle_out,
                                   std::string& error_out);

}  // namespace eippf::script_guard

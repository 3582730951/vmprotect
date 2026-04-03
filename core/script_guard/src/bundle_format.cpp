#include "script_guard/bundle_format.hpp"

#include <limits>

namespace eippf::script_guard {

namespace {

constexpr std::size_t kFixedHeaderBytes = 21u;

[[nodiscard]] std::uint16_t read_u16_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) |
                                    static_cast<std::uint16_t>(bytes[offset + 1u] << 8u));
}

[[nodiscard]] std::uint64_t read_u64_le(const std::vector<std::uint8_t>& bytes,
                                        std::size_t offset) noexcept {
  std::uint64_t value = 0u;
  for (std::size_t i = 0u; i < 8u; ++i) {
    value |= static_cast<std::uint64_t>(bytes[offset + i]) << static_cast<unsigned>(8u * i);
  }
  return value;
}

void append_u16_le(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

void append_u64_le(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (std::size_t i = 0u; i < 8u; ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> static_cast<unsigned>(i * 8u)) & 0xFFu));
  }
}

}  // namespace

bool is_supported_interpreter_tag(std::string_view tag) noexcept {
  return tag == "sh" || tag == "bash" || tag == "dash";
}

bool read_bundle_header(const std::vector<std::uint8_t>& bundle,
                        BundleHeader& header_out,
                        std::string& error_out) {
  if (bundle.size() < kFixedHeaderBytes) {
    error_out = "bundle header too small";
    return false;
  }
  if (bundle[0u] != static_cast<std::uint8_t>('E') || bundle[1u] != static_cast<std::uint8_t>('S') ||
      bundle[2u] != static_cast<std::uint8_t>('H') || bundle[3u] != static_cast<std::uint8_t>('B')) {
    error_out = "bundle magic mismatch";
    return false;
  }

  const std::uint8_t format_version = bundle[4u];
  if (format_version != kShellBundleFormatVersion) {
    error_out = "bundle format version mismatch";
    return false;
  }

  const std::uint8_t key_material_marker = bundle[5u];
  const std::uint8_t flags = bundle[6u];
  const std::uint8_t interpreter_tag_length = bundle[7u];
  const std::uint16_t key_id_length = read_u16_le(bundle, 9u);
  const std::uint16_t key_schema_version = read_u16_le(bundle, 11u);
  const std::uint64_t payload_length = read_u64_le(bundle, 13u);

  const std::size_t variable_header_bytes = static_cast<std::size_t>(interpreter_tag_length);
  if (kFixedHeaderBytes > std::numeric_limits<std::size_t>::max() - variable_header_bytes) {
    error_out = "bundle header size overflow";
    return false;
  }
  const std::size_t header_size = kFixedHeaderBytes + variable_header_bytes;
  if (bundle.size() < header_size) {
    error_out = "bundle interpreter tag exceeds input size";
    return false;
  }

  if (bundle.size() < header_size + static_cast<std::size_t>(key_id_length)) {
    error_out = "bundle key id exceeds input size";
    return false;
  }
  if (payload_length >
      static_cast<std::uint64_t>(bundle.size() - header_size - static_cast<std::size_t>(key_id_length))) {
    error_out = "bundle payload exceeds input size";
    return false;
  }

  const std::size_t interpreter_offset = kFixedHeaderBytes;
  const std::string interpreter_tag(
      reinterpret_cast<const char*>(bundle.data() + interpreter_offset),
      reinterpret_cast<const char*>(bundle.data() + interpreter_offset + interpreter_tag_length));
  if (!is_supported_interpreter_tag(interpreter_tag)) {
    error_out = "bundle interpreter tag is unsupported";
    return false;
  }

  header_out = BundleHeader{
      .format_version = format_version,
      .key_material_marker = key_material_marker,
      .shebang_present = (flags & 0x01u) != 0u,
      .interpreter_tag = interpreter_tag,
      .key_id_length = key_id_length,
      .key_binding_schema_version = key_schema_version,
      .payload_length = payload_length,
      .header_size_bytes = header_size,
  };
  return true;
}

bool write_bundle_v3(std::string_view key_id,
                     std::string_view interpreter_tag,
                     bool shebang_present,
                     const std::vector<std::uint8_t>& encrypted_payload,
                     std::vector<std::uint8_t>& bundle_out,
                     std::string& error_out) {
  if (key_id.empty()) {
    error_out = "key id must not be empty";
    return false;
  }
  if (key_id.size() > std::numeric_limits<std::uint16_t>::max()) {
    error_out = "key id is too long";
    return false;
  }
  if (interpreter_tag.empty() || interpreter_tag.size() > std::numeric_limits<std::uint8_t>::max()) {
    error_out = "interpreter tag is malformed";
    return false;
  }
  if (!is_supported_interpreter_tag(interpreter_tag)) {
    error_out = "interpreter tag is unsupported";
    return false;
  }

  bundle_out.clear();
  bundle_out.reserve(kFixedHeaderBytes + interpreter_tag.size() + key_id.size() + encrypted_payload.size());

  bundle_out.push_back(static_cast<std::uint8_t>('E'));
  bundle_out.push_back(static_cast<std::uint8_t>('S'));
  bundle_out.push_back(static_cast<std::uint8_t>('H'));
  bundle_out.push_back(static_cast<std::uint8_t>('B'));
  bundle_out.push_back(kShellBundleFormatVersion);
  bundle_out.push_back(0u);  // key material external only
  bundle_out.push_back(shebang_present ? 0x01u : 0u);
  bundle_out.push_back(static_cast<std::uint8_t>(interpreter_tag.size()));
  bundle_out.push_back(0u);  // reserved
  append_u16_le(bundle_out, static_cast<std::uint16_t>(key_id.size()));
  append_u16_le(bundle_out, kShellKeyBindingSchemaVersion);
  append_u64_le(bundle_out, static_cast<std::uint64_t>(encrypted_payload.size()));

  bundle_out.insert(bundle_out.end(), interpreter_tag.begin(), interpreter_tag.end());
  bundle_out.insert(bundle_out.end(), key_id.begin(), key_id.end());
  bundle_out.insert(bundle_out.end(), encrypted_payload.begin(), encrypted_payload.end());
  return true;
}

}  // namespace eippf::script_guard

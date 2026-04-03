#include "dex_toolchain/manifest_contract.hpp"

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <string>
#include <string_view>
#include <utility>

namespace eippf::dex_toolchain {

namespace {

constexpr std::uint32_t kSchemaVersion = 2u;
constexpr std::uint32_t kLoaderFormatVersion = 3u;
constexpr std::string_view kKind = "android_dex_bundle";
constexpr std::string_view kTargetKindAndroidDex = "android_dex";
constexpr std::string_view kTargetKindAndroidDexLegacy = "android_dex_research";
constexpr std::string_view kBackendKind = "dex_loader_vm";
constexpr std::string_view kRuntimeLane = "dex_loader_vm";
constexpr std::string_view kMutationProfile = "dex_bundle";
constexpr std::string_view kSignaturePolicy = "required_verifier";
constexpr std::string_view kArtifactKind = "dex_bundle";
constexpr std::string_view kKeyProviderProtocol = "eippf.external_key.v1";
constexpr std::string_view kEndpointExecutableAdapter = "executable_adapter";
constexpr std::string_view kEndpointFifo = "fifo";
constexpr std::string_view kEndpointUnixSocket = "unix_socket";
constexpr std::string_view kBridgeSurface = "allowlist_only";
constexpr std::string_view kClassLoaderPolicy = "private_handle_only";
constexpr std::string_view kAntiDebugPolicy = "block_jdwp_attach";
constexpr std::string_view kAntiHookPolicy = "best_effort_frida_xposed_guard";

enum class JsonValueType : std::uint8_t {
  kString = 0u,
  kBool = 1u,
  kNumber = 2u,
};

struct JsonValue final {
  JsonValueType type = JsonValueType::kString;
  std::string string_value;
  bool bool_value = false;
  std::uint64_t number_value = 0u;
};

[[nodiscard]] bool fail(std::string& error_out, std::string_view message) {
  error_out.assign(message);
  return false;
}

[[nodiscard]] bool is_allowed_endpoint_kind(std::string_view endpoint_kind) noexcept {
  return endpoint_kind == kEndpointExecutableAdapter ||
         endpoint_kind == kEndpointFifo ||
         endpoint_kind == kEndpointUnixSocket;
}

[[nodiscard]] bool is_allowed_target_kind(std::string_view target_kind) noexcept {
  return target_kind == kTargetKindAndroidDex ||
         target_kind == kTargetKindAndroidDexLegacy;
}

[[nodiscard]] std::string json_escape(std::string_view value) {
  std::string escaped;
  escaped.reserve(value.size() + 8u);
  for (char ch : value) {
    switch (ch) {
      case '\\':
        escaped += "\\\\";
        break;
      case '"':
        escaped += "\\\"";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        escaped.push_back(ch);
        break;
    }
  }
  return escaped;
}

[[nodiscard]] bool append_utf8(std::uint32_t codepoint, std::string& out) {
  if (codepoint <= 0x7Fu) {
    out.push_back(static_cast<char>(codepoint));
    return true;
  }
  if (codepoint <= 0x7FFu) {
    out.push_back(static_cast<char>(0xC0u | ((codepoint >> 6u) & 0x1Fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
    return true;
  }
  if (codepoint <= 0xFFFFu) {
    if (codepoint >= 0xD800u && codepoint <= 0xDFFFu) {
      return false;
    }
    out.push_back(static_cast<char>(0xE0u | ((codepoint >> 12u) & 0x0Fu)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
    return true;
  }
  if (codepoint <= 0x10FFFFu) {
    out.push_back(static_cast<char>(0xF0u | ((codepoint >> 18u) & 0x07u)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 12u) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | ((codepoint >> 6u) & 0x3Fu)));
    out.push_back(static_cast<char>(0x80u | (codepoint & 0x3Fu)));
    return true;
  }
  return false;
}

class FlatJsonObjectParser final {
 public:
  explicit FlatJsonObjectParser(std::string_view input) : input_(input) {}

  [[nodiscard]] bool parse(std::map<std::string, JsonValue>& fields_out,
                           std::string& error_out) {
    fields_out.clear();
    skip_ws();
    if (!consume_char('{')) {
      return fail(error_out, "manifest is not a JSON object");
    }

    skip_ws();
    if (consume_char('}')) {
      skip_ws();
      if (pos_ != input_.size()) {
        return fail(error_out, "manifest has trailing data");
      }
      return true;
    }

    while (true) {
      std::string key;
      if (!parse_string(key, error_out)) {
        return false;
      }
      skip_ws();
      if (!consume_char(':')) {
        return fail(error_out, "manifest key is missing ':'");
      }
      skip_ws();

      JsonValue value{};
      if (!parse_value(value, error_out)) {
        return false;
      }

      if (fields_out.find(key) != fields_out.end()) {
        return fail(error_out, "manifest has duplicate key");
      }
      fields_out.insert(std::make_pair(std::move(key), std::move(value)));

      skip_ws();
      if (consume_char('}')) {
        break;
      }
      if (!consume_char(',')) {
        return fail(error_out, "manifest object expects ',' or '}'");
      }
      skip_ws();
    }

    skip_ws();
    if (pos_ != input_.size()) {
      return fail(error_out, "manifest has trailing data");
    }
    return true;
  }

 private:
  void skip_ws() noexcept {
    while (pos_ < input_.size() &&
           std::isspace(static_cast<unsigned char>(input_[pos_])) != 0) {
      ++pos_;
    }
  }

  [[nodiscard]] bool consume_char(char expected) noexcept {
    if (pos_ < input_.size() && input_[pos_] == expected) {
      ++pos_;
      return true;
    }
    return false;
  }

  [[nodiscard]] bool consume_literal(std::string_view literal) noexcept {
    if (literal.empty() || pos_ > input_.size() ||
        literal.size() > (input_.size() - pos_)) {
      return false;
    }
    if (input_.compare(pos_, literal.size(), literal) != 0) {
      return false;
    }
    pos_ += literal.size();
    return true;
  }

  [[nodiscard]] bool parse_hex4(std::uint32_t& codepoint_out,
                                std::string& error_out) {
    if (pos_ > input_.size() || 4u > (input_.size() - pos_)) {
      return fail(error_out, "manifest has incomplete unicode escape");
    }
    std::uint32_t value = 0u;
    for (std::size_t i = 0u; i < 4u; ++i) {
      const char ch = input_[pos_ + i];
      value <<= 4u;
      if (ch >= '0' && ch <= '9') {
        value |= static_cast<std::uint32_t>(ch - '0');
        continue;
      }
      if (ch >= 'a' && ch <= 'f') {
        value |= static_cast<std::uint32_t>((ch - 'a') + 10);
        continue;
      }
      if (ch >= 'A' && ch <= 'F') {
        value |= static_cast<std::uint32_t>((ch - 'A') + 10);
        continue;
      }
      return fail(error_out, "manifest has invalid unicode escape");
    }
    pos_ += 4u;
    codepoint_out = value;
    return true;
  }

  [[nodiscard]] bool parse_string(std::string& out, std::string& error_out) {
    if (!consume_char('"')) {
      return fail(error_out, "manifest expected a JSON string");
    }
    out.clear();

    while (pos_ < input_.size()) {
      const char ch = input_[pos_++];
      if (ch == '"') {
        return true;
      }
      if (ch == '\\') {
        if (pos_ >= input_.size()) {
          return fail(error_out, "manifest has invalid escape sequence");
        }
        const char esc = input_[pos_++];
        switch (esc) {
          case '"':
          case '\\':
          case '/':
            out.push_back(esc);
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'u': {
            std::uint32_t codepoint = 0u;
            if (!parse_hex4(codepoint, error_out)) {
              return false;
            }
            if (!append_utf8(codepoint, out)) {
              return fail(error_out, "manifest has unsupported unicode codepoint");
            }
            break;
          }
          default:
            return fail(error_out, "manifest has invalid escape sequence");
        }
        continue;
      }
      if (static_cast<unsigned char>(ch) < 0x20u) {
        return fail(error_out, "manifest string contains control character");
      }
      out.push_back(ch);
    }

    return fail(error_out, "manifest has unterminated string");
  }

  [[nodiscard]] bool parse_number(std::uint64_t& value_out,
                                  std::string& error_out) {
    if (pos_ >= input_.size() ||
        std::isdigit(static_cast<unsigned char>(input_[pos_])) == 0) {
      return fail(error_out, "manifest expected an unsigned integer");
    }

    std::uint64_t value = 0u;
    while (pos_ < input_.size() &&
           std::isdigit(static_cast<unsigned char>(input_[pos_])) != 0) {
      const unsigned digit = static_cast<unsigned>(input_[pos_] - '0');
      if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10u) {
        return fail(error_out, "manifest integer is out of range");
      }
      value = value * 10u + digit;
      ++pos_;
    }

    value_out = value;
    return true;
  }

  [[nodiscard]] bool parse_value(JsonValue& value_out, std::string& error_out) {
    if (pos_ >= input_.size()) {
      return fail(error_out, "manifest has incomplete value");
    }

    const char lead = input_[pos_];
    if (lead == '"') {
      value_out.type = JsonValueType::kString;
      return parse_string(value_out.string_value, error_out);
    }
    if (lead == 't') {
      if (!consume_literal("true")) {
        return fail(error_out, "manifest has invalid literal");
      }
      value_out.type = JsonValueType::kBool;
      value_out.bool_value = true;
      return true;
    }
    if (lead == 'f') {
      if (!consume_literal("false")) {
        return fail(error_out, "manifest has invalid literal");
      }
      value_out.type = JsonValueType::kBool;
      value_out.bool_value = false;
      return true;
    }
    if (std::isdigit(static_cast<unsigned char>(lead)) != 0) {
      value_out.type = JsonValueType::kNumber;
      return parse_number(value_out.number_value, error_out);
    }
    return fail(error_out, "manifest has unsupported value type");
  }

  std::string_view input_;
  std::size_t pos_ = 0u;
};

[[nodiscard]] bool read_text_file(const std::filesystem::path& path,
                                  std::string& out,
                                  std::string& error_out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return fail(error_out, "manifest read failed");
  }

  out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  if (!input.good() && !input.eof()) {
    out.clear();
    return fail(error_out, "manifest read failed");
  }
  return true;
}

[[nodiscard]] bool read_string_field(const std::map<std::string, JsonValue>& fields,
                                     std::string_view key,
                                     std::string& value_out,
                                     std::string& error_out) {
  const auto it = fields.find(std::string(key));
  if (it == fields.end()) {
    return fail(error_out, std::string("manifest missing field: ") + std::string(key));
  }
  if (it->second.type != JsonValueType::kString) {
    return fail(error_out, std::string("manifest field must be string: ") + std::string(key));
  }
  value_out = it->second.string_value;
  return true;
}

[[nodiscard]] bool read_bool_field(const std::map<std::string, JsonValue>& fields,
                                   std::string_view key,
                                   bool& value_out,
                                   std::string& error_out) {
  const auto it = fields.find(std::string(key));
  if (it == fields.end()) {
    return fail(error_out, std::string("manifest missing field: ") + std::string(key));
  }
  if (it->second.type != JsonValueType::kBool) {
    return fail(error_out, std::string("manifest field must be bool: ") + std::string(key));
  }
  value_out = it->second.bool_value;
  return true;
}

[[nodiscard]] bool read_u64_field(const std::map<std::string, JsonValue>& fields,
                                  std::string_view key,
                                  std::uint64_t& value_out,
                                  std::string& error_out) {
  const auto it = fields.find(std::string(key));
  if (it == fields.end()) {
    return fail(error_out, std::string("manifest missing field: ") + std::string(key));
  }
  if (it->second.type != JsonValueType::kNumber) {
    return fail(error_out, std::string("manifest field must be integer: ") + std::string(key));
  }
  value_out = it->second.number_value;
  return true;
}

[[nodiscard]] bool ensure_field_absent(const std::map<std::string, JsonValue>& fields,
                                       std::string_view key,
                                       std::string& error_out) {
  if (fields.find(std::string(key)) != fields.end()) {
    return fail(error_out, std::string("manifest contains forbidden field: ") + std::string(key));
  }
  return true;
}

[[nodiscard]] bool ensure_value(bool condition,
                                std::string_view message,
                                std::string& error_out) {
  if (!condition) {
    return fail(error_out, message);
  }
  return true;
}

}  // namespace

std::string build_android_dex_manifest_v2_json(const DexManifestContract& manifest) {
  const std::string_view endpoint_kind = manifest.key_provider_endpoint_kind.empty()
                                             ? kEndpointExecutableAdapter
                                             : std::string_view(manifest.key_provider_endpoint_kind);

  std::string json;
  json.reserve(1024u);
  json += "{";
  json += "\"schema_version\":2,";
  json += "\"kind\":\"android_dex_bundle\",";
  json += "\"target_kind\":\"android_dex\",";
  json += "\"backend_kind\":\"dex_loader_vm\",";
  json += "\"runtime_lane\":\"dex_loader_vm\",";
  json += "\"mutation_profile\":\"dex_bundle\",";
  json += "\"signature_policy\":\"required_verifier\",";
  json += "\"artifact_kind\":\"dex_bundle\",";
  json += "\"allow_jit\":false,";
  json += "\"allow_runtime_executable_pages\":false,";
  json += "\"allow_persistent_plaintext\":false,";
  json += "\"require_fail_closed\":true,";
  json += "\"plaintext_ttl_ms\":0,";
  json += "\"loader_format_version\":3,";
  json += "\"key_provider_protocol\":\"eippf.external_key.v1\",";
  json += "\"key_provider_endpoint_kind\":\"";
  json += json_escape(endpoint_kind);
  json += "\",";
  json += "\"key_provider_static_file\":false,";
  json += "\"external_key_required\":true,";
  json += "\"key_id\":\"";
  json += json_escape(manifest.key_id);
  json += "\",";
  json += "\"key_material_embedded\":false,";
  json += "\"bridge_surface\":\"allowlist_only\",";
  json += "\"class_loader_policy\":\"private_handle_only\",";
  json += "\"class_loader_exported\":false,";
  json += "\"anti_debug_policy\":\"block_jdwp_attach\",";
  json += "\"anti_hook_policy\":\"best_effort_frida_xposed_guard\",";
  json += "\"plaintext_output\":false,";
  json += "\"no_persistent_plaintext_goal\":true";
  json += "}";
  return json;
}

bool load_and_validate_manifest_contract(const std::filesystem::path& path,
                                         std::string_view expected_key_id,
                                         DexManifestContract& out,
                                         std::string& error_out) {
  error_out.clear();

  std::string manifest_text;
  if (!read_text_file(path, manifest_text, error_out)) {
    return false;
  }

  std::map<std::string, JsonValue> fields;
  FlatJsonObjectParser parser(manifest_text);
  if (!parser.parse(fields, error_out)) {
    return false;
  }

  if (!ensure_field_absent(fields, "encryption_key", error_out) ||
      !ensure_field_absent(fields, "input_hash_fnv1a64", error_out)) {
    return false;
  }

  DexManifestContract parsed{};

  std::uint64_t schema_version_u64 = 0u;
  std::uint64_t plaintext_ttl_ms_u64 = 0u;
  std::uint64_t loader_format_version_u64 = 0u;
  if (!read_u64_field(fields, "schema_version", schema_version_u64, error_out) ||
      !read_string_field(fields, "kind", parsed.kind, error_out) ||
      !read_string_field(fields, "target_kind", parsed.target_kind, error_out) ||
      !read_string_field(fields, "backend_kind", parsed.backend_kind, error_out) ||
      !read_string_field(fields, "runtime_lane", parsed.runtime_lane, error_out) ||
      !read_string_field(fields, "mutation_profile", parsed.mutation_profile, error_out) ||
      !read_string_field(fields, "signature_policy", parsed.signature_policy, error_out) ||
      !read_string_field(fields, "artifact_kind", parsed.artifact_kind, error_out) ||
      !read_bool_field(fields, "allow_jit", parsed.allow_jit, error_out) ||
      !read_bool_field(
          fields, "allow_runtime_executable_pages", parsed.allow_runtime_executable_pages, error_out) ||
      !read_bool_field(fields, "allow_persistent_plaintext", parsed.allow_persistent_plaintext, error_out) ||
      !read_bool_field(fields, "require_fail_closed", parsed.require_fail_closed, error_out) ||
      !read_u64_field(fields, "plaintext_ttl_ms", plaintext_ttl_ms_u64, error_out) ||
      !read_u64_field(fields, "loader_format_version", loader_format_version_u64, error_out) ||
      !read_string_field(fields, "key_provider_protocol", parsed.key_provider_protocol, error_out) ||
      !read_string_field(
          fields, "key_provider_endpoint_kind", parsed.key_provider_endpoint_kind, error_out) ||
      !read_bool_field(fields, "key_provider_static_file", parsed.key_provider_static_file, error_out) ||
      !read_bool_field(fields, "external_key_required", parsed.external_key_required, error_out) ||
      !read_string_field(fields, "key_id", parsed.key_id, error_out) ||
      !read_bool_field(fields, "key_material_embedded", parsed.key_material_embedded, error_out) ||
      !read_string_field(fields, "bridge_surface", parsed.bridge_surface, error_out) ||
      !read_string_field(fields, "class_loader_policy", parsed.class_loader_policy, error_out) ||
      !read_bool_field(fields, "class_loader_exported", parsed.class_loader_exported, error_out) ||
      !read_string_field(fields, "anti_debug_policy", parsed.anti_debug_policy, error_out) ||
      !read_string_field(fields, "anti_hook_policy", parsed.anti_hook_policy, error_out) ||
      !read_bool_field(fields, "plaintext_output", parsed.plaintext_output, error_out) ||
      !read_bool_field(
          fields, "no_persistent_plaintext_goal", parsed.no_persistent_plaintext_goal, error_out)) {
    return false;
  }

  if (schema_version_u64 > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max()) ||
      loader_format_version_u64 >
          static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
    return fail(error_out, "manifest integer field is out of range");
  }
  parsed.schema_version = static_cast<std::uint32_t>(schema_version_u64);
  parsed.plaintext_ttl_ms = plaintext_ttl_ms_u64;
  parsed.loader_format_version = static_cast<std::uint32_t>(loader_format_version_u64);

  if (!ensure_value(parsed.schema_version == kSchemaVersion, "manifest schema_version must be 2", error_out) ||
      !ensure_value(parsed.kind == kKind, "manifest kind mismatch", error_out) ||
      !ensure_value(is_allowed_target_kind(parsed.target_kind), "manifest target_kind mismatch", error_out) ||
      !ensure_value(parsed.backend_kind == kBackendKind, "manifest backend_kind mismatch", error_out) ||
      !ensure_value(parsed.runtime_lane == kRuntimeLane, "manifest runtime_lane mismatch", error_out) ||
      !ensure_value(parsed.mutation_profile == kMutationProfile, "manifest mutation_profile mismatch", error_out) ||
      !ensure_value(parsed.signature_policy == kSignaturePolicy, "manifest signature_policy mismatch", error_out) ||
      !ensure_value(parsed.artifact_kind == kArtifactKind, "manifest artifact_kind mismatch", error_out) ||
      !ensure_value(!parsed.allow_jit, "manifest allow_jit must be false", error_out) ||
      !ensure_value(!parsed.allow_runtime_executable_pages,
                    "manifest allow_runtime_executable_pages must be false",
                    error_out) ||
      !ensure_value(!parsed.allow_persistent_plaintext,
                    "manifest allow_persistent_plaintext must be false",
                    error_out) ||
      !ensure_value(parsed.require_fail_closed, "manifest require_fail_closed must be true", error_out) ||
      !ensure_value(parsed.plaintext_ttl_ms == 0u, "manifest plaintext_ttl_ms must be 0", error_out) ||
      !ensure_value(parsed.loader_format_version == kLoaderFormatVersion,
                    "manifest loader_format_version must be 3",
                    error_out) ||
      !ensure_value(parsed.key_provider_protocol == kKeyProviderProtocol,
                    "manifest key_provider_protocol mismatch",
                    error_out) ||
      !ensure_value(is_allowed_endpoint_kind(parsed.key_provider_endpoint_kind),
                    "manifest key_provider_endpoint_kind mismatch",
                    error_out) ||
      !ensure_value(!parsed.key_provider_static_file,
                    "manifest key_provider_static_file must be false",
                    error_out) ||
      !ensure_value(parsed.external_key_required, "manifest external_key_required must be true", error_out) ||
      !ensure_value(!parsed.key_id.empty(), "manifest key_id must be non-empty", error_out) ||
      !ensure_value(parsed.key_id == expected_key_id, "manifest key_id mismatch", error_out) ||
      !ensure_value(!parsed.key_material_embedded, "manifest key_material_embedded must be false", error_out) ||
      !ensure_value(parsed.bridge_surface == kBridgeSurface, "manifest bridge_surface mismatch", error_out) ||
      !ensure_value(parsed.class_loader_policy == kClassLoaderPolicy,
                    "manifest class_loader_policy mismatch",
                    error_out) ||
      !ensure_value(!parsed.class_loader_exported,
                    "manifest class_loader_exported must be false",
                    error_out) ||
      !ensure_value(parsed.anti_debug_policy == kAntiDebugPolicy,
                    "manifest anti_debug_policy mismatch",
                    error_out) ||
      !ensure_value(parsed.anti_hook_policy == kAntiHookPolicy,
                    "manifest anti_hook_policy mismatch",
                    error_out) ||
      !ensure_value(!parsed.plaintext_output, "manifest plaintext_output must be false", error_out) ||
      !ensure_value(parsed.no_persistent_plaintext_goal,
                    "manifest no_persistent_plaintext_goal must be true",
                    error_out)) {
    return false;
  }

  out = std::move(parsed);
  error_out.clear();
  return true;
}

}  // namespace eippf::dex_toolchain

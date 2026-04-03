#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace eippf::script_guard {

constexpr std::string_view kKeyProviderProtocol = "eippf.external_key.v1";

enum class ProviderEndpointKind : std::uint8_t {
  kExecutableAdapter = 0u,
  kFifo = 1u,
  kUnixSocket = 2u,
  kInvalid = 3u,
};

enum class KeyProviderError : std::uint8_t {
  kOk = 0u,
  kReadFailed = 1u,
  kMalformed = 2u,
  kProviderRejected = 3u,
  kKeyIdMismatch = 4u,
  kUnsupportedEndpoint = 5u,
  kStaticFileRejected = 6u,
  kExecutionFailed = 7u,
};

[[nodiscard]] std::string_view provider_endpoint_kind_name(ProviderEndpointKind kind) noexcept;

[[nodiscard]] ProviderEndpointKind classify_provider_endpoint(
    const std::filesystem::path& provider_path) noexcept;

[[nodiscard]] KeyProviderError read_provider_response_from_executable(
    const std::filesystem::path& provider_path,
    std::string& response_out);

[[nodiscard]] KeyProviderError read_provider_response_from_fifo(
    const std::filesystem::path& provider_path,
    std::string& response_out);

[[nodiscard]] KeyProviderError read_provider_response_from_unix_socket(
    const std::filesystem::path& provider_path,
    std::string& response_out);

[[nodiscard]] KeyProviderError resolve_external_key_from_endpoint(
    const std::filesystem::path& provider_path,
    std::string_view expected_key_id,
    const std::filesystem::path& workspace_root,
    const std::filesystem::path& temp_root,
    std::uint8_t& key_out,
    ProviderEndpointKind& endpoint_kind_out);

}  // namespace eippf::script_guard

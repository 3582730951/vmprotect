#pragma once

#include "dex_toolchain/manifest_contract.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace eippf::dex_toolchain {

struct LoaderOptions final {
  std::filesystem::path input_bundle_path;
  std::filesystem::path manifest_path;
  std::filesystem::path key_provider_path;
  std::string key_id;
  std::string bridge_token_hex;
  std::filesystem::path report_path;
};

enum class LoaderError : std::uint8_t {
  ok = 0u,
  invalid_cli = 1u,
  manifest_read_failed = 2u,
  manifest_invalid = 3u,
  bundle_read_failed = 4u,
  bundle_invalid = 5u,
  provider_failed = 6u,
  guardrail_blocked = 7u,
  bridge_token_missing = 8u,
  report_write_failed = 9u,
};

[[nodiscard]] bool parse_loader_options(int argc,
                                        char** argv,
                                        LoaderOptions& options_out,
                                        LoaderError& error_out) noexcept;

[[nodiscard]] int run_loader_session(const LoaderOptions& options,
                                     LoaderError& error_out) noexcept;

[[nodiscard]] bool write_loader_report(const LoaderOptions& options,
                                       const DexManifestContract& manifest,
                                       std::uint64_t bridge_record_count,
                                       bool bridge_token_checked,
                                       std::string_view bridge_token_status,
                                       std::string_view guardrail_status,
                                       std::string_view provider_endpoint_kind,
                                       std::string_view result,
                                       LoaderError& error_out) noexcept;

[[nodiscard]] const char* loader_error_message(LoaderError error) noexcept;

}  // namespace eippf::dex_toolchain

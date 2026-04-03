#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace eippf::dex_toolchain {

struct DexManifestContract final {
  std::uint32_t schema_version = 2u;
  std::string kind = "android_dex_bundle";
  std::string target_kind = "android_dex";
  std::string backend_kind = "dex_loader_vm";
  std::string runtime_lane = "dex_loader_vm";
  std::string mutation_profile = "dex_bundle";
  std::string signature_policy = "required_verifier";
  std::string artifact_kind = "dex_bundle";
  bool allow_jit = false;
  bool allow_runtime_executable_pages = false;
  bool allow_persistent_plaintext = false;
  bool require_fail_closed = true;
  std::uint64_t plaintext_ttl_ms = 0u;
  std::uint32_t loader_format_version = 3u;
  std::string key_provider_protocol = "eippf.external_key.v1";
  std::string key_provider_endpoint_kind = "executable_adapter";
  bool key_provider_static_file = false;
  bool external_key_required = true;
  std::string key_id;
  bool key_material_embedded = false;
  std::string bridge_surface = "allowlist_only";
  std::string class_loader_policy = "private_handle_only";
  bool class_loader_exported = false;
  std::string anti_debug_policy = "block_jdwp_attach";
  std::string anti_hook_policy = "best_effort_frida_xposed_guard";
  bool plaintext_output = false;
  bool no_persistent_plaintext_goal = true;
};

[[nodiscard]] std::string build_android_dex_manifest_v2_json(
    const DexManifestContract& manifest);

[[nodiscard]] bool load_and_validate_manifest_contract(
    const std::filesystem::path& path,
    std::string_view expected_key_id,
    DexManifestContract& out,
    std::string& error_out);

}  // namespace eippf::dex_toolchain

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

namespace eippf::tests::ios_safe {

inline constexpr std::uint32_t kLcSegment32 = 0x1u;
inline constexpr std::uint32_t kLcLoadDylib = 0xCu;
inline constexpr std::uint32_t kLcCodeSignature = 0x1Du;

[[nodiscard]] inline std::string quote_arg(const std::string& value) {
  std::string out = "\"";
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

[[nodiscard]] inline int normalize_status(int status) {
#if defined(__unix__) || defined(__APPLE__)
  if (status == -1) {
    return -1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
#endif
  return status;
}

inline bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

inline bool write_text(const std::filesystem::path& path, std::string_view text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

inline bool write_bytes(const std::filesystem::path& path,
                        const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] inline std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

inline bool write_executable_script(const std::filesystem::path& path, std::string_view content) {
  if (!write_text(path, content)) {
    return false;
  }
  std::error_code ec;
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
          std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
          std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
          std::filesystem::perms::others_exec,
      std::filesystem::perm_options::replace,
      ec);
  return !ec;
}

[[nodiscard]] inline std::filesystem::path make_temp_dir(std::string_view prefix) {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     (std::string(prefix) + "_" +
                                      std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    return {};
  }
  return path;
}

inline void write_u32_le(std::vector<std::uint8_t>& bytes,
                         std::size_t offset,
                         std::uint32_t value) {
  bytes[offset + 0u] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
}

inline void write_u32_be(std::vector<std::uint8_t>& bytes,
                         std::size_t offset,
                         std::uint32_t value) {
  bytes[offset + 0u] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  bytes[offset + 1u] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 2u] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 3u] = static_cast<std::uint8_t>(value & 0xFFu);
}

[[nodiscard]] inline std::vector<std::uint8_t> build_macho_fixture(
    bool with_codesig_command,
    std::string_view dylib_name = {},
    bool writable_executable_segment = false) {
  std::vector<std::vector<std::uint8_t>> commands;

  if (writable_executable_segment) {
    std::vector<std::uint8_t> segment(56u, 0u);
    write_u32_le(segment, 0u, kLcSegment32);
    write_u32_le(segment, 4u, 56u);
    const char segname[] = "__TEXT";
    for (std::size_t i = 0u; i < sizeof(segname) - 1u; ++i) {
      segment[8u + i] = static_cast<std::uint8_t>(segname[i]);
    }
    write_u32_le(segment, 40u, 0x7u);
    write_u32_le(segment, 44u, 0x7u);
    commands.push_back(std::move(segment));
  }

  if (!dylib_name.empty()) {
    const std::size_t cmdsize = 24u + dylib_name.size() + 1u;
    std::vector<std::uint8_t> dylib(cmdsize, 0u);
    write_u32_le(dylib, 0u, kLcLoadDylib);
    write_u32_le(dylib, 4u, static_cast<std::uint32_t>(cmdsize));
    write_u32_le(dylib, 8u, 24u);
    for (std::size_t i = 0u; i < dylib_name.size(); ++i) {
      dylib[24u + i] = static_cast<std::uint8_t>(dylib_name[i]);
    }
    commands.push_back(std::move(dylib));
  }

  std::size_t command_bytes = 0u;
  for (const auto& command : commands) {
    command_bytes += command.size();
  }
  if (with_codesig_command) {
    command_bytes += 16u;
  }

  const std::size_t header_bytes = 28u;
  const std::size_t codesig_blob_bytes = with_codesig_command ? 16u : 0u;
  std::vector<std::uint8_t> bytes(header_bytes + command_bytes + codesig_blob_bytes, 0u);
  bytes[0u] = 0xCEu;
  bytes[1u] = 0xFAu;
  bytes[2u] = 0xEDu;
  bytes[3u] = 0xFEu;
  write_u32_le(bytes, 16u, static_cast<std::uint32_t>(commands.size() + (with_codesig_command ? 1u : 0u)));
  write_u32_le(bytes, 20u, static_cast<std::uint32_t>(command_bytes));

  std::size_t cursor = header_bytes;
  for (const auto& command : commands) {
    std::copy(command.begin(), command.end(), bytes.begin() + static_cast<std::ptrdiff_t>(cursor));
    cursor += command.size();
  }

  if (with_codesig_command) {
    const std::size_t blob_offset = header_bytes + command_bytes;
    write_u32_le(bytes, cursor + 0u, kLcCodeSignature);
    write_u32_le(bytes, cursor + 4u, 16u);
    write_u32_le(bytes, cursor + 8u, static_cast<std::uint32_t>(blob_offset));
    write_u32_le(bytes, cursor + 12u, 16u);
    write_u32_be(bytes, blob_offset + 0u, 0xFADE0CC0u);
    write_u32_be(bytes, blob_offset + 4u, 16u);
  }

  return bytes;
}

[[nodiscard]] inline std::string make_ios_manifest_json(bool allow_jit) {
  const char* allow_jit_text = allow_jit ? "true" : "false";
  const char* allow_exec_text = allow_jit ? "true" : "false";
  return std::string(
             "{\"target_kind\":\"ios_appstore\",\"artifact_kind\":\"macho\","
             "\"runtime_lane\":\"ios_safe\",\"backend_kind\":\"ios_safe_aot\","
             "\"mutation_profile\":\"ios_macho\",\"signature_policy\":\"required_verifier\","
             "\"allow_jit\":") +
         allow_jit_text +
         ",\"allow_runtime_executable_pages\":" + allow_exec_text +
         ",\"allow_persistent_plaintext\":false,\"require_fail_closed\":true,"
         "\"ios_compliance_profile\":\"app_store_safe\"}\n";
}

[[nodiscard]] inline std::filesystem::path make_verifier_wrapper(
    const std::filesystem::path& dir,
    std::string_view name,
    std::string_view mode) {
  const std::filesystem::path wrapper = dir / (std::string(name) + ".sh");
  const std::string script = std::string("#!/usr/bin/env bash\nexec python3 ") +
                             quote_arg(EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH) +
                             " --mode " + quote_arg(std::string(mode)) + " \"$@\"\n";
  if (!write_executable_script(wrapper, script)) {
    return {};
  }
  return wrapper;
}

[[nodiscard]] inline int run_audit(const std::filesystem::path& artifact,
                                   const std::filesystem::path& report,
                                   const std::filesystem::path& manifest,
                                   const std::filesystem::path& verifier = {}) {
  std::string command = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) +
                        " --input " + quote_arg(artifact.string()) + " --denylist " +
                        quote_arg(EIPPF_LEXICAL_DENYLIST_PATH) + " --output " +
                        quote_arg(report.string()) + " --manifest " +
                        quote_arg(manifest.string()) + " --strict";
  if (!verifier.empty()) {
    command += " --signature-verifier ";
    command += quote_arg(verifier.string());
  }
  return normalize_status(std::system(command.c_str()));
}

}  // namespace eippf::tests::ios_safe

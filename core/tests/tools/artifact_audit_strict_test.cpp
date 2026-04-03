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

#ifndef EIPPF_ARTIFACT_AUDIT_PATH
#error "EIPPF_ARTIFACT_AUDIT_PATH must be defined"
#endif

#ifndef EIPPF_LEXICAL_DENYLIST_PATH
#error "EIPPF_LEXICAL_DENYLIST_PATH must be defined"
#endif

#ifndef EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH
#error "EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH must be defined"
#endif

#ifndef EIPPF_SIGNATURE_VERIFIER_WORK_DIR
#error "EIPPF_SIGNATURE_VERIFIER_WORK_DIR must be defined"
#endif

namespace {

constexpr std::string_view kDexBundleMagic = "EDXB";
constexpr std::size_t kDexBundleHeaderBytes = 26u;
constexpr std::size_t kDexBundleFlagsOffset = 5u;
constexpr std::size_t kDexBundleKeyMarkerOffset = 9u;
constexpr std::size_t kDexBundlePayloadLengthOffset = 18u;

struct PeFixtureOptions final {
  std::uint32_t text_characteristics = 0x60000020u;
  std::string payload = "clean_payload";
  std::string import_dll;
  std::string import_symbol;
  bool with_signature = false;
};

[[nodiscard]] std::string quote_arg(const std::string& value) {
  std::string out = "\"";
  out.reserve(value.size() + 2u);
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

[[nodiscard]] int normalize_status(int status) {
#if defined(__unix__) || defined(__APPLE__)
  if (status == -1) {
    return -1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return status;
#else
  return status;
#endif
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

bool write_text(const std::filesystem::path& path, std::string_view text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_artifact_audit_test_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void write_u16_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
}

void write_u32_le(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 3] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
}

void write_u32_be(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  bytes[offset] = static_cast<std::uint8_t>((value >> 24u) & 0xFFu);
  bytes[offset + 1] = static_cast<std::uint8_t>((value >> 16u) & 0xFFu);
  bytes[offset + 2] = static_cast<std::uint8_t>((value >> 8u) & 0xFFu);
  bytes[offset + 3] = static_cast<std::uint8_t>(value & 0xFFu);
}

[[nodiscard]] std::vector<std::uint8_t> build_pe_fixture(const PeFixtureOptions& options) {
  constexpr std::size_t kPeOffset = 0x80u;
  constexpr std::size_t kOptionalHeaderSize = 0xE0u;
  const bool has_import = !options.import_dll.empty() && !options.import_symbol.empty();
  const std::size_t section_count = has_import ? 2u : 1u;
  const std::size_t section_table_offset = kPeOffset + 4u + 20u + kOptionalHeaderSize;
  const std::size_t text_raw_offset = section_table_offset + (section_count * 40u);
  const std::size_t text_raw_size = std::max<std::size_t>(options.payload.size(), 1u);
  const std::size_t idata_raw_offset = text_raw_offset + text_raw_size;
  const std::size_t idata_raw_size = has_import ? 0x80u : 0u;
  const std::size_t cert_offset = idata_raw_offset + idata_raw_size;
  const std::size_t cert_size = options.with_signature ? 8u : 0u;

  std::vector<std::uint8_t> bytes(cert_offset + cert_size, 0u);
  bytes[0] = static_cast<std::uint8_t>('M');
  bytes[1] = static_cast<std::uint8_t>('Z');
  write_u32_le(bytes, 0x3Cu, static_cast<std::uint32_t>(kPeOffset));
  bytes[kPeOffset + 0u] = static_cast<std::uint8_t>('P');
  bytes[kPeOffset + 1u] = static_cast<std::uint8_t>('E');
  write_u16_le(bytes, kPeOffset + 4u, 0x014Cu);
  write_u16_le(bytes, kPeOffset + 6u, static_cast<std::uint16_t>(section_count));
  write_u16_le(bytes, kPeOffset + 20u, static_cast<std::uint16_t>(kOptionalHeaderSize));

  const std::size_t optional_offset = kPeOffset + 24u;
  write_u16_le(bytes, optional_offset + 0u, 0x10Bu);
  write_u32_le(bytes, optional_offset + 92u, 16u);

  const std::size_t text_section_offset = section_table_offset;
  bytes[text_section_offset + 0u] = static_cast<std::uint8_t>('.');
  bytes[text_section_offset + 1u] = static_cast<std::uint8_t>('t');
  bytes[text_section_offset + 2u] = static_cast<std::uint8_t>('e');
  bytes[text_section_offset + 3u] = static_cast<std::uint8_t>('x');
  bytes[text_section_offset + 4u] = static_cast<std::uint8_t>('t');
  write_u32_le(bytes, text_section_offset + 8u, static_cast<std::uint32_t>(text_raw_size));
  write_u32_le(bytes, text_section_offset + 12u, 0x1000u);
  write_u32_le(bytes, text_section_offset + 16u, static_cast<std::uint32_t>(text_raw_size));
  write_u32_le(bytes, text_section_offset + 20u, static_cast<std::uint32_t>(text_raw_offset));
  write_u32_le(bytes, text_section_offset + 36u, options.text_characteristics);

  for (std::size_t i = 0; i < options.payload.size(); ++i) {
    bytes[text_raw_offset + i] = static_cast<std::uint8_t>(options.payload[i]);
  }

  if (has_import) {
    const std::size_t idata_section_offset = text_section_offset + 40u;
    constexpr std::uint32_t kIdataVa = 0x2000u;
    bytes[idata_section_offset + 0u] = static_cast<std::uint8_t>('.');
    bytes[idata_section_offset + 1u] = static_cast<std::uint8_t>('i');
    bytes[idata_section_offset + 2u] = static_cast<std::uint8_t>('d');
    bytes[idata_section_offset + 3u] = static_cast<std::uint8_t>('a');
    bytes[idata_section_offset + 4u] = static_cast<std::uint8_t>('t');
    bytes[idata_section_offset + 5u] = static_cast<std::uint8_t>('a');
    write_u32_le(bytes, idata_section_offset + 8u, static_cast<std::uint32_t>(idata_raw_size));
    write_u32_le(bytes, idata_section_offset + 12u, kIdataVa);
    write_u32_le(bytes, idata_section_offset + 16u, static_cast<std::uint32_t>(idata_raw_size));
    write_u32_le(bytes, idata_section_offset + 20u, static_cast<std::uint32_t>(idata_raw_offset));
    write_u32_le(bytes, idata_section_offset + 36u, 0x40000040u);

    const std::string dll_name = options.import_dll + '\0';
    const std::string symbol_name = options.import_symbol + '\0';
    const std::size_t symbol_name_offset = idata_raw_offset + 0x3Au;
    const std::size_t dll_name_offset = symbol_name_offset + symbol_name.size();

    write_u32_le(bytes, optional_offset + 104u, kIdataVa);
    write_u32_le(bytes, optional_offset + 108u, 40u);

    write_u32_le(bytes, idata_raw_offset + 0u, kIdataVa + 0x28u);
    write_u32_le(bytes, idata_raw_offset + 12u,
                 kIdataVa + static_cast<std::uint32_t>(dll_name_offset - idata_raw_offset));
    write_u32_le(bytes, idata_raw_offset + 16u, kIdataVa + 0x30u);

    write_u32_le(bytes, idata_raw_offset + 0x28u, kIdataVa + 0x38u);
    write_u32_le(bytes, idata_raw_offset + 0x30u, kIdataVa + 0x38u);
    write_u16_le(bytes, idata_raw_offset + 0x38u, 0u);
    for (std::size_t i = 0; i < symbol_name.size(); ++i) {
      bytes[symbol_name_offset + i] = static_cast<std::uint8_t>(symbol_name[i]);
    }
    for (std::size_t i = 0; i < dll_name.size(); ++i) {
      bytes[dll_name_offset + i] = static_cast<std::uint8_t>(dll_name[i]);
    }
  }

  if (options.with_signature) {
    write_u32_le(bytes, optional_offset + 128u, static_cast<std::uint32_t>(cert_offset));
    write_u32_le(bytes, optional_offset + 132u, static_cast<std::uint32_t>(cert_size));
    write_u32_le(bytes, cert_offset + 0u, 8u);
    write_u16_le(bytes, cert_offset + 4u, 0x0200u);
    write_u16_le(bytes, cert_offset + 6u, 0x0002u);
  }

  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> build_elf64_fixture(bool add_signature_trailer) {
  std::vector<std::uint8_t> bytes(0x40 + 0x38, 0u);
  bytes[0] = 0x7f;
  bytes[1] = static_cast<std::uint8_t>('E');
  bytes[2] = static_cast<std::uint8_t>('L');
  bytes[3] = static_cast<std::uint8_t>('F');
  bytes[4] = 2;
  bytes[5] = 1;
  bytes[0x20] = 0x40;
  bytes[0x36] = 0x38;
  bytes[0x38] = 1;
  const std::size_t ph = 0x40;
  bytes[ph + 0] = 1;
  bytes[ph + 4] = 0;
  if (add_signature_trailer) {
    const std::string signer = "ci";
    const std::string key_id = "keyid";
    const std::vector<std::uint8_t> signature = {0x30u, 0x82u, 0x01u, 0x0Au};
    bytes.insert(bytes.end(), signer.begin(), signer.end());
    bytes.insert(bytes.end(), key_id.begin(), key_id.end());
    bytes.insert(bytes.end(), signature.begin(), signature.end());

    std::vector<std::uint8_t> footer(12u, 0u);
    footer[0] = 1u;
    footer[1] = 1u;
    footer[2] = 2u;
    footer[3] = static_cast<std::uint8_t>(signer.size());
    footer[4] = static_cast<std::uint8_t>(key_id.size());
    const std::uint32_t sig_len = static_cast<std::uint32_t>(signature.size());
    footer[8] = static_cast<std::uint8_t>((sig_len >> 24u) & 0xFFu);
    footer[9] = static_cast<std::uint8_t>((sig_len >> 16u) & 0xFFu);
    footer[10] = static_cast<std::uint8_t>((sig_len >> 8u) & 0xFFu);
    footer[11] = static_cast<std::uint8_t>(sig_len & 0xFFu);
    bytes.insert(bytes.end(), footer.begin(), footer.end());
    const char magic[] = "~Module signature appended~\n";
    bytes.insert(bytes.end(), magic, magic + sizeof(magic) - 1);
  }
  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> build_macho32_fixture(
    bool with_codesig_command,
    std::string_view dylib_name = {},
    bool writable_executable_segment = false) {
  constexpr std::uint32_t kLcSegment = 0x1u;
  constexpr std::uint32_t kLcLoadDylib = 0xCu;
  constexpr std::uint32_t kLcCodeSignature = 0x1Du;

  std::vector<std::vector<std::uint8_t>> commands;
  if (writable_executable_segment) {
    std::vector<std::uint8_t> segment(56u, 0u);
    write_u32_le(segment, 0u, kLcSegment);
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

  constexpr std::size_t kHeaderBytes = 28u;
  const std::size_t blob_bytes = with_codesig_command ? 16u : 0u;
  std::vector<std::uint8_t> bytes(kHeaderBytes + command_bytes + blob_bytes, 0u);
  bytes[0] = 0xCE;
  bytes[1] = 0xFA;
  bytes[2] = 0xED;
  bytes[3] = 0xFE;
  write_u32_le(bytes, 16u,
               static_cast<std::uint32_t>(commands.size() + (with_codesig_command ? 1u : 0u)));
  write_u32_le(bytes, 20u, static_cast<std::uint32_t>(command_bytes));

  std::size_t cursor = kHeaderBytes;
  for (const auto& command : commands) {
    std::copy(command.begin(), command.end(), bytes.begin() + static_cast<std::ptrdiff_t>(cursor));
    cursor += command.size();
  }

  if (!with_codesig_command) {
    return bytes;
  }

  const std::size_t blob_offset = kHeaderBytes + command_bytes;
  write_u32_le(bytes, cursor + 0u, kLcCodeSignature);
  write_u32_le(bytes, cursor + 4u, 16u);
  write_u32_le(bytes, cursor + 8u, static_cast<std::uint32_t>(blob_offset));
  write_u32_le(bytes, cursor + 12u, 16u);
  write_u32_be(bytes, blob_offset + 0u, 0xFADE0CC0u);
  write_u32_be(bytes, blob_offset + 4u, 16u);
  return bytes;
}

[[nodiscard]] int run_audit(const std::filesystem::path& artifact,
                            const std::filesystem::path& report,
                            const std::filesystem::path& denylist,
                            bool strict,
                            const std::vector<std::string>& extra_args = {}) {
  std::string cmd = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) + " --input " +
                    quote_arg(artifact.string()) + " --denylist " + quote_arg(denylist.string()) +
                    " --output " + quote_arg(report.string());
  for (const std::string& arg : extra_args) {
    cmd += " " + quote_arg(arg);
  }
  if (strict) {
    cmd += " --strict";
  }
  return normalize_status(std::system(cmd.c_str()));
}

bool write_executable_script(const std::filesystem::path& path, std::string_view content) {
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

[[nodiscard]] std::filesystem::path make_verifier_wrapper(const std::filesystem::path& output_dir,
                                                          std::string_view name,
                                                          std::string_view mode) {
  const std::filesystem::path wrapper_path = output_dir / (std::string(name) + ".sh");
  const std::string content = std::string("#!/usr/bin/env bash\nexec python3 ") +
                              quote_arg(EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH) + " --mode " +
                              quote_arg(std::string(mode)) + " \"$@\"\n";
  if (!write_executable_script(wrapper_path, content)) {
    return {};
  }
  return wrapper_path;
}

[[nodiscard]] bool report_has(const std::string& report, std::string_view needle) {
  return report.find(std::string(needle)) != std::string::npos;
}

bool expect_report_contains(const std::string& report, std::string_view needle, const char* message) {
  return expect(report_has(report, needle), message);
}

bool expect_report_not_contains(const std::string& report, std::string_view needle, const char* message) {
  return expect(!report_has(report, needle), message);
}

[[nodiscard]] std::string json_bool(bool value) {
  return value ? "true" : "false";
}

[[nodiscard]] std::string make_kernel_manifest_json(std::string_view target_kind,
                                                    std::string_view artifact_kind,
                                                    std::string_view kernel_compat_profile,
                                                    bool hvci_profile,
                                                    bool vermagic_profile,
                                                    bool gki_kmi_profile,
                                                    bool allow_jit = false,
                                                    bool allow_runtime_executable_pages = false,
                                                    bool allow_persistent_plaintext = false,
                                                    bool require_fail_closed = true,
                                                    bool sign_after_mutate_required = true) {
  std::string manifest = "{";
  manifest += "\"target_kind\":\"" + std::string(target_kind) + "\",";
  manifest += "\"artifact_kind\":\"" + std::string(artifact_kind) + "\",";
  manifest += "\"runtime_lane\":\"kernel_safe\",";
  manifest += "\"mutation_profile\":\"kernel_module\",";
  manifest += "\"signature_policy\":\"sign_after_mutate\",";
  manifest += "\"sign_after_mutate_required\":" + json_bool(sign_after_mutate_required) + ",";
  manifest += "\"allow_jit\":" + json_bool(allow_jit) + ",";
  manifest += "\"allow_runtime_executable_pages\":" + json_bool(allow_runtime_executable_pages) + ",";
  manifest += "\"allow_persistent_plaintext\":" + json_bool(allow_persistent_plaintext) + ",";
  manifest += "\"require_fail_closed\":" + json_bool(require_fail_closed) + ",";
  manifest += "\"kernel_compat_profile\":\"" + std::string(kernel_compat_profile) + "\",";
  manifest += "\"hvci_profile\":" + json_bool(hvci_profile) + ",";
  manifest += "\"vermagic_profile\":" + json_bool(vermagic_profile) + ",";
  manifest += "\"gki_kmi_profile\":" + json_bool(gki_kmi_profile);
  manifest += "}\n";
  return manifest;
}

[[nodiscard]] std::vector<std::uint8_t> build_shell_bundle_fixture() {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(32u);
  bytes.push_back(static_cast<std::uint8_t>('E'));
  bytes.push_back(static_cast<std::uint8_t>('S'));
  bytes.push_back(static_cast<std::uint8_t>('H'));
  bytes.push_back(static_cast<std::uint8_t>('B'));
  bytes.push_back(3u);  // version
  bytes.push_back(0u);  // key marker: external only
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(1u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(0u);
  bytes.push_back(static_cast<std::uint8_t>('C'));
  bytes.push_back(static_cast<std::uint8_t>('I'));
  bytes.push_back(static_cast<std::uint8_t>('P'));
  bytes.push_back(static_cast<std::uint8_t>('H'));
  bytes.push_back(static_cast<std::uint8_t>('E'));
  bytes.push_back(static_cast<std::uint8_t>('R'));
  return bytes;
}

[[nodiscard]] std::string make_shell_manifest_json(std::string_view endpoint_kind,
                                                   bool key_provider_static_file,
                                                   bool allow_jit = false,
                                                   bool allow_runtime_executable_pages = false,
                                                   bool allow_persistent_plaintext = false,
                                                   bool require_fail_closed = true,
                                                   bool trace_env_scrubbed = true,
                                                   std::string_view source_policy = "self_contained_only",
                                                   std::string_view unsafe_shell_features = "[]",
                                                   bool key_material_embedded = false,
                                                   bool plaintext_output = false,
                                                   bool no_persistent_plaintext_goal = true) {
  std::string manifest = "{";
  manifest += "\"schema_version\":2,";
  manifest += "\"kind\":\"shell_script_bundle\",";
  manifest += "\"target_kind\":\"shell_ephemeral\",";
  manifest += "\"artifact_kind\":\"shell_bundle\",";
  manifest += "\"backend_kind\":\"shell_launcher\",";
  manifest += "\"runtime_lane\":\"shell_launcher\",";
  manifest += "\"mutation_profile\":\"shell_bundle\",";
  manifest += "\"signature_policy\":\"required_verifier\",";
  manifest += "\"plaintext_ttl_ms\":0,";
  manifest += "\"loader_format_version\":3,";
  manifest += "\"key_provider_protocol\":\"eippf.external_key.v1\",";
  manifest += "\"key_id\":\"shell-key\",";
  manifest += "\"allow_jit\":" + json_bool(allow_jit) + ",";
  manifest += "\"allow_runtime_executable_pages\":" + json_bool(allow_runtime_executable_pages) + ",";
  manifest += "\"allow_persistent_plaintext\":" + json_bool(allow_persistent_plaintext) + ",";
  manifest += "\"require_fail_closed\":" + json_bool(require_fail_closed) + ",";
  manifest += "\"execution_model\":\"pipe_stdin_exec\",";
  manifest += "\"launcher_host\":\"linux_posix\",";
  manifest += "\"interpreter_tag\":\"sh\",";
  manifest += "\"contains_shebang\":true,";
  manifest += "\"trace_env_scrubbed\":" + json_bool(trace_env_scrubbed) + ",";
  manifest += "\"source_policy\":\"" + std::string(source_policy) + "\",";
  manifest += "\"key_provider_endpoint_kind\":\"" + std::string(endpoint_kind) + "\",";
  manifest += "\"key_provider_static_file\":" + json_bool(key_provider_static_file) + ",";
  manifest += "\"unsafe_shell_features\":" + std::string(unsafe_shell_features) + ",";
  manifest += "\"key_material_embedded\":" + json_bool(key_material_embedded) + ",";
  manifest += "\"plaintext_output\":" + json_bool(plaintext_output) + ",";
  manifest += "\"no_persistent_plaintext_goal\":" + json_bool(no_persistent_plaintext_goal);
  manifest += "}\n";
  return manifest;
}

[[nodiscard]] std::vector<std::uint8_t> build_dex_bundle_fixture(std::uint8_t flags = 0u,
                                                                  std::uint8_t key_marker = 0u) {
  std::vector<std::uint8_t> bytes(kDexBundleHeaderBytes, 0u);
  bytes[0u] = static_cast<std::uint8_t>(kDexBundleMagic[0u]);
  bytes[1u] = static_cast<std::uint8_t>(kDexBundleMagic[1u]);
  bytes[2u] = static_cast<std::uint8_t>(kDexBundleMagic[2u]);
  bytes[3u] = static_cast<std::uint8_t>(kDexBundleMagic[3u]);
  bytes[4u] = 3u;  // loader format version
  bytes[kDexBundleFlagsOffset] = flags;
  bytes[6u] = static_cast<std::uint8_t>('0');
  bytes[7u] = static_cast<std::uint8_t>('3');
  bytes[8u] = static_cast<std::uint8_t>('5');
  bytes[kDexBundleKeyMarkerOffset] = key_marker;

  constexpr std::string_view kPayload = "CIPHER";
  const std::uint64_t payload_len = static_cast<std::uint64_t>(kPayload.size());
  for (std::size_t i = 0; i < 8u; ++i) {
    bytes[kDexBundlePayloadLengthOffset + i] = static_cast<std::uint8_t>((payload_len >> (8u * i)) & 0xFFu);
  }

  bytes.insert(bytes.end(), kPayload.begin(), kPayload.end());
  return bytes;
}

[[nodiscard]] std::vector<std::uint8_t> build_raw_dex_fixture(std::string_view payload) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(8u + payload.size());
  bytes.push_back(static_cast<std::uint8_t>('d'));
  bytes.push_back(static_cast<std::uint8_t>('e'));
  bytes.push_back(static_cast<std::uint8_t>('x'));
  bytes.push_back(static_cast<std::uint8_t>('\n'));
  bytes.push_back(static_cast<std::uint8_t>('0'));
  bytes.push_back(static_cast<std::uint8_t>('3'));
  bytes.push_back(static_cast<std::uint8_t>('5'));
  bytes.push_back(0u);
  for (const char ch : payload) {
    bytes.push_back(static_cast<std::uint8_t>(ch));
  }
  return bytes;
}

[[nodiscard]] std::string make_dex_manifest_json(
    std::string_view target_kind = "android_dex",
    std::string_view backend_kind = "dex_loader_vm",
    std::string_view runtime_lane = "dex_loader_vm",
    std::string_view mutation_profile = "dex_bundle",
    std::string_view artifact_kind = "dex_bundle",
    bool allow_jit = false,
    bool allow_runtime_executable_pages = false,
    bool allow_persistent_plaintext = false,
    bool require_fail_closed = true,
    std::string_view bridge_surface = "allowlist_only",
    std::string_view class_loader_policy = "private_handle_only",
    bool class_loader_exported = false,
    std::string_view anti_debug_policy = "block_jdwp_attach",
    std::string_view anti_hook_policy = "best_effort_frida_xposed_guard",
    std::string_view key_provider_endpoint_kind = "executable_adapter",
    bool key_provider_static_file = false,
    bool key_material_embedded = false,
    bool plaintext_output = false,
    bool no_persistent_plaintext_goal = true,
    int loader_format_version = 3,
    bool external_key_required = true,
    std::string_view key_provider_protocol = "eippf.external_key.v1") {
  std::string manifest = "{";
  manifest += "\"target_kind\":\"" + std::string(target_kind) + "\",";
  manifest += "\"backend_kind\":\"" + std::string(backend_kind) + "\",";
  manifest += "\"runtime_lane\":\"" + std::string(runtime_lane) + "\",";
  manifest += "\"mutation_profile\":\"" + std::string(mutation_profile) + "\",";
  manifest += "\"artifact_kind\":\"" + std::string(artifact_kind) + "\",";
  manifest += "\"loader_format_version\":" + std::to_string(loader_format_version) + ",";
  manifest += "\"external_key_required\":" + json_bool(external_key_required) + ",";
  manifest += "\"key_provider_protocol\":\"" + std::string(key_provider_protocol) + "\",";
  manifest += "\"allow_jit\":" + json_bool(allow_jit) + ",";
  manifest += "\"allow_runtime_executable_pages\":" + json_bool(allow_runtime_executable_pages) + ",";
  manifest += "\"allow_persistent_plaintext\":" + json_bool(allow_persistent_plaintext) + ",";
  manifest += "\"require_fail_closed\":" + json_bool(require_fail_closed) + ",";
  manifest += "\"bridge_surface\":\"" + std::string(bridge_surface) + "\",";
  manifest += "\"class_loader_policy\":\"" + std::string(class_loader_policy) + "\",";
  manifest += "\"class_loader_exported\":" + json_bool(class_loader_exported) + ",";
  manifest += "\"anti_debug_policy\":\"" + std::string(anti_debug_policy) + "\",";
  manifest += "\"anti_hook_policy\":\"" + std::string(anti_hook_policy) + "\",";
  manifest += "\"key_provider_endpoint_kind\":\"" + std::string(key_provider_endpoint_kind) + "\",";
  manifest += "\"key_provider_static_file\":" + json_bool(key_provider_static_file) + ",";
  manifest += "\"key_material_embedded\":" + json_bool(key_material_embedded) + ",";
  manifest += "\"plaintext_output\":" + json_bool(plaintext_output) + ",";
  manifest += "\"no_persistent_plaintext_goal\":" + json_bool(no_persistent_plaintext_goal);
  manifest += "}\n";
  return manifest;
}

[[nodiscard]] std::string make_ios_manifest_json(bool allow_jit = false) {
  std::string manifest = "{";
  manifest += "\"target_kind\":\"ios_appstore\",";
  manifest += "\"artifact_kind\":\"macho\",";
  manifest += "\"runtime_lane\":\"ios_safe\",";
  manifest += "\"backend_kind\":\"ios_safe_aot\",";
  manifest += "\"mutation_profile\":\"ios_macho\",";
  manifest += "\"signature_policy\":\"required_verifier\",";
  manifest += "\"allow_jit\":";
  manifest += json_bool(allow_jit);
  manifest += ",";
  manifest += "\"allow_runtime_executable_pages\":";
  manifest += json_bool(allow_jit);
  manifest += ",";
  manifest += "\"allow_persistent_plaintext\":false,";
  manifest += "\"require_fail_closed\":true,";
  manifest += "\"ios_compliance_profile\":\"app_store_safe\"";
  manifest += "}\n";
  return manifest;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp dir\n";
    return 1;
  }

  const std::filesystem::path trusted_verifier_dir = EIPPF_SIGNATURE_VERIFIER_WORK_DIR;
  std::error_code ec;
  std::filesystem::create_directories(trusted_verifier_dir, ec);
  if (ec) {
    std::cerr << "[FAIL] cannot create trusted verifier dir\n";
    return 1;
  }

  const std::filesystem::path clean_artifact = temp_dir / "clean.exe";
  const std::filesystem::path dirty_artifact = temp_dir / "dirty.exe";
  const std::filesystem::path rwx_artifact = temp_dir / "rwx.exe";
  const std::filesystem::path suspicious_import_artifact = temp_dir / "analysis_surface.exe";
  const std::filesystem::path unsigned_driver_artifact = temp_dir / "driver_unsigned.sys";
  const std::filesystem::path signed_driver_artifact = temp_dir / "driver_signed.sys";
  const std::filesystem::path manifest_driver_unsigned_artifact = temp_dir / "driver_by_manifest.exe";
  const std::filesystem::path manifest_driver_signed_artifact = temp_dir / "driver_signed_by_manifest.exe";
  const std::filesystem::path signed_ko_artifact = temp_dir / "signed_module.ko";
  const std::filesystem::path signed_macho_artifact = temp_dir / "signed_ios.bin";
  const std::filesystem::path unsigned_macho_artifact = temp_dir / "unsigned_ios.bin";
  const std::filesystem::path private_api_macho_artifact = temp_dir / "private_api_ios.bin";
  const std::filesystem::path rwx_macho_artifact = temp_dir / "rwx_ios.bin";
  const std::filesystem::path ko_manifest_path = temp_dir / "ko.manifest.json";
  const std::filesystem::path android_ko_manifest_path = temp_dir / "android_ko.manifest.json";
  const std::filesystem::path ios_manifest_path = temp_dir / "ios.manifest.json";
  const std::filesystem::path ios_bad_manifest_path = temp_dir / "ios_bad.manifest.json";
  const std::filesystem::path win_driver_manifest_path = temp_dir / "win_driver.manifest.json";
  const std::filesystem::path win_driver_bad_manifest_path = temp_dir / "win_driver_bad.manifest.json";
  const std::filesystem::path ko_bad_vermagic_manifest_path = temp_dir / "ko_bad_vermagic.manifest.json";
  const std::filesystem::path ko_bad_security_manifest_path = temp_dir / "ko_bad_security.manifest.json";
  const std::filesystem::path android_ko_bad_gki_manifest_path =
      temp_dir / "android_ko_bad_gki.manifest.json";
  const std::filesystem::path android_ko_bad_security_manifest_path =
      temp_dir / "android_ko_bad_security.manifest.json";
  const std::filesystem::path shell_bundle_artifact = temp_dir / "shell_bundle.eippf";
  const std::filesystem::path shell_manifest_success_path = temp_dir / "shell_success.manifest.json";
  const std::filesystem::path shell_manifest_bad_gate_path = temp_dir / "shell_bad_gate.manifest.json";
  const std::filesystem::path shell_manifest_unsafe_path = temp_dir / "shell_unsafe.manifest.json";
  const std::filesystem::path shell_manifest_leak_path = temp_dir / "shell_leak.manifest.json";
  const std::filesystem::path shell_manifest_static_provider_path =
      temp_dir / "shell_static_provider.manifest.json";
  const std::filesystem::path shell_manifest_symlink_provider_path =
      temp_dir / "shell_symlink_provider.manifest.json";
  const std::filesystem::path dex_bundle_artifact = temp_dir / "loader_bundle.eippf";
  const std::filesystem::path dex_bundle_flags_artifact = temp_dir / "loader_bundle_flags.eippf";
  const std::filesystem::path dex_bundle_key_marker_artifact = temp_dir / "loader_bundle_key_marker.eippf";
  const std::filesystem::path raw_dex_plaintext_artifact = temp_dir / "classes.dex";
  const std::filesystem::path dex_manifest_success_path = temp_dir / "dex_success.manifest.json";
  const std::filesystem::path dex_manifest_missing_metadata_path =
      temp_dir / "dex_missing_metadata.manifest.json";
  const std::filesystem::path dex_manifest_bad_gate_path = temp_dir / "dex_bad_gate.manifest.json";
  const std::filesystem::path report_path = temp_dir / "artifact.audit.json";
  const std::filesystem::path missing_denylist = temp_dir / "missing_denylist.txt";

  const std::vector<std::uint8_t> clean_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> dirty_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "SECRET_ANCHOR",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> rwx_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0xE0000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> suspicious_import_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "dbghelp.dll",
                                        .import_symbol = "SymInitialize"});
  const std::vector<std::uint8_t> signed_driver_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = "",
                                        .with_signature = true});
  const std::vector<std::uint8_t> unsigned_driver_bytes =
      build_pe_fixture(PeFixtureOptions{.text_characteristics = 0x60000020u,
                                        .payload = "clean_payload",
                                        .import_dll = "",
                                        .import_symbol = ""});
  const std::vector<std::uint8_t> signed_ko_bytes = build_elf64_fixture(true);
  const std::vector<std::uint8_t> signed_macho_bytes = build_macho32_fixture(true);
  const std::vector<std::uint8_t> unsigned_macho_bytes = build_macho32_fixture(false);
  const std::vector<std::uint8_t> private_api_macho_bytes =
      build_macho32_fixture(
          true,
          "/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices");
  const std::vector<std::uint8_t> rwx_macho_bytes = build_macho32_fixture(true, {}, true);
  const std::vector<std::uint8_t> shell_bundle_bytes = build_shell_bundle_fixture();
  const std::vector<std::uint8_t> dex_bundle_bytes = build_dex_bundle_fixture(0u, 0u);
  const std::vector<std::uint8_t> dex_bundle_flags_bytes = build_dex_bundle_fixture(0x03u, 0u);
  const std::vector<std::uint8_t> dex_bundle_key_marker_bytes = build_dex_bundle_fixture(0u, 1u);
  const std::vector<std::uint8_t> raw_dex_plaintext_bytes = build_raw_dex_fixture("SECRET_ANCHOR");

  if (!write_bytes(clean_artifact, clean_bytes) || !write_bytes(dirty_artifact, dirty_bytes) ||
      !write_bytes(rwx_artifact, rwx_bytes) ||
      !write_bytes(suspicious_import_artifact, suspicious_import_bytes) ||
      !write_bytes(unsigned_driver_artifact, unsigned_driver_bytes) ||
      !write_bytes(signed_driver_artifact, signed_driver_bytes) ||
      !write_bytes(manifest_driver_unsigned_artifact, unsigned_driver_bytes) ||
      !write_bytes(manifest_driver_signed_artifact, signed_driver_bytes) ||
      !write_bytes(signed_ko_artifact, signed_ko_bytes) ||
      !write_bytes(signed_macho_artifact, signed_macho_bytes) ||
      !write_bytes(unsigned_macho_artifact, unsigned_macho_bytes) ||
      !write_bytes(private_api_macho_artifact, private_api_macho_bytes) ||
      !write_bytes(rwx_macho_artifact, rwx_macho_bytes) ||
      !write_bytes(shell_bundle_artifact, shell_bundle_bytes) ||
      !write_bytes(dex_bundle_artifact, dex_bundle_bytes) ||
      !write_bytes(dex_bundle_flags_artifact, dex_bundle_flags_bytes) ||
      !write_bytes(dex_bundle_key_marker_artifact, dex_bundle_key_marker_bytes) ||
      !write_bytes(raw_dex_plaintext_artifact, raw_dex_plaintext_bytes)) {
    std::cerr << "[FAIL] cannot write test artifacts\n";
    return 1;
  }

  if (!write_text(ko_manifest_path,
                  make_kernel_manifest_json("linux_kernel_module",
                                            "linux_kernel_module_ko",
                                            "vermagic_profile",
                                            false,
                                            true,
                                            false)) ||
      !write_text(android_ko_manifest_path,
                  make_kernel_manifest_json("android_kernel_module",
                                            "linux_kernel_module_ko",
                                            "gki_kmi_profile",
                                            false,
                                            false,
                                            true)) ||
      !write_text(ios_manifest_path, make_ios_manifest_json(false)) ||
      !write_text(ios_bad_manifest_path, make_ios_manifest_json(true)) ||
      !write_text(win_driver_manifest_path,
                  make_kernel_manifest_json("windows_driver",
                                            "windows_driver_sys",
                                            "hvci_profile",
                                            true,
                                            false,
                                            false)) ||
      !write_text(win_driver_bad_manifest_path,
                  make_kernel_manifest_json("windows_driver",
                                            "windows_driver_sys",
                                            "hvci_profile",
                                            true,
                                            false,
                                            false,
                                            true,
                                            false)) ||
      !write_text(ko_bad_vermagic_manifest_path,
                  make_kernel_manifest_json("linux_kernel_module",
                                            "linux_kernel_module_ko",
                                            "vermagic_profile",
                                            false,
                                            false,
                                            false)) ||
      !write_text(ko_bad_security_manifest_path,
                  make_kernel_manifest_json("linux_kernel_module",
                                            "linux_kernel_module_ko",
                                            "vermagic_profile",
                                            false,
                                            true,
                                            false,
                                            false,
                                            true)) ||
      !write_text(android_ko_bad_gki_manifest_path,
                  make_kernel_manifest_json("android_kernel_module",
                                            "linux_kernel_module_ko",
                                            "gki_kmi_profile",
                                            false,
                                            false,
                                            false)) ||
      !write_text(android_ko_bad_security_manifest_path,
                  make_kernel_manifest_json("android_kernel_module",
                                            "linux_kernel_module_ko",
                                            "gki_kmi_profile",
                                            false,
                                            false,
                                            true,
                                            true,
                                            false)) ||
      !write_text(shell_manifest_success_path,
                  make_shell_manifest_json("executable_adapter", false)) ||
      !write_text(shell_manifest_bad_gate_path,
                  make_shell_manifest_json("executable_adapter", false, true)) ||
      !write_text(shell_manifest_unsafe_path,
                  make_shell_manifest_json("executable_adapter", false,
                                           false, false, false, true, true,
                                           "self_contained_only", "[\"xtrace\"]")) ||
      !write_text(shell_manifest_leak_path,
                  make_shell_manifest_json("executable_adapter", false,
                                           false, false, false, true, true,
                                           "self_contained_only", "[]",
                                           true, true, false)) ||
      !write_text(shell_manifest_static_provider_path,
                  make_shell_manifest_json("executable_adapter", true)) ||
      !write_text(shell_manifest_symlink_provider_path,
                  make_shell_manifest_json("symlink_file", false)) ||
      !write_text(dex_manifest_success_path,
                  make_dex_manifest_json()) ||
      !write_text(dex_manifest_missing_metadata_path,
                  make_dex_manifest_json("android_dex", "unexpected_backend")) ||
      !write_text(dex_manifest_bad_gate_path,
                  make_dex_manifest_json("android_dex",
                                         "dex_loader_vm",
                                         "dex_loader_vm",
                                         "dex_bundle",
                                         "dex_bundle",
                                         true))) {
    std::cerr << "[FAIL] cannot write manifest fixtures\n";
    return 1;
  }

  const std::filesystem::path verifier_success =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_success", "success");
  const std::filesystem::path verifier_reject =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_reject", "reject");
  const std::filesystem::path verifier_invalid_json =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_invalid_json", "invalid-json");
  const std::filesystem::path verifier_bad_schema =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_bad_schema", "bad-schema");
  const std::filesystem::path verifier_digest_mismatch =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_digest_mismatch", "digest-mismatch");
  const std::filesystem::path verifier_nonzero =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_nonzero", "nonzero");
  const std::filesystem::path verifier_empty =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_empty", "empty");
  const std::filesystem::path verifier_timeout =
      make_verifier_wrapper(trusted_verifier_dir, "signature_verifier_timeout", "timeout");
  const std::filesystem::path untrusted_verifier =
      make_verifier_wrapper(temp_dir, "signature_verifier_untrusted", "success");

  if (verifier_success.empty() || verifier_reject.empty() || verifier_invalid_json.empty() ||
      verifier_bad_schema.empty() || verifier_digest_mismatch.empty() || verifier_nonzero.empty() ||
      verifier_empty.empty() || verifier_timeout.empty() || untrusted_verifier.empty()) {
    std::cerr << "[FAIL] cannot write verifier wrappers\n";
    return 1;
  }

  const std::filesystem::path relative_verifier_path =
      std::filesystem::relative(verifier_success, std::filesystem::current_path(), ec);
  if (ec || relative_verifier_path.empty()) {
    std::cerr << "[FAIL] cannot build relative verifier path\n";
    return 1;
  }

  if (!expect(run_audit(clean_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) == 0,
              "strict audit should pass clean artifact")) {
    return 1;
  }
  const std::string clean_report = read_text(report_path);
  if (!expect_report_contains(clean_report, "\"validation_mode\": \"not_required\"",
                              "clean artifact should report not_required")) {
    return 1;
  }
  if (!expect_report_contains(clean_report, "\"signature_state_passed\": true",
                              "clean artifact should pass signature state")) {
    return 1;
  }
  if (!expect_report_contains(clean_report, "\"verifier_invoked\": false",
                              "clean artifact should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(clean_report, "\"verifier_error\": null",
                              "clean artifact should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--signature-verifier", verifier_success.string()}) == 0,
              "non-required artifact should ignore success verifier")) {
    return 1;
  }
  const std::string optional_success_report = read_text(report_path);
  if (!expect_report_contains(optional_success_report, "\"validation_mode\": \"optional_verifier_ignored\"",
                              "non-required artifact should ignore verifier")) {
    return 1;
  }
  if (!expect_report_contains(optional_success_report, "\"verifier_invoked\": false",
                              "non-required artifact should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(optional_success_report, "\"verifier_error\": null",
                              "ignored verifier should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(optional_success_report, "\"signature_state_passed\": true",
                              "ignored verifier should keep signature state passing")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--signature-verifier", verifier_nonzero.string()}) == 0,
              "non-required artifact should ignore failing verifier")) {
    return 1;
  }
  const std::string optional_nonzero_report = read_text(report_path);
  if (!expect_report_contains(optional_nonzero_report, "\"validation_mode\": \"optional_verifier_ignored\"",
                              "non-required artifact should ignore failing verifier")) {
    return 1;
  }
  if (!expect_report_contains(optional_nonzero_report, "\"verifier_invoked\": false",
                              "ignored failing verifier should not be invoked")) {
    return 1;
  }
  if (!expect_report_contains(optional_nonzero_report, "\"verifier_error\": null",
                              "ignored failing verifier should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(optional_nonzero_report, "\"signature_state_passed\": true",
                              "ignored failing verifier should keep signature state passing")) {
    return 1;
  }

  if (!expect(run_audit(dirty_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) != 0,
              "strict audit should fail artifact containing denylisted anchor")) {
    return 1;
  }

  if (!expect(run_audit(rwx_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) != 0,
              "strict audit should fail PE with writable executable section")) {
    return 1;
  }

  if (!expect(run_audit(suspicious_import_artifact, report_path, EIPPF_LEXICAL_DENYLIST_PATH, true) != 0,
              "strict audit should fail PE importing analysis-surface libraries")) {
    return 1;
  }

  if (!expect(run_audit(unsigned_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver"}) != 0,
              "unsigned driver should fail required_missing")) {
    return 1;
  }
  const std::string unsigned_driver_report = read_text(report_path);
  if (!expect_report_contains(unsigned_driver_report, "\"validation_mode\": \"required_missing\"",
                              "unsigned driver should report required_missing")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "\"signature_state_passed\": false",
                              "unsigned driver should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "\"verifier_invoked\": false",
                              "unsigned driver should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "\"verifier_error\": null",
                              "unsigned driver should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_driver_report, "signature_missing",
                              "unsigned driver should fail missing signature")) {
    return 1;
  }

  if (!expect(run_audit(manifest_driver_unsigned_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", win_driver_manifest_path.string()}) != 0,
              "manifest-driven unsigned driver should fail missing signature")) {
    return 1;
  }
  const std::string required_missing_report = read_text(report_path);
  if (!expect_report_contains(required_missing_report, "\"validation_mode\": \"required_missing\"",
                              "manifest-driven unsigned driver should report required_missing")) {
    return 1;
  }
  if (!expect_report_contains(required_missing_report, "signature_missing",
                              "manifest-driven unsigned driver should fail missing signature")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver"}) != 0,
              "required signed driver without verifier should fail authenticity")) {
    return 1;
  }
  const std::string required_no_verifier_report = read_text(report_path);
  if (!expect_report_contains(required_no_verifier_report,
                              "\"validation_mode\": \"required_authenticity_missing\"",
                              "required signed driver should require authenticity verifier")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "\"signature_state_passed\": false",
                              "required signed driver without verifier should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "\"verifier_invoked\": false",
                              "required signed driver without verifier should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "\"verifier_error\": null",
                              "required signed driver without verifier should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(required_no_verifier_report, "signature_authenticity_missing",
                              "required signed driver should fail missing authenticity")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--manifest", win_driver_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "required signed driver with success verifier should pass")) {
    return 1;
  }
  const std::string verifier_success_report = read_text(report_path);
  if (!expect_report_contains(verifier_success_report, "\"validation_mode\": \"external_verifier\"",
                              "success verifier should report external_verifier")) {
    return 1;
  }
  if (!expect_report_contains(verifier_success_report, "\"signature_state_passed\": true",
                              "success verifier should pass signature state")) {
    return 1;
  }
  if (!expect_report_contains(verifier_success_report, "\"verifier_invoked\": true",
                              "success verifier should be invoked")) {
    return 1;
  }
  if (!expect_report_contains(verifier_success_report, "\"verifier_error\": null",
                              "success verifier should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--manifest", win_driver_manifest_path.string(),
                         "--signature-verifier", verifier_reject.string()}) != 0,
              "reject verifier should fail required signed driver")) {
    return 1;
  }
  const std::string verifier_reject_report = read_text(report_path);
  if (!expect_report_contains(verifier_reject_report, "\"validation_mode\": \"external_verifier\"",
                              "reject verifier should stay in external_verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report, "\"signature_state_passed\": false",
                              "reject verifier should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report, "\"verifier_invoked\": true",
                              "reject verifier should be invoked")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report,
                              "\"verifier_error\": \"signature_authenticity_rejected\"",
                              "reject verifier should report signature_authenticity_rejected")) {
    return 1;
  }
  if (!expect_report_contains(verifier_reject_report, "signature_authenticity_rejected",
                              "reject verifier should fail with authenticity rejected")) {
    return 1;
  }
  if (!expect_report_not_contains(verifier_reject_report, "signature_verifier_failed",
                                  "reject verifier should not report transport failure")) {
    return 1;
  }

  const std::vector<std::pair<std::filesystem::path, std::string>> verifier_failure_cases = {
      {verifier_nonzero, "signature_verifier_failed"},
      {verifier_invalid_json, "signature_verifier_failed"},
      {verifier_bad_schema, "signature_verifier_failed"},
      {verifier_empty, "signature_verifier_failed"},
      {verifier_timeout, "signature_verifier_failed"},
      {verifier_digest_mismatch, "signature_verifier_digest_mismatch"},
  };
  for (const auto& [verifier_path, expected_failure] : verifier_failure_cases) {
    if (!expect(run_audit(signed_driver_artifact,
                          report_path,
                          EIPPF_LEXICAL_DENYLIST_PATH,
                          true,
                          {"--target-kind", "windows_driver",
                           "--manifest", win_driver_manifest_path.string(),
                           "--signature-verifier", verifier_path.string()}) != 0,
                "failing verifier should fail required signed driver")) {
      return 1;
    }
    const std::string failure_report = read_text(report_path);
    if (!expect_report_contains(failure_report, "\"validation_mode\": \"external_verifier\"",
                                "failing verifier should stay in external_verifier mode")) {
      return 1;
    }
    if (!expect_report_contains(failure_report, "\"signature_state_passed\": false",
                                "failing verifier should fail signature state")) {
      return 1;
    }
    if (!expect_report_contains(failure_report, expected_failure,
                                "failing verifier should report precise failure code")) {
      return 1;
    }
    if (!expect_report_contains(failure_report, "\"verifier_invoked\": true",
                                "failing verifier should be invoked when trusted")) {
      return 1;
    }
    if (!expect_report_contains(failure_report,
                                std::string("\"verifier_error\": \"") + expected_failure + "\"",
                                "failing verifier should expose verifier_error")) {
      return 1;
    }
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--signature-verifier", verifier_success.string()}) != 0,
              "suffix-only signed driver should fail policy resolution")) {
    return 1;
  }
  const std::string suffix_only_report = read_text(report_path);
  if (!expect_report_contains(suffix_only_report, "\"validation_mode\": \"policy_unresolved\"",
                              "suffix-only signed driver should report policy_unresolved")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "\"signature_state_passed\": false",
                              "suffix-only signed driver should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "\"verifier_invoked\": false",
                              "suffix-only signed driver should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "\"verifier_error\": null",
                              "suffix-only signed driver should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(suffix_only_report, "signature_policy_unresolved",
                              "suffix-only signed driver should fail policy resolution")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--manifest", win_driver_manifest_path.string(),
                         "--signature-verifier", relative_verifier_path.string()}) != 0,
              "relative verifier path should be rejected")) {
    return 1;
  }
  const std::string relative_verifier_report = read_text(report_path);
  if (!expect_report_contains(relative_verifier_report, "\"validation_mode\": \"external_verifier\"",
                              "relative verifier path should still report external_verifier")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report, "\"signature_state_passed\": false",
                              "relative verifier path should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report, "signature_verifier_untrusted",
                              "relative verifier path should be untrusted")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report, "\"verifier_invoked\": false",
                              "relative verifier path should not be invoked")) {
    return 1;
  }
  if (!expect_report_contains(relative_verifier_report,
                              "\"verifier_error\": \"signature_verifier_untrusted\"",
                              "relative verifier path should expose untrusted verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "windows_driver",
                         "--manifest", win_driver_manifest_path.string(),
                         "--signature-verifier", untrusted_verifier.string()}) != 0,
              "temp verifier path should be rejected")) {
    return 1;
  }
  const std::string untrusted_verifier_report = read_text(report_path);
  if (!expect_report_contains(untrusted_verifier_report, "signature_verifier_untrusted",
                              "temp verifier path should be untrusted")) {
    return 1;
  }
  if (!expect_report_contains(untrusted_verifier_report, "\"signature_state_passed\": false",
                              "temp verifier path should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(untrusted_verifier_report, "\"verifier_invoked\": false",
                              "temp verifier path should not be invoked")) {
    return 1;
  }
  if (!expect_report_contains(untrusted_verifier_report,
                              "\"verifier_error\": \"signature_verifier_untrusted\"",
                              "temp verifier path should expose untrusted verifier error")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--target-kind", "ios_appstore",
                         "--signature-verifier", verifier_success.string()}) != 0,
              "mismatched target kind should fail policy resolution")) {
    return 1;
  }
  const std::string mismatch_report = read_text(report_path);
  if (!expect_report_contains(mismatch_report, "\"validation_mode\": \"policy_unresolved\"",
                              "mismatched target kind should report policy_unresolved")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "\"signature_state_passed\": false",
                              "mismatched target kind should fail signature state")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "\"verifier_invoked\": false",
                              "mismatched target kind should not invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "\"verifier_error\": null",
                              "mismatched target kind should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(mismatch_report, "signature_policy_unresolved",
                              "mismatched target kind should fail policy resolution")) {
    return 1;
  }

  if (!expect(run_audit(manifest_driver_signed_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", win_driver_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "manifest-driven signed driver with verifier should pass")) {
    return 1;
  }
  const std::string manifest_driver_report = read_text(report_path);
  if (!expect_report_contains(manifest_driver_report,
                              "\"requirement_source\": \"manifest_target_kind\"",
                              "manifest-driven signed driver should prefer manifest target kind")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"validation_mode\": \"external_verifier\"",
                              "manifest-driven signed driver should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"signature_state_passed\": true",
                              "manifest-driven signed driver should pass signature state")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"verifier_invoked\": true",
                              "manifest-driven signed driver should invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(manifest_driver_report, "\"verifier_error\": null",
                              "manifest-driven signed driver should not report verifier error")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ko_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "signed .ko with verifier should pass")) {
    return 1;
  }
  const std::string signed_ko_report = read_text(report_path);
  if (!expect_report_contains(signed_ko_report, "\"validation_mode\": \"external_verifier\"",
                              "signed .ko should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"signature_state_passed\": true",
                              "signed .ko should pass signature gate")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"verifier_invoked\": true",
                              "signed .ko should invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"verifier_error\": null",
                              "signed .ko should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(signed_ko_report, "\"strict_failures\": []",
                              "signed .ko should have empty strict failures")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ko_bad_vermagic_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "signed .ko with vermagic mismatch should fail")) {
    return 1;
  }
  const std::string signed_ko_vermagic_bad_report = read_text(report_path);
  if (!expect_report_contains(signed_ko_vermagic_bad_report, "vermagic_mismatch",
                              "signed .ko mismatch should report vermagic_mismatch")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", android_ko_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "signed Android .ko with verifier should pass")) {
    return 1;
  }
  const std::string signed_android_ko_report = read_text(report_path);
  if (!expect_report_contains(signed_android_ko_report, "\"validation_mode\": \"external_verifier\"",
                              "signed Android .ko should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(signed_android_ko_report, "\"gki_kmi_profile\": true",
                              "signed Android .ko should keep gki_kmi_profile=true")) {
    return 1;
  }
  if (!expect_report_contains(signed_android_ko_report, "\"strict_failures\": []",
                              "signed Android .ko should have empty strict failures")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", android_ko_bad_gki_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "signed Android .ko with gki mismatch should fail")) {
    return 1;
  }
  const std::string signed_android_ko_bad_gki_report = read_text(report_path);
  if (!expect_report_contains(signed_android_ko_bad_gki_report, "gki_kmi_mismatch",
                              "signed Android .ko mismatch should report gki_kmi_mismatch")) {
    return 1;
  }

  if (!expect(run_audit(signed_driver_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", win_driver_bad_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "windows driver security-edge should fail kernel gate")) {
    return 1;
  }
  const std::string windows_driver_bad_gate_report = read_text(report_path);
  if (!expect_report_contains(windows_driver_bad_gate_report, "kernel_gate_failed",
                              "windows driver security-edge should report kernel_gate_failed")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ko_bad_security_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "linux kernel security-edge should fail kernel gate")) {
    return 1;
  }
  const std::string linux_ko_bad_gate_report = read_text(report_path);
  if (!expect_report_contains(linux_ko_bad_gate_report, "kernel_gate_failed",
                              "linux kernel security-edge should report kernel_gate_failed")) {
    return 1;
  }

  if (!expect(run_audit(signed_ko_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", android_ko_bad_security_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "android kernel security-edge should fail kernel gate")) {
    return 1;
  }
  const std::string android_ko_bad_gate_report = read_text(report_path);
  if (!expect_report_contains(android_ko_bad_gate_report, "kernel_gate_failed",
                              "android kernel security-edge should report kernel_gate_failed")) {
    return 1;
  }

  if (!expect(run_audit(signed_macho_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ios_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) == 0,
              "signed Mach-O with verifier should pass")) {
    return 1;
  }
  const std::string signed_macho_report = read_text(report_path);
  if (!expect_report_contains(signed_macho_report, "\"validation_mode\": \"external_verifier\"",
                              "signed Mach-O should use external verifier mode")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"signature_state_passed\": true",
                              "signed Mach-O should pass signature gate")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"verifier_invoked\": true",
                              "signed Mach-O should invoke verifier")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"verifier_error\": null",
                              "signed Mach-O should not report verifier error")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"ios_compliance_profile\": \"app_store_safe\"",
                              "signed Mach-O should keep iOS compliance profile")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"private_api_hits\": []",
                              "signed Mach-O should keep private_api_hits empty")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"present\": true",
                              "signed Mach-O should report code signature present")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"rwx_detected\": false",
                              "signed Mach-O should report no rwx segment")) {
    return 1;
  }
  if (!expect_report_contains(signed_macho_report, "\"strict_failures\": []",
                              "signed Mach-O should keep strict_failures empty")) {
    return 1;
  }

  if (!expect(run_audit(unsigned_macho_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ios_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "unsigned Mach-O should fail required_missing")) {
    return 1;
  }
  const std::string unsigned_macho_report = read_text(report_path);
  if (!expect_report_contains(unsigned_macho_report, "\"validation_mode\": \"required_missing\"",
                              "unsigned Mach-O should report required_missing")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_macho_report, "macho_code_signature_missing",
                              "unsigned Mach-O should report macho_code_signature_missing")) {
    return 1;
  }
  if (!expect_report_contains(unsigned_macho_report, "signature_missing",
                              "unsigned Mach-O should report signature_missing")) {
    return 1;
  }

  if (!expect(run_audit(private_api_macho_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ios_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "private-framework Mach-O should fail strict audit")) {
    return 1;
  }
  const std::string private_api_macho_report = read_text(report_path);
  if (!expect_report_contains(private_api_macho_report, "private_api_detected",
                              "private-framework Mach-O should report private_api_detected")) {
    return 1;
  }
  if (!expect_report_contains(
          private_api_macho_report,
          "FrontBoardServices.framework/FrontBoardServices",
          "private-framework Mach-O should surface the offending private API hit")) {
    return 1;
  }

  if (!expect(run_audit(rwx_macho_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ios_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "rwx Mach-O should fail strict audit")) {
    return 1;
  }
  const std::string rwx_macho_report = read_text(report_path);
  if (!expect_report_contains(rwx_macho_report, "rwx_segment_detected",
                              "rwx Mach-O should report rwx_segment_detected")) {
    return 1;
  }

  if (!expect(run_audit(signed_macho_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", ios_bad_manifest_path.string(),
                         "--signature-verifier", verifier_success.string()}) != 0,
              "bad iOS manifest should fail strict audit")) {
    return 1;
  }
  const std::string bad_ios_manifest_report = read_text(report_path);
  if (!expect_report_contains(bad_ios_manifest_report, "ios_gate_failed",
                              "bad iOS manifest should report ios_gate_failed")) {
    return 1;
  }

  if (!expect(run_audit(shell_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", shell_manifest_success_path.string()}) == 0,
              "shell strict success manifest should pass")) {
    return 1;
  }
  const std::string shell_success_report = read_text(report_path);
  if (!expect_report_contains(shell_success_report, "\"strict_failures\": []",
                              "shell strict success should keep strict_failures empty")) {
    return 1;
  }

  if (!expect(run_audit(shell_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", shell_manifest_bad_gate_path.string()}) != 0,
              "shell bad-gate manifest should fail strict audit")) {
    return 1;
  }
  const std::string shell_bad_gate_report = read_text(report_path);
  if (!expect_report_contains(shell_bad_gate_report, "shell_gate_failed",
                              "shell bad-gate manifest should report shell_gate_failed")) {
    return 1;
  }

  if (!expect(run_audit(shell_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", shell_manifest_unsafe_path.string()}) != 0,
              "shell unsafe manifest should fail strict audit")) {
    return 1;
  }
  const std::string shell_unsafe_report = read_text(report_path);
  if (!expect_report_contains(shell_unsafe_report, "shell_unsafe_feature_present",
                              "shell unsafe manifest should report shell_unsafe_feature_present")) {
    return 1;
  }

  if (!expect(run_audit(shell_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", shell_manifest_leak_path.string()}) != 0,
              "shell leak manifest should fail strict audit")) {
    return 1;
  }
  const std::string shell_leak_report = read_text(report_path);
  if (!expect_report_contains(shell_leak_report, "shell_plaintext_leak_indicator",
                              "shell leak manifest should report shell_plaintext_leak_indicator")) {
    return 1;
  }

  if (!expect(run_audit(dex_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", dex_manifest_success_path.string()}) == 0,
              "dex strict success manifest should pass")) {
    return 1;
  }
  const std::string dex_success_report = read_text(report_path);
  if (!expect_report_contains(dex_success_report, "\"strict_failures\": []",
                              "dex strict success should keep strict_failures empty")) {
    return 1;
  }

  if (!expect(run_audit(dex_bundle_flags_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", dex_manifest_success_path.string()}) == 0,
              "dex bundle with non-zero flags and zero key marker should pass strict audit")) {
    return 1;
  }
  const std::string dex_flags_report = read_text(report_path);
  if (!expect_report_contains(dex_flags_report, "\"strict_failures\": []",
                              "dex non-zero flags should keep strict_failures empty")) {
    return 1;
  }

  if (!expect(run_audit(dex_bundle_key_marker_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", dex_manifest_success_path.string()}) != 0,
              "dex bundle with non-zero key marker should fail strict audit")) {
    return 1;
  }
  const std::string dex_key_marker_report = read_text(report_path);
  if (!expect_report_contains(dex_key_marker_report, "bundle_invariant_violation",
                              "dex non-zero key marker should report bundle_invariant_violation")) {
    return 1;
  }

  if (!expect(run_audit(dex_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", dex_manifest_missing_metadata_path.string()}) != 0,
              "dex manifest with missing loader metadata should fail strict audit")) {
    return 1;
  }
  const std::string dex_missing_metadata_report = read_text(report_path);
  if (!expect_report_contains(dex_missing_metadata_report, "loader_metadata_missing",
                              "dex missing metadata should report loader_metadata_missing")) {
    return 1;
  }

  if (!expect(run_audit(raw_dex_plaintext_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", dex_manifest_success_path.string()}) != 0,
              "raw dex plaintext artifact should fail strict audit")) {
    return 1;
  }
  const std::string dex_plaintext_report = read_text(report_path);
  if (!expect_report_contains(dex_plaintext_report, "dex_plaintext_leak_detected",
                              "raw dex/plaintext leak should report dex_plaintext_leak_detected")) {
    return 1;
  }

  if (!expect(run_audit(dex_bundle_artifact,
                        report_path,
                        EIPPF_LEXICAL_DENYLIST_PATH,
                        true,
                        {"--manifest", dex_manifest_bad_gate_path.string()}) != 0,
              "dex manifest with unresolved gate should fail strict audit")) {
    return 1;
  }
  const std::string dex_bad_gate_report = read_text(report_path);
  if (!expect_report_contains(dex_bad_gate_report, "loader_gate_unresolved",
                              "dex unresolved gate should report loader_gate_unresolved")) {
    return 1;
  }

  if (!expect(run_audit(clean_artifact, report_path, missing_denylist, true) != 0,
              "strict audit should fail when denylist is unavailable")) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

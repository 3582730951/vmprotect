#include <algorithm>
#include <array>
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

#ifndef EIPPF_POST_LINK_MUTATOR_BIN
#error "EIPPF_POST_LINK_MUTATOR_BIN must be defined"
#endif

namespace {

constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";

struct ExpectedManifest final {
  std::string artifact_kind;
  std::string target_kind;
  std::string backend_kind;
  std::string runtime_lane;
  std::string mutation_profile;
  std::string signature_policy;
  std::string kernel_compat_profile;
  std::string signing_profile;
  std::string attestation_profile;
  bool sign_after_mutate_required = false;
  bool allow_jit = false;
  bool allow_runtime_executable_pages = false;
  bool allow_persistent_plaintext = false;
  bool require_fail_closed = true;
  bool hvci_profile = false;
  bool vermagic_profile = false;
  bool gki_kmi_profile = false;
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

[[nodiscard]] std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path base = std::filesystem::temp_directory_path();
  const std::filesystem::path dir =
      base / ("eippf_post_link_mutator_smoke_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return {};
  }
  return dir;
}

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

bool expect_manifest_fields(const std::filesystem::path& manifest_path,
                            std::string_view target_label,
                            std::string_view target_kind_source,
                            const ExpectedManifest& expected) {
  const std::string manifest = read_text_file(manifest_path);
  const std::string sign_after_mutate_required =
      expected.sign_after_mutate_required ? "true" : "false";
  const std::string allow_jit = expected.allow_jit ? "true" : "false";
  const std::string allow_runtime_executable_pages =
      expected.allow_runtime_executable_pages ? "true" : "false";
  const std::string allow_persistent_plaintext =
      expected.allow_persistent_plaintext ? "true" : "false";
  const std::string require_fail_closed = expected.require_fail_closed ? "true" : "false";
  const std::string hvci_profile = expected.hvci_profile ? "true" : "false";
  const std::string vermagic_profile = expected.vermagic_profile ? "true" : "false";
  const std::string gki_kmi_profile = expected.gki_kmi_profile ? "true" : "false";

  return expect(manifest.find("\"schema_version\": 2") != std::string::npos,
                "manifest schema version mismatch") &&
         expect(manifest.find("\"mutation_status\": \"mutated_with_trailer_v1\"") != std::string::npos,
                "manifest mutation status mismatch") &&
         expect(manifest.find("\"target_label\": \"" + std::string(target_label) + "\"") !=
                    std::string::npos,
                "manifest target label mismatch") &&
         expect(manifest.find("\"target_kind_source\": \"" + std::string(target_kind_source) + "\"") !=
                    std::string::npos,
                "manifest target kind source mismatch") &&
         expect(manifest.find("\"artifact_kind\": \"" + expected.artifact_kind + "\"") !=
                    std::string::npos,
                "manifest artifact kind mismatch") &&
         expect(manifest.find("\"target_kind\": \"" + expected.target_kind + "\"") !=
                    std::string::npos,
                "manifest target kind mismatch") &&
         expect(manifest.find("\"backend_kind\": \"" + expected.backend_kind + "\"") !=
                    std::string::npos,
                "manifest backend kind mismatch") &&
         expect(manifest.find("\"runtime_lane\": \"" + expected.runtime_lane + "\"") !=
                    std::string::npos,
                "manifest runtime lane mismatch") &&
         expect(manifest.find("\"mutation_profile\": \"" + expected.mutation_profile + "\"") !=
                    std::string::npos,
                "manifest mutation profile mismatch") &&
         expect(manifest.find("\"signature_policy\": \"" + expected.signature_policy + "\"") !=
                    std::string::npos,
                "manifest signature policy mismatch") &&
         expect(manifest.find("\"kernel_compat_profile\": \"" + expected.kernel_compat_profile + "\"") !=
                    std::string::npos,
                "manifest kernel compat profile mismatch") &&
         expect(manifest.find("\"signing_profile\": \"" + expected.signing_profile + "\"") !=
                    std::string::npos,
                "manifest signing profile mismatch") &&
         expect(manifest.find("\"attestation_profile\": \"" + expected.attestation_profile + "\"") !=
                    std::string::npos,
                "manifest attestation profile mismatch") &&
         expect(manifest.find("\"sign_after_mutate_required\": " + sign_after_mutate_required) !=
                    std::string::npos,
                "manifest sign-after-mutate mismatch") &&
         expect(manifest.find("\"allow_jit\": " + allow_jit) != std::string::npos,
                "manifest allow_jit mismatch") &&
         expect(manifest.find("\"allow_runtime_executable_pages\": " + allow_runtime_executable_pages) !=
                    std::string::npos,
                "manifest allow_runtime_executable_pages mismatch") &&
         expect(manifest.find("\"allow_persistent_plaintext\": " + allow_persistent_plaintext) !=
                    std::string::npos,
                "manifest allow_persistent_plaintext mismatch") &&
         expect(manifest.find("\"require_fail_closed\": " + require_fail_closed) !=
                    std::string::npos,
                "manifest require_fail_closed mismatch") &&
         expect(manifest.find("\"hvci_profile\": " + hvci_profile) != std::string::npos,
                "manifest hvci_profile mismatch") &&
         expect(manifest.find("\"vermagic_profile\": " + vermagic_profile) != std::string::npos,
                "manifest vermagic_profile mismatch") &&
         expect(manifest.find("\"gki_kmi_profile\": " + gki_kmi_profile) != std::string::npos,
                "manifest gki_kmi_profile mismatch");
}

bool expect_trailer_magic_and_version(const std::vector<std::uint8_t>& original,
                                      const std::vector<std::uint8_t>& mutated) {
  const auto trailer_begin = mutated.begin() + static_cast<std::ptrdiff_t>(original.size());
  const auto magic_begin = std::search(trailer_begin,
                                       mutated.end(),
                                       kMutationTrailerMagic.begin(),
                                       kMutationTrailerMagic.end());
  if (!expect(magic_begin != mutated.end(), "mutation trailer magic missing from appended bytes")) {
    return false;
  }
  const auto version_it =
      magic_begin + static_cast<std::ptrdiff_t>(kMutationTrailerMagic.size());
  if (!expect(version_it != mutated.end(), "mutation trailer version byte missing")) {
    return false;
  }
  return expect(*version_it == 1u, "mutation trailer version mismatch");
}

int run_success_case(const std::filesystem::path& temp_dir,
                     std::string_view label,
                     std::string_view target_label,
                     const std::vector<std::uint8_t>& input_content,
                     const ExpectedManifest& expected,
                     bool in_place_output) {
  const std::filesystem::path input = temp_dir / (std::string(label) + ".in.bin");
  const std::filesystem::path output = in_place_output
                                           ? input
                                           : temp_dir / (std::string(label) + ".out.bin");
  const std::filesystem::path manifest = temp_dir / (std::string(label) + ".manifest.json");

  if (!write_bytes(input, input_content)) {
    std::cerr << "[FAIL] cannot write input for case " << label << '\n';
    return 1;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg(std::string(target_label)) + " --target-kind " +
                              quote_arg(expected.target_kind);
  const int status = normalize_status(std::system(command.c_str()));
  if (status != 0) {
    std::cerr << "[FAIL] mutator returned " << status << " for case " << label << '\n';
    return 1;
  }

  const std::vector<std::uint8_t> got = read_file_bytes(output);
  if (!expect(got.size() > input_content.size(), "mutated output should grow after trailer append")) {
    return 1;
  }
  if (!expect(std::equal(input_content.begin(), input_content.end(), got.begin()),
              "mutated output should preserve original prefix")) {
    return 1;
  }
  if (!expect(got != input_content, "mutated output must differ from input")) {
    return 1;
  }
  if (!expect_trailer_magic_and_version(input_content, got)) {
    return 1;
  }

  if (!expect_manifest_fields(manifest, target_label, "explicit_cli", expected)) {
    return 1;
  }
  return 0;
}

int run_failure_case(const std::filesystem::path& temp_dir,
                     std::string_view label,
                     std::string_view target_kind,
                     const std::vector<std::uint8_t>& input_content) {
  const std::filesystem::path input = temp_dir / (std::string(label) + ".bad.bin");
  const std::filesystem::path output = temp_dir / (std::string(label) + ".bad.out");
  const std::filesystem::path manifest = temp_dir / (std::string(label) + ".bad.manifest.json");

  if (!write_bytes(input, input_content)) {
    std::cerr << "[FAIL] cannot write negative input for case " << label << '\n';
    return 1;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg("unknown_target") + " --target-kind " +
                              quote_arg(std::string(target_kind));
  const int status = normalize_status(std::system(command.c_str()));
  if (!expect(status != 0, "invalid target/artifact pairing should fail closed")) {
    return 1;
  }
  return 0;
}

int run_fail_closed_spoof_cases(const std::filesystem::path& temp_dir,
                                const std::vector<std::uint8_t>& random_bytes) {
  struct SpoofCase final {
    const char* label;
    const char* input_name;
    const char* output_name;
    const char* target_label;
    const char* target_kind;
  };

  const std::array<SpoofCase, 4u> cases{{
      {"spoof_output_shell",
       "spoof_output_shell.bin",
       "spoof_output_shell.sh",
       "bootstrap.sh",
       "shell_ephemeral"},
      {"spoof_output_dex",
       "spoof_output_dex.bin",
       "spoof_output_dex.dex",
       "classes.dex",
       "android_dex"},
      {"spoof_input_shell",
       "fake_input_shell.sh",
       "fake_input_shell.out",
       "bootstrap.sh",
       "shell_ephemeral"},
      {"spoof_input_dex",
       "fake_input_dex.dex",
       "fake_input_dex.out",
       "classes.dex",
       "android_dex"},
  }};

  for (const SpoofCase& test_case : cases) {
    const std::filesystem::path input = temp_dir / test_case.input_name;
    const std::filesystem::path output = temp_dir / test_case.output_name;
    const std::filesystem::path manifest =
        temp_dir / (std::string(test_case.label) + ".manifest.json");
    if (!write_bytes(input, random_bytes)) {
      std::cerr << "[FAIL] cannot write spoof input for case " << test_case.label << '\n';
      return 1;
    }

    const std::string command =
        std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " + quote_arg(input.string()) +
        " --output " + quote_arg(output.string()) + " --manifest " + quote_arg(manifest.string()) +
        " --target " + quote_arg(test_case.target_label) + " --target-kind " +
        quote_arg(test_case.target_kind);
    const int status = normalize_status(std::system(command.c_str()));
    if (!expect(status != 0, "spoofed dex/shell path must fail closed")) {
      std::cerr << "[INFO] spoof_case=" << test_case.label << " status=" << status << '\n';
      return 1;
    }
  }

  return 0;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  std::vector<std::uint8_t> pe(256u, 0u);
  pe[0] = static_cast<std::uint8_t>('M');
  pe[1] = static_cast<std::uint8_t>('Z');
  pe[0x3c] = 0x80u;
  pe[0x80] = static_cast<std::uint8_t>('P');
  pe[0x81] = static_cast<std::uint8_t>('E');
  pe[0x82] = 0x00u;
  pe[0x83] = 0x00u;

  const std::vector<std::uint8_t> elf{
      0x7fu, static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('F'), 0x02u, 0x01u, 0x01u, 0x00u};

  const std::vector<std::uint8_t> macho{
      0xFEu, 0xEDu, 0xFAu, 0xCFu, 0x00u, 0x00u, 0x00u, 0x00u};

  const std::vector<std::uint8_t> unknown{
      0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u};

  if (run_success_case(
          temp_dir,
          "desktop_pe",
          "target_pe",
          pe,
          ExpectedManifest{"pe",
                           "desktop_native",
                           "desktop_jit",
                           "desktop_user_mode",
                           "pe_user_mode",
                           "optional_verifier",
                           "",
                           "unsigned_dev_or_sign_after_mutation",
                           "default",
                           false,
                           true,
                           true,
                           false,
                           true,
                           false,
                           false,
                           false},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "desktop_elf",
          "target_elf",
          elf,
          ExpectedManifest{"elf",
                           "desktop_native",
                           "desktop_jit",
                           "desktop_user_mode",
                           "elf_user_mode",
                           "optional_verifier",
                           "",
                           "unsigned_dev_or_sign_after_mutation",
                           "default",
                           false,
                           true,
                           true,
                           false,
                           true,
                           false,
                           false,
                           false},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "ios_macho",
          "ios_target_macho",
          macho,
          ExpectedManifest{"macho",
                           "ios_appstore",
                           "ios_safe_aot",
                           "ios_safe",
                           "ios_macho",
                           "required_verifier",
                           "",
                           "ios_codesign_after_mutation",
                           "ios_safe",
                           false,
                           false,
                           false,
                           false,
                           true,
                           false,
                           false,
                           false},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "windows_driver",
          "windows_driver_sys",
          pe,
          ExpectedManifest{"windows_driver_sys",
                           "windows_driver",
                           "kernel_safe_aot",
                           "kernel_safe",
                           "kernel_module",
                           "sign_after_mutate",
                           "hvci_profile",
                           "windows_driver_sign_after_mutation",
                           "kernel_safe",
                           true,
                           false,
                           false,
                           false,
                           true,
                           true,
                           false,
                           false},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "linux_ko",
          "linux_kernel_module.ko",
          elf,
          ExpectedManifest{"linux_kernel_module_ko",
                           "linux_kernel_module",
                           "kernel_safe_aot",
                           "kernel_safe",
                           "kernel_module",
                           "sign_after_mutate",
                           "vermagic_profile",
                           "kernel_module_sign_after_mutation",
                           "kernel_safe",
                           true,
                           false,
                           false,
                           false,
                           true,
                           false,
                           true,
                           false},
          true) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "android_ko",
          "android_kernel_module.ko",
          elf,
          ExpectedManifest{"linux_kernel_module_ko",
                           "android_kernel_module",
                           "kernel_safe_aot",
                           "kernel_safe",
                           "kernel_module",
                           "sign_after_mutate",
                           "gki_kmi_profile",
                           "kernel_module_sign_after_mutation",
                           "kernel_safe",
                           true,
                           false,
                           false,
                           false,
                           true,
                           false,
                           false,
                           true},
          true) != 0) {
    return 1;
  }
  if (run_failure_case(temp_dir, "unknown", "desktop_native", unknown) != 0) {
    return 1;
  }
  if (run_failure_case(temp_dir, "elf_as_driver", "windows_driver", elf) != 0) {
    return 1;
  }
  if (run_fail_closed_spoof_cases(temp_dir, unknown) != 0) {
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

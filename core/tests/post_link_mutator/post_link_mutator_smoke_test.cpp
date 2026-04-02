#include <array>
#include <chrono>
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

struct ExpectedManifest final {
  std::string artifact_kind;
  std::string target_kind;
  std::string backend_kind;
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
                "manifest backend kind mismatch");
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
          ExpectedManifest{"pe", "desktop_native", "desktop_jit"},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "desktop_elf",
          "target_elf",
          elf,
          ExpectedManifest{"elf", "desktop_native", "desktop_jit"},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "ios_macho",
          "ios_target_macho",
          macho,
          ExpectedManifest{"macho", "ios_appstore", "ios_safe_aot"},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "windows_driver",
          "windows_driver_sys",
          pe,
          ExpectedManifest{"windows_driver_sys", "windows_driver", "kernel_safe_aot"},
          false) != 0) {
    return 1;
  }
  if (run_success_case(
          temp_dir,
          "linux_ko",
          "linux_kernel_module.ko",
          elf,
          ExpectedManifest{"linux_kernel_module_ko", "linux_kernel_module", "kernel_safe_aot"},
          true) != 0) {
    return 1;
  }
  if (run_failure_case(temp_dir, "unknown", "desktop_native", unknown) != 0) {
    return 1;
  }
  if (run_failure_case(temp_dir, "elf_as_driver", "windows_driver", elf) != 0) {
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

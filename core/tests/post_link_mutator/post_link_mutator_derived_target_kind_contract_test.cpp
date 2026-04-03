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

struct DerivedCase final {
  std::string case_name;
  std::string target_label;
  std::vector<std::uint8_t> input_bytes;
  std::string expected_target_kind;
  std::string expected_artifact_kind;
};

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

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
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     ("eippf_post_link_mutator_derived_contract_" +
                                      std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    return {};
  }
  return path;
}

[[nodiscard]] std::vector<std::uint8_t> make_pe_fixture() {
  std::vector<std::uint8_t> pe(256u, 0u);
  pe[0] = static_cast<std::uint8_t>('M');
  pe[1] = static_cast<std::uint8_t>('Z');
  pe[0x3c] = 0x80u;
  pe[0x80] = static_cast<std::uint8_t>('P');
  pe[0x81] = static_cast<std::uint8_t>('E');
  pe[0x82] = 0x00u;
  pe[0x83] = 0x00u;
  return pe;
}

[[nodiscard]] std::vector<std::uint8_t> make_elf_fixture() {
  return {
      0x7fu, static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('F'), 0x02u, 0x01u, 0x01u, 0x00u};
}

[[nodiscard]] std::vector<std::uint8_t> make_macho_fixture() {
  return {
      0xFEu, 0xEDu, 0xFAu, 0xCFu, 0x00u, 0x00u, 0x00u, 0x00u};
}

[[nodiscard]] std::vector<std::uint8_t> make_shell_fixture() {
  const std::string shebang = "#!/bin/sh\nexit 0\n";
  return std::vector<std::uint8_t>(shebang.begin(), shebang.end());
}

bool run_success_case(const std::filesystem::path& temp_dir, const DerivedCase& test_case) {
  const bool is_shell_case = test_case.expected_target_kind == "shell_ephemeral";
  const std::string input_suffix = is_shell_case ? ".in.sh" : ".in.bin";
  const std::string output_suffix = is_shell_case ? ".out.sh" : ".out.bin";
  const std::filesystem::path input = temp_dir / (test_case.case_name + input_suffix);
  const std::filesystem::path output = temp_dir / (test_case.case_name + output_suffix);
  const std::filesystem::path manifest = temp_dir / (test_case.case_name + ".manifest.json");

  if (!write_bytes(input, test_case.input_bytes)) {
    std::cerr << "[FAIL] cannot write input fixture for " << test_case.case_name << '\n';
    return false;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg(test_case.target_label);
  const int status = normalize_status(std::system(command.c_str()));
  if (!expect(status == 0, "derived contract success case must succeed")) {
    std::cerr << "[INFO] case=" << test_case.case_name << " status=" << status << '\n';
    return false;
  }

  const std::string manifest_text = read_text_file(manifest);
  return expect(manifest_text.find("\"target_kind_source\": \"derived_from_target_label\"") !=
                    std::string::npos,
                "manifest target_kind_source must be derived_from_target_label") &&
         expect(manifest_text.find("\"target_kind_source\": \"explicit_cli\"") == std::string::npos,
                "success manifest must not contain explicit_cli target_kind_source") &&
         expect(manifest_text.find("\"target_kind\": \"" + test_case.expected_target_kind + "\"") !=
                    std::string::npos,
                "manifest target_kind mismatch for derived case") &&
         expect(manifest_text.find("\"artifact_kind\": \"" + test_case.expected_artifact_kind + "\"") !=
                    std::string::npos,
                "manifest artifact_kind mismatch for derived case");
}

bool run_failure_case_target_artifact_mismatch(const std::filesystem::path& temp_dir,
                                               const std::vector<std::uint8_t>& input_bytes) {
  const std::filesystem::path input = temp_dir / "mismatch.in.bin";
  const std::filesystem::path output = temp_dir / "mismatch.out.bin";
  const std::filesystem::path manifest = temp_dir / "mismatch.manifest.json";
  if (!write_bytes(input, input_bytes)) {
    std::cerr << "[FAIL] cannot write mismatch input fixture\n";
    return false;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg("bootstrap.sh");
  const int status = normalize_status(std::system(command.c_str()));
  return expect(status == 6, "target/artifact mismatch must return exit code 6");
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::vector<DerivedCase> cases{
      {"derived_exe", "desktop_app.exe", make_pe_fixture(), "desktop_native", "pe"},
      {"derived_dll", "desktop_plugin.dll", make_pe_fixture(), "desktop_native", "pe"},
      {"derived_sys", "driver_entry.sys", make_pe_fixture(), "windows_driver", "windows_driver_sys"},
      {"derived_elf", "desktop_payload.elf", make_elf_fixture(), "desktop_native", "elf"},
      {"derived_so", "android_native.so", make_elf_fixture(), "android_so", "elf"},
      {"derived_ko",
       "android_kernel_module.ko",
       make_elf_fixture(),
       "android_kernel_module",
       "linux_kernel_module_ko"},
      {"derived_dylib", "ios_runtime.dylib", make_macho_fixture(), "ios_appstore", "macho"},
      {"derived_sh", "bootstrap.sh", make_shell_fixture(), "shell_ephemeral", "shell_bundle"},
  };

  for (const DerivedCase& test_case : cases) {
    if (!run_success_case(temp_dir, test_case)) {
      std::filesystem::remove_all(temp_dir);
      return 1;
    }
  }

  if (!run_failure_case_target_artifact_mismatch(temp_dir, make_elf_fixture())) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  std::filesystem::remove_all(temp_dir);
  return 0;
}

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

#ifndef EIPPF_ARTIFACT_AUDIT_PATH
#error "EIPPF_ARTIFACT_AUDIT_PATH must be defined"
#endif

#ifndef EIPPF_LEXICAL_DENYLIST_PATH
#error "EIPPF_LEXICAL_DENYLIST_PATH must be defined"
#endif

namespace {

struct SampleCase final {
  std::string case_name;
  std::string file_name;
  std::string target_label;
  std::string target_kind;
  std::string expected_artifact_kind;
  std::vector<std::uint8_t> bytes;
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

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("eippf_user_mode_pipeline_test_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::vector<std::uint8_t> make_pe_fixture() {
  std::vector<std::uint8_t> pe(256u, 0u);
  pe[0] = static_cast<std::uint8_t>('M');
  pe[1] = static_cast<std::uint8_t>('Z');
  pe[0x3Cu] = 0x80u;
  pe[0x80u] = static_cast<std::uint8_t>('P');
  pe[0x81u] = static_cast<std::uint8_t>('E');
  pe[0x82u] = 0x00u;
  pe[0x83u] = 0x00u;
  const std::string payload = "WINDOWS_SAMPLE_MINIMAL_PAYLOAD";
  pe.insert(pe.end(), payload.begin(), payload.end());
  return pe;
}

[[nodiscard]] std::vector<std::uint8_t> make_elf_fixture() {
  std::vector<std::uint8_t> elf(0x40u + 0x38u, 0u);
  elf[0] = 0x7Fu;
  elf[1] = static_cast<std::uint8_t>('E');
  elf[2] = static_cast<std::uint8_t>('L');
  elf[3] = static_cast<std::uint8_t>('F');
  elf[4] = 2u;
  elf[5] = 1u;
  elf[6] = 1u;
  elf[0x20u] = 0x40u;
  elf[0x36u] = 0x38u;
  elf[0x38u] = 1u;
  const std::size_t ph = 0x40u;
  elf[ph + 0u] = 1u;
  elf[ph + 4u] = 0u;
  const std::string payload = "ELF_SAMPLE_MINIMAL_PAYLOAD";
  elf.insert(elf.end(), payload.begin(), payload.end());
  return elf;
}

[[nodiscard]] int run_mutator(const std::filesystem::path& input_path,
                              const std::filesystem::path& output_path,
                              const std::filesystem::path& manifest_path,
                              std::string_view target_label,
                              std::string_view target_kind) {
  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input_path.string()) + " --output " +
                              quote_arg(output_path.string()) + " --manifest " +
                              quote_arg(manifest_path.string()) + " --target " +
                              quote_arg(std::string(target_label)) + " --target-kind " +
                              quote_arg(std::string(target_kind));
  return normalize_status(std::system(command.c_str()));
}

[[nodiscard]] int run_audit(const std::filesystem::path& input_path,
                            const std::filesystem::path& output_path,
                            std::string_view target_kind) {
  const std::string command = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) +
                              " --input " + quote_arg(input_path.string()) + " --denylist " +
                              quote_arg(EIPPF_LEXICAL_DENYLIST_PATH) + " --output " +
                              quote_arg(output_path.string()) + " --target-kind " +
                              quote_arg(std::string(target_kind));
  return normalize_status(std::system(command.c_str()));
}

bool run_pipeline_case(const std::filesystem::path& temp_dir, const SampleCase& test_case) {
  const std::filesystem::path input_path = temp_dir / test_case.file_name;
  const std::filesystem::path output_path = temp_dir / (test_case.case_name + ".mutated.bin");
  const std::filesystem::path manifest_path = temp_dir / (test_case.case_name + ".manifest.json");
  const std::filesystem::path audit_path = temp_dir / (test_case.case_name + ".audit.json");

  if (!expect(write_bytes(input_path, test_case.bytes), "failed to write sample fixture")) {
    return false;
  }
  if (!expect(run_mutator(input_path,
                          output_path,
                          manifest_path,
                          test_case.target_label,
                          test_case.target_kind) == 0,
              "post-link mutator must succeed")) {
    return false;
  }
  if (!expect(std::filesystem::exists(manifest_path), "manifest output must exist")) {
    return false;
  }

  if (!expect(run_audit(output_path, audit_path, test_case.target_kind) == 0,
              "artifact audit must succeed")) {
    return false;
  }
  if (!expect(std::filesystem::exists(audit_path), "audit output must exist")) {
    return false;
  }

  const std::string manifest = read_text_file(manifest_path);
  if (!expect(!manifest.empty(), "manifest must be readable")) {
    return false;
  }
  if (!expect(manifest.find("\"target_kind\": \"" + test_case.target_kind + "\"") != std::string::npos,
              "manifest target_kind mismatch")) {
    return false;
  }
  return expect(manifest.find("\"artifact_kind\": \"" + test_case.expected_artifact_kind + "\"") !=
                    std::string::npos,
                "manifest artifact_kind mismatch");
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::vector<std::uint8_t> pe_fixture = make_pe_fixture();
  const std::vector<std::uint8_t> elf_fixture = make_elf_fixture();

  const std::vector<SampleCase> cases{
      {"windows_sample", "windows_sample.exe", "windows_sample.exe", "desktop_native", "pe", pe_fixture},
      {"linux_sample", "linux_sample.so", "linux_sample.so", "desktop_native", "elf", elf_fixture},
      {"android_sample", "android_sample.so", "android_sample.so", "android_so", "elf", elf_fixture},
  };

  bool ok = true;
  for (const SampleCase& test_case : cases) {
    ok = run_pipeline_case(temp_dir, test_case) && ok;
  }

  std::filesystem::remove_all(temp_dir);
  return ok ? 0 : 1;
}

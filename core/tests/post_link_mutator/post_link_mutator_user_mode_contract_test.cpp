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

#ifndef EIPPF_POST_LINK_MUTATOR_BIN
#error "EIPPF_POST_LINK_MUTATOR_BIN must be defined"
#endif

namespace {

constexpr std::string_view kPeUserModeMarker = "EIPPF_PE_USERMODE_V1";
constexpr std::string_view kElfUserModeMarker = "EIPPF_ELF_USERMODE_V1";
constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";

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

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("eippf_post_link_mutator_user_mode_contract_" +
       std::to_string(static_cast<long long>(stamp)));
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

[[nodiscard]] std::vector<std::uint8_t> read_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::size_t find_subsequence(const std::vector<std::uint8_t>& bytes,
                                           std::string_view needle) {
  const auto begin = std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end());
  if (begin == bytes.end()) {
    return bytes.size();
  }
  return static_cast<std::size_t>(std::distance(bytes.begin(), begin));
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

bool run_success_case(const std::filesystem::path& temp_dir,
                      std::string_view case_name,
                      const std::vector<std::uint8_t>& input_content,
                      std::string_view target_label,
                      std::string_view target_kind,
                      std::string_view expected_marker) {
  const std::filesystem::path input = temp_dir / (std::string(case_name) + ".in.bin");
  const std::filesystem::path output = temp_dir / (std::string(case_name) + ".out.bin");
  const std::filesystem::path manifest = temp_dir / (std::string(case_name) + ".manifest.json");
  if (!write_bytes(input, input_content)) {
    return false;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg(std::string(target_label)) + " --target-kind " +
                              quote_arg(std::string(target_kind));
  const int status = normalize_status(std::system(command.c_str()));
  if (!expect(status == 0, "user-mode success case must succeed")) {
    return false;
  }

  const std::vector<std::uint8_t> mutated = read_bytes(output);
  if (!expect(mutated.size() > input_content.size(), "mutated output must be larger than input")) {
    return false;
  }
  if (!expect(std::equal(input_content.begin(), input_content.end(), mutated.begin()),
              "mutated output must preserve original prefix")) {
    return false;
  }

  const std::size_t marker_offset = find_subsequence(mutated, expected_marker);
  const std::size_t trailer_offset = find_subsequence(mutated, kMutationTrailerMagic);
  if (!expect(marker_offset != mutated.size(), "expected user-mode marker missing")) {
    return false;
  }
  if (!expect(trailer_offset != mutated.size(), "mutation trailer missing")) {
    return false;
  }
  return expect(marker_offset < trailer_offset, "marker must be written before trailer");
}

bool run_mismatch_fail_closed_case(const std::filesystem::path& temp_dir,
                                   const std::vector<std::uint8_t>& pe_input) {
  const std::filesystem::path input = temp_dir / "mismatch.in.bin";
  const std::filesystem::path output = temp_dir / "mismatch.out.bin";
  const std::filesystem::path manifest = temp_dir / "mismatch.manifest.json";
  if (!write_bytes(input, pe_input)) {
    return false;
  }

  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input.string()) + " --output " + quote_arg(output.string()) +
                              " --manifest " + quote_arg(manifest.string()) + " --target " +
                              quote_arg("android_native.so") + " --target-kind " +
                              quote_arg("android_so");
  const int status = normalize_status(std::system(command.c_str()));
  return expect(status != 0, "artifact mismatch must fail closed");
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::vector<std::uint8_t> pe_fixture = make_pe_fixture();
  const std::vector<std::uint8_t> elf_fixture = make_elf_fixture();

  if (!run_success_case(temp_dir,
                        "pe_user_mode_success",
                        pe_fixture,
                        "desktop.exe",
                        "desktop_native",
                        kPeUserModeMarker) ||
      !run_success_case(temp_dir,
                        "elf_user_mode_success",
                        elf_fixture,
                        "android_native.so",
                        "android_so",
                        kElfUserModeMarker) ||
      !run_mismatch_fail_closed_case(temp_dir, pe_fixture)) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  std::filesystem::remove_all(temp_dir);
  return 0;
}

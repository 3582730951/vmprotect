#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

#ifndef EIPPF_HARDENED_FIXTURE_PATH
#error "EIPPF_HARDENED_FIXTURE_PATH must be defined"
#endif

#ifndef EIPPF_HARDENED_FIXTURE_PRE_PATH
#error "EIPPF_HARDENED_FIXTURE_PRE_PATH must be defined"
#endif

#ifndef EIPPF_HARDENED_FIXTURE_MANIFEST_PATH
#error "EIPPF_HARDENED_FIXTURE_MANIFEST_PATH must be defined"
#endif

#ifndef EIPPF_HARDENED_FIXTURE_AUDIT_PATH
#error "EIPPF_HARDENED_FIXTURE_AUDIT_PATH must be defined"
#endif

namespace {

constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::vector<std::uint8_t> read_binary_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>());
}

bool expect_trailer_magic_and_version(const std::vector<std::uint8_t>& bytes) {
  if (!expect(bytes.size() > kMutationTrailerMagic.size(),
              "fixture must include trailer payload")) {
    return false;
  }
  const auto magic_begin = std::search(bytes.begin(),
                                       bytes.end(),
                                       kMutationTrailerMagic.begin(),
                                       kMutationTrailerMagic.end());
  if (!expect(magic_begin != bytes.end(), "fixture trailer magic missing")) {
    return false;
  }
  const auto version_it =
      magic_begin + static_cast<std::ptrdiff_t>(kMutationTrailerMagic.size());
  if (!expect(version_it != bytes.end(), "fixture trailer version byte missing")) {
    return false;
  }
  return expect(*version_it == 1u, "fixture trailer version mismatch");
}

}  // namespace

int main() {
  const std::filesystem::path fixture_path = EIPPF_HARDENED_FIXTURE_PATH;
  const std::filesystem::path pre_path = EIPPF_HARDENED_FIXTURE_PRE_PATH;
  const std::filesystem::path manifest_path = EIPPF_HARDENED_FIXTURE_MANIFEST_PATH;
  const std::filesystem::path audit_path = EIPPF_HARDENED_FIXTURE_AUDIT_PATH;

  if (!expect(std::filesystem::exists(fixture_path), "mutated fixture must exist")) {
    return 1;
  }
  if (!expect(std::filesystem::exists(pre_path), "pre-mutation backup must exist")) {
    return 1;
  }
  if (!expect(std::filesystem::exists(manifest_path), "manifest sidecar must exist")) {
    return 1;
  }
  if (!expect(std::filesystem::exists(audit_path), "audit sidecar must exist")) {
    return 1;
  }

  const std::uintmax_t fixture_size = std::filesystem::file_size(fixture_path);
  const std::uintmax_t pre_size = std::filesystem::file_size(pre_path);
  if (!expect(fixture_size > pre_size, "mutated fixture must be larger than pre-mutation backup")) {
    return 1;
  }

  const std::string manifest = read_text_file(manifest_path);
  if (!expect(manifest.find("\"mutation_status\": \"mutated_with_trailer_v1\"") != std::string::npos,
              "manifest mutation status mismatch")) {
    return 1;
  }
  if (!expect(manifest.find("\"target_kind\": \"desktop_native\"") != std::string::npos,
              "manifest target kind mismatch")) {
    return 1;
  }
  if (!expect(manifest.find("\"target_kind_source\": \"explicit_cli\"") != std::string::npos,
              "manifest target kind source mismatch")) {
    return 1;
  }
  if (!expect(manifest.find("\"signing_profile\": \"unsigned_dev_or_sign_after_mutation\"") !=
                  std::string::npos,
              "manifest signing profile mismatch")) {
    return 1;
  }

  if (!expect_trailer_magic_and_version(read_binary_file(fixture_path))) {
    return 1;
  }

  const std::string audit = read_text_file(audit_path);
  if (!expect(audit.find("\"string_anchor_scan_passed\": true") != std::string::npos,
              "audit report must indicate string scan success")) {
    return 1;
  }
  if (!expect(audit.find("\"section_permission_scan_passed\": true") != std::string::npos,
              "audit report must indicate safe native permissions")) {
    return 1;
  }
  if (!expect(audit.find("\"strict_failures\": []") != std::string::npos,
              "audit report must have no strict failures")) {
    return 1;
  }
  if (!expect(audit.find("\"artifact_kind\": \"pe\"") != std::string::npos ||
                  audit.find("\"artifact_kind\": \"elf\"") != std::string::npos ||
                  audit.find("\"artifact_kind\": \"macho\"") != std::string::npos,
              "audit report must classify a native artifact")) {
    return 1;
  }

  return 0;
}

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

#ifndef EIPPF_HARDENED_FIXTURE_MANIFEST_PATH
#error "EIPPF_HARDENED_FIXTURE_MANIFEST_PATH must be defined"
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
  const auto magic_begin = std::search(bytes.begin(),
                                       bytes.end(),
                                       kMutationTrailerMagic.begin(),
                                       kMutationTrailerMagic.end());
  if (!expect(magic_begin != bytes.end(), "fixture trailer magic missing")) {
    return false;
  }
  const auto version_it =
      magic_begin + static_cast<std::ptrdiff_t>(kMutationTrailerMagic.size());
  if (!expect(version_it != bytes.end(), "fixture trailer version missing")) {
    return false;
  }
  return expect(*version_it == 1u, "fixture trailer version mismatch");
}

}  // namespace

int main() {
  const std::filesystem::path fixture_path = EIPPF_HARDENED_FIXTURE_PATH;
  const std::filesystem::path manifest_path = EIPPF_HARDENED_FIXTURE_MANIFEST_PATH;

  if (!expect(std::filesystem::exists(fixture_path), "hardened fixture binary must exist")) {
    return 1;
  }
  if (!expect(std::filesystem::exists(manifest_path), "hardened fixture manifest must exist")) {
    return 1;
  }

  const std::string manifest = read_text_file(manifest_path);
  if (!expect(manifest.find("\"target_kind_source\": \"explicit_cli\"") != std::string::npos,
              "manifest target_kind_source must be explicit_cli")) {
    return 1;
  }
  if (!expect(manifest.find("\"signing_profile\": \"unsigned_dev_or_sign_after_mutation\"") !=
                  std::string::npos,
              "manifest signing_profile must be unsigned_dev_or_sign_after_mutation")) {
    return 1;
  }

  if (!expect_trailer_magic_and_version(read_binary_file(fixture_path))) {
    return 1;
  }

  return 0;
}

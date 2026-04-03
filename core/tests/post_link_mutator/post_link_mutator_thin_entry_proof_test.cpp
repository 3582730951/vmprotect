#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kMainPath = "/workspace/core/post_link_mutator/src/main.cpp";
constexpr std::string_view kThinEntryDelegationLine =
    "return eippf::post_link_mutator::run_mutator(argc, argv, std::cout, std::cerr);";

constexpr std::array<std::string_view, 6> kForbiddenMainSymbols = {
    "detect_base_artifact_kind(",
    "classify_target_kind(",
    "target_kind_matches_artifact_kind(",
    "mutate_artifact(",
    "build_mutation_trailer(",
    "write_manifest(",
};

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

}  // namespace

int main() {
  const std::string main_cpp = read_text_file(kMainPath);
  if (!expect(!main_cpp.empty(), "failed to read main.cpp")) {
    return 1;
  }
  if (!expect(main_cpp.find(kThinEntryDelegationLine) != std::string::npos,
              "main.cpp must delegate argc/argv/stdout/stderr to run_mutator")) {
    return 1;
  }

  for (const std::string_view token : kForbiddenMainSymbols) {
    if (!expect(main_cpp.find(token) == std::string::npos,
                "main.cpp must remain thin and avoid embedded mutator logic")) {
      return 1;
    }
  }

  return 0;
}

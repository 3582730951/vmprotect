#pragma once

#include <filesystem>
#include <optional>
#include <ostream>
#include <string>

namespace eippf::post_link_mutator {

struct CliOptions final {
  std::filesystem::path input_path;
  std::filesystem::path output_path;
  std::filesystem::path manifest_path;
  std::string target_label;
  std::string target_kind_hint;
  bool show_help = false;
};

[[nodiscard]] std::optional<CliOptions> parse_cli(int argc, char** argv);

void print_usage(std::ostream& out);

}  // namespace eippf::post_link_mutator

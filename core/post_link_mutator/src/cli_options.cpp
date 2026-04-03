#include "post_link_mutator/cli_options.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace eippf::post_link_mutator {
namespace {

[[nodiscard]] std::optional<std::string> read_option_value(int& index, int argc, char** argv) {
  if (index + 1 >= argc) {
    return std::nullopt;
  }
  ++index;
  return std::string(argv[index]);
}

}  // namespace

std::optional<CliOptions> parse_cli(int argc, char** argv) {
  CliOptions options{};

  for (int i = 1; i < argc; ++i) {
    const std::string_view token(argv[i]);
    if (token == "--help" || token == "-h") {
      options.show_help = true;
      return options;
    }
    if (token.rfind("--input=", 0u) == 0u) {
      options.input_path = std::filesystem::path(std::string(token.substr(8u)));
      continue;
    }
    if (token.rfind("--output=", 0u) == 0u) {
      options.output_path = std::filesystem::path(std::string(token.substr(9u)));
      continue;
    }
    if (token.rfind("--manifest=", 0u) == 0u) {
      options.manifest_path = std::filesystem::path(std::string(token.substr(11u)));
      continue;
    }
    if (token.rfind("--target=", 0u) == 0u) {
      options.target_label = std::string(token.substr(9u));
      continue;
    }
    if (token.rfind("--target-kind=", 0u) == 0u) {
      options.target_kind_hint = std::string(token.substr(14u));
      continue;
    }
    if (token == "--input") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.input_path = std::filesystem::path(*value);
      continue;
    }
    if (token == "--output") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.output_path = std::filesystem::path(*value);
      continue;
    }
    if (token == "--manifest") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.manifest_path = std::filesystem::path(*value);
      continue;
    }
    if (token == "--target") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.target_label = *value;
      continue;
    }
    if (token == "--target-kind") {
      const std::optional<std::string> value = read_option_value(i, argc, argv);
      if (!value.has_value()) {
        return std::nullopt;
      }
      options.target_kind_hint = *value;
      continue;
    }
    return std::nullopt;
  }

  if (options.target_label.empty()) {
    options.target_label = "unspecified";
  }
  if (options.input_path.empty() || options.output_path.empty() || options.manifest_path.empty()) {
    return std::nullopt;
  }
  return options;
}

void print_usage(std::ostream& out) {
  out << "eippf_post_link_mutator --input <file> --output <file> --manifest <file> "
         "--target-kind <kind> [--target <label>]\n";
}

}  // namespace eippf::post_link_mutator

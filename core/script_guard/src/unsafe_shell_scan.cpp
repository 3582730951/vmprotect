#include "script_guard/unsafe_shell_scan.hpp"

#include <algorithm>
#include <cstddef>

namespace eippf::script_guard {

namespace {

[[nodiscard]] bool contains_source_keyword(std::string_view line) {
  const std::size_t source_pos = line.find("source ");
  if (source_pos != std::string_view::npos) {
    return true;
  }
  std::size_t cursor = 0u;
  while (cursor < line.size() && (line[cursor] == ' ' || line[cursor] == '\t')) {
    ++cursor;
  }
  return cursor + 1u < line.size() && line[cursor] == '.' && line[cursor + 1u] == ' ';
}

void append_once(std::vector<std::string>& output, std::string_view token) {
  const bool exists = std::any_of(output.begin(), output.end(), [token](const std::string& value) {
    return value == token;
  });
  if (!exists) {
    output.emplace_back(token);
  }
}

}  // namespace

std::vector<std::string> scan_unsafe_shell_features(std::string_view script_text) {
  std::vector<std::string> features;

  if (script_text.find("set -x") != std::string_view::npos ||
      script_text.find("set -o xtrace") != std::string_view::npos) {
    append_once(features, "xtrace");
  }

  std::size_t cursor = 0u;
  while (cursor <= script_text.size()) {
    const std::size_t next = script_text.find('\n', cursor);
    const std::size_t end = next == std::string_view::npos ? script_text.size() : next;
    const std::string_view line = script_text.substr(cursor, end - cursor);
    if (contains_source_keyword(line)) {
      append_once(features, "source");
      break;
    }
    cursor = next == std::string_view::npos ? script_text.size() + 1u : next + 1u;
  }

  if (script_text.find("$0") != std::string_view::npos ||
      script_text.find("${BASH_SOURCE") != std::string_view::npos) {
    append_once(features, "self_argv0_introspection");
  }

  return features;
}

}  // namespace eippf::script_guard

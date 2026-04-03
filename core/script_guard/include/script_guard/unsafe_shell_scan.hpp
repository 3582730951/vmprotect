#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace eippf::script_guard {

[[nodiscard]] std::vector<std::string> scan_unsafe_shell_features(std::string_view script_text);

}  // namespace eippf::script_guard

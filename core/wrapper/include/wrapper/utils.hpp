#pragma once

#include <cstdlib>
#include <optional>
#include <string>

namespace eippf::wrapper::utils {

inline std::optional<std::string> get_env_non_empty(const char* key) {
#ifdef _WIN32
  char* value = nullptr;
  std::size_t len = 0;
  if (_dupenv_s(&value, &len, key) != 0 || value == nullptr) {
    return std::nullopt;
  }
  std::string result(value);
  std::free(value);
  if (result.empty()) {
    return std::nullopt;
  }
  return result;
#else
  const char* value = std::getenv(key);
  if (value == nullptr || *value == '\0') {
    return std::nullopt;
  }
  return std::string(value);
#endif
}

}  // namespace eippf::wrapper::utils


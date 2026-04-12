#pragma once

#include <cstddef>
#include <cstdint>

#include "runtime/constexpr_obfuscated_string.hpp"

namespace eippf::runtime::analysis {

inline char ascii_lower(char value) noexcept {
  if (value >= 'A' && value <= 'Z') {
    return static_cast<char>(value - 'A' + 'a');
  }
  return value;
}

inline bool is_ascii_alpha(char value) noexcept {
  return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
}

inline bool is_ascii_digit(char value) noexcept {
  return value >= '0' && value <= '9';
}

inline bool is_ascii_alnum(char value) noexcept {
  return is_ascii_alpha(value) || is_ascii_digit(value);
}

inline std::size_t c_string_size(const char* text) noexcept {
  if (text == nullptr) {
    return 0u;
  }
  std::size_t size = 0u;
  while (text[size] != '\0') {
    ++size;
  }
  return size;
}

inline bool starts_with_ignore_case(const char* text, std::size_t size, const char* prefix,
                                    std::size_t prefix_size) noexcept {
  if (text == nullptr || prefix == nullptr || size < prefix_size) {
    return false;
  }
  for (std::size_t i = 0; i < prefix_size; ++i) {
    if (ascii_lower(text[i]) != ascii_lower(prefix[i])) {
      return false;
    }
  }
  return true;
}

inline bool equals_ignore_case(const char* lhs, std::size_t lhs_size, const char* rhs,
                               std::size_t rhs_size) noexcept {
  if (lhs == nullptr || rhs == nullptr || lhs_size != rhs_size) {
    return false;
  }
  for (std::size_t i = 0; i < lhs_size; ++i) {
    if (ascii_lower(lhs[i]) != ascii_lower(rhs[i])) {
      return false;
    }
  }
  return true;
}

inline std::size_t trim_trailing_digits(const char* text, std::size_t size) noexcept {
  while (size > 0u && is_ascii_digit(text[size - 1u])) {
    --size;
  }
  return size;
}

inline bool normalized_component_matches_short_keyword(const char* component,
                                                       std::size_t component_size,
                                                       const char* keyword,
                                                       std::size_t keyword_size) noexcept {
  if (component == nullptr || keyword == nullptr || component_size == 0u || keyword_size == 0u) {
    return false;
  }

  if (equals_ignore_case(component, component_size, keyword, keyword_size)) {
    return true;
  }

  const std::size_t digit_trimmed_size = trim_trailing_digits(component, component_size);
  if (digit_trimmed_size != component_size &&
      equals_ignore_case(component, digit_trimmed_size, keyword, keyword_size)) {
    return true;
  }

  constexpr char kLibPrefix[] = "lib";
  if (component_size > 3u &&
      starts_with_ignore_case(component, component_size, kLibPrefix, sizeof(kLibPrefix) - 1u)) {
    const char* lib_trimmed = component + 3u;
    const std::size_t lib_trimmed_size = component_size - 3u;
    if (equals_ignore_case(lib_trimmed, lib_trimmed_size, keyword, keyword_size)) {
      return true;
    }
    const std::size_t lib_digit_trimmed_size = trim_trailing_digits(lib_trimmed, lib_trimmed_size);
    if (lib_digit_trimmed_size != lib_trimmed_size &&
        equals_ignore_case(lib_trimmed, lib_digit_trimmed_size, keyword, keyword_size)) {
      return true;
    }
  }

  return false;
}

inline bool contains_ignore_case(const char* text, const char* token,
                                 bool require_short_keyword_component_match) noexcept {
  if (text == nullptr || token == nullptr || *text == '\0' || *token == '\0') {
    return false;
  }

  const std::size_t token_size = c_string_size(token);
  if (token_size == 0u) {
    return false;
  }

  if (require_short_keyword_component_match) {
    const char* cursor = text;
    while (*cursor != '\0') {
      while (*cursor != '\0' && !is_ascii_alnum(*cursor)) {
        ++cursor;
      }
      const char* component_begin = cursor;
      while (*cursor != '\0' && is_ascii_alnum(*cursor)) {
        ++cursor;
      }
      const std::size_t component_size = static_cast<std::size_t>(cursor - component_begin);
      if (component_size > 0u &&
          normalized_component_matches_short_keyword(component_begin, component_size, token,
                                                     token_size)) {
        return true;
      }
    }
    return false;
  }

  for (const char* cursor = text; *cursor != '\0'; ++cursor) {
    std::size_t i = 0u;
    while (token[i] != '\0' && cursor[i] != '\0' &&
           ascii_lower(cursor[i]) == ascii_lower(token[i])) {
      ++i;
    }
    if (token[i] == '\0') {
      return true;
    }
  }
  return false;
}

template <typename EncodedToken>
inline bool contains_obfuscated_token(const char* text, const EncodedToken& token,
                                      bool require_short_keyword_boundary = false) noexcept {
  auto plain = token.decrypt();
  return contains_ignore_case(text, plain.c_str(), require_short_keyword_boundary);
}

inline bool contains_suspicious_marker(const char* text) noexcept {
  if (text == nullptr || *text == '\0') {
    return false;
  }

  constexpr auto kFrida = security::make_obfuscated_string<0x31u>("frida");
  constexpr auto kXposed = security::make_obfuscated_string<0x32u>("xposed");
  constexpr auto kLsposed = security::make_obfuscated_string<0x33u>("lsposed");
  constexpr auto kMagisk = security::make_obfuscated_string<0x34u>("magisk");
  constexpr auto kZygisk = security::make_obfuscated_string<0x35u>("zygisk");
  constexpr auto kCheatEngine = security::make_obfuscated_string<0x36u>("cheat engine");
  constexpr auto kCheatEngineCompact = security::make_obfuscated_string<0x37u>("cheatengine");
  constexpr auto kOllydbg = security::make_obfuscated_string<0x38u>("ollydbg");
  constexpr auto kX64dbg = security::make_obfuscated_string<0x39u>("x64dbg");
  constexpr auto kIda = security::make_obfuscated_string<0x3Au>("ida");
  constexpr auto kIdapro = security::make_obfuscated_string<0x3Bu>("idapro");
  constexpr auto kGdb = security::make_obfuscated_string<0x3Cu>("gdb");
  constexpr auto kLldb = security::make_obfuscated_string<0x3Du>("lldb");
  constexpr auto kSubstrate = security::make_obfuscated_string<0x3Eu>("substrate");
  constexpr auto kSubstitute = security::make_obfuscated_string<0x3Fu>("substitute");

  return contains_obfuscated_token(text, kFrida) ||
         contains_obfuscated_token(text, kXposed) ||
         contains_obfuscated_token(text, kLsposed) ||
         contains_obfuscated_token(text, kMagisk) ||
         contains_obfuscated_token(text, kZygisk) ||
         contains_obfuscated_token(text, kCheatEngine) ||
         contains_obfuscated_token(text, kCheatEngineCompact) ||
         contains_obfuscated_token(text, kOllydbg) ||
         contains_obfuscated_token(text, kX64dbg) ||
         contains_obfuscated_token(text, kIda, true) ||
         contains_obfuscated_token(text, kIdapro) ||
         contains_obfuscated_token(text, kGdb, true) ||
         contains_obfuscated_token(text, kLldb, true) ||
         contains_obfuscated_token(text, kSubstrate) ||
         contains_obfuscated_token(text, kSubstitute);
}

inline bool parse_tracer_pid_zero(const char* text, std::size_t size) noexcept {
  if (text == nullptr || size == 0u) {
    return false;
  }

  constexpr auto kTracerPid = security::make_obfuscated_string<0x40u>("TracerPid:");
  auto token = kTracerPid.decrypt();
  const char* marker = token.c_str();

  std::size_t marker_size = 0u;
  while (marker[marker_size] != '\0') {
    ++marker_size;
  }
  if (size < marker_size) {
    return false;
  }

  for (std::size_t i = 0; i + marker_size <= size; ++i) {
    bool match = true;
    for (std::size_t j = 0; j < marker_size; ++j) {
      if (text[i + j] != marker[j]) {
        match = false;
        break;
      }
    }
    if (!match) {
      continue;
    }

    std::size_t cursor = i + marker_size;
    while (cursor < size && (text[cursor] == ' ' || text[cursor] == '\t')) {
      ++cursor;
    }

    std::uint32_t tracer_pid = 0u;
    bool has_digit = false;
    while (cursor < size && text[cursor] >= '0' && text[cursor] <= '9') {
      has_digit = true;
      tracer_pid = static_cast<std::uint32_t>((tracer_pid * 10u) +
                                              static_cast<std::uint32_t>(text[cursor] - '0'));
      ++cursor;
    }
    return has_digit && tracer_pid == 0u;
  }

  return false;
}

}  // namespace eippf::runtime::analysis

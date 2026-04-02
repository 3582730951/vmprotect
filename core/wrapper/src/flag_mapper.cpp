#include "flag_mapper.hpp"
#include "wrapper/utils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <string_view>

namespace eippf::wrapper {
namespace {

std::string to_lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return value;
}

bool starts_with(std::string_view value, std::string_view prefix) {
  return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

std::string filename_only(const std::string& path) {
  const std::filesystem::path fs_path(path);
  const std::string filename = fs_path.filename().string();
  return filename.empty() ? path : filename;
}

bool compiler_name_is_msvc_like(const std::string& compiler) {
  const std::string name = to_lower_copy(filename_only(compiler));
  return name == "cl" || name == "cl.exe" || name == "clang-cl" || name == "clang-cl.exe";
}

bool compiler_name_is_gnu_like(const std::string& compiler) {
  const std::string name = to_lower_copy(filename_only(compiler));
  return name == "gcc" || name == "g++" || name == "cc" || name == "c++" ||
         name == "clang" || name == "clang++";
}

bool is_known_msvc_switch(const std::string& argument) {
  if (argument.size() < 2 || argument[0] != '/') {
    return false;
  }

  const std::string lower = to_lower_copy(argument);
  constexpr std::array<std::string_view, 19> kPrefixes = {
      "/c",      "/fo",   "/fe",  "/i",    "/d",   "/std:", "/o",   "/w",
      "/wx",     "/zi",   "/z7",  "/eh",   "/gr",  "/md",   "/mt",  "/link",
      "/nologo", "/ld",   "/tp"};

  return std::any_of(
      kPrefixes.begin(), kPrefixes.end(),
      [&lower](std::string_view prefix) { return starts_with(lower, prefix); });
}

bool has_cxx_extension(const std::string& argument) {
  const std::filesystem::path fs_path(argument);
  const std::string ext = to_lower_copy(fs_path.extension().string());
  return ext == ".cc" || ext == ".cp" || ext == ".cxx" || ext == ".cpp" || ext == ".c++" ||
         ext == ".cxxm" || ext == ".mm" || ext == ".hpp" || ext == ".hh" || ext == ".hxx";
}

bool has_source_extension(const std::string& argument) {
  const std::filesystem::path fs_path(argument);
  const std::string ext = to_lower_copy(fs_path.extension().string());
  return ext == ".c" || ext == ".cc" || ext == ".cp" || ext == ".cxx" || ext == ".cpp" ||
         ext == ".c++" || ext == ".ixx" || ext == ".cppm" || ext == ".cxxm" || ext == ".m" ||
         ext == ".mm" || ext == ".s" || ext == ".asm" || ext == ".ll";
}

bool has_object_or_library_extension(const std::string& argument) {
  const std::filesystem::path fs_path(argument);
  const std::string ext = to_lower_copy(fs_path.extension().string());
  return ext == ".o" || ext == ".obj" || ext == ".a" || ext == ".lib" || ext == ".so" ||
         ext == ".dylib";
}

bool is_compile_only_mode(CompilerFlavor flavor, const std::vector<std::string>& args) {
  for (const auto& arg : args) {
    if (flavor == CompilerFlavor::kMsvcLike) {
      if (arg.empty() || arg[0] != '/') {
        continue;
      }
      const std::string lower = to_lower_copy(arg);
      if (lower == "/c" || lower == "/e" || lower == "/ep") {
        return true;
      }
      continue;
    }

    if (arg == "-c" || arg == "-S" || arg == "-E") {
      return true;
    }
  }
  return false;
}

bool gnu_option_expects_value(const std::string& arg) {
  constexpr std::array<std::string_view, 20> kExact = {
      "-o",      "-x",       "-I",        "-D",       "-U",        "-include", "-imacros",
      "-isystem", "-isysroot", "-target",   "-arch",    "-MF",       "-MT",      "-MQ",
      "-L",      "-B",       "-Xclang",   "-Xlinker", "-Xassembler", "-mllvm"};
  return std::any_of(kExact.begin(), kExact.end(),
                     [&arg](std::string_view opt) { return arg == opt; });
}

bool msvc_option_expects_value(const std::string& arg_lower) {
  constexpr std::array<std::string_view, 13> kExact = {
      "/fi", "/fo", "/fe", "/fd", "/fa", "/fp", "/ifcoutput", "/ifcsearchdir",
      "/i",  "/d",  "/u",  "/external:i", "/winsysroot"};
  return std::any_of(kExact.begin(), kExact.end(),
                     [&arg_lower](std::string_view opt) { return arg_lower == opt; });
}

bool contains_source_inputs(CompilerFlavor flavor, const std::vector<std::string>& args) {
  bool expect_value_for_previous = false;
  bool expect_source_after_lang_switch = false;

  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& arg = args[i];
    if (expect_value_for_previous) {
      expect_value_for_previous = false;
      continue;
    }

    if (flavor == CompilerFlavor::kMsvcLike) {
      if (!arg.empty() && arg[0] == '/') {
        const std::string lower = to_lower_copy(arg);
        if (lower == "/tc" || lower == "/tp") {
          expect_source_after_lang_switch = true;
          continue;
        }
        if (starts_with(lower, "/tc") || starts_with(lower, "/tp")) {
          if (arg.size() > 3) {
            return true;
          }
          expect_source_after_lang_switch = true;
          continue;
        }
        if (lower == "/link") {
          break;
        }
        if (msvc_option_expects_value(lower)) {
          expect_value_for_previous = true;
        }
        continue;
      }
    } else {
      if (arg == "-x") {
        if ((i + 1) < args.size()) {
          const std::string lang = to_lower_copy(args[i + 1]);
          expect_source_after_lang_switch = (lang == "c" || lang.find("c++") != std::string::npos ||
                                             lang == "objective-c" || lang == "objective-c++");
        }
        expect_value_for_previous = true;
        continue;
      }
      if (!arg.empty() && arg[0] == '-') {
        if (gnu_option_expects_value(arg)) {
          expect_value_for_previous = true;
        }
        continue;
      }
    }

    if (has_source_extension(arg)) {
      return true;
    }
    if (expect_source_after_lang_switch && !has_object_or_library_extension(arg)) {
      return true;
    }
    expect_source_after_lang_switch = false;
  }
  return false;
}

bool is_cxx_mode(const std::string& compiler_invocation, const std::vector<std::string>& args) {
  const std::string name = to_lower_copy(filename_only(compiler_invocation));
  if (name.find("++") != std::string::npos || name == "clang-cl" || name == "clang-cl.exe") {
    return true;
  }

  for (std::size_t i = 0; i < args.size(); ++i) {
    const std::string& arg = args[i];
    if (arg == "-x" && (i + 1) < args.size()) {
      const std::string lang = to_lower_copy(args[i + 1]);
      if (lang.find("c++") != std::string::npos) {
        return true;
      }
      if (lang == "c") {
        return false;
      }
    }
    if (starts_with(arg, "-x")) {
      const std::string lang = to_lower_copy(arg.substr(2));
      if (lang.find("c++") != std::string::npos) {
        return true;
      }
      if (lang == "c") {
        return false;
      }
    }
    if (!arg.empty() && arg[0] == '-') {
      continue;
    }
    if (has_cxx_extension(arg)) {
      return true;
    }
  }
  return false;
}

CompilerFlavor detect_compiler_flavor(const std::string& compiler_invocation,
                                      const std::vector<std::string>& args) {
  if (compiler_name_is_msvc_like(compiler_invocation)) {
    return CompilerFlavor::kMsvcLike;
  }

  const bool has_msvc_flags = std::any_of(args.begin(), args.end(), is_known_msvc_switch);
  if (has_msvc_flags) {
    return CompilerFlavor::kMsvcLike;
  }

  if (compiler_name_is_gnu_like(compiler_invocation)) {
    return CompilerFlavor::kGnuLike;
  }

#ifdef _WIN32
  return CompilerFlavor::kMsvcLike;
#else
  return CompilerFlavor::kGnuLike;
#endif
}

bool contains_pass_plugin_flag(const std::vector<std::string>& args) {
  return std::any_of(args.begin(), args.end(), [](const std::string& arg) {
    return starts_with(arg, "-fpass-plugin=") || starts_with(arg, "/clang:-fpass-plugin=");
  });
}

std::string resolve_compiler_binary(CompilerFlavor flavor, bool cxx_mode,
                                    const MappingOptions& options) {
  if (options.forced_compiler && !options.forced_compiler->empty()) {
    return *options.forced_compiler;
  }

  if (flavor == CompilerFlavor::kMsvcLike) {
    if (const auto override_compiler = utils::get_env_non_empty("EIPPF_CLANG_CL")) {
      return *override_compiler;
    }
    return "clang-cl";
  }

  if (cxx_mode) {
    if (const auto override_compiler = utils::get_env_non_empty("EIPPF_CLANGXX")) {
      return *override_compiler;
    }
    return "clang++";
  }

  if (const auto override_compiler = utils::get_env_non_empty("EIPPF_CLANG")) {
    return *override_compiler;
  }
  return "clang";
}

}  // namespace

MappedCommand map_flags(const std::string& compiler_invocation,
                        const std::vector<std::string>& original_args,
                        const MappingOptions& options) {
  MappedCommand mapped{};
  mapped.flavor = detect_compiler_flavor(compiler_invocation, original_args);

  const bool cxx_mode = is_cxx_mode(compiler_invocation, original_args);
  mapped.compiler = resolve_compiler_binary(mapped.flavor, cxx_mode, options);
  mapped.arguments = original_args;

  const bool compile_only_mode = is_compile_only_mode(mapped.flavor, mapped.arguments);
  const bool has_sources = contains_source_inputs(mapped.flavor, mapped.arguments);
  const bool should_inject_pass_plugin = compile_only_mode || has_sources;

  if (options.pass_plugin && !options.pass_plugin->empty() &&
      should_inject_pass_plugin && !contains_pass_plugin_flag(mapped.arguments)) {
    if (mapped.flavor == CompilerFlavor::kMsvcLike) {
      mapped.arguments.push_back("/clang:-fpass-plugin=" + *options.pass_plugin);
    } else {
      mapped.arguments.push_back("-fpass-plugin=" + *options.pass_plugin);
    }
  }

  return mapped;
}

}  // namespace eippf::wrapper

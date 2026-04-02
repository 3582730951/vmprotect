#pragma once

#include <optional>
#include <string>
#include <vector>

namespace eippf::wrapper {

enum class CompilerFlavor {
  kGnuLike,
  kMsvcLike,
};

struct MappingOptions {
  std::optional<std::string> pass_plugin;
  std::optional<std::string> forced_compiler;
};

struct MappedCommand {
  std::string compiler;
  std::vector<std::string> arguments;
  CompilerFlavor flavor;
};

MappedCommand map_flags(const std::string& compiler_invocation,
                        const std::vector<std::string>& original_args,
                        const MappingOptions& options);

}  // namespace eippf::wrapper


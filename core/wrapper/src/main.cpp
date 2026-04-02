#include "flag_mapper.hpp"
#include "wrapper/utils.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

struct WrapperCli {
  eippf::wrapper::MappingOptions mapping_options;
  bool print_command = false;
  std::vector<std::string> compiler_command;
};

void print_usage(const std::string& binary_name) {
  std::cerr
      << "Usage:\n"
      << "  " << binary_name << " [wrapper-options] -- <compiler> [compiler-args...]\n"
      << "  " << binary_name << " [wrapper-options] <compiler> [compiler-args...]\n\n"
      << "Wrapper options:\n"
      << "  --pass-plugin <path>     Inject LLVM pass plugin path.\n"
      << "  --compiler <path>        Force underlying compiler executable.\n"
      << "  --print-command          Print mapped command instead of executing it.\n"
      << "  --help                   Print this message.\n";
}

bool starts_with(std::string_view value, std::string_view prefix) {
  return value.size() >= prefix.size() && value.substr(0, prefix.size()) == prefix;
}

bool parse_wrapper_cli(int argc, char** argv, WrapperCli* cli, std::string* error) {
  if (cli == nullptr || error == nullptr) {
    return false;
  }
  if (argc < 2) {
    *error = "missing compiler command";
    return false;
  }

  std::vector<std::string> args;
  args.reserve(static_cast<std::size_t>(argc - 1));
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);
  }

  std::size_t i = 0;
  while (i < args.size()) {
    const std::string& token = args[i];
    if (token == "--") {
      ++i;
      break;
    }
    if (token == "--help") {
      print_usage(argv[0]);
      std::exit(0);
    }
    if (token == "--print-command") {
      cli->print_command = true;
      ++i;
      continue;
    }
    if (token == "--pass-plugin") {
      if ((i + 1) >= args.size()) {
        *error = "--pass-plugin requires a value";
        return false;
      }
      cli->mapping_options.pass_plugin = args[i + 1];
      i += 2;
      continue;
    }
    if (starts_with(token, "--pass-plugin=")) {
      cli->mapping_options.pass_plugin = token.substr(std::string("--pass-plugin=").size());
      ++i;
      continue;
    }
    if (token == "--compiler") {
      if ((i + 1) >= args.size()) {
        *error = "--compiler requires a value";
        return false;
      }
      cli->mapping_options.forced_compiler = args[i + 1];
      i += 2;
      continue;
    }
    if (starts_with(token, "--compiler=")) {
      cli->mapping_options.forced_compiler = token.substr(std::string("--compiler=").size());
      ++i;
      continue;
    }
    break;
  }

  if (!cli->mapping_options.pass_plugin) {
    cli->mapping_options.pass_plugin = eippf::wrapper::utils::get_env_non_empty("EIPPF_PASS_PLUGIN");
  }

  if (i >= args.size()) {
    *error = "compiler command is empty";
    return false;
  }

  cli->compiler_command.assign(args.begin() + static_cast<std::ptrdiff_t>(i), args.end());
  return true;
}

std::string quote_for_display(const std::string& arg) {
  if (arg.find_first_of(" \t\"") == std::string::npos) {
    return arg;
  }
  std::string escaped;
  escaped.reserve(arg.size() + 2);
  escaped.push_back('"');
  for (char ch : arg) {
    if (ch == '\\' || ch == '"') {
      escaped.push_back('\\');
    }
    escaped.push_back(ch);
  }
  escaped.push_back('"');
  return escaped;
}

void print_mapped_command(const eippf::wrapper::MappedCommand& mapped) {
  std::cout << quote_for_display(mapped.compiler);
  for (const auto& arg : mapped.arguments) {
    std::cout << ' ' << quote_for_display(arg);
  }
  std::cout << '\n';
}

int run_compiler_process(const eippf::wrapper::MappedCommand& mapped) {
#ifdef _WIN32
  std::vector<const char*> argv;
  argv.reserve(mapped.arguments.size() + 2);
  argv.push_back(mapped.compiler.c_str());
  for (const auto& arg : mapped.arguments) {
    argv.push_back(arg.c_str());
  }
  argv.push_back(nullptr);

  const intptr_t rc = _spawnvp(_P_WAIT, mapped.compiler.c_str(), argv.data());
  if (rc == -1) {
    std::cerr << "failed to execute compiler '" << mapped.compiler
              << "': " << std::strerror(errno) << '\n';
    return errno == 0 ? 1 : errno;
  }
  if (rc > static_cast<intptr_t>(std::numeric_limits<int>::max())) {
    return 1;
  }
  return static_cast<int>(rc);
#else
  std::vector<char*> argv;
  argv.reserve(mapped.arguments.size() + 2);
  argv.push_back(const_cast<char*>(mapped.compiler.c_str()));
  for (const auto& arg : mapped.arguments) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);

  const pid_t pid = fork();
  if (pid < 0) {
    std::cerr << "fork failed: " << std::strerror(errno) << '\n';
    return errno == 0 ? 1 : errno;
  }
  if (pid == 0) {
    execvp(mapped.compiler.c_str(), argv.data());
    std::cerr << "execvp failed for '" << mapped.compiler << "': " << std::strerror(errno)
              << '\n';
    _exit(127);
  }

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    std::cerr << "waitpid failed: " << std::strerror(errno) << '\n';
    return errno == 0 ? 1 : errno;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
#endif
}

}  // namespace

int main(int argc, char** argv) {
  WrapperCli cli{};
  std::string parse_error;
  if (!parse_wrapper_cli(argc, argv, &cli, &parse_error)) {
    std::cerr << "eippf_wrapper: " << parse_error << '\n';
    print_usage(argv[0]);
    return 2;
  }

  const std::string& compiler = cli.compiler_command.front();
  const std::vector<std::string> compiler_args(cli.compiler_command.begin() + 1,
                                               cli.compiler_command.end());

  const eippf::wrapper::MappedCommand mapped =
      eippf::wrapper::map_flags(compiler, compiler_args, cli.mapping_options);

  if (cli.print_command) {
    print_mapped_command(mapped);
    return 0;
  }

  return run_compiler_process(mapped);
}

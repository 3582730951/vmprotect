#include "script_guard/launcher.hpp"

#include <iostream>

namespace {

void print_usage(const char* argv0) {
  std::cerr << "Usage: " << argv0
            << " --input-bundle=<path> --manifest=<path> --key-provider=<path> --key-id=<id>"
               " [-- <script-args...>]\n";
}

}  // namespace

int main(int argc, char** argv) {
  eippf::script_guard::LauncherOptions options{};
  if (!eippf::script_guard::parse_launcher_options(argc, argv, options)) {
    print_usage(argv[0]);
    return 2;
  }

  eippf::script_guard::LauncherError error = eippf::script_guard::LauncherError::kOk;
  const int rc = eippf::script_guard::launch_bundle_via_pipe(options, error);
  if (error != eippf::script_guard::LauncherError::kOk) {
    std::cerr << "[script_launcher] " << eippf::script_guard::launcher_error_message(error) << '\n';
  }
  return rc;
}

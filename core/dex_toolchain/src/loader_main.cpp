#include "dex_toolchain/loader.hpp"

#include <iostream>

namespace {

void print_usage(const char* argv0) {
  const char* program = (argv0 != nullptr && argv0[0] != '\0') ? argv0 : "eippf_dex_loader";
  std::cerr << "Usage: " << program
            << " --input-bundle=<path> --manifest=<path> --key-provider=<path>"
            << " --key-id=<id> [--bridge-token=<hex>] [--report=<path>]\n";
}

}  // namespace

int main(int argc, char** argv) {
  eippf::dex_toolchain::LoaderOptions options{};
  eippf::dex_toolchain::LoaderError error = eippf::dex_toolchain::LoaderError::ok;

  if (!eippf::dex_toolchain::parse_loader_options(argc, argv, options, error)) {
    print_usage((argv != nullptr) ? argv[0] : nullptr);
    return 2;
  }

  return eippf::dex_toolchain::run_loader_session(options, error);
}

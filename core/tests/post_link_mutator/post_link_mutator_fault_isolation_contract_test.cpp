#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "post_link_mutator/mutator_app.hpp"

#ifndef EIPPF_POST_LINK_MUTATOR_MAIN_CPP
#error "EIPPF_POST_LINK_MUTATOR_MAIN_CPP must be defined"
#endif

namespace {

class ArgvBuilder final {
 public:
  explicit ArgvBuilder(std::vector<std::string> args) : args_(std::move(args)) {
    argv_.reserve(args_.size());
    for (std::string& arg : args_) {
      argv_.push_back(arg.data());
    }
  }

  [[nodiscard]] int argc() const { return static_cast<int>(argv_.size()); }

  [[nodiscard]] char** argv() { return argv_.data(); }

 private:
  std::vector<std::string> args_;
  std::vector<char*> argv_;
};

struct RunResult final {
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
};

struct FaultCase final {
  const char* name = "";
  eippf::post_link_mutator::TestFault fault = eippf::post_link_mutator::TestFault::kNone;
  int expected_exit_code = -1;
  const char* expected_stderr_token = "";
};

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path path = std::filesystem::temp_directory_path() /
                                     ("eippf_post_link_mutator_fault_contract_" +
                                      std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    return {};
  }
  return path;
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::string read_text_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] RunResult run_without_fault(const std::vector<std::string>& args) {
  ArgvBuilder argv(args);
  std::ostringstream out;
  std::ostringstream err;
  RunResult result{};
  result.exit_code = eippf::post_link_mutator::run_mutator(argv.argc(), argv.argv(), out, err);
  result.stdout_text = out.str();
  result.stderr_text = err.str();
  return result;
}

[[nodiscard]] RunResult run_with_fault(const std::vector<std::string>& args,
                                       eippf::post_link_mutator::TestFault fault) {
  ArgvBuilder argv(args);
  std::ostringstream out;
  std::ostringstream err;
  RunResult result{};
  result.exit_code = eippf::post_link_mutator::run_mutator_with_test_fault(
      argv.argc(), argv.argv(), out, err, fault);
  result.stdout_text = out.str();
  result.stderr_text = err.str();
  return result;
}

bool expect_main_route_contract() {
  const std::filesystem::path main_cpp_path = EIPPF_POST_LINK_MUTATOR_MAIN_CPP;
  if (!expect(std::filesystem::exists(main_cpp_path),
              "post_link_mutator main.cpp path must exist")) {
    return false;
  }

  const std::string main_cpp_text = read_text_file(main_cpp_path);
  if (!expect(!main_cpp_text.empty(), "post_link_mutator main.cpp must be readable")) {
    return false;
  }
  if (!expect(main_cpp_text.find("run_mutator(argc, argv, std::cout, std::cerr)") !=
                  std::string::npos,
              "main.cpp must call run_mutator(argc, argv, std::cout, std::cerr)")) {
    return false;
  }
  return expect(main_cpp_text.find("run_mutator_with_test_fault(") == std::string::npos,
                "main.cpp must not call run_mutator_with_test_fault");
}

}  // namespace

int main() {
  if (!expect_main_route_contract()) {
    return 1;
  }

  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::filesystem::path input_path = temp_dir / "input.elf";
  const std::vector<std::uint8_t> elf_bytes{
      0x7fu, static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('F'), 0x02u, 0x01u, 0x01u, 0x00u};
  if (!expect(write_bytes(input_path, elf_bytes), "failed to write input fixture")) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  const std::vector<FaultCase> fault_cases{
      {"force_read_input_failure",
       eippf::post_link_mutator::TestFault::kForceReadInputFailure,
       7,
       "Failed to read input artifact"},
      {"force_backend_unknown",
       eippf::post_link_mutator::TestFault::kForceBackendUnknown,
       8,
       "Unable to classify backend kind"},
      {"force_mutation_identity",
       eippf::post_link_mutator::TestFault::kForceMutationIdentity,
       9,
       "Mutation did not alter artifact output"},
  };

  for (const FaultCase& fault_case : fault_cases) {
    const std::filesystem::path output_path = temp_dir / (std::string(fault_case.name) + ".out.bin");
    const std::filesystem::path manifest_path =
        temp_dir / (std::string(fault_case.name) + ".manifest.json");

    const std::vector<std::string> args{
        "post_link_mutator_fault_contract",
        "--input",
        input_path.string(),
        "--output",
        output_path.string(),
        "--manifest",
        manifest_path.string(),
        "--target",
        "linux_kernel_module.ko",
        "--target-kind",
        "linux_kernel_module",
    };

    const RunResult fault_result = run_with_fault(args, fault_case.fault);
    if (!expect(fault_result.exit_code == fault_case.expected_exit_code,
                "fault case exit code mismatch")) {
      std::cerr << "[INFO] fault=" << fault_case.name << " code=" << fault_result.exit_code << '\n';
      std::filesystem::remove_all(temp_dir);
      return 1;
    }
    if (!expect(fault_result.stderr_text.find(fault_case.expected_stderr_token) != std::string::npos,
                "fault case stderr token mismatch")) {
      std::cerr << "[INFO] fault=" << fault_case.name << " stderr=" << fault_result.stderr_text
                << '\n';
      std::filesystem::remove_all(temp_dir);
      return 1;
    }
  }

  const std::filesystem::path normal_output_path = temp_dir / "normal.out.bin";
  const std::filesystem::path normal_manifest_path = temp_dir / "normal.manifest.json";
  const std::vector<std::string> normal_args{
      "post_link_mutator_fault_contract",
      "--input",
      input_path.string(),
      "--output",
      normal_output_path.string(),
      "--manifest",
      normal_manifest_path.string(),
      "--target",
      "linux_kernel_module.ko",
      "--target-kind",
      "linux_kernel_module",
  };
  const RunResult normal_result = run_without_fault(normal_args);
  if (!expect(normal_result.exit_code != 7 && normal_result.exit_code != 8 &&
                  normal_result.exit_code != 9,
              "non-fault path must not return fault-only exit codes")) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  std::filesystem::remove_all(temp_dir);
  return 0;
}

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "post_link_mutator/mutator_app.hpp"

namespace {

constexpr std::string_view kMutationTrailerMagic = "EIPPFMT1";

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
                                     ("eippf_post_link_mutator_exit_contract_" +
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

[[nodiscard]] std::vector<std::uint8_t> read_binary(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>());
}

[[nodiscard]] bool contains_trailer_magic_and_version(const std::vector<std::uint8_t>& bytes) {
  const auto magic_begin = std::search(bytes.begin(),
                                       bytes.end(),
                                       kMutationTrailerMagic.begin(),
                                       kMutationTrailerMagic.end());
  if (magic_begin == bytes.end()) {
    return false;
  }
  const auto version_it =
      magic_begin + static_cast<std::ptrdiff_t>(kMutationTrailerMagic.size());
  return version_it != bytes.end() && *version_it == 1u;
}

void cleanup_temp_dir(const std::filesystem::path& temp_dir) {
  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
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

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::filesystem::path input_path = temp_dir / "input.elf";
  const std::filesystem::path success_output = temp_dir / "success.out";
  const std::filesystem::path success_manifest = temp_dir / "success.manifest.json";
  const std::filesystem::path identity_output = temp_dir / "identity.out";
  const std::filesystem::path identity_manifest = temp_dir / "identity.manifest.json";

  const std::vector<std::uint8_t> elf_bytes{
      0x7fu, static_cast<std::uint8_t>('E'), static_cast<std::uint8_t>('L'),
      static_cast<std::uint8_t>('F'), 0x02u, 0x01u, 0x01u, 0x00u};

  if (!expect(write_bytes(input_path, elf_bytes), "failed to write input fixture")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::vector<std::string> success_args{
      "post_link_mutator_exit_contract",
      "--input",
      input_path.string(),
      "--output",
      success_output.string(),
      "--manifest",
      success_manifest.string(),
      "--target",
      "linux_kernel_module.ko",
      "--target-kind",
      "linux_kernel_module",
  };

  const RunResult success = run_without_fault(success_args);
  if (!expect(success.exit_code == 0, "success path should return exit code 0")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::vector<std::uint8_t> success_bytes = read_binary(success_output);
  if (!expect(success_bytes.size() > elf_bytes.size(), "success path should append trailer bytes")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }
  if (!expect(contains_trailer_magic_and_version(success_bytes),
              "success path output must contain trailer magic/version")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  const std::vector<std::string> identity_args{
      "post_link_mutator_exit_contract",
      "--input",
      input_path.string(),
      "--output",
      identity_output.string(),
      "--manifest",
      identity_manifest.string(),
      "--target",
      "linux_kernel_module.ko",
      "--target-kind",
      "linux_kernel_module",
  };

  const RunResult identity = run_with_fault(
      identity_args, eippf::post_link_mutator::TestFault::kForceMutationIdentity);
  if (!expect(identity.exit_code == 9,
              "forced mutation identity fault must return existing failure code 9")) {
    cleanup_temp_dir(temp_dir);
    return 1;
  }

  if (std::filesystem::exists(identity_output)) {
    const std::vector<std::uint8_t> identity_bytes = read_binary(identity_output);
    if (!expect(!contains_trailer_magic_and_version(identity_bytes),
                "forced mutation identity fault output must not contain trailer")) {
      cleanup_temp_dir(temp_dir);
      return 1;
    }
  }

  cleanup_temp_dir(temp_dir);
  return 0;
}

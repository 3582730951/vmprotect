#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

#ifndef EIPPF_CLANG_PATH
#error "EIPPF_CLANG_PATH must be defined"
#endif

#ifndef EIPPF_JIT_ENCLAVE_PLUGIN_PATH
#error "EIPPF_JIT_ENCLAVE_PLUGIN_PATH must be defined"
#endif

namespace {

constexpr std::string_view kGateCode = "jit_route_forbidden_for_target";
constexpr std::string_view kGateErrorLinePrefix = "error: jit_route_forbidden_for_target:";

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

[[nodiscard]] std::string quote_arg(const std::string& value) {
  std::string out = "\"";
  out.reserve(value.size() + 2u);
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

[[nodiscard]] int normalize_status(int status) {
#if defined(__unix__) || defined(__APPLE__)
  if (status == -1) {
    return -1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return status;
#else
  return status;
#endif
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_jit_gate_test_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

bool write_text(const std::filesystem::path& path, std::string_view text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

[[nodiscard]] std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

[[nodiscard]] std::string_view first_non_empty_line(std::string_view text) {
  std::size_t line_begin = 0;
  while (line_begin < text.size()) {
    const std::size_t line_end = text.find('\n', line_begin);
    std::string_view line =
        (line_end == std::string_view::npos) ? text.substr(line_begin) : text.substr(line_begin, line_end - line_begin);
    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1);
    }
    if (!line.empty()) {
      return line;
    }
    if (line_end == std::string_view::npos) {
      break;
    }
    line_begin = line_end + 1;
  }
  return {};
}

struct CompileResult final {
  int status = -1;
  std::string stderr_text;
};

CompileResult run_compile(const std::filesystem::path& clang_path,
                          const std::filesystem::path& plugin_path,
                          const std::filesystem::path& source_path,
                          const std::filesystem::path& object_path,
                          const char* target_kind) {
  const std::filesystem::path stdout_path = object_path.string() + ".stdout.log";
  const std::filesystem::path stderr_path = object_path.string() + ".stderr.log";

  std::string command = quote_arg(clang_path.string()) +
                        " -std=c++20 -O2 -Xclang -load -Xclang " +
                        quote_arg(plugin_path.string()) + " -fpass-plugin=" +
                        quote_arg(plugin_path.string()) +
                        " -c " + quote_arg(source_path.string()) + " -o " +
                        quote_arg(object_path.string());
  if (target_kind != nullptr) {
    command += " -mllvm -eippf-target-kind=";
    command += target_kind;
  }
  command += " >";
  command += quote_arg(stdout_path.string());
  command += " 2>";
  command += quote_arg(stderr_path.string());

  CompileResult result{};
  result.status = normalize_status(std::system(command.c_str()));
  result.stderr_text = read_text(stderr_path);
  return result;
}

bool expect_compile_success(const CompileResult& result, const char* message) {
  return expect(result.status == 0, message);
}

bool expect_compile_gate_failure(const CompileResult& result, const char* message) {
  if (!expect(result.status != 0, message)) {
    return false;
  }
  if (!expect(result.stderr_text.find(kGateCode) != std::string::npos,
              "expected stderr to contain jit_route_forbidden_for_target")) {
    return false;
  }
  const std::string_view first_line = first_non_empty_line(result.stderr_text);
  return expect(first_line.rfind(kGateErrorLinePrefix, 0) == 0,
                "expected first non-empty stderr line to start with error: jit_route_forbidden_for_target:");
}

}  // namespace

int main() {
  const std::filesystem::path clang_path = EIPPF_CLANG_PATH;
  const std::filesystem::path plugin_path = EIPPF_JIT_ENCLAVE_PLUGIN_PATH;
  if (!expect(!clang_path.empty(), "clang path must be non-empty")) {
    return 1;
  }
  if (!expect(!plugin_path.empty(), "plugin path must be non-empty")) {
    return 1;
  }
  if (!expect(std::filesystem::exists(clang_path), "clang path must exist")) {
    return 1;
  }
  if (!expect(std::filesystem::exists(plugin_path), "plugin path must exist")) {
    return 1;
  }

  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  bool ok = true;
  const std::filesystem::path jit_source = temp_dir / "jit_route.cpp";
  const std::filesystem::path non_jit_source = temp_dir / "non_jit_route.cpp";

  ok = write_text(jit_source,
                  "__attribute__((used,noinline,annotate(\"drm_jit_target\"))) int f(){ return 7; }\n") &&
       ok;
  ok = write_text(non_jit_source, "__attribute__((used,noinline)) int g(){ return 9; }\n") && ok;
  if (!expect(ok, "failed to write source fixtures")) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  const auto run_jit = [&](std::string_view name, const char* target_kind) {
    return run_compile(clang_path, plugin_path, jit_source, temp_dir / (std::string(name) + ".o"),
                       target_kind);
  };

  const auto run_non_jit = [&](std::string_view name, const char* target_kind) {
    return run_compile(clang_path, plugin_path, non_jit_source,
                       temp_dir / (std::string(name) + ".o"), target_kind);
  };

  ok = expect_compile_success(run_jit("desktop_jit", "desktop_native"),
                              "desktop_native + jit route should compile") &&
       ok;

  constexpr std::array<const char*, 8> kForbiddenKinds = {
      "android_so", "ios_appstore", "windows_driver", "linux_kernel_module",
      "android_kernel_module", "android_dex", "shell_ephemeral", "unknown",
  };
  for (const char* kind : kForbiddenKinds) {
    ok = expect_compile_gate_failure(run_jit(std::string("forbidden_jit_") + kind, kind),
                                     "forbidden target + jit route should fail with gate code") &&
         ok;
  }

  ok = expect_compile_gate_failure(run_jit("missing_target_kind_jit", nullptr),
                                   "missing target-kind + jit route should fail with gate code") &&
       ok;

  ok = expect_compile_success(run_non_jit("android_dex_non_jit", "android_dex"),
                              "android_dex + non-jit route should compile") &&
       ok;
  ok = expect_compile_success(run_non_jit("desktop_non_jit", "desktop_native"),
                              "desktop_native + non-jit route should compile") &&
       ok;

  std::filesystem::remove_all(temp_dir);
  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] jit_enclave_pipeline_gate_test\n";
  return 0;
}

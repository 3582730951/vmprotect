#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef EIPPF_PROXY_PATH
#define EIPPF_PROXY_PATH ""
#endif

#ifndef EIPPF_WEAVER_PATH
#define EIPPF_WEAVER_PATH ""
#endif

#ifndef EIPPF_VM_RT_PATH
#define EIPPF_VM_RT_PATH ""
#endif

namespace {

int normalize_status(int raw_status) {
  if (raw_status == -1) {
    return -1;
  }
#if defined(_WIN32)
  return raw_status;
#else
  if (WIFEXITED(raw_status)) {
    return WEXITSTATUS(raw_status);
  }
  if (WIFSIGNALED(raw_status)) {
    return 128 + WTERMSIG(raw_status);
  }
  return raw_status;
#endif
}

bool command_exists(const char* command) {
  if (command == nullptr || command[0] == '\0') {
    return false;
  }
#if defined(_WIN32)
  std::string probe = "where ";
  probe += command;
  probe += " >NUL 2>NUL";
#else
  std::string probe = "command -v ";
  probe += command;
  probe += " >/dev/null 2>&1";
#endif
  return normalize_status(std::system(probe.c_str())) == 0;
}

std::string shell_quote(const std::string& value) {
  std::string result;
  result.reserve(value.size() + 2u);
  result.push_back('\'');
  for (char ch : value) {
    if (ch == '\'') {
      result.append("'\\''");
    } else {
      result.push_back(ch);
    }
  }
  result.push_back('\'');
  return result;
}

bool write_text_file(const std::filesystem::path& path, const std::string& text) {
  std::ofstream out(path, std::ios::binary);
  if (!out.is_open()) {
    return false;
  }
  out << text;
  return out.good();
}

std::string create_temp_dir() {
#if defined(_WIN32)
  char* temp = std::getenv("TEMP");
  if (temp == nullptr) {
    return {};
  }
  std::filesystem::path dir = std::filesystem::path(temp) / "eippf_rust_vm_cov";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return {};
  }
  return dir.string();
#else
  char tmpl[] = "/tmp/eippf_rust_vm_cov_XXXXXX";
  char* created = ::mkdtemp(tmpl);
  if (created == nullptr) {
    return {};
  }
  return std::string(created);
#endif
}

bool file_contains_exact(const std::filesystem::path& path, const std::string& expected) {
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return content == expected;
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return {};
  }
  return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

int main() {
  const std::string proxy_path = EIPPF_PROXY_PATH;
  const std::string weaver_path = EIPPF_WEAVER_PATH;
  const std::string vm_rt_path = EIPPF_VM_RT_PATH;

  if (proxy_path.empty() || weaver_path.empty() || vm_rt_path.empty()) {
    std::cout << "[SKIP] runtime_rust_vm_full_coverage_test: test paths are not configured\n";
    return 0;
  }
  if (!std::filesystem::exists(proxy_path) || !std::filesystem::exists(weaver_path) ||
      !std::filesystem::exists(vm_rt_path)) {
    std::cout << "[SKIP] runtime_rust_vm_full_coverage_test: required files are missing\n";
    return 0;
  }
  if (!command_exists("rustc") || !command_exists("clang") || !command_exists("python3")) {
    std::cout << "[SKIP] runtime_rust_vm_full_coverage_test: rustc/clang/python3 missing\n";
    return 0;
  }

  const std::string temp = create_temp_dir();
  if (temp.empty()) {
    std::cerr << "[FAIL] unable to create temp directory\n";
    return 1;
  }

  const std::filesystem::path temp_dir(temp);
  const std::filesystem::path rust_src = temp_dir / "demo.rs";
  const std::filesystem::path c_src = temp_dir / "driver.c";
  const std::filesystem::path rust_obj = temp_dir / "demo.weaved.o";
  const std::filesystem::path exe_path = temp_dir / "driver";
  const std::filesystem::path run_out = temp_dir / "run.out";
  const std::filesystem::path compile_log = temp_dir / "compile.log";
  const std::filesystem::path link_log = temp_dir / "link.log";

  const std::string rust_code = R"(#![no_std]

#[no_mangle]
pub extern "C" fn add_rule(x: i64, y: i64) -> i64 {
    let mut z = x + y;
    if (z & 1) == 0 { z += 3; } else { z -= 2; }
    z
}

#[no_mangle]
pub extern "C" fn mul_rule(x: i64) -> i64 {
    add_rule(x, x + 1) * 2
}
)";
  const std::string c_code = R"(#include <stdio.h>

long add_rule(long x, long y);
long mul_rule(long x);

int main(void) {
  printf("%ld %ld\n", add_rule(9, 3), mul_rule(5));
  return 0;
}
)";

  if (!write_text_file(rust_src, rust_code) || !write_text_file(c_src, c_code)) {
    std::cerr << "[FAIL] unable to write temporary source files\n";
    return 1;
  }

  const std::string compile_cmd =
      "python3 " + shell_quote(proxy_path) + " --ir-weaver-bin " + shell_quote(weaver_path) +
      " --vm-runtime-lib " + shell_quote(vm_rt_path) + " rustc " + shell_quote(rust_src.string()) +
      " --crate-name eippf_rust_demo --crate-type lib --emit=obj -C panic=abort -C opt-level=2 -o " +
      shell_quote(rust_obj.string()) + " >" + shell_quote(compile_log.string()) + " 2>&1";
  if (normalize_status(std::system(compile_cmd.c_str())) != 0) {
    const std::string log_text = read_file(compile_log);
    if (log_text.find("Opaque pointers are only supported in -opaque-pointers mode") !=
            std::string::npos ||
        log_text.find("Producer: 'LLVM") != std::string::npos) {
      std::cout << "[SKIP] runtime_rust_vm_full_coverage_test: Rust/LLVM bitcode version mismatch\n";
      return 0;
    }
    std::cerr << "[FAIL] Rust proxy compile failed\n";
    if (!log_text.empty()) {
      std::cerr << log_text;
    }
    return 1;
  }

  const std::string link_cmd = "clang -O2 " + shell_quote(c_src.string()) + " " +
                               shell_quote(rust_obj.string()) + " " + shell_quote(vm_rt_path) +
                               " -lstdc++ -ldl -pthread -lm -o " + shell_quote(exe_path.string()) +
                               " >" + shell_quote(link_log.string()) + " 2>&1";
  if (normalize_status(std::system(link_cmd.c_str())) != 0) {
    std::cerr << "[FAIL] C/Rust link failed\n";
    std::ifstream log(link_log);
    if (log.is_open()) {
      std::cerr << log.rdbuf();
    }
    return 1;
  }

  const std::string run_cmd =
      shell_quote(exe_path.string()) + " >" + shell_quote(run_out.string()) + " 2>&1";
  if (normalize_status(std::system(run_cmd.c_str())) != 0) {
    std::cerr << "[FAIL] executable returned non-zero\n";
    return 1;
  }
  if (!file_contains_exact(run_out, "15 18\n")) {
    std::cerr << "[FAIL] unexpected output from integrated Rust VM test\n";
    std::ifstream out(run_out);
    if (out.is_open()) {
      std::cerr << out.rdbuf();
    }
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  std::cout << "[PASS] runtime_rust_vm_full_coverage_test\n";
  return 0;
}

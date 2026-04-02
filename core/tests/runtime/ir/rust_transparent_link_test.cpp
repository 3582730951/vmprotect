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
  std::filesystem::path dir = std::filesystem::path(temp) / "eippf_rust_transparent_link";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return {};
  }
  return dir.string();
#else
  char tmpl[] = "/tmp/eippf_rust_link_XXXXXX";
  char* created = ::mkdtemp(tmpl);
  if (created == nullptr) {
    return {};
  }
  return std::string(created);
#endif
}

bool read_all(const std::filesystem::path& path, std::string& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in.is_open()) {
    return false;
  }
  out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return true;
}

bool run_and_expect_exact(const std::string& command,
                          const std::filesystem::path& out_file,
                          const std::string& expected,
                          std::string& out_got) {
  if (normalize_status(std::system(command.c_str())) != 0) {
    return false;
  }
  if (!read_all(out_file, out_got)) {
    return false;
  }
  return out_got == expected;
}

}  // namespace

int main() {
  const std::string proxy_path = EIPPF_PROXY_PATH;
  const std::string weaver_path = EIPPF_WEAVER_PATH;
  const std::string vm_rt_path = EIPPF_VM_RT_PATH;

  if (proxy_path.empty() || weaver_path.empty() || vm_rt_path.empty()) {
    std::cout << "[SKIP] runtime_rust_transparent_link_test: test paths are not configured\n";
    return 0;
  }
  if (!std::filesystem::exists(proxy_path) || !std::filesystem::exists(weaver_path) ||
      !std::filesystem::exists(vm_rt_path)) {
    std::cout << "[SKIP] runtime_rust_transparent_link_test: required files are missing\n";
    return 0;
  }
  if (!command_exists("python3") || !command_exists("rustc") || !command_exists("cargo")) {
    std::cout << "[SKIP] runtime_rust_transparent_link_test: python3/rustc/cargo missing\n";
    return 0;
  }

  const std::string temp = create_temp_dir();
  if (temp.empty()) {
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  const std::filesystem::path temp_dir(temp);
  const std::filesystem::path rust_main = temp_dir / "rustc_main.rs";
  const std::filesystem::path rust_exe = temp_dir / "rustc_main";
  const std::filesystem::path rust_out = temp_dir / "rustc_main.out";

  const std::string rust_main_code = R"(fn protected_calc(x:i64)->i64 {
    let y = x * 3 + 1;
    if (y & 1) == 0 { y + 5 } else { y - 2 }
}
fn main() { println!("{}", protected_calc(10)); }
)";
  if (!write_text_file(rust_main, rust_main_code)) {
    std::cerr << "[FAIL] cannot write rustc_main.rs\n";
    return 1;
  }

  const std::string rustc_cmd =
      "python3 " + shell_quote(proxy_path) + " --ir-weaver-bin " + shell_quote(weaver_path) +
      " --vm-runtime-lib " + shell_quote(vm_rt_path) + " rustc " + shell_quote(rust_main.string()) +
      " --crate-name rustc_main -C panic=abort -C opt-level=2 -o " + shell_quote(rust_exe.string());
  if (normalize_status(std::system(rustc_cmd.c_str())) != 0) {
    std::cerr << "[FAIL] rustc transparent link command failed\n";
    return 1;
  }

  const std::string rustc_run_cmd =
      shell_quote(rust_exe.string()) + " >" + shell_quote(rust_out.string()) + " 2>&1";
  std::string rustc_got;
  if (!run_and_expect_exact(rustc_run_cmd, rust_out, "29\n", rustc_got)) {
    std::cerr << "[FAIL] rustc transparent link output mismatch\n";
    std::cerr << "[INFO] got: " << rustc_got;
    return 1;
  }

  const std::filesystem::path cargo_dir = temp_dir / "cargo_demo";
  const std::filesystem::path cargo_src = cargo_dir / "src";
  std::error_code ec;
  std::filesystem::create_directories(cargo_src, ec);
  if (ec) {
    std::cerr << "[FAIL] cannot create cargo project tree\n";
    return 1;
  }
  if (!write_text_file(cargo_dir / "Cargo.toml",
                       "[package]\nname = \"cargo_demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")) {
    std::cerr << "[FAIL] cannot write Cargo.toml\n";
    return 1;
  }
  const std::string cargo_main_code = R"(fn protected_calc(x:i64)->i64 {
    let y = x * 2 + 7;
    if y > 20 { y - 4 } else { y + 3 }
}
fn main() { println!("{}", protected_calc(10)); }
)";
  if (!write_text_file(cargo_src / "main.rs", cargo_main_code)) {
    std::cerr << "[FAIL] cannot write cargo src/main.rs\n";
    return 1;
  }

  const std::string cargo_build_cmd =
      "cd " + shell_quote(cargo_dir.string()) +
      " && RUSTC_WRAPPER=" + shell_quote(proxy_path) + " EIPPF_IR_WEAVER_BIN=" + shell_quote(weaver_path) +
      " EIPPF_VM_RUNTIME_LIB=" + shell_quote(vm_rt_path) + " cargo build -q";
  if (normalize_status(std::system(cargo_build_cmd.c_str())) != 0) {
    std::cerr << "[FAIL] cargo transparent build failed\n";
    return 1;
  }

  const std::filesystem::path cargo_exe = cargo_dir / "target" / "debug" / "cargo_demo";
  const std::filesystem::path cargo_out = temp_dir / "cargo_demo.out";
  const std::string cargo_run_cmd =
      shell_quote(cargo_exe.string()) + " >" + shell_quote(cargo_out.string()) + " 2>&1";
  std::string cargo_got;
  if (!run_and_expect_exact(cargo_run_cmd, cargo_out, "23\n", cargo_got)) {
    std::cerr << "[FAIL] cargo transparent run output mismatch\n";
    std::cerr << "[INFO] got: " << cargo_got;
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  std::cout << "[PASS] runtime_rust_transparent_link_test\n";
  return 0;
}

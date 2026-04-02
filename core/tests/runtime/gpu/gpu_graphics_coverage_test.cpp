#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

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

bool has_clang() {
#if defined(_WIN32)
  const int status = std::system("where clang >NUL 2>NUL");
#else
  const int status = std::system("command -v clang >/dev/null 2>&1");
#endif
  return normalize_status(status) == 0;
}

std::string create_temp_dir() {
#if defined(_WIN32)
  char* temp = std::getenv("TEMP");
  if (temp == nullptr) {
    return {};
  }
  std::filesystem::path base(temp);
  std::filesystem::path dir = base / "eippf_gpu_cov";
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    return {};
  }
  return dir.string();
#else
  char dir_template[] = "/tmp/eippf_gpu_cov_XXXXXX";
  char* created = ::mkdtemp(dir_template);
  if (created == nullptr) {
    return {};
  }
  return std::string(created);
#endif
}

bool write_text_file(const std::filesystem::path& path, const std::string& text) {
  std::ofstream output(path, std::ios::binary);
  if (!output.is_open()) {
    return false;
  }
  output << text;
  return output.good();
}

int compile_opencl_to_llvm(const std::filesystem::path& src,
                           const std::filesystem::path& out_ll,
                           const std::filesystem::path& log_file) {
  const std::string command =
      "clang -x cl -cl-std=CL2.0 -target spir64 -emit-llvm -S " +
      shell_quote(src.string()) + " -o " + shell_quote(out_ll.string()) + " >" +
      shell_quote(log_file.string()) + " 2>&1";
  return normalize_status(std::system(command.c_str()));
}

bool file_contains(const std::filesystem::path& path, const std::string& pattern) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  return content.find(pattern) != std::string::npos;
}

bool test_success_path(const std::filesystem::path& temp_dir) {
  const std::filesystem::path source = temp_dir / "kernel_ok.cl";
  const std::filesystem::path output = temp_dir / "kernel_ok.ll";
  const std::filesystem::path log = temp_dir / "kernel_ok.log";
  const std::string kernel = R"(
__kernel void saxpy(__global const float* a,
                    __global const float* b,
                    __global float* c,
                    float alpha) {
  int gid = get_global_id(0);
  c[gid] = alpha * a[gid] + b[gid];
}
)";
  if (!expect(write_text_file(source, kernel), "write kernel_ok.cl failed")) {
    return false;
  }

  const int rc = compile_opencl_to_llvm(source, output, log);
  if (!expect(rc == 0, "OpenCL success-path compile should pass")) {
    return false;
  }
  if (!expect(std::filesystem::exists(output), "kernel_ok.ll should exist")) {
    return false;
  }
  if (!expect(file_contains(output, "spir_kernel"), "kernel_ok.ll should contain spir_kernel")) {
    return false;
  }
  return expect(file_contains(output, "saxpy"), "kernel_ok.ll should contain kernel symbol");
}

bool test_failure_path(const std::filesystem::path& temp_dir) {
  const std::filesystem::path source = temp_dir / "kernel_bad.cl";
  const std::filesystem::path output = temp_dir / "kernel_bad.ll";
  const std::filesystem::path log = temp_dir / "kernel_bad.log";
  const std::string broken_kernel = R"(
__kernel void broken(__global float* out) {
  int gid = get_global_id(0)
  out[gid] = 1.0f;
}
)";
  if (!expect(write_text_file(source, broken_kernel), "write kernel_bad.cl failed")) {
    return false;
  }

  const int rc = compile_opencl_to_llvm(source, output, log);
  if (!expect(rc != 0, "OpenCL failure-path compile should fail")) {
    return false;
  }
  return expect(!std::filesystem::exists(output), "kernel_bad.ll should not exist");
}

bool test_edge_security_path(const std::filesystem::path& temp_dir) {
  const std::filesystem::path source = temp_dir / "kernel_edge.cl";
  const std::filesystem::path output = temp_dir / "kernel_edge.ll";
  const std::filesystem::path log = temp_dir / "kernel_edge.log";
  const std::string edge_kernel = R"(
__kernel void tiled_mix(__global const float4* in,
                        __global float4* out,
                        __local float4* tile) {
  const int lid = get_local_id(0);
  const int gid = get_global_id(0);
  const int lsz = get_local_size(0);
  tile[lid] = in[gid];
  barrier(CLK_LOCAL_MEM_FENCE);
  const int next = (lid + 1) % (lsz == 0 ? 1 : lsz);
  out[gid] = tile[next];
}
)";
  if (!expect(write_text_file(source, edge_kernel), "write kernel_edge.cl failed")) {
    return false;
  }

  const int rc = compile_opencl_to_llvm(source, output, log);
  if (!expect(rc == 0, "OpenCL edge-path compile should pass")) {
    return false;
  }
  if (!expect(file_contains(output, "barrier"), "edge kernel should contain barrier call")) {
    return false;
  }
  return expect(file_contains(output, "tiled_mix"), "edge kernel symbol should exist");
}

}  // namespace

int main() {
  if (!has_clang()) {
    std::cout << "[SKIP] gpu_graphics_coverage_test: clang not found\n";
    return 0;
  }

  const std::string temp = create_temp_dir();
  if (temp.empty()) {
    std::cerr << "[FAIL] failed to create temp dir for GPU coverage test\n";
    return 1;
  }

  const std::filesystem::path temp_dir(temp);
  bool ok = true;
  ok = test_success_path(temp_dir) && ok;
  ok = test_failure_path(temp_dir) && ok;
  ok = test_edge_security_path(temp_dir) && ok;

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] gpu_graphics_coverage_test\n";
  return 0;
}

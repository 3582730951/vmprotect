#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

using cl_int = std::int32_t;
using cl_uint = std::uint32_t;
using cl_ulong = std::uint64_t;
using cl_bool = cl_uint;
using cl_bitfield = cl_ulong;
using cl_device_type = cl_bitfield;
using cl_mem_flags = cl_bitfield;
using cl_context_properties = std::intptr_t;
using cl_command_queue_properties = cl_bitfield;
using cl_queue_properties = std::intptr_t;
using cl_program_build_info = cl_uint;

struct _cl_platform_id;
struct _cl_device_id;
struct _cl_context;
struct _cl_command_queue;
struct _cl_mem;
struct _cl_program;
struct _cl_kernel;
struct _cl_event;

using cl_platform_id = _cl_platform_id*;
using cl_device_id = _cl_device_id*;
using cl_context = _cl_context*;
using cl_command_queue = _cl_command_queue*;
using cl_mem = _cl_mem*;
using cl_program = _cl_program*;
using cl_kernel = _cl_kernel*;
using cl_event = _cl_event*;

constexpr cl_int kClSuccess = 0;
constexpr cl_int kClInvalidArgIndex = -49;
constexpr cl_device_type kClDeviceTypeGpu = (1ull << 2);
constexpr cl_device_type kClDeviceTypeCpu = (1ull << 1);
constexpr cl_device_type kClDeviceTypeAll = 0xFFFFFFFFull;
constexpr cl_mem_flags kClMemReadOnly = (1ull << 2);
constexpr cl_mem_flags kClMemWriteOnly = (1ull << 1);
constexpr cl_mem_flags kClMemCopyHostPtr = (1ull << 5);
constexpr cl_bool kClTrue = 1u;
constexpr cl_program_build_info kClProgramBuildLog = 0x1183u;

class DynLib final {
 public:
  ~DynLib() { close(); }

  bool open() {
    close();
#if defined(_WIN32)
    static constexpr const char* kCandidates[] = {"OpenCL.dll"};
    for (const char* candidate : kCandidates) {
      handle_ = ::LoadLibraryA(candidate);
      if (handle_ != nullptr) {
        return true;
      }
    }
#else
    static constexpr const char* kCandidates[] = {"libOpenCL.so.1", "libOpenCL.so"};
    for (const char* candidate : kCandidates) {
      handle_ = ::dlopen(candidate, RTLD_NOW | RTLD_LOCAL);
      if (handle_ != nullptr) {
        return true;
      }
    }
#endif
    return false;
  }

  void close() {
#if defined(_WIN32)
    if (handle_ != nullptr) {
      ::FreeLibrary(static_cast<HMODULE>(handle_));
      handle_ = nullptr;
    }
#else
    if (handle_ != nullptr) {
      ::dlclose(handle_);
      handle_ = nullptr;
    }
#endif
  }

  template <typename Fn>
  Fn load(const char* name) const {
    if (handle_ == nullptr) {
      return nullptr;
    }
#if defined(_WIN32)
    return reinterpret_cast<Fn>(::GetProcAddress(static_cast<HMODULE>(handle_), name));
#else
    return reinterpret_cast<Fn>(::dlsym(handle_, name));
#endif
  }

  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }

 private:
  void* handle_ = nullptr;
};

struct OpenClApi final {
  cl_int (*get_platform_ids)(cl_uint, cl_platform_id*, cl_uint*) = nullptr;
  cl_int (*get_device_ids)(cl_platform_id, cl_device_type, cl_uint, cl_device_id*, cl_uint*) = nullptr;
  cl_context (*create_context)(const cl_context_properties*,
                               cl_uint,
                               const cl_device_id*,
                               void (*)(const char*, const void*, std::size_t, void*),
                               void*,
                               cl_int*) = nullptr;
  cl_command_queue (*create_command_queue)(cl_context, cl_device_id, cl_command_queue_properties, cl_int*) = nullptr;
  cl_command_queue (*create_command_queue_with_properties)(cl_context,
                                                           cl_device_id,
                                                           const cl_queue_properties*,
                                                           cl_int*) = nullptr;
  cl_program (*create_program_with_source)(cl_context, cl_uint, const char**, const std::size_t*, cl_int*) = nullptr;
  cl_int (*build_program)(cl_program, cl_uint, const cl_device_id*, const char*, void (*)(cl_program, void*), void*) =
      nullptr;
  cl_int (*get_program_build_info)(cl_program, cl_device_id, cl_program_build_info, std::size_t, void*, std::size_t*) =
      nullptr;
  cl_kernel (*create_kernel)(cl_program, const char*, cl_int*) = nullptr;
  cl_mem (*create_buffer)(cl_context, cl_mem_flags, std::size_t, void*, cl_int*) = nullptr;
  cl_int (*set_kernel_arg)(cl_kernel, cl_uint, std::size_t, const void*) = nullptr;
  cl_int (*enqueue_ndrange_kernel)(cl_command_queue,
                                   cl_kernel,
                                   cl_uint,
                                   const std::size_t*,
                                   const std::size_t*,
                                   const std::size_t*,
                                   cl_uint,
                                   const cl_event*,
                                   cl_event*) = nullptr;
  cl_int (*enqueue_read_buffer)(cl_command_queue,
                                cl_mem,
                                cl_bool,
                                std::size_t,
                                std::size_t,
                                void*,
                                cl_uint,
                                const cl_event*,
                                cl_event*) = nullptr;
  cl_int (*finish)(cl_command_queue) = nullptr;
  cl_int (*release_mem_object)(cl_mem) = nullptr;
  cl_int (*release_kernel)(cl_kernel) = nullptr;
  cl_int (*release_program)(cl_program) = nullptr;
  cl_int (*release_command_queue)(cl_command_queue) = nullptr;
  cl_int (*release_context)(cl_context) = nullptr;
};

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool load_opencl_api(const DynLib& lib, OpenClApi& api) {
  api.get_platform_ids = lib.load<decltype(api.get_platform_ids)>("clGetPlatformIDs");
  api.get_device_ids = lib.load<decltype(api.get_device_ids)>("clGetDeviceIDs");
  api.create_context = lib.load<decltype(api.create_context)>("clCreateContext");
  api.create_command_queue = lib.load<decltype(api.create_command_queue)>("clCreateCommandQueue");
  api.create_command_queue_with_properties =
      lib.load<decltype(api.create_command_queue_with_properties)>("clCreateCommandQueueWithProperties");
  api.create_program_with_source = lib.load<decltype(api.create_program_with_source)>("clCreateProgramWithSource");
  api.build_program = lib.load<decltype(api.build_program)>("clBuildProgram");
  api.get_program_build_info = lib.load<decltype(api.get_program_build_info)>("clGetProgramBuildInfo");
  api.create_kernel = lib.load<decltype(api.create_kernel)>("clCreateKernel");
  api.create_buffer = lib.load<decltype(api.create_buffer)>("clCreateBuffer");
  api.set_kernel_arg = lib.load<decltype(api.set_kernel_arg)>("clSetKernelArg");
  api.enqueue_ndrange_kernel = lib.load<decltype(api.enqueue_ndrange_kernel)>("clEnqueueNDRangeKernel");
  api.enqueue_read_buffer = lib.load<decltype(api.enqueue_read_buffer)>("clEnqueueReadBuffer");
  api.finish = lib.load<decltype(api.finish)>("clFinish");
  api.release_mem_object = lib.load<decltype(api.release_mem_object)>("clReleaseMemObject");
  api.release_kernel = lib.load<decltype(api.release_kernel)>("clReleaseKernel");
  api.release_program = lib.load<decltype(api.release_program)>("clReleaseProgram");
  api.release_command_queue = lib.load<decltype(api.release_command_queue)>("clReleaseCommandQueue");
  api.release_context = lib.load<decltype(api.release_context)>("clReleaseContext");

  if (api.get_platform_ids == nullptr || api.get_device_ids == nullptr || api.create_context == nullptr ||
      api.create_program_with_source == nullptr || api.build_program == nullptr || api.create_kernel == nullptr ||
      api.create_buffer == nullptr || api.set_kernel_arg == nullptr || api.enqueue_ndrange_kernel == nullptr ||
      api.enqueue_read_buffer == nullptr || api.finish == nullptr || api.release_mem_object == nullptr ||
      api.release_kernel == nullptr || api.release_program == nullptr || api.release_context == nullptr) {
    return false;
  }
  return api.create_command_queue_with_properties != nullptr || api.create_command_queue != nullptr;
}

cl_device_id pick_device(const OpenClApi& api, cl_platform_id platform) {
  cl_uint count = 0;
  if (api.get_device_ids(platform, kClDeviceTypeGpu, 0, nullptr, &count) == kClSuccess && count > 0) {
    std::vector<cl_device_id> devices(count);
    if (api.get_device_ids(platform, kClDeviceTypeGpu, count, devices.data(), nullptr) == kClSuccess) {
      return devices[0];
    }
  }
  if (api.get_device_ids(platform, kClDeviceTypeCpu, 0, nullptr, &count) == kClSuccess && count > 0) {
    std::vector<cl_device_id> devices(count);
    if (api.get_device_ids(platform, kClDeviceTypeCpu, count, devices.data(), nullptr) == kClSuccess) {
      return devices[0];
    }
  }
  if (api.get_device_ids(platform, kClDeviceTypeAll, 0, nullptr, &count) == kClSuccess && count > 0) {
    std::vector<cl_device_id> devices(count);
    if (api.get_device_ids(platform, kClDeviceTypeAll, count, devices.data(), nullptr) == kClSuccess) {
      return devices[0];
    }
  }
  return nullptr;
}

cl_command_queue create_queue(const OpenClApi& api, cl_context context, cl_device_id device, cl_int& err) {
  err = kClSuccess;
  if (api.create_command_queue_with_properties != nullptr) {
    const cl_queue_properties props[] = {0};
    return api.create_command_queue_with_properties(context, device, props, &err);
  }
  return api.create_command_queue(context, device, 0, &err);
}

bool test_success_path(const OpenClApi& api, cl_context context, cl_command_queue queue, cl_device_id device) {
  static constexpr char kSource[] = R"(
__kernel void vec_add(__global const int* a, __global const int* b, __global int* c) {
  int gid = get_global_id(0);
  c[gid] = a[gid] + b[gid];
}
)";

  cl_int err = kClSuccess;
  const char* src = kSource;
  cl_program program = api.create_program_with_source(context, 1, &src, nullptr, &err);
  if (!expect(program != nullptr && err == kClSuccess, "clCreateProgramWithSource failed in success-path")) {
    return false;
  }

  err = api.build_program(program, 1, &device, "", nullptr, nullptr);
  if (!expect(err == kClSuccess, "clBuildProgram failed in success-path")) {
    api.release_program(program);
    return false;
  }

  cl_kernel kernel = api.create_kernel(program, "vec_add", &err);
  if (!expect(kernel != nullptr && err == kClSuccess, "clCreateKernel(vec_add) failed")) {
    api.release_program(program);
    return false;
  }

  std::vector<std::int32_t> a = {1, 2, 3, 4, 5, 6, 7, 8};
  std::vector<std::int32_t> b = {8, 7, 6, 5, 4, 3, 2, 1};
  std::vector<std::int32_t> out(a.size(), 0);
  const std::size_t bytes = a.size() * sizeof(std::int32_t);

  cl_mem a_buf = api.create_buffer(context, kClMemReadOnly | kClMemCopyHostPtr, bytes, a.data(), &err);
  if (!expect(a_buf != nullptr && err == kClSuccess, "clCreateBuffer(a) failed")) {
    api.release_kernel(kernel);
    api.release_program(program);
    return false;
  }
  cl_mem b_buf = api.create_buffer(context, kClMemReadOnly | kClMemCopyHostPtr, bytes, b.data(), &err);
  if (!expect(b_buf != nullptr && err == kClSuccess, "clCreateBuffer(b) failed")) {
    api.release_mem_object(a_buf);
    api.release_kernel(kernel);
    api.release_program(program);
    return false;
  }
  cl_mem out_buf = api.create_buffer(context, kClMemWriteOnly, bytes, nullptr, &err);
  if (!expect(out_buf != nullptr && err == kClSuccess, "clCreateBuffer(out) failed")) {
    api.release_mem_object(b_buf);
    api.release_mem_object(a_buf);
    api.release_kernel(kernel);
    api.release_program(program);
    return false;
  }

  bool ok = true;
  ok = expect(api.set_kernel_arg(kernel, 0, sizeof(cl_mem), &a_buf) == kClSuccess, "clSetKernelArg(0) failed") && ok;
  ok = expect(api.set_kernel_arg(kernel, 1, sizeof(cl_mem), &b_buf) == kClSuccess, "clSetKernelArg(1) failed") && ok;
  ok = expect(api.set_kernel_arg(kernel, 2, sizeof(cl_mem), &out_buf) == kClSuccess, "clSetKernelArg(2) failed") && ok;
  if (ok) {
    const std::size_t global = a.size();
    ok = expect(api.enqueue_ndrange_kernel(queue, kernel, 1, nullptr, &global, nullptr, 0, nullptr, nullptr) ==
                    kClSuccess,
                "clEnqueueNDRangeKernel failed") &&
         ok;
  }
  if (ok) {
    ok = expect(api.finish(queue) == kClSuccess, "clFinish failed") && ok;
  }
  if (ok) {
    ok = expect(api.enqueue_read_buffer(queue, out_buf, kClTrue, 0, bytes, out.data(), 0, nullptr, nullptr) ==
                    kClSuccess,
                "clEnqueueReadBuffer failed") &&
         ok;
  }
  if (ok) {
    for (std::size_t i = 0; i < out.size(); ++i) {
      if (out[i] != a[i] + b[i]) {
        std::cerr << "[FAIL] vec_add mismatch at index " << i << ": got " << out[i] << '\n';
        ok = false;
        break;
      }
    }
  }

  api.release_mem_object(out_buf);
  api.release_mem_object(b_buf);
  api.release_mem_object(a_buf);
  api.release_kernel(kernel);
  api.release_program(program);
  return ok;
}

bool test_failure_path(const OpenClApi& api, cl_context context, cl_device_id device) {
  static constexpr char kBadSource[] = R"(
__kernel void broken(__global int* out) {
  int gid = get_global_id(0)
  out[gid] = 1;
}
)";

  cl_int err = kClSuccess;
  const char* src = kBadSource;
  cl_program program = api.create_program_with_source(context, 1, &src, nullptr, &err);
  if (!expect(program != nullptr && err == kClSuccess, "clCreateProgramWithSource failed in failure-path")) {
    return false;
  }

  err = api.build_program(program, 1, &device, "", nullptr, nullptr);
  bool ok = expect(err != kClSuccess, "clBuildProgram should fail for invalid kernel source");
  if (!ok && api.get_program_build_info != nullptr) {
    std::vector<char> log(4096, '\0');
    std::size_t written = 0;
    (void)api.get_program_build_info(
        program, device, kClProgramBuildLog, log.size(), log.data(), &written);
    std::cerr << "[INFO] unexpected build log: " << log.data() << '\n';
  }
  api.release_program(program);
  return ok;
}

bool test_edge_security_path(const OpenClApi& api, cl_context context, cl_command_queue queue, cl_device_id device) {
  static constexpr char kSource[] = R"(
__kernel void touch(__global int* out) {
  int gid = get_global_id(0);
  out[gid] = gid;
}
)";

  cl_int err = kClSuccess;
  const char* src = kSource;
  cl_program program = api.create_program_with_source(context, 1, &src, nullptr, &err);
  if (!expect(program != nullptr && err == kClSuccess, "edge: clCreateProgramWithSource failed")) {
    return false;
  }
  err = api.build_program(program, 1, &device, "", nullptr, nullptr);
  if (!expect(err == kClSuccess, "edge: clBuildProgram failed")) {
    api.release_program(program);
    return false;
  }
  cl_kernel kernel = api.create_kernel(program, "touch", &err);
  if (!expect(kernel != nullptr && err == kClSuccess, "edge: clCreateKernel failed")) {
    api.release_program(program);
    return false;
  }

  std::vector<std::int32_t> out(4, 0);
  cl_mem out_buf = api.create_buffer(context, kClMemWriteOnly, out.size() * sizeof(std::int32_t), nullptr, &err);
  if (!expect(out_buf != nullptr && err == kClSuccess, "edge: clCreateBuffer(out) failed")) {
    api.release_kernel(kernel);
    api.release_program(program);
    return false;
  }

  bool ok = expect(api.set_kernel_arg(kernel, 0, sizeof(cl_mem), &out_buf) == kClSuccess,
                   "edge: clSetKernelArg(valid) failed");
  const cl_int invalid_index_rc = api.set_kernel_arg(kernel, 99u, sizeof(cl_mem), &out_buf);
  ok = expect(invalid_index_rc == kClInvalidArgIndex || invalid_index_rc != kClSuccess,
              "edge: invalid arg index should fail") &&
       ok;

  const std::size_t global = out.size();
  if (ok) {
    ok = expect(api.enqueue_ndrange_kernel(queue, kernel, 1, nullptr, &global, nullptr, 0, nullptr, nullptr) ==
                    kClSuccess,
                "edge: clEnqueueNDRangeKernel failed") &&
         ok;
    ok = expect(api.finish(queue) == kClSuccess, "edge: clFinish failed") && ok;
  }

  api.release_mem_object(out_buf);
  api.release_kernel(kernel);
  api.release_program(program);
  return ok;
}

}  // namespace

int main() {
  DynLib lib;
  if (!lib.open()) {
    std::cout << "[SKIP] opencl_device_integration_test: OpenCL loader not found\n";
    return 0;
  }

  OpenClApi api{};
  if (!load_opencl_api(lib, api)) {
    std::cout << "[SKIP] opencl_device_integration_test: required OpenCL symbols unavailable\n";
    return 0;
  }

  cl_uint platform_count = 0;
  if (api.get_platform_ids(0, nullptr, &platform_count) != kClSuccess || platform_count == 0) {
    std::cout << "[SKIP] opencl_device_integration_test: no OpenCL platform\n";
    return 0;
  }

  std::vector<cl_platform_id> platforms(platform_count, nullptr);
  if (api.get_platform_ids(platform_count, platforms.data(), nullptr) != kClSuccess) {
    std::cout << "[SKIP] opencl_device_integration_test: failed to enumerate platforms\n";
    return 0;
  }

  cl_device_id selected_device = nullptr;
  for (cl_platform_id platform : platforms) {
    selected_device = pick_device(api, platform);
    if (selected_device != nullptr) {
      break;
    }
  }
  if (selected_device == nullptr) {
    std::cout << "[SKIP] opencl_device_integration_test: no OpenCL device\n";
    return 0;
  }

  cl_int err = kClSuccess;
  cl_context context = api.create_context(nullptr, 1, &selected_device, nullptr, nullptr, &err);
  if (context == nullptr || err != kClSuccess) {
    std::cout << "[SKIP] opencl_device_integration_test: unable to create OpenCL context\n";
    return 0;
  }
  cl_command_queue queue = create_queue(api, context, selected_device, err);
  if (queue == nullptr || err != kClSuccess) {
    api.release_context(context);
    std::cout << "[SKIP] opencl_device_integration_test: unable to create command queue\n";
    return 0;
  }

  bool ok = true;
  ok = test_success_path(api, context, queue, selected_device) && ok;
  ok = test_failure_path(api, context, selected_device) && ok;
  ok = test_edge_security_path(api, context, queue, selected_device) && ok;

  api.release_command_queue(queue);
  api.release_context(context);

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] opencl_device_integration_test\n";
  return 0;
}

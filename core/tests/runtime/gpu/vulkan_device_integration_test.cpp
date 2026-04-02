#include <cstdint>
#include <iostream>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

using VkFlags = std::uint32_t;
using VkBool32 = std::uint32_t;
using VkQueueFlags = VkFlags;
using VkDeviceSize = std::uint64_t;
using VkFence = std::uint64_t;

struct VkInstance_T;
struct VkPhysicalDevice_T;
struct VkDevice_T;
struct VkQueue_T;
struct VkCommandBuffer_T;
struct VkSemaphore_T;
struct VkAllocationCallbacks;

using VkInstance = VkInstance_T*;
using VkPhysicalDevice = VkPhysicalDevice_T*;
using VkDevice = VkDevice_T*;
using VkQueue = VkQueue_T*;
using VkCommandBuffer = VkCommandBuffer_T*;
using VkSemaphore = VkSemaphore_T*;

enum VkResult : std::int32_t {
  VK_SUCCESS = 0,
  VK_NOT_READY = 1,
  VK_TIMEOUT = 2,
  VK_ERROR_INITIALIZATION_FAILED = -3,
  VK_ERROR_EXTENSION_NOT_PRESENT = -7,
  VK_ERROR_INCOMPATIBLE_DRIVER = -9,
};

enum VkStructureType : std::uint32_t {
  VK_STRUCTURE_TYPE_APPLICATION_INFO = 0,
  VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO = 1,
  VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO = 2,
  VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO = 3,
  VK_STRUCTURE_TYPE_FENCE_CREATE_INFO = 8,
};

constexpr VkQueueFlags VK_QUEUE_GRAPHICS_BIT = 0x00000001u;
constexpr VkQueueFlags VK_QUEUE_COMPUTE_BIT = 0x00000002u;
constexpr std::uint32_t VK_API_VERSION_1_0 = (1u << 22u);

struct VkExtent3D final {
  std::uint32_t width;
  std::uint32_t height;
  std::uint32_t depth;
};

struct VkApplicationInfo final {
  VkStructureType sType;
  const void* pNext;
  const char* pApplicationName;
  std::uint32_t applicationVersion;
  const char* pEngineName;
  std::uint32_t engineVersion;
  std::uint32_t apiVersion;
};

struct VkInstanceCreateInfo final {
  VkStructureType sType;
  const void* pNext;
  VkFlags flags;
  const VkApplicationInfo* pApplicationInfo;
  std::uint32_t enabledLayerCount;
  const char* const* ppEnabledLayerNames;
  std::uint32_t enabledExtensionCount;
  const char* const* ppEnabledExtensionNames;
};

struct VkQueueFamilyProperties final {
  VkQueueFlags queueFlags;
  std::uint32_t queueCount;
  std::uint32_t timestampValidBits;
  VkExtent3D minImageTransferGranularity;
};

struct VkDeviceQueueCreateInfo final {
  VkStructureType sType;
  const void* pNext;
  VkFlags flags;
  std::uint32_t queueFamilyIndex;
  std::uint32_t queueCount;
  const float* pQueuePriorities;
};

struct VkDeviceCreateInfo final {
  VkStructureType sType;
  const void* pNext;
  VkFlags flags;
  std::uint32_t queueCreateInfoCount;
  const VkDeviceQueueCreateInfo* pQueueCreateInfos;
  std::uint32_t enabledLayerCount;
  const char* const* ppEnabledLayerNames;
  std::uint32_t enabledExtensionCount;
  const char* const* ppEnabledExtensionNames;
  const void* pEnabledFeatures;
};

struct VkFenceCreateInfo final {
  VkStructureType sType;
  const void* pNext;
  VkFlags flags;
};

using PFN_vkVoidFunction = void (*)();
using PFN_vkGetInstanceProcAddr = PFN_vkVoidFunction (*)(VkInstance, const char*);
using PFN_vkGetDeviceProcAddr = PFN_vkVoidFunction (*)(VkDevice, const char*);
using PFN_vkCreateInstance = VkResult (*)(const VkInstanceCreateInfo*, const VkAllocationCallbacks*, VkInstance*);
using PFN_vkDestroyInstance = void (*)(VkInstance, const VkAllocationCallbacks*);
using PFN_vkEnumeratePhysicalDevices = VkResult (*)(VkInstance, std::uint32_t*, VkPhysicalDevice*);
using PFN_vkGetPhysicalDeviceQueueFamilyProperties =
    void (*)(VkPhysicalDevice, std::uint32_t*, VkQueueFamilyProperties*);
using PFN_vkCreateDevice = VkResult (*)(VkPhysicalDevice, const VkDeviceCreateInfo*, const VkAllocationCallbacks*, VkDevice*);
using PFN_vkDestroyDevice = void (*)(VkDevice, const VkAllocationCallbacks*);
using PFN_vkGetDeviceQueue = void (*)(VkDevice, std::uint32_t, std::uint32_t, VkQueue*);
using PFN_vkQueueSubmit = VkResult (*)(VkQueue, std::uint32_t, const void*, VkFence);
using PFN_vkQueueWaitIdle = VkResult (*)(VkQueue);
using PFN_vkDeviceWaitIdle = VkResult (*)(VkDevice);
using PFN_vkCreateFence = VkResult (*)(VkDevice, const VkFenceCreateInfo*, const VkAllocationCallbacks*, VkFence*);
using PFN_vkWaitForFences = VkResult (*)(VkDevice, std::uint32_t, const VkFence*, VkBool32, std::uint64_t);
using PFN_vkDestroyFence = void (*)(VkDevice, VkFence, const VkAllocationCallbacks*);

class DynLib final {
 public:
  ~DynLib() { close(); }

  bool open() {
    close();
#if defined(_WIN32)
    static constexpr const char* kCandidates[] = {"vulkan-1.dll"};
    for (const char* candidate : kCandidates) {
      handle_ = ::LoadLibraryA(candidate);
      if (handle_ != nullptr) {
        return true;
      }
    }
#else
    static constexpr const char* kCandidates[] = {"libvulkan.so.1", "libvulkan.so"};
    for (const char* candidate : kCandidates) {
      handle_ = ::dlopen(candidate, RTLD_NOW | RTLD_LOCAL);
      if (handle_ != nullptr) {
        return true;
      }
    }
#endif
    return false;
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

 private:
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

  void* handle_ = nullptr;
};

struct VulkanApi final {
  PFN_vkGetInstanceProcAddr get_instance_proc_addr = nullptr;
  PFN_vkCreateInstance create_instance_direct = nullptr;
  PFN_vkGetDeviceProcAddr get_device_proc_addr_direct = nullptr;
};

struct VulkanRuntime final {
  PFN_vkCreateInstance create_instance = nullptr;
  PFN_vkDestroyInstance destroy_instance = nullptr;
  PFN_vkEnumeratePhysicalDevices enumerate_physical_devices = nullptr;
  PFN_vkGetPhysicalDeviceQueueFamilyProperties get_queue_family_props = nullptr;
  PFN_vkCreateDevice create_device = nullptr;
  PFN_vkGetDeviceProcAddr get_device_proc_addr = nullptr;
};

struct VulkanDeviceApi final {
  PFN_vkDestroyDevice destroy_device = nullptr;
  PFN_vkGetDeviceQueue get_device_queue = nullptr;
  PFN_vkQueueSubmit queue_submit = nullptr;
  PFN_vkQueueWaitIdle queue_wait_idle = nullptr;
  PFN_vkDeviceWaitIdle device_wait_idle = nullptr;
  PFN_vkCreateFence create_fence = nullptr;
  PFN_vkWaitForFences wait_for_fences = nullptr;
  PFN_vkDestroyFence destroy_fence = nullptr;
};

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool load_runtime_api(const VulkanApi& api, VulkanRuntime& runtime) {
  runtime.create_instance = api.create_instance_direct;
  if (runtime.create_instance == nullptr && api.get_instance_proc_addr != nullptr) {
    runtime.create_instance =
        reinterpret_cast<PFN_vkCreateInstance>(api.get_instance_proc_addr(nullptr, "vkCreateInstance"));
  }
  runtime.get_device_proc_addr = api.get_device_proc_addr_direct;
  if (runtime.get_device_proc_addr == nullptr && api.get_instance_proc_addr != nullptr) {
    runtime.get_device_proc_addr =
        reinterpret_cast<PFN_vkGetDeviceProcAddr>(api.get_instance_proc_addr(nullptr, "vkGetDeviceProcAddr"));
  }
  if (runtime.create_instance == nullptr || runtime.get_device_proc_addr == nullptr) {
    return false;
  }
  return true;
}

bool load_instance_api(const VulkanApi& api, VkInstance instance, VulkanRuntime& runtime) {
  runtime.enumerate_physical_devices = reinterpret_cast<PFN_vkEnumeratePhysicalDevices>(
      api.get_instance_proc_addr(instance, "vkEnumeratePhysicalDevices"));
  runtime.destroy_instance =
      reinterpret_cast<PFN_vkDestroyInstance>(api.get_instance_proc_addr(instance, "vkDestroyInstance"));
  runtime.get_queue_family_props = reinterpret_cast<PFN_vkGetPhysicalDeviceQueueFamilyProperties>(
      api.get_instance_proc_addr(instance, "vkGetPhysicalDeviceQueueFamilyProperties"));
  runtime.create_device =
      reinterpret_cast<PFN_vkCreateDevice>(api.get_instance_proc_addr(instance, "vkCreateDevice"));
  return runtime.enumerate_physical_devices != nullptr && runtime.destroy_instance != nullptr &&
         runtime.get_queue_family_props != nullptr &&
         runtime.create_device != nullptr;
}

bool load_device_api(const VulkanRuntime& runtime, VkDevice device, VulkanDeviceApi& out) {
  out.destroy_device =
      reinterpret_cast<PFN_vkDestroyDevice>(runtime.get_device_proc_addr(device, "vkDestroyDevice"));
  out.get_device_queue =
      reinterpret_cast<PFN_vkGetDeviceQueue>(runtime.get_device_proc_addr(device, "vkGetDeviceQueue"));
  out.queue_submit =
      reinterpret_cast<PFN_vkQueueSubmit>(runtime.get_device_proc_addr(device, "vkQueueSubmit"));
  out.queue_wait_idle =
      reinterpret_cast<PFN_vkQueueWaitIdle>(runtime.get_device_proc_addr(device, "vkQueueWaitIdle"));
  out.device_wait_idle =
      reinterpret_cast<PFN_vkDeviceWaitIdle>(runtime.get_device_proc_addr(device, "vkDeviceWaitIdle"));
  out.create_fence =
      reinterpret_cast<PFN_vkCreateFence>(runtime.get_device_proc_addr(device, "vkCreateFence"));
  out.wait_for_fences =
      reinterpret_cast<PFN_vkWaitForFences>(runtime.get_device_proc_addr(device, "vkWaitForFences"));
  out.destroy_fence =
      reinterpret_cast<PFN_vkDestroyFence>(runtime.get_device_proc_addr(device, "vkDestroyFence"));

  return out.destroy_device != nullptr && out.get_device_queue != nullptr && out.queue_submit != nullptr &&
         out.queue_wait_idle != nullptr && out.device_wait_idle != nullptr && out.create_fence != nullptr &&
         out.wait_for_fences != nullptr && out.destroy_fence != nullptr;
}

VkInstance create_instance(const VulkanRuntime& runtime, const char* const* exts, std::uint32_t ext_count, VkResult& out) {
  VkApplicationInfo app_info{};
  app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
  app_info.pApplicationName = "eippf_vulkan_device_test";
  app_info.applicationVersion = 1;
  app_info.pEngineName = "eippf";
  app_info.engineVersion = 1;
  app_info.apiVersion = VK_API_VERSION_1_0;

  VkInstanceCreateInfo create_info{};
  create_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
  create_info.pApplicationInfo = &app_info;
  create_info.enabledExtensionCount = ext_count;
  create_info.ppEnabledExtensionNames = exts;

  VkInstance instance = nullptr;
  out = runtime.create_instance(&create_info, nullptr, &instance);
  return instance;
}

int pick_queue_family(const VulkanRuntime& runtime, VkPhysicalDevice physical) {
  std::uint32_t queue_family_count = 0;
  runtime.get_queue_family_props(physical, &queue_family_count, nullptr);
  if (queue_family_count == 0) {
    return -1;
  }
  std::vector<VkQueueFamilyProperties> properties(queue_family_count);
  runtime.get_queue_family_props(physical, &queue_family_count, properties.data());
  for (std::uint32_t i = 0; i < queue_family_count; ++i) {
    if (properties[i].queueCount == 0) {
      continue;
    }
    if ((properties[i].queueFlags & VK_QUEUE_COMPUTE_BIT) != 0u) {
      return static_cast<int>(i);
    }
  }
  for (std::uint32_t i = 0; i < queue_family_count; ++i) {
    if (properties[i].queueCount == 0) {
      continue;
    }
    if ((properties[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) != 0u) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

bool test_failure_path(const VulkanRuntime& runtime) {
  static constexpr const char* kBadExt = "VK_EIPPF_NON_EXISTENT_EXTENSION";
  const char* exts[] = {kBadExt};
  VkResult rc = VK_SUCCESS;
  VkInstance instance = create_instance(runtime, exts, 1, rc);
  if (instance != nullptr) {
    return expect(false, "vkCreateInstance should not succeed with invalid extension");
  }
  return expect(rc == VK_ERROR_EXTENSION_NOT_PRESENT || rc == VK_ERROR_INCOMPATIBLE_DRIVER,
                "vkCreateInstance invalid extension should return extension error");
}

bool test_success_and_edge_paths(const VulkanApi& api, VulkanRuntime& runtime) {
  VkResult rc = VK_SUCCESS;
  VkInstance instance = create_instance(runtime, nullptr, 0, rc);
  if (instance == nullptr || rc != VK_SUCCESS) {
    if (rc == VK_ERROR_INCOMPATIBLE_DRIVER || rc == VK_ERROR_INITIALIZATION_FAILED) {
      std::cout << "[SKIP] vulkan_device_integration_test: vkCreateInstance unavailable in this environment\n";
      return true;
    }
    return expect(false, "vkCreateInstance failed in success-path");
  }

  bool ok = true;
  if (!load_instance_api(api, instance, runtime)) {
    runtime.destroy_instance(instance, nullptr);
    return expect(false, "failed to load Vulkan instance-level symbols");
  }

  std::uint32_t physical_count = 0;
  rc = runtime.enumerate_physical_devices(instance, &physical_count, nullptr);
  if (rc != VK_SUCCESS || physical_count == 0) {
    runtime.destroy_instance(instance, nullptr);
    std::cout << "[SKIP] vulkan_device_integration_test: no Vulkan physical device\n";
    return true;
  }

  std::vector<VkPhysicalDevice> physical_devices(physical_count);
  rc = runtime.enumerate_physical_devices(instance, &physical_count, physical_devices.data());
  if (!expect(rc == VK_SUCCESS && !physical_devices.empty(), "vkEnumeratePhysicalDevices(list) failed")) {
    runtime.destroy_instance(instance, nullptr);
    return false;
  }

  int queue_family = pick_queue_family(runtime, physical_devices[0]);
  if (queue_family < 0) {
    runtime.destroy_instance(instance, nullptr);
    std::cout << "[SKIP] vulkan_device_integration_test: no compute/graphics queue family\n";
    return true;
  }

  const float priority = 1.0f;
  VkDeviceQueueCreateInfo queue_info{};
  queue_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
  queue_info.queueFamilyIndex = static_cast<std::uint32_t>(queue_family);
  queue_info.queueCount = 1;
  queue_info.pQueuePriorities = &priority;

  VkDeviceCreateInfo device_info{};
  device_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
  device_info.queueCreateInfoCount = 1;
  device_info.pQueueCreateInfos = &queue_info;

  VkDevice device = nullptr;
  rc = runtime.create_device(physical_devices[0], &device_info, nullptr, &device);
  if (!expect(rc == VK_SUCCESS && device != nullptr, "vkCreateDevice failed")) {
    runtime.destroy_instance(instance, nullptr);
    return false;
  }

  VulkanDeviceApi device_api{};
  if (!load_device_api(runtime, device, device_api)) {
    device_api.destroy_device(device, nullptr);
    runtime.destroy_instance(instance, nullptr);
    return expect(false, "failed to load Vulkan device-level symbols");
  }

  VkQueue queue = nullptr;
  device_api.get_device_queue(device, static_cast<std::uint32_t>(queue_family), 0, &queue);
  if (!expect(queue != nullptr, "vkGetDeviceQueue returned null queue")) {
    device_api.destroy_device(device, nullptr);
    runtime.destroy_instance(instance, nullptr);
    return false;
  }

  rc = device_api.queue_submit(queue, 0, nullptr, 0);
  ok = expect(rc == VK_SUCCESS, "vkQueueSubmit(empty) failed") && ok;
  rc = device_api.queue_wait_idle(queue);
  ok = expect(rc == VK_SUCCESS, "vkQueueWaitIdle failed") && ok;

  VkFence fence = 0;
  VkFenceCreateInfo fence_info{};
  fence_info.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO;
  rc = device_api.create_fence(device, &fence_info, nullptr, &fence);
  ok = expect(rc == VK_SUCCESS && fence != 0, "vkCreateFence failed") && ok;
  if (fence != 0) {
    rc = device_api.wait_for_fences(device, 1, &fence, 1u, 0u);
    ok = expect(rc == VK_TIMEOUT || rc == VK_NOT_READY, "vkWaitForFences(timeout=0) should not signal") && ok;
    device_api.destroy_fence(device, fence, nullptr);
  }

  rc = device_api.device_wait_idle(device);
  ok = expect(rc == VK_SUCCESS, "vkDeviceWaitIdle failed") && ok;

  device_api.destroy_device(device, nullptr);
  runtime.destroy_instance(instance, nullptr);
  return ok;
}

}  // namespace

int main() {
  DynLib lib;
  if (!lib.open()) {
    std::cout << "[SKIP] vulkan_device_integration_test: Vulkan loader not found\n";
    return 0;
  }

  VulkanApi api{};
  api.get_instance_proc_addr = lib.load<PFN_vkGetInstanceProcAddr>("vkGetInstanceProcAddr");
  api.create_instance_direct = lib.load<PFN_vkCreateInstance>("vkCreateInstance");
  api.get_device_proc_addr_direct = lib.load<PFN_vkGetDeviceProcAddr>("vkGetDeviceProcAddr");
  if (api.get_instance_proc_addr == nullptr) {
    std::cout << "[SKIP] vulkan_device_integration_test: vkGetInstanceProcAddr not found\n";
    return 0;
  }

  VulkanRuntime runtime{};
  if (!load_runtime_api(api, runtime)) {
    std::cout << "[SKIP] vulkan_device_integration_test: required Vulkan runtime symbols unavailable\n";
    return 0;
  }

  bool ok = true;
  ok = test_failure_path(runtime) && ok;
  ok = test_success_and_edge_paths(api, runtime) && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] vulkan_device_integration_test\n";
  return 0;
}

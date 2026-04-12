#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif
#if defined(__APPLE__) && (defined(__aarch64__) || defined(_M_ARM64))
#include <pthread.h>
#if defined(__has_include)
#if __has_include(<sys/icache.h>)
#include <sys/icache.h>
#define EIPPF_HAS_SYS_ICACHE_INVALIDATE 1
#elif __has_include(<libkern/OSCacheControl.h>)
#include <libkern/OSCacheControl.h>
#define EIPPF_HAS_SYS_ICACHE_INVALIDATE 1
#endif
#endif
#endif
#include <sys/mman.h>
#include <sys/types.h>
#endif

#include "contracts/protection_contracts.hpp"
#include "runtime/backend_policy.hpp"
#include "runtime/constexpr_obfuscated_string.hpp"
#include "runtime/dynamic_api_resolver.hpp"

#if defined(__APPLE__) && (defined(__GNUC__) || defined(__clang__))
extern "C" const std::uint32_t eippf_rtk0 __attribute__((weak_import));
#elif defined(__GNUC__) || defined(__clang__)
extern "C" const std::uint32_t eippf_rtk0 __attribute__((weak));
#endif

#if defined(_WIN32) || defined(_WIN64)
extern "C" IMAGE_DOS_HEADER __ImageBase;
#endif

namespace eippf::runtime {

struct MemoryHAL final {
  struct Region final {
    void* base = nullptr;
    std::size_t size = 0u;

    [[nodiscard]] bool valid() const noexcept { return base != nullptr && size > 0u; }
  };

  [[nodiscard]] static contracts::ProtectionTargetKind configured_target_kind() noexcept {
    const std::uint32_t linked_target = linked_target_kind();
    if (linked_target != 0u) {
      return target_kind_from_u32(linked_target);
    }
#if defined(EIPPF_RUNTIME_TARGET_KIND)
    return target_kind_from_u32(static_cast<std::uint32_t>(EIPPF_RUNTIME_TARGET_KIND));
#else
    return contracts::ProtectionTargetKind::kUnknown;
#endif
  }

  [[nodiscard]] static bool runtime_dynamic_code_allowed() noexcept {
    const contracts::ProtectionTargetKind target = configured_target_kind();
    return backend::target_kind_supports_desktop_jit(target) &&
           !backend::target_forbids_runtime_executable_pages(target);
  }

  template <std::size_t kMaxSymbolCache, std::size_t kMaxModuleCache>
  [[nodiscard]] static Region allocate_rw(
      DynamicAPIResolver<kMaxSymbolCache, kMaxModuleCache>& resolver,
      std::size_t requested_size) noexcept {
    if (requested_size == 0u) {
      return {};
    }

#if defined(_WIN32) || defined(_WIN64)
    constexpr auto kKernel32 = security::make_obfuscated_string<0x21u>("kernel32.dll");
    constexpr auto kVirtualAlloc = security::make_obfuscated_string<0x22u>("VirtualAlloc");
    using VirtualAllocFn = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);

    const VirtualAllocFn virtual_alloc =
        resolver.template resolve<VirtualAllocFn>(kKernel32, kVirtualAlloc);
    if (virtual_alloc == nullptr) {
      return {};
    }

    void* const memory = virtual_alloc(nullptr,
                                       static_cast<SIZE_T>(requested_size),
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
    return Region{memory, requested_size};
#elif defined(__linux__) || defined(__APPLE__)
#if defined(__linux__)
    constexpr auto kLibC = security::make_obfuscated_string<0x31u>("libc.so.6");
#else
    constexpr auto kLibC = security::make_obfuscated_string<0x31u>("libSystem.B.dylib");
#endif
    constexpr auto kMmap = security::make_obfuscated_string<0x32u>("mmap");
    using MmapFn = void* (*)(void*, std::size_t, int, int, int, off_t);

    const MmapFn mmap_fn = resolver.template resolve<MmapFn>(kLibC, kMmap);
    if (mmap_fn == nullptr) {
      return {};
    }

#if defined(__APPLE__) && (defined(__aarch64__) || defined(_M_ARM64))
    int map_flags = MAP_PRIVATE | MAP_ANON;
    if (runtime_dynamic_code_allowed()) {
#if defined(MAP_JIT)
      map_flags |= MAP_JIT;
#endif
    }
    void* const mapped = mmap_fn(nullptr,
                                 requested_size,
                                 PROT_READ | PROT_WRITE,
                                 map_flags,
                                 -1,
                                 0);
#else
    void* const mapped = mmap_fn(nullptr,
                                 requested_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS,
                                 -1,
                                 0);
#endif
    if (mapped == MAP_FAILED) {
      return {};
    }

    return Region{mapped, requested_size};
#else
    (void)resolver;
    return {};
#endif
  }

  template <std::size_t kMaxSymbolCache, std::size_t kMaxModuleCache>
  [[nodiscard]] static bool protect_rx(
      DynamicAPIResolver<kMaxSymbolCache, kMaxModuleCache>& resolver,
      const Region& region) noexcept {
    if (!region.valid()) {
      return false;
    }
    if (!runtime_dynamic_code_allowed()) {
      return false;
    }

#if defined(_WIN32) || defined(_WIN64)
    constexpr auto kKernel32 = security::make_obfuscated_string<0x23u>("kernel32.dll");
    constexpr auto kVirtualProtect = security::make_obfuscated_string<0x24u>("VirtualProtect");
    constexpr auto kFlushInstructionCache =
        security::make_obfuscated_string<0x29u>("FlushInstructionCache");
    using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);
    using FlushInstructionCacheFn = BOOL(WINAPI*)(HANDLE, LPCVOID, SIZE_T);

    const VirtualProtectFn virtual_protect =
        resolver.template resolve<VirtualProtectFn>(kKernel32, kVirtualProtect);
    if (virtual_protect == nullptr) {
      return false;
    }

    DWORD old_protect = 0u;
    const bool protected_ok = virtual_protect(region.base,
                                              static_cast<SIZE_T>(region.size),
                                              PAGE_EXECUTE_READ,
                                              &old_protect) != FALSE;
    if (!protected_ok) {
      return false;
    }

    const FlushInstructionCacheFn flush_instruction_cache =
        resolver.template resolve<FlushInstructionCacheFn>(kKernel32, kFlushInstructionCache);
    if (flush_instruction_cache == nullptr) {
      return false;
    }
    return flush_instruction_cache(GetCurrentProcess(),
                                   region.base,
                                   static_cast<SIZE_T>(region.size)) != FALSE;
#elif defined(__linux__) || defined(__APPLE__)
#if defined(__APPLE__) && (defined(__aarch64__) || defined(_M_ARM64)) && \
    (!defined(TARGET_OS_IPHONE) || !TARGET_OS_IPHONE)
    (void)resolver;
    pthread_jit_write_protect_np(1);
#if defined(EIPPF_HAS_SYS_ICACHE_INVALIDATE)
    sys_icache_invalidate(region.base, region.size);
#elif defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache(static_cast<char*>(region.base),
                            static_cast<char*>(region.base) + region.size);
#endif
    return true;
#else
#if defined(__linux__)
    constexpr auto kLibC = security::make_obfuscated_string<0x33u>("libc.so.6");
#else
    constexpr auto kLibC = security::make_obfuscated_string<0x33u>("libSystem.B.dylib");
#endif
    constexpr auto kMprotect = security::make_obfuscated_string<0x34u>("mprotect");
    using MprotectFn = int (*)(void*, std::size_t, int);

    const MprotectFn mprotect_fn = resolver.template resolve<MprotectFn>(kLibC, kMprotect);
    if (mprotect_fn == nullptr) {
      return false;
    }

    const bool ok = mprotect_fn(region.base, region.size, PROT_READ | PROT_EXEC) == 0;
    if (ok) {
#if defined(EIPPF_HAS_SYS_ICACHE_INVALIDATE)
      sys_icache_invalidate(region.base, region.size);
#elif defined(__GNUC__) || defined(__clang__)
      __builtin___clear_cache(static_cast<char*>(region.base),
                              static_cast<char*>(region.base) + region.size);
#endif
    }
    return ok;
#endif
#else
    (void)resolver;
    return false;
#endif
  }

  template <std::size_t kMaxSymbolCache, std::size_t kMaxModuleCache>
  [[nodiscard]] static bool protect_rw(
      DynamicAPIResolver<kMaxSymbolCache, kMaxModuleCache>& resolver,
      const Region& region) noexcept {
    if (!region.valid()) {
      return false;
    }
    if (!runtime_dynamic_code_allowed()) {
      return true;
    }

#if defined(_WIN32) || defined(_WIN64)
    constexpr auto kKernel32 = security::make_obfuscated_string<0x25u>("kernel32.dll");
    constexpr auto kVirtualProtect = security::make_obfuscated_string<0x26u>("VirtualProtect");
    using VirtualProtectFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD);

    const VirtualProtectFn virtual_protect =
        resolver.template resolve<VirtualProtectFn>(kKernel32, kVirtualProtect);
    if (virtual_protect == nullptr) {
      return false;
    }

    DWORD old_protect = 0u;
    return virtual_protect(region.base,
                           static_cast<SIZE_T>(region.size),
                           PAGE_READWRITE,
                           &old_protect) != FALSE;
#elif defined(__linux__) || defined(__APPLE__)
#if defined(__APPLE__) && (defined(__aarch64__) || defined(_M_ARM64)) && \
    (!defined(TARGET_OS_IPHONE) || !TARGET_OS_IPHONE)
    (void)resolver;
    pthread_jit_write_protect_np(0);
    return true;
#else
#if defined(__linux__)
    constexpr auto kLibC = security::make_obfuscated_string<0x35u>("libc.so.6");
#else
    constexpr auto kLibC = security::make_obfuscated_string<0x35u>("libSystem.B.dylib");
#endif
    constexpr auto kMprotect = security::make_obfuscated_string<0x36u>("mprotect");
    using MprotectFn = int (*)(void*, std::size_t, int);

    const MprotectFn mprotect_fn = resolver.template resolve<MprotectFn>(kLibC, kMprotect);
    if (mprotect_fn == nullptr) {
      return false;
    }

    return mprotect_fn(region.base, region.size, PROT_READ | PROT_WRITE) == 0;
#endif
#else
    (void)resolver;
    return false;
#endif
  }

  template <std::size_t kMaxSymbolCache, std::size_t kMaxModuleCache>
  static void release(DynamicAPIResolver<kMaxSymbolCache, kMaxModuleCache>& resolver,
                      Region& region) noexcept {
    if (!region.valid()) {
      return;
    }

#if defined(_WIN32) || defined(_WIN64)
    constexpr auto kKernel32 = security::make_obfuscated_string<0x27u>("kernel32.dll");
    constexpr auto kVirtualFree = security::make_obfuscated_string<0x28u>("VirtualFree");
    using VirtualFreeFn = BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD);

    const VirtualFreeFn virtual_free =
        resolver.template resolve<VirtualFreeFn>(kKernel32, kVirtualFree);
    if (virtual_free != nullptr) {
      (void)virtual_free(region.base, 0u, MEM_RELEASE);
    }
#elif defined(__linux__) || defined(__APPLE__)
#if defined(__linux__)
    constexpr auto kLibC = security::make_obfuscated_string<0x37u>("libc.so.6");
#else
    constexpr auto kLibC = security::make_obfuscated_string<0x37u>("libSystem.B.dylib");
#endif
    constexpr auto kMunmap = security::make_obfuscated_string<0x38u>("munmap");
    using MunmapFn = int (*)(void*, std::size_t);

    const MunmapFn munmap_fn = resolver.template resolve<MunmapFn>(kLibC, kMunmap);
    if (munmap_fn != nullptr) {
      (void)munmap_fn(region.base, region.size);
    }
#else
    (void)resolver;
#endif

    region.base = nullptr;
    region.size = 0u;
  }

 private:
  [[nodiscard]] static constexpr std::array<std::uint8_t, 8u> marker_magic() noexcept {
    return {'E', 'I', 'P', 'P', 'F', 'T', 'K', '1'};
  }

  [[nodiscard]] static constexpr std::uint32_t read_u32_le(
      const std::uint8_t* bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[2]) << 16u) |
           (static_cast<std::uint32_t>(bytes[3]) << 24u);
  }

  [[nodiscard]] static constexpr contracts::ProtectionTargetKind target_kind_from_u32(
      std::uint32_t raw_target) noexcept {
    switch (raw_target) {
      case 1u:
        return contracts::ProtectionTargetKind::kDesktopNative;
      case 2u:
        return contracts::ProtectionTargetKind::kAndroidSo;
      case 3u:
        return contracts::ProtectionTargetKind::kAndroidDex;
      case 4u:
        return contracts::ProtectionTargetKind::kIosAppStore;
      case 5u:
        return contracts::ProtectionTargetKind::kWindowsDriver;
      case 6u:
        return contracts::ProtectionTargetKind::kLinuxKernelModule;
      case 7u:
        return contracts::ProtectionTargetKind::kAndroidKernelModule;
      case 8u:
        return contracts::ProtectionTargetKind::kShellEphemeral;
      default:
        return contracts::ProtectionTargetKind::kUnknown;
    }
  }

  [[nodiscard]] static bool target_forbids_runtime_executable_pages(
      contracts::ProtectionTargetKind target) noexcept {
    return target == contracts::ProtectionTargetKind::kIosAppStore ||
           contracts::is_kernel_target(target);
  }

  [[nodiscard]] static std::uint32_t linked_target_kind() noexcept {
#if defined(_WIN32) || defined(_WIN64)
    const auto* const image_base = reinterpret_cast<const std::uint8_t*>(&__ImageBase);
    const auto* const dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
      return 0u;
    }

    const auto nt_offset = static_cast<std::size_t>(dos->e_lfanew);
    const auto* const nt_headers =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(image_base + nt_offset);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
      return 0u;
    }

    const std::size_t image_size = static_cast<std::size_t>(nt_headers->OptionalHeader.SizeOfImage);
    const auto* const section =
        IMAGE_FIRST_SECTION(const_cast<IMAGE_NT_HEADERS*>(nt_headers));
    const auto magic = marker_magic();
    constexpr std::size_t kMarkerSize = 12u;

    for (unsigned index = 0; index < nt_headers->FileHeader.NumberOfSections; ++index) {
      const IMAGE_SECTION_HEADER& current = section[index];
      const std::size_t section_offset = static_cast<std::size_t>(current.VirtualAddress);
      const std::size_t section_size =
          std::max(static_cast<std::size_t>(current.Misc.VirtualSize),
                   static_cast<std::size_t>(current.SizeOfRawData));
      if (section_size < kMarkerSize || section_offset >= image_size) {
        continue;
      }
      const std::size_t bounded_size = std::min(section_size, image_size - section_offset);
      const auto* const bytes = image_base + section_offset;
      for (std::size_t cursor = 0u; cursor + kMarkerSize <= bounded_size; ++cursor) {
        bool matched = true;
        for (std::size_t i = 0u; i < magic.size(); ++i) {
          if (bytes[cursor + i] != magic[i]) {
            matched = false;
            break;
          }
        }
        if (!matched) {
          continue;
        }
        const std::uint32_t raw_target = read_u32_le(bytes + cursor + magic.size());
        if (target_kind_from_u32(raw_target) != contracts::ProtectionTargetKind::kUnknown) {
          return raw_target;
        }
      }
    }
    return 0u;
#elif defined(__APPLE__) && (defined(__GNUC__) || defined(__clang__))
    return &eippf_rtk0 != nullptr ? eippf_rtk0 : 0u;
#elif defined(__GNUC__) || defined(__clang__)
    return &eippf_rtk0 != nullptr ? eippf_rtk0 : 0u;
#else
    return 0u;
#endif
  }
};

}  // namespace eippf::runtime

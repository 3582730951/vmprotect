#pragma once

#include <array>
#include <atomic>
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
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#elif defined(__linux__)
#include <fcntl.h>
#include <sys/types.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#endif

#include "runtime/analysis_marker_scan.hpp"
#include "runtime/constexpr_obfuscated_string.hpp"
#include "runtime/android_so_policy.hpp"
#include "runtime/dynamic_api_resolver.hpp"

namespace eippf::runtime {

class EnvironmentAttestation final {
 public:
  enum class Verdict : std::uint8_t {
    kUnknown = 0u,
    kTrusted = 1u,
    kMitigated = 2u,
  };

  EnvironmentAttestation() noexcept = default;

  template <std::size_t kMaxSymbolCache, std::size_t kMaxModuleCache>
  [[nodiscard]] Verdict evaluate(
      DynamicAPIResolver<kMaxSymbolCache, kMaxModuleCache>& resolver) noexcept {
    const std::uint8_t cached = cached_verdict_.load(std::memory_order_acquire);
    if (cached == static_cast<std::uint8_t>(Verdict::kTrusted)) {
      return Verdict::kTrusted;
    }
    if (cached == static_cast<std::uint8_t>(Verdict::kMitigated)) {
      return Verdict::kMitigated;
    }

    const Verdict verdict = evaluate_uncached(resolver);
    cached_verdict_.store(static_cast<std::uint8_t>(verdict), std::memory_order_release);
    return verdict;
  }

  void reset_cache_for_testing() noexcept {
    cached_verdict_.store(static_cast<std::uint8_t>(Verdict::kUnknown), std::memory_order_release);
  }

  [[nodiscard]] static bool parse_tracer_pid_status(const char* text, std::size_t size) noexcept {
    return analysis::parse_tracer_pid_zero(text, size);
  }

  [[nodiscard]] static bool contains_suspicious_module_token(const char* text) noexcept {
    return analysis::contains_suspicious_marker(text);
  }

  [[nodiscard]] static bool proc_maps_contains_suspicious_module(const char* text,
                                                                 std::size_t size) noexcept {
    if (text == nullptr || size == 0u) {
      return false;
    }

    std::array<char, 512u> line{};
    std::size_t line_size = 0u;
    for (std::size_t i = 0; i < size; ++i) {
      const char ch = text[i];
      if (ch == '\n' || line_size + 1u >= line.size()) {
        line[line_size] = '\0';
        if (contains_suspicious_module_token(line.data())) {
          return true;
        }
        line_size = 0u;
        if (ch != '\n' && ch != '\0') {
          line[line_size++] = ch;
        }
        continue;
      }
      if (ch == '\0') {
        break;
      }
      line[line_size++] = ch;
    }
    line[line_size] = '\0';
    return contains_suspicious_module_token(line.data());
  }

  [[nodiscard]] static AndroidSoPolicyResult evaluate_android_so_baseline(
      const AndroidSoPolicyInput& input) noexcept {
    return evaluate_android_so_policy(input);
  }

 private:
  template <std::size_t kMaxSymbolCache, std::size_t kMaxModuleCache>
  [[nodiscard]] Verdict evaluate_uncached(
      DynamicAPIResolver<kMaxSymbolCache, kMaxModuleCache>& resolver) noexcept {
#if defined(_WIN32) || defined(_WIN64)
    constexpr auto kKernel32 = security::make_obfuscated_string<0x41u>("kernel32.dll");
    constexpr auto kIsDebuggerPresent =
        security::make_obfuscated_string<0x42u>("IsDebuggerPresent");
    constexpr auto kCheckRemoteDebuggerPresent =
        security::make_obfuscated_string<0x43u>("CheckRemoteDebuggerPresent");
    constexpr auto kGetCurrentProcess =
        security::make_obfuscated_string<0x44u>("GetCurrentProcess");

    using IsDebuggerPresentFn = BOOL(WINAPI*)();
    using CheckRemoteDebuggerPresentFn = BOOL(WINAPI*)(HANDLE, PBOOL);
    using GetCurrentProcessFn = HANDLE(WINAPI*)();

    const IsDebuggerPresentFn is_debugger_present =
        resolver.template resolve<IsDebuggerPresentFn>(kKernel32, kIsDebuggerPresent);
    const CheckRemoteDebuggerPresentFn check_remote_debugger =
        resolver.template resolve<CheckRemoteDebuggerPresentFn>(kKernel32, kCheckRemoteDebuggerPresent);
    const GetCurrentProcessFn get_current_process =
        resolver.template resolve<GetCurrentProcessFn>(kKernel32, kGetCurrentProcess);

    bool has_runtime_check = false;
    if (is_debugger_present != nullptr) {
      has_runtime_check = true;
      if (is_debugger_present() != FALSE) {
        return Verdict::kMitigated;
      }
    }

    if (check_remote_debugger != nullptr && get_current_process != nullptr) {
      has_runtime_check = true;
      BOOL has_remote_debugger = FALSE;
      const BOOL ok = check_remote_debugger(get_current_process(), &has_remote_debugger);
      if (ok != FALSE && has_remote_debugger != FALSE) {
        return Verdict::kMitigated;
      }
    }

    if (peb_being_debugged()) {
      return Verdict::kMitigated;
    }

    return has_runtime_check ? Verdict::kTrusted : Verdict::kMitigated;
#elif defined(__linux__)
    constexpr auto kLibC = security::make_obfuscated_string<0x51u>("libc.so.6");
    constexpr auto kOpen = security::make_obfuscated_string<0x52u>("open");
    constexpr auto kRead = security::make_obfuscated_string<0x53u>("read");
    constexpr auto kClose = security::make_obfuscated_string<0x54u>("close");
    constexpr auto kProcSelfStatus =
        security::make_obfuscated_string<0x55u>("/proc/self/status");
    constexpr auto kProcSelfMaps =
        security::make_obfuscated_string<0x56u>("/proc/self/maps");

    using OpenFn = int (*)(const char*, int, ...);
    using ReadFn = long (*)(int, void*, std::size_t);
    using CloseFn = int (*)(int);

    const OpenFn open_fn = resolver.template resolve<OpenFn>(kLibC, kOpen);
    const ReadFn read_fn = resolver.template resolve<ReadFn>(kLibC, kRead);
    const CloseFn close_fn = resolver.template resolve<CloseFn>(kLibC, kClose);
    if (open_fn == nullptr || read_fn == nullptr || close_fn == nullptr) {
      return Verdict::kMitigated;
    }

    auto proc_status_path = kProcSelfStatus.decrypt();
    const int fd = open_fn(proc_status_path.c_str(), O_RDONLY, 0);
    proc_status_path.wipe();
    if (fd < 0) {
      return Verdict::kMitigated;
    }

    std::array<char, 4096u> status_buffer{};
    const long read_size = read_fn(fd, status_buffer.data(), status_buffer.size() - 1u);
    (void)close_fn(fd);
    if (read_size <= 0) {
      return Verdict::kMitigated;
    }

    const std::size_t text_size = static_cast<std::size_t>(read_size);
    status_buffer[text_size] = '\0';
    if (!parse_tracer_pid_status(status_buffer.data(), text_size)) {
      return Verdict::kMitigated;
    }

    auto proc_maps_path = kProcSelfMaps.decrypt();
    const int maps_fd = open_fn(proc_maps_path.c_str(), O_RDONLY, 0);
    proc_maps_path.wipe();
    if (maps_fd < 0) {
      return Verdict::kMitigated;
    }

    std::array<char, 8192u> maps_buffer{};
    const long maps_read_size = read_fn(maps_fd, maps_buffer.data(), maps_buffer.size() - 1u);
    (void)close_fn(maps_fd);
    if (maps_read_size <= 0) {
      return Verdict::kMitigated;
    }

    const std::size_t maps_size = static_cast<std::size_t>(maps_read_size);
    maps_buffer[maps_size] = '\0';
    return proc_maps_contains_suspicious_module(maps_buffer.data(), maps_size)
               ? Verdict::kMitigated
               : Verdict::kTrusted;
#elif defined(__APPLE__) && defined(__MACH__)
    constexpr auto kLibSystem = security::make_obfuscated_string<0x61u>("libSystem.B.dylib");
    constexpr auto kPtrace = security::make_obfuscated_string<0x62u>("ptrace");
    using PtraceFn = int (*)(int, pid_t, caddr_t, int);

    const PtraceFn ptrace_fn = resolver.template resolve<PtraceFn>(kLibSystem, kPtrace);
    if (ptrace_fn == nullptr) {
      return Verdict::kMitigated;
    }

#ifndef PT_DENY_ATTACH
    constexpr int kPtDenyAttach = 31;
#else
    constexpr int kPtDenyAttach = PT_DENY_ATTACH;
#endif
    const int rc = ptrace_fn(kPtDenyAttach, 0, static_cast<caddr_t>(nullptr), 0);
    return rc == -1 ? Verdict::kMitigated : Verdict::kTrusted;
#else
    (void)resolver;
    return Verdict::kMitigated;
#endif
  }

  [[nodiscard]] static bool peb_being_debugged() noexcept {
#if defined(_WIN32) || defined(_WIN64)
#if defined(_MSC_VER) && defined(_M_X64)
    const auto* peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
    return peb != nullptr && peb[2] != 0;
#elif defined(_MSC_VER) && defined(_M_IX86)
    const auto* peb = reinterpret_cast<const std::uint8_t*>(__readfsdword(0x30));
    return peb != nullptr && peb[2] != 0;
#else
    return false;
#endif
#else
    return false;
#endif
  }

  std::atomic<std::uint8_t> cached_verdict_{static_cast<std::uint8_t>(Verdict::kUnknown)};
};

}  // namespace eippf::runtime

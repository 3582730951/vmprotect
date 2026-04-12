#include "runtime/string_token_runtime.hpp"
#include "runtime/analysis_marker_scan.hpp"

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
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#elif defined(__linux__)
#include <fcntl.h>
#include <linux/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace {

std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 37u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

#if defined(_WIN32) || defined(_WIN64)
bool peb_being_debugged() noexcept {
#if defined(_MSC_VER) && defined(_M_X64)
  const auto peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
#elif defined(_MSC_VER) && defined(_M_IX86)
  const auto peb = reinterpret_cast<const std::uint8_t*>(__readfsdword(0x30));
#else
  const std::uint8_t* peb = nullptr;
#endif
  return peb != nullptr && peb[2] != 0u;
}

bool windows_debugger_present() noexcept {
  if (::IsDebuggerPresent() != FALSE) {
    return true;
  }

  BOOL remote_debugger_present = FALSE;
  if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &remote_debugger_present) != FALSE &&
      remote_debugger_present != FALSE) {
    return true;
  }

  return peb_being_debugged();
}
#elif defined(__linux__)
long raw_syscall6(long number,
                  long arg0,
                  long arg1,
                  long arg2,
                  long arg3,
                  long arg4,
                  long arg5) noexcept {
#if defined(__x86_64__)
  long result = 0;
  register long r10 __asm__("r10") = arg3;
  register long r8 __asm__("r8") = arg4;
  register long r9 __asm__("r9") = arg5;
  __asm__ __volatile__("syscall"
                       : "=a"(result)
                       : "a"(number), "D"(arg0), "S"(arg1), "d"(arg2), "r"(r10), "r"(r8), "r"(r9)
                       : "rcx", "r11", "memory");
  return result;
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = number;
  register long x0 __asm__("x0") = arg0;
  register long x1 __asm__("x1") = arg1;
  register long x2 __asm__("x2") = arg2;
  register long x3 __asm__("x3") = arg3;
  register long x4 __asm__("x4") = arg4;
  register long x5 __asm__("x5") = arg5;
  __asm__ __volatile__("svc #0"
                       : "+r"(x0)
                       : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                       : "memory");
  return x0;
#else
  return ::syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
#endif
}

long raw_syscall3(long number, long arg0, long arg1, long arg2) noexcept {
  return raw_syscall6(number, arg0, arg1, arg2, 0, 0, 0);
}

long raw_syscall4(long number, long arg0, long arg1, long arg2, long arg3) noexcept {
  return raw_syscall6(number, arg0, arg1, arg2, arg3, 0, 0);
}

std::size_t c_string_length(const char* text) noexcept {
  if (text == nullptr) {
    return 0u;
  }
  std::size_t length = 0u;
  while (text[length] != '\0') {
    ++length;
  }
  return length;
}

bool read_linux_file(const char* path, char* dest, std::size_t capacity) noexcept {
  if (path == nullptr || dest == nullptr || capacity < 2u) {
    return false;
  }

  const long fd =
      raw_syscall4(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0) {
    return false;
  }

  const long size =
      raw_syscall3(SYS_read, fd, reinterpret_cast<long>(dest), static_cast<long>(capacity - 1u));
  (void)raw_syscall3(SYS_close, fd, 0, 0);
  if (size <= 0) {
    dest[0] = '\0';
    return false;
  }

  const std::size_t text_size = static_cast<std::size_t>(size);
  dest[text_size] = '\0';
  return true;
}

bool linux_status_trusted(const char* text) noexcept {
  return eippf::runtime::analysis::parse_tracer_pid_zero(text, c_string_length(text));
}

bool linux_maps_trusted(const char* text) noexcept {
  return text != nullptr && !eippf::runtime::analysis::contains_suspicious_marker(text);
}

bool linux_guard_ready() noexcept {
  if (raw_syscall6(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0, 0) != 0) {
    return false;
  }
#if defined(PR_SET_PTRACER)
  (void)raw_syscall6(SYS_prctl, PR_SET_PTRACER, 0, 0, 0, 0, 0);
#endif

  std::array<char, 4096u> status{};
  if (!read_linux_file("/proc/self/status", status.data(), status.size())) {
    return false;
  }
  if (!linux_status_trusted(status.data())) {
    return false;
  }

  std::array<char, 8192u> maps{};
  if (!read_linux_file("/proc/self/maps", maps.data(), maps.size())) {
    return false;
  }
  return linux_maps_trusted(maps.data());
}
#elif defined(__APPLE__)
bool apple_guard_ready() noexcept {
  return true;
}
#endif

}  // namespace

extern "C" void eippf_sd0(std::uint8_t* dest, const std::uint8_t* src, std::size_t size,
                          std::uint8_t key) {
  if (dest == nullptr || src == nullptr || size == 0u) {
    return;
  }

  for (std::size_t i = 0; i < size; ++i) {
    dest[i] = static_cast<std::uint8_t>(src[i] ^ stream_mask(key, i));
  }
}

extern "C" void eippf_sw0(std::uint8_t* data, std::size_t size) {
  if (data == nullptr || size == 0u) {
    return;
  }

  auto* volatile bytes = reinterpret_cast<volatile std::uint8_t*>(data);
  for (std::size_t i = 0; i < size; ++i) {
    bytes[i] = 0u;
  }

#if defined(_MSC_VER)
  _ReadWriteBarrier();
#elif defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : : "memory");
#endif
}

extern "C" int eippf_rg0(void) {
#if defined(_WIN32) || defined(_WIN64)
  return windows_debugger_present() ? 0 : 1;
#elif defined(__linux__)
  return linux_guard_ready() ? 1 : 0;
#elif defined(__APPLE__)
  return apple_guard_ready() ? 1 : 0;
#else
  return 1;
#endif
}

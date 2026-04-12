#include "runtime/string_token_runtime.hpp"
#include "runtime/analysis_marker_scan.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

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
#elif defined(__APPLE__)
#include <sys/ptrace.h>
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
bool read_linux_file(const char* path, char* dest, std::size_t capacity) noexcept {
  if (path == nullptr || dest == nullptr || capacity < 2u) {
    return false;
  }

  const long fd = ::syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0) {
    return false;
  }

  const long size = ::syscall(SYS_read, fd, dest, capacity - 1u);
  (void)::syscall(SYS_close, fd);
  if (size <= 0) {
    dest[0] = '\0';
    return false;
  }

  const std::size_t text_size = static_cast<std::size_t>(size);
  dest[text_size] = '\0';
  return true;
}

bool linux_status_trusted(const char* text) noexcept {
  return eippf::runtime::analysis::parse_tracer_pid_zero(text, std::strlen(text));
}

bool linux_maps_trusted(const char* text) noexcept {
  return text != nullptr && !eippf::runtime::analysis::contains_suspicious_marker(text);
}

bool linux_guard_ready() noexcept {
  if (::syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
    return false;
  }
#if defined(PR_SET_PTRACER)
  (void)::syscall(SYS_prctl, PR_SET_PTRACER, 0, 0, 0, 0);
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

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "runtime/analysis_marker_scan.hpp"
#include "runtime/memory_hal.hpp"
#include "runtime/spin_lock.hpp"

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <intrin.h>
#include <windows.h>
#include "bootstrap/os_hal_windows.hpp"
#else
#include <cerrno>
#if defined(__APPLE__) && defined(__MACH__)
#include <TargetConditionals.h>
#endif
#if defined(__linux__)
#include <fcntl.h>
#include <sys/syscall.h>
#endif
#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/mman.h>
#include <sys/types.h>
#endif
#if defined(__APPLE__) && defined(__MACH__) && (!defined(TARGET_OS_IPHONE) || TARGET_OS_IPHONE == 0)
#include <sys/ptrace.h>
#endif
#if defined(__linux__)
#include <elf.h>
#include <link.h>
#endif
#if defined(__APPLE__) && defined(__MACH__)
#include <dlfcn.h>
#endif
#include <unistd.h>
#endif

namespace {

constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;
constexpr std::size_t kMaxDecodedApiNameBytes = 64u;
constexpr std::size_t kMaxDecodedModuleNameBytes = 32u;
constexpr std::size_t kResolverCacheCapacity = 256u;
constexpr std::uint32_t kJitEnclaveProbeGateChecked = 0x1u;
constexpr std::uint32_t kJitEnclaveProbeResolveAttempted = 0x2u;
constexpr std::uint32_t kJitEnclaveProbeExecAllocAttempted = 0x4u;
constexpr std::uint32_t kJitEnclaveProbeWxTransitioned = 0x8u;
constexpr const char* kJitRouteForbiddenForTarget = "jit_route_forbidden_for_target";

thread_local const char* g_last_gate_code = "";
thread_local std::uint32_t g_jit_enclave_probe_flags = 0u;

struct ResolverCacheEntry final {
  std::uint64_t hash = 0u;
  void* symbol = nullptr;
  bool occupied = false;
};

constexpr std::uint64_t fnv1a_step(std::uint64_t hash, std::uint8_t value) noexcept {
  hash ^= static_cast<std::uint64_t>(value);
  hash *= kFnv1aPrime;
  return hash;
}

constexpr std::uint64_t fnv1a_hash_cstr(const char* text) noexcept {
  if (text == nullptr) {
    return 0u;
  }

  std::uint64_t hash = kFnv1aOffset;
  for (const char* cursor = text; *cursor != '\0'; ++cursor) {
    hash = fnv1a_step(hash, static_cast<std::uint8_t>(static_cast<unsigned char>(*cursor)));
  }
  return hash;
}

template <std::size_t N>
constexpr std::uint64_t fnv1a_hash_literal(const char (&text)[N]) noexcept {
  std::uint64_t hash = kFnv1aOffset;
  for (std::size_t i = 0; i + 1u < N; ++i) {
    hash = fnv1a_step(hash, static_cast<std::uint8_t>(text[i]));
  }
  return hash;
}

constexpr std::uint8_t obfuscation_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 41u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

template <std::size_t Capacity>
struct EncodedField final {
  std::array<std::uint8_t, Capacity> bytes{};
  std::uint8_t key = 0u;
  std::uint8_t length = 0u;
};

template <std::size_t Capacity, std::size_t N>
constexpr EncodedField<Capacity> encode_field(const char (&text)[N], std::uint8_t key_salt) noexcept {
  static_assert(N <= Capacity, "encoded field capacity is too small");

  EncodedField<Capacity> field{};
  std::uint64_t seed = fnv1a_hash_literal(text) ^ (static_cast<std::uint64_t>(N) << 17u) ^
                       (static_cast<std::uint64_t>(key_salt) << 9u);
  std::uint8_t key =
      static_cast<std::uint8_t>((seed ^ (seed >> 11u) ^ (seed >> 29u) ^ (seed >> 47u)) & 0xFFu);
  if (key == 0u) {
    key = 0xA5u;
  }

  field.key = key;
  field.length = static_cast<std::uint8_t>(N);
  for (std::size_t i = 0; i < N; ++i) {
    field.bytes[i] = static_cast<std::uint8_t>(text[i]) ^ obfuscation_mask(key, i);
  }
  return field;
}

template <std::size_t Capacity>
bool decode_field(const EncodedField<Capacity>& field, std::array<char, Capacity>& output) noexcept {
  if (field.length == 0u || field.length > Capacity) {
    return false;
  }

  for (std::size_t i = 0; i < field.length; ++i) {
    output[i] = static_cast<char>(field.bytes[i] ^ obfuscation_mask(field.key, i));
  }
  return output[field.length - 1u] == '\0';
}

void secure_zero_buffer(void* data, std::size_t size) noexcept {
  if (data == nullptr || size == 0u) {
    return;
  }

  auto* bytes = static_cast<volatile std::uint8_t*>(data);
  for (std::size_t i = 0; i < size; ++i) {
    bytes[i] = 0u;
  }

#if defined(_MSC_VER)
  _ReadWriteBarrier();
#elif defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : : "memory");
#endif
}

template <std::size_t N>
void secure_zero_buffer(std::array<char, N>& buffer) noexcept {
  secure_zero_buffer(buffer.data(), buffer.size());
}

[[noreturn]] void fail_closed_now() noexcept {
#if defined(_WIN32)
  std::abort();
#else
  ::_exit(137);
#endif
}

enum class RuntimeInitState : std::uint8_t {
  kUninitialized = 0u,
  kInitializing = 1u,
  kReady = 2u,
  kPoisoned = 3u,
};

std::atomic<RuntimeInitState>& init_state() noexcept {
  static std::atomic<RuntimeInitState> state(RuntimeInitState::kUninitialized);
  return state;
}

void ensure_runtime_initialized() noexcept;

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

#if defined(__linux__)
#if defined(__x86_64__)
long raw_syscall6(long number,
                  long arg0,
                  long arg1,
                  long arg2,
                  long arg3,
                  long arg4,
                  long arg5) noexcept {
  long result = 0;
  register long r10 __asm__("r10") = arg3;
  register long r8 __asm__("r8") = arg4;
  register long r9 __asm__("r9") = arg5;
  __asm__ __volatile__("syscall"
                       : "=a"(result)
                       : "a"(number), "D"(arg0), "S"(arg1), "d"(arg2), "r"(r10), "r"(r8), "r"(r9)
                       : "rcx", "r11", "memory");
  return result;
}
#elif defined(__aarch64__)
long raw_syscall6(long number,
                  long arg0,
                  long arg1,
                  long arg2,
                  long arg3,
                  long arg4,
                  long arg5) noexcept {
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
}
#else
long raw_syscall6(long number,
                  long arg0,
                  long arg1,
                  long arg2,
                  long arg3,
                  long arg4,
                  long arg5) noexcept {
  return ::syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
}
#endif

long raw_syscall3(long number, long arg0, long arg1, long arg2) noexcept {
  return raw_syscall6(number, arg0, arg1, arg2, 0, 0, 0);
}

long raw_syscall4(long number, long arg0, long arg1, long arg2, long arg3) noexcept {
  return raw_syscall6(number, arg0, arg1, arg2, arg3, 0, 0);
}
#endif

#if defined(__linux__)
bool read_linux_text_file(const char* path, char* dest, std::size_t capacity) noexcept {
  if (path == nullptr || dest == nullptr || capacity < 2u) {
    return false;
  }

  const long fd = raw_syscall4(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0) {
    return false;
  }

  const long read_size =
      raw_syscall3(SYS_read, fd, reinterpret_cast<long>(dest), static_cast<long>(capacity - 1u));
  (void)raw_syscall3(SYS_close, fd, 0, 0);
  if (read_size <= 0) {
    dest[0] = '\0';
    return false;
  }

  const std::size_t text_size = static_cast<std::size_t>(read_size);
  dest[text_size] = '\0';
  return true;
}

bool linux_tracer_pid_is_zero(const char* text) noexcept {
  return eippf::runtime::analysis::parse_tracer_pid_zero(text, c_string_length(text));
}

bool contains_suspicious_linux_module(const char* text) noexcept {
  return eippf::runtime::analysis::contains_suspicious_marker(text);
}

bool linux_maps_are_trusted(const char* text) noexcept {
  return text != nullptr && !contains_suspicious_linux_module(text);
}
#endif

bool anti_tamper_check_passed() noexcept {
#if defined(_WIN32) || defined(_WIN64)
  if (::IsDebuggerPresent() != FALSE) {
    return false;
  }

  BOOL has_remote_debugger = FALSE;
  if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &has_remote_debugger) != FALSE &&
      has_remote_debugger != FALSE) {
    return false;
  }

#if defined(_M_X64)
  const auto* peb = reinterpret_cast<const std::uint8_t*>(__readgsqword(0x60));
  if (peb == nullptr) {
    return false;
  }
  return peb[2] == 0;
#elif defined(_M_IX86)
  const auto* peb = reinterpret_cast<const std::uint8_t*>(__readfsdword(0x30));
  if (peb == nullptr) {
    return false;
  }
  return peb[2] == 0;
#elif defined(_M_ARM64) || defined(_M_ARM)
  return has_remote_debugger == FALSE;
#else
  return false;
#endif
#elif defined(__linux__)
#if defined(__x86_64__) || defined(__i386__) || defined(__arm__) || defined(__aarch64__)
  std::array<char, 4096u> status{};
  if (!read_linux_text_file("/proc/self/status", status.data(), status.size())) {
    return false;
  }
  if (!linux_tracer_pid_is_zero(status.data())) {
    return false;
  }

  std::array<char, 8192u> maps{};
  if (!read_linux_text_file("/proc/self/maps", maps.data(), maps.size())) {
    return false;
  }
  return linux_maps_are_trusted(maps.data());
#else
  return false;
#endif
#elif defined(__APPLE__) && defined(__MACH__)
#if defined(__x86_64__) || defined(__i386__) || defined(__arm64__) || defined(__aarch64__)
#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
  return true;
#else
  errno = 0;
  const int ptrace_result = ::ptrace(PT_DENY_ATTACH, 0, static_cast<caddr_t>(nullptr), 0);
  return ptrace_result != -1;
#endif
#else
  return false;
#endif
#else
  return false;
#endif
}

void ensure_runtime_initialized() noexcept {
  RuntimeInitState observed = init_state().load(std::memory_order_acquire);
  if (observed == RuntimeInitState::kReady) {
    return;
  }
  if (observed == RuntimeInitState::kPoisoned) {
    fail_closed_now();
  }

  RuntimeInitState expected = RuntimeInitState::kUninitialized;
  if (init_state().compare_exchange_strong(expected,
                                           RuntimeInitState::kInitializing,
                                           std::memory_order_acq_rel,
                                           std::memory_order_acquire)) {
    if (!anti_tamper_check_passed()) {
      init_state().store(RuntimeInitState::kPoisoned, std::memory_order_release);
      fail_closed_now();
    }
    init_state().store(RuntimeInitState::kReady, std::memory_order_release);
    return;
  }

  for (;;) {
    observed = init_state().load(std::memory_order_acquire);
    if (observed == RuntimeInitState::kReady) {
      return;
    }
    if (observed == RuntimeInitState::kPoisoned) {
      fail_closed_now();
    }
  }
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor)) void eippf_runtime_constructor() noexcept {
  ensure_runtime_initialized();
}
#endif

class AntiTamperInitializer final {
 public:
  AntiTamperInitializer() noexcept { ensure_runtime_initialized(); }
};

[[maybe_unused]] const AntiTamperInitializer kAntiTamperInitializer{};

eippf::runtime::SpinLock& cache_mutex() noexcept {
  static eippf::runtime::SpinLock mutex;
  return mutex;
}

std::array<ResolverCacheEntry, kResolverCacheCapacity>& resolver_cache() noexcept {
  static std::array<ResolverCacheEntry, kResolverCacheCapacity> cache{};
  return cache;
}

void* lookup_cached_symbol(std::uint64_t hash) noexcept {
  auto& cache = resolver_cache();
  for (const ResolverCacheEntry& entry : cache) {
    if (entry.occupied && entry.hash == hash) {
      return entry.symbol;
    }
  }
  return nullptr;
}

void cache_resolved_symbol(std::uint64_t hash, void* symbol) noexcept {
  auto& cache = resolver_cache();
  std::size_t first_empty = kResolverCacheCapacity;

  for (std::size_t i = 0; i < cache.size(); ++i) {
    ResolverCacheEntry& entry = cache[i];
    if (entry.occupied && entry.hash == hash) {
      entry.symbol = symbol;
      return;
    }
    if (!entry.occupied && first_empty == kResolverCacheCapacity) {
      first_empty = i;
    }
  }

  if (first_empty != kResolverCacheCapacity) {
    cache[first_empty] = ResolverCacheEntry{hash, symbol, true};
    return;
  }

  ResolverCacheEntry& victim = cache[static_cast<std::size_t>(hash % cache.size())];
  victim.hash = hash;
  victim.symbol = symbol;
  victim.occupied = true;
}

struct ApiCandidate final {
  std::uint64_t api_hash = 0u;
  EncodedField<kMaxDecodedApiNameBytes> api_name{};
  EncodedField<kMaxDecodedModuleNameBytes> module_name{};
};

template <std::size_t NameN, std::size_t ModuleN>
constexpr ApiCandidate make_candidate(const char (&api_name)[NameN],
                                      const char (&module_name)[ModuleN],
                                      std::uint8_t salt) noexcept {
  ApiCandidate candidate{};
  candidate.api_hash = fnv1a_hash_literal(api_name);
  candidate.api_name = encode_field<kMaxDecodedApiNameBytes>(api_name, salt);
  candidate.module_name = encode_field<kMaxDecodedModuleNameBytes>(module_name,
                                                                   static_cast<std::uint8_t>(salt ^ 0x3Cu));
  return candidate;
}

#if defined(_WIN32) || defined(_WIN64)
constexpr std::array<ApiCandidate, 39> kApiCandidates = {{
    make_candidate("Sleep", "kernel32.dll", 0x10u),
    make_candidate("VirtualAlloc", "kernel32.dll", 0x11u),
    make_candidate("VirtualFree", "kernel32.dll", 0x12u),
    make_candidate("VirtualProtect", "kernel32.dll", 0x13u),
    make_candidate("LoadLibraryA", "kernel32.dll", 0x14u),
    make_candidate("LoadLibraryW", "kernel32.dll", 0x15u),
    make_candidate("GetProcAddress", "kernel32.dll", 0x16u),
    make_candidate("GetModuleHandleA", "kernel32.dll", 0x17u),
    make_candidate("GetModuleHandleW", "kernel32.dll", 0x18u),
    make_candidate("GetModuleFileNameA", "kernel32.dll", 0x19u),
    make_candidate("GetModuleFileNameW", "kernel32.dll", 0x1Au),
    make_candidate("GetLastError", "kernel32.dll", 0x1Bu),
    make_candidate("SetLastError", "kernel32.dll", 0x1Cu),
    make_candidate("CreateFileA", "kernel32.dll", 0x1Du),
    make_candidate("ReadFile", "kernel32.dll", 0x1Eu),
    make_candidate("WriteFile", "kernel32.dll", 0x1Fu),
    make_candidate("CloseHandle", "kernel32.dll", 0x20u),
    make_candidate("HeapAlloc", "kernel32.dll", 0x21u),
    make_candidate("HeapFree", "kernel32.dll", 0x22u),
    make_candidate("ExitProcess", "kernel32.dll", 0x23u),
    make_candidate("TerminateProcess", "kernel32.dll", 0x24u),
    make_candidate("RtlMoveMemory", "kernel32.dll", 0x25u),
    make_candidate("RtlFillMemory", "kernel32.dll", 0x26u),
    make_candidate("MessageBoxA", "user32.dll", 0x27u),
    make_candidate("MessageBoxW", "user32.dll", 0x28u),
    make_candidate("malloc", "ucrtbase.dll", 0x29u),
    make_candidate("free", "ucrtbase.dll", 0x2Au),
    make_candidate("calloc", "ucrtbase.dll", 0x2Bu),
    make_candidate("realloc", "ucrtbase.dll", 0x2Cu),
    make_candidate("memcpy", "ucrtbase.dll", 0x2Du),
    make_candidate("memmove", "ucrtbase.dll", 0x2Eu),
    make_candidate("memset", "ucrtbase.dll", 0x2Fu),
    make_candidate("memcmp", "ucrtbase.dll", 0x30u),
    make_candidate("getenv", "ucrtbase.dll", 0x31u),
    make_candidate("strtol", "ucrtbase.dll", 0x32u),
    make_candidate("puts", "ucrtbase.dll", 0x33u),
    make_candidate("printf", "ucrtbase.dll", 0x34u),
    make_candidate("malloc", "msvcrt.dll", 0x35u),
    make_candidate("free", "msvcrt.dll", 0x36u),
    make_candidate("getenv", "msvcrt.dll", 0x37u),
    make_candidate("strtol", "msvcrt.dll", 0x38u),
    make_candidate("puts", "msvcrt.dll", 0x39u),
}};
#else
constexpr std::array<ApiCandidate, 39> kApiCandidates = {{
    make_candidate("malloc", "libc.so.6", 0x41u),
    make_candidate("free", "libc.so.6", 0x42u),
    make_candidate("calloc", "libc.so.6", 0x43u),
    make_candidate("realloc", "libc.so.6", 0x44u),
    make_candidate("memcpy", "libc.so.6", 0x45u),
    make_candidate("memmove", "libc.so.6", 0x46u),
    make_candidate("memset", "libc.so.6", 0x47u),
    make_candidate("memcmp", "libc.so.6", 0x48u),
    make_candidate("strlen", "libc.so.6", 0x49u),
    make_candidate("strnlen", "libc.so.6", 0x4Au),
    make_candidate("strcmp", "libc.so.6", 0x4Bu),
    make_candidate("strncmp", "libc.so.6", 0x4Cu),
    make_candidate("strchr", "libc.so.6", 0x4Du),
    make_candidate("strrchr", "libc.so.6", 0x4Eu),
    make_candidate("strstr", "libc.so.6", 0x4Fu),
    make_candidate("getenv", "libc.so.6", 0x50u),
    make_candidate("strtol", "libc.so.6", 0x51u),
    make_candidate("usleep", "libc.so.6", 0x52u),
    make_candidate("printf", "libc.so.6", 0x53u),
    make_candidate("fprintf", "libc.so.6", 0x54u),
    make_candidate("snprintf", "libc.so.6", 0x55u),
    make_candidate("puts", "libc.so.6", 0x56u),
    make_candidate("fputs", "libc.so.6", 0x57u),
    make_candidate("fopen", "libc.so.6", 0x58u),
    make_candidate("fclose", "libc.so.6", 0x59u),
    make_candidate("fread", "libc.so.6", 0x5Au),
    make_candidate("fwrite", "libc.so.6", 0x5Bu),
    make_candidate("open", "libc.so.6", 0x5Cu),
    make_candidate("close", "libc.so.6", 0x5Du),
    make_candidate("read", "libc.so.6", 0x5Eu),
    make_candidate("write", "libc.so.6", 0x5Fu),
    make_candidate("mmap", "libc.so.6", 0x60u),
    make_candidate("munmap", "libc.so.6", 0x61u),
    make_candidate("mprotect", "libc.so.6", 0x62u),
    make_candidate("dlopen", "libdl.so.2", 0x63u),
    make_candidate("dlsym", "libdl.so.2", 0x64u),
    make_candidate("dlclose", "libdl.so.2", 0x65u),
    make_candidate("abort", "libc.so.6", 0x66u),
    make_candidate("exit", "libc.so.6", 0x67u),
}};
#endif

#if defined(__linux__)
const char* basename_ptr(const char* path) noexcept {
  if (path == nullptr) {
    return nullptr;
  }
  const char* cursor = path;
  const char* base = path;
  while (*cursor != '\0') {
    if (*cursor == '/') {
      base = cursor + 1;
    }
    ++cursor;
  }
  return base;
}

std::uintptr_t relocate_dynamic_ptr(std::uintptr_t base, std::uintptr_t value) noexcept {
  if (value == 0u) {
    return 0u;
  }
  return value < base ? base + value : value;
}

std::size_t gnu_hash_symbol_upper_bound(const std::uint32_t* gnu_hash) noexcept {
  if (gnu_hash == nullptr) {
    return 0u;
  }

  const std::uint32_t bucket_count = gnu_hash[0];
  const std::uint32_t symbol_offset = gnu_hash[1];
  const std::uint32_t bloom_size = gnu_hash[2];
  if (bucket_count == 0u) {
    return 0u;
  }

  const auto* bloom = reinterpret_cast<const ElfW(Addr)*>(gnu_hash + 4u);
  const auto* buckets = reinterpret_cast<const std::uint32_t*>(bloom + bloom_size);
  const auto* chains = buckets + bucket_count;

  std::uint32_t max_symbol_index = 0u;
  for (std::uint32_t bucket = 0u; bucket < bucket_count; ++bucket) {
    std::uint32_t symbol_index = buckets[bucket];
    if (symbol_index < symbol_offset) {
      continue;
    }

    std::uint32_t chain_index = symbol_index - symbol_offset;
    for (std::size_t guard = 0u; guard < (1u << 20u); ++guard) {
      const std::uint32_t hash = chains[chain_index];
      if ((hash & 1u) != 0u) {
        if (symbol_index > max_symbol_index) {
          max_symbol_index = symbol_index;
        }
        break;
      }
      ++symbol_index;
      ++chain_index;
    }
  }

  return max_symbol_index == 0u ? 0u : static_cast<std::size_t>(max_symbol_index) + 1u;
}

void* resolve_symbol_in_module(std::uintptr_t module_base,
                               const ElfW(Dyn)* dynamic,
                               std::uint64_t target_hash) noexcept {
  if (dynamic == nullptr) {
    return nullptr;
  }

  const char* strtab = nullptr;
  const ElfW(Sym)* symtab = nullptr;
  const std::uint32_t* sysv_hash = nullptr;
  const std::uint32_t* gnu_hash = nullptr;

  for (const ElfW(Dyn)* entry = dynamic; entry != nullptr && entry->d_tag != DT_NULL; ++entry) {
    switch (entry->d_tag) {
      case DT_STRTAB:
        strtab = reinterpret_cast<const char*>(
            relocate_dynamic_ptr(module_base, static_cast<std::uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_SYMTAB:
        symtab = reinterpret_cast<const ElfW(Sym)*>(
            relocate_dynamic_ptr(module_base, static_cast<std::uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_HASH:
        sysv_hash = reinterpret_cast<const std::uint32_t*>(
            relocate_dynamic_ptr(module_base, static_cast<std::uintptr_t>(entry->d_un.d_ptr)));
        break;
      case DT_GNU_HASH:
        gnu_hash = reinterpret_cast<const std::uint32_t*>(
            relocate_dynamic_ptr(module_base, static_cast<std::uintptr_t>(entry->d_un.d_ptr)));
        break;
      default:
        break;
    }
  }

  if (strtab == nullptr || symtab == nullptr) {
    return nullptr;
  }

  std::size_t symbol_count = 0u;
  if (sysv_hash != nullptr) {
    symbol_count = static_cast<std::size_t>(sysv_hash[1]);
  } else if (gnu_hash != nullptr) {
    symbol_count = gnu_hash_symbol_upper_bound(gnu_hash);
  }
  if (symbol_count == 0u) {
    return nullptr;
  }

  for (std::size_t i = 0; i < symbol_count; ++i) {
    const ElfW(Sym)& symbol = symtab[i];
    if (symbol.st_name == 0u || symbol.st_value == 0u || symbol.st_shndx == SHN_UNDEF) {
      continue;
    }

    const unsigned symbol_type = static_cast<unsigned>(symbol.st_info & 0x0Fu);
    if (symbol_type != STT_FUNC && symbol_type != STT_GNU_IFUNC && symbol_type != STT_NOTYPE) {
      continue;
    }

    const char* symbol_name = strtab + symbol.st_name;
    if (fnv1a_hash_cstr(symbol_name) != target_hash) {
      continue;
    }

    return reinterpret_cast<void*>(module_base + static_cast<std::uintptr_t>(symbol.st_value));
  }

  return nullptr;
}

const r_debug* runtime_debug_state() noexcept {
  for (const ElfW(Dyn)* entry = _DYNAMIC; entry != nullptr && entry->d_tag != DT_NULL; ++entry) {
    if (entry->d_tag == DT_DEBUG && entry->d_un.d_ptr != 0u) {
      return reinterpret_cast<const r_debug*>(entry->d_un.d_ptr);
    }
  }
  return nullptr;
}

void* resolve_symbol_linux(const char* module_name, std::uint64_t symbol_hash) noexcept {
  if (module_name == nullptr || *module_name == '\0') {
    return nullptr;
  }

  const r_debug* debug = runtime_debug_state();
  if (debug == nullptr) {
    return nullptr;
  }

  const std::uint64_t module_hash = fnv1a_hash_cstr(module_name);
  for (const link_map* cursor = debug->r_map; cursor != nullptr; cursor = cursor->l_next) {
    const char* module_path = cursor->l_name;
    if (module_path == nullptr || module_path[0] == '\0') {
      continue;
    }

    const char* basename = basename_ptr(module_path);
    if (basename == nullptr || fnv1a_hash_cstr(basename) != module_hash) {
      continue;
    }

    void* symbol = resolve_symbol_in_module(static_cast<std::uintptr_t>(cursor->l_addr),
                                            cursor->l_ld,
                                            symbol_hash);
    if (symbol != nullptr) {
      return symbol;
    }
  }
  return nullptr;
}

#endif

void* resolve_candidate(const ApiCandidate& candidate) noexcept {
  std::array<char, kMaxDecodedApiNameBytes> api_name{};
  if (!decode_field(candidate.api_name, api_name)) {
    secure_zero_buffer(api_name);
    return nullptr;
  }

  std::array<char, kMaxDecodedModuleNameBytes> module_name{};
  if (!decode_field(candidate.module_name, module_name)) {
    secure_zero_buffer(api_name);
    secure_zero_buffer(module_name);
    return nullptr;
  }

#if defined(_WIN32) || defined(_WIN64)
  const std::uint32_t module_hash =
      eippf::bootstrap::hal::windows::hash_ascii_ci(module_name.data());
  const std::uint64_t symbol_hash =
      eippf::bootstrap::hal::windows::hash_ascii_ci64(api_name.data());

  void* module_base = eippf::bootstrap::hal::windows::get_module_base(module_hash);
  void* symbol = module_base == nullptr
                     ? nullptr
                     : eippf::bootstrap::hal::windows::get_export_address(module_base, symbol_hash);
#elif defined(__linux__)
  void* symbol = resolve_symbol_linux(module_name.data(), candidate.api_hash);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)module_name;
  ::dlerror();
  void* symbol = ::dlsym(RTLD_DEFAULT, api_name.data());
  if (symbol == nullptr) {
    (void)::dlerror();
  }
#else
  void* symbol = nullptr;
#endif

  secure_zero_buffer(module_name);
  secure_zero_buffer(api_name);
  return symbol;
}

void* resolve_api_mvp(std::uint64_t hash) noexcept {
  for (const ApiCandidate& candidate : kApiCandidates) {
    if (candidate.api_hash != hash) {
      continue;
    }

    void* symbol = resolve_candidate(candidate);
    if (symbol != nullptr) {
      return symbol;
    }
  }
  return nullptr;
}

void* lookup_or_resolve(std::uint64_t hash) noexcept {
  eippf::runtime::SpinLockGuard lock(cache_mutex());
  if (void* cached = lookup_cached_symbol(hash); cached != nullptr) {
    return cached;
  }

  void* symbol = resolve_api_mvp(hash);
  if (symbol != nullptr) {
    cache_resolved_symbol(hash, symbol);
  }
  return symbol;
}

}  // namespace

extern "C" void* eippf_ra0(std::uint64_t hash) noexcept {
  ensure_runtime_initialized();
  if (hash == 0u) {
    return nullptr;
  }
  return lookup_or_resolve(hash);
}

extern "C" const char* eippf_jgc0() noexcept {
  return g_last_gate_code;
}

extern "C" void eippf_jgr0() noexcept {
  g_last_gate_code = "";
  g_jit_enclave_probe_flags = 0u;
}

extern "C" std::uint32_t eippf_jgf0() noexcept {
  return g_jit_enclave_probe_flags;
}

extern "C" void eippf_je0(const std::uint8_t* encrypted_payload, std::size_t size,
                          std::uint8_t key) noexcept {
  ensure_runtime_initialized();
  g_last_gate_code = "";
  g_jit_enclave_probe_flags = 0u;
  g_jit_enclave_probe_flags |= kJitEnclaveProbeGateChecked;
  if (!eippf::runtime::MemoryHAL::runtime_dynamic_code_allowed()) {
    g_last_gate_code = kJitRouteForbiddenForTarget;
    return;
  }
  if (encrypted_payload == nullptr || size == 0u) {
    return;
  }
  g_jit_enclave_probe_flags |= kJitEnclaveProbeResolveAttempted;

  using Resolver = eippf::runtime::DynamicAPIResolver<64u, 4u>;
  Resolver resolver;

  g_jit_enclave_probe_flags |= kJitEnclaveProbeExecAllocAttempted;
  eippf::runtime::MemoryHAL::Region region =
      eippf::runtime::MemoryHAL::allocate_rw(resolver, size);
  if (!region.valid()) {
    return;
  }

  auto release_region = [&]() noexcept {
    eippf::runtime::MemoryHAL::release(resolver, region);
  };

  auto* executable_bytes = static_cast<std::uint8_t*>(region.base);
  for (std::size_t i = 0; i < size; ++i) {
    executable_bytes[i] = static_cast<std::uint8_t>(encrypted_payload[i] ^ key);
  }

  if (!eippf::runtime::MemoryHAL::protect_rx(resolver, region)) {
    if (eippf::runtime::MemoryHAL::protect_rw(resolver, region)) {
      secure_zero_buffer(region.base, region.size);
    }
    release_region();
    return;
  }

  auto* payload_entry = reinterpret_cast<void (*)()>(region.base);
  payload_entry();

  if (eippf::runtime::MemoryHAL::protect_rw(resolver, region)) {
    g_jit_enclave_probe_flags |= kJitEnclaveProbeWxTransitioned;
    secure_zero_buffer(region.base, region.size);
  }

  release_region();
}

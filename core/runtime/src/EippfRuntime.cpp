#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <mutex>

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
#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
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
consteval std::uint64_t fnv1a_hash_literal(const char (&text)[N]) noexcept {
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
consteval EncodedField<Capacity> encode_field(const char (&text)[N], std::uint8_t key_salt) noexcept {
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
  kReady = 1u,
  kPoisoned = 2u,
};

std::atomic<RuntimeInitState>& init_state() noexcept {
  static std::atomic<RuntimeInitState> state(RuntimeInitState::kUninitialized);
  return state;
}

std::once_flag& init_once_flag() noexcept {
  static std::once_flag flag;
  return flag;
}

void ensure_runtime_initialized() noexcept;

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
  errno = 0;
  const long ptrace_result = ::ptrace(PTRACE_TRACEME, 0, nullptr, 0);
  return ptrace_result != -1;
#else
  return false;
#endif
#elif defined(__APPLE__) && defined(__MACH__)
#if defined(__x86_64__) || defined(__i386__) || defined(__arm64__) || defined(__aarch64__)
  errno = 0;
  const int ptrace_result = ::ptrace(PT_DENY_ATTACH, 0, static_cast<caddr_t>(nullptr), 0);
  return ptrace_result != -1;
#else
  return false;
#endif
#else
  return false;
#endif
}

void ensure_runtime_initialized() noexcept {
  std::call_once(init_once_flag(), []() noexcept {
    if (init_state().load(std::memory_order_acquire) == RuntimeInitState::kReady) {
      return;
    }
    if (!anti_tamper_check_passed()) {
      init_state().store(RuntimeInitState::kPoisoned, std::memory_order_release);
      fail_closed_now();
    }
    init_state().store(RuntimeInitState::kReady, std::memory_order_release);
  });

  if (init_state().load(std::memory_order_acquire) != RuntimeInitState::kReady) {
    fail_closed_now();
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

std::mutex& cache_mutex() noexcept {
  static std::mutex mutex;
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
consteval ApiCandidate make_candidate(const char (&api_name)[NameN],
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
constexpr std::array<ApiCandidate, 35> kApiCandidates = {{
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
    make_candidate("printf", "ucrtbase.dll", 0x31u),
    make_candidate("malloc", "msvcrt.dll", 0x32u),
    make_candidate("free", "msvcrt.dll", 0x33u),
}};
#else
constexpr std::array<ApiCandidate, 36> kApiCandidates = {{
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
    make_candidate("printf", "libc.so.6", 0x50u),
    make_candidate("fprintf", "libc.so.6", 0x51u),
    make_candidate("snprintf", "libc.so.6", 0x52u),
    make_candidate("puts", "libc.so.6", 0x53u),
    make_candidate("fputs", "libc.so.6", 0x54u),
    make_candidate("fopen", "libc.so.6", 0x55u),
    make_candidate("fclose", "libc.so.6", 0x56u),
    make_candidate("fread", "libc.so.6", 0x57u),
    make_candidate("fwrite", "libc.so.6", 0x58u),
    make_candidate("open", "libc.so.6", 0x59u),
    make_candidate("close", "libc.so.6", 0x5Au),
    make_candidate("read", "libc.so.6", 0x5Bu),
    make_candidate("write", "libc.so.6", 0x5Cu),
    make_candidate("mmap", "libc.so.6", 0x5Du),
    make_candidate("munmap", "libc.so.6", 0x5Eu),
    make_candidate("mprotect", "libc.so.6", 0x5Fu),
    make_candidate("dlopen", "libdl.so.2", 0x60u),
    make_candidate("dlsym", "libdl.so.2", 0x61u),
    make_candidate("dlclose", "libdl.so.2", 0x62u),
    make_candidate("abort", "libc.so.6", 0x63u),
    make_candidate("exit", "libc.so.6", 0x64u),
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

void* resolve_symbol_in_module(const dl_phdr_info& info, std::uint64_t target_hash) noexcept {
  const std::uintptr_t module_base = static_cast<std::uintptr_t>(info.dlpi_addr);
  const ElfW(Phdr)* dynamic_header = nullptr;

  for (ElfW(Half) i = 0; i < info.dlpi_phnum; ++i) {
    if (info.dlpi_phdr[i].p_type == PT_DYNAMIC) {
      dynamic_header = &info.dlpi_phdr[i];
      break;
    }
  }
  if (dynamic_header == nullptr) {
    return nullptr;
  }

  const auto* dynamic = reinterpret_cast<const ElfW(Dyn)*>(module_base + dynamic_header->p_vaddr);
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

struct LinuxLookupContext {
  std::uint64_t module_hash = 0u;
  std::uint64_t symbol_hash = 0u;
  void* result = nullptr;
};

int linux_lookup_callback(dl_phdr_info* info, std::size_t, void* userdata) noexcept {
  auto* ctx = static_cast<LinuxLookupContext*>(userdata);
  if (ctx == nullptr || info == nullptr || ctx->result != nullptr) {
    return 1;
  }

  const char* module_path = info->dlpi_name;
  if (module_path == nullptr || module_path[0] == '\0') {
    return 0;
  }

  const char* module_name = basename_ptr(module_path);
  if (module_name == nullptr || fnv1a_hash_cstr(module_name) != ctx->module_hash) {
    return 0;
  }

  ctx->result = resolve_symbol_in_module(*info, ctx->symbol_hash);
  return ctx->result != nullptr ? 1 : 0;
}

void* resolve_symbol_linux(const char* module_name, std::uint64_t symbol_hash) noexcept {
  LinuxLookupContext context{};
  context.module_hash = fnv1a_hash_cstr(module_name);
  context.symbol_hash = symbol_hash;

  ::dl_iterate_phdr(linux_lookup_callback, &context);
  return context.result;
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
  std::lock_guard<std::mutex> lock(cache_mutex());
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

extern "C" void* eippf_resolve_api(std::uint64_t hash) noexcept {
  ensure_runtime_initialized();
  if (hash == 0u) {
    return nullptr;
  }
  return lookup_or_resolve(hash);
}

extern "C" void eippf_execute_jit_enclave(const std::uint8_t* encrypted_payload, std::size_t size,
                                          std::uint8_t key) noexcept {
  ensure_runtime_initialized();
  if (encrypted_payload == nullptr || size == 0u) {
    return;
  }

#if defined(_WIN32) || defined(_WIN64)
  using VirtualAllocFn = void* (WINAPI*)(void*, SIZE_T, DWORD, DWORD);
  using VirtualFreeFn = BOOL(WINAPI*)(void*, SIZE_T, DWORD);

  auto* virtual_alloc = reinterpret_cast<VirtualAllocFn>(
      eippf_resolve_api(fnv1a_hash_literal("VirtualAlloc")));
  auto* virtual_free = reinterpret_cast<VirtualFreeFn>(
      eippf_resolve_api(fnv1a_hash_literal("VirtualFree")));
  if (virtual_alloc == nullptr || virtual_free == nullptr) {
    return;
  }

  void* executable_page = virtual_alloc(
      nullptr, static_cast<SIZE_T>(size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (executable_page == nullptr) {
    return;
  }

  auto* executable_bytes = static_cast<std::uint8_t*>(executable_page);
  for (std::size_t i = 0; i < size; ++i) {
    executable_bytes[i] = static_cast<std::uint8_t>(encrypted_payload[i] ^ key);
  }

  auto* payload_entry = reinterpret_cast<void (*)()>(executable_page);
  payload_entry();

  auto* shred_bytes = static_cast<volatile std::uint8_t*>(executable_page);
  for (std::size_t i = 0; i < size; ++i) {
    shred_bytes[i] = 0u;
  }
#if defined(_MSC_VER)
  _ReadWriteBarrier();
#elif defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : : "memory");
#endif

  (void)virtual_free(executable_page, 0u, MEM_RELEASE);
#elif defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))
  using MmapFn = void* (*)(void*, std::size_t, int, int, int, off_t);
  using MunmapFn = int (*)(void*, std::size_t);

  auto* mmap_fn = reinterpret_cast<MmapFn>(eippf_resolve_api(fnv1a_hash_literal("mmap")));
  auto* munmap_fn = reinterpret_cast<MunmapFn>(eippf_resolve_api(fnv1a_hash_literal("munmap")));
  if (mmap_fn == nullptr || munmap_fn == nullptr) {
    return;
  }

  int map_flags = MAP_PRIVATE;
#if defined(MAP_ANONYMOUS)
  map_flags |= MAP_ANONYMOUS;
#elif defined(MAP_ANON)
  map_flags |= MAP_ANON;
#else
  return;
#endif

  void* executable_page = mmap_fn(
      nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, map_flags, -1, static_cast<off_t>(0));
  if (executable_page == MAP_FAILED || executable_page == nullptr) {
    return;
  }

  auto* executable_bytes = static_cast<std::uint8_t*>(executable_page);
  for (std::size_t i = 0; i < size; ++i) {
    executable_bytes[i] = static_cast<std::uint8_t>(encrypted_payload[i] ^ key);
  }

  auto* payload_entry = reinterpret_cast<void (*)()>(executable_page);
  payload_entry();

  auto* shred_bytes = static_cast<volatile std::uint8_t*>(executable_page);
  for (std::size_t i = 0; i < size; ++i) {
    shred_bytes[i] = 0u;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : : "memory");
#endif

  (void)munmap_fn(executable_page, size);
#else
  (void)encrypted_payload;
  (void)size;
  (void)key;
#endif
}

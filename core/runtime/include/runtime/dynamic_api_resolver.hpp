#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

#include "runtime/constexpr_obfuscated_string.hpp"
#include "runtime/os_hal_standard.hpp"
#include "runtime/spin_lock.hpp"

namespace eippf::runtime {

template <std::size_t kMaxSymbolCache = 128u, std::size_t kMaxModuleCache = 8u>
class DynamicAPIResolver final {
 public:
  static_assert(kMaxSymbolCache > 0u, "kMaxSymbolCache must be > 0");
  static_assert(kMaxModuleCache > 0u, "kMaxModuleCache must be > 0");

  DynamicAPIResolver() noexcept = default;
  DynamicAPIResolver(const DynamicAPIResolver&) = delete;
  DynamicAPIResolver& operator=(const DynamicAPIResolver&) = delete;

  ~DynamicAPIResolver() { wipe(); }

  template <typename FunctionT,
            std::uint8_t ModuleKey,
            std::size_t ModuleN,
            std::uint8_t SymbolKey,
            std::size_t SymbolN>
  [[nodiscard]] FunctionT resolve(
      const security::ConstexprObfuscatedString<ModuleKey, ModuleN>& module_name,
      const security::ConstexprObfuscatedString<SymbolKey, SymbolN>& symbol_name) noexcept {
    auto decoded_module = module_name.decrypt();
    auto decoded_symbol = symbol_name.decrypt();

    const std::uint64_t module_hash = fnv1a_hash(decoded_module.c_str());
    const std::uint64_t symbol_hash = fnv1a_hash(decoded_symbol.c_str());
    const std::uint64_t symbol_key = combine_hashes(module_hash, symbol_hash);

    SpinLockGuard lock(mutex_);
    if (void* cached = lookup_symbol_locked(symbol_key); cached != nullptr) {
      decoded_module.wipe();
      decoded_symbol.wipe();
      return reinterpret_cast<FunctionT>(cached);
    }

    LibraryLoader* module = ensure_module_locked(module_hash, decoded_module.c_str());
    void* resolved_symbol = nullptr;
    if (module != nullptr) {
      const std::optional<void*> resolved = module->resolve(decoded_symbol.c_str());
      if (resolved.has_value()) {
        resolved_symbol = *resolved;
        cache_symbol_locked(symbol_key, resolved_symbol);
      }
    }

    decoded_module.wipe();
    decoded_symbol.wipe();
    return reinterpret_cast<FunctionT>(resolved_symbol);
  }

  void wipe() noexcept {
    SpinLockGuard lock(mutex_);

    for (ModuleCacheEntry& module : modules_) {
      if (module.occupied) {
        module.loader.reset();
      }
      module.module_hash = 0u;
      module.occupied = false;
    }

    for (SymbolCacheEntry& symbol : symbols_) {
      symbol.cache_key = 0u;
      symbol.address = nullptr;
      symbol.occupied = false;
    }
  }

  [[nodiscard]] std::size_t cached_symbol_count_for_testing() const noexcept {
    SpinLockGuard lock(mutex_);
    std::size_t used = 0u;
    for (const SymbolCacheEntry& symbol : symbols_) {
      used += symbol.occupied ? 1u : 0u;
    }
    return used;
  }

 private:
  struct SymbolCacheEntry final {
    std::uint64_t cache_key = 0u;
    void* address = nullptr;
    bool occupied = false;
  };

  struct ModuleCacheEntry final {
    std::uint64_t module_hash = 0u;
    LibraryLoader loader{};
    bool occupied = false;
  };

  static constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
  static constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;

  [[nodiscard]] static constexpr std::uint64_t fnv1a_step(std::uint64_t hash,
                                                          std::uint8_t value) noexcept {
    hash ^= static_cast<std::uint64_t>(value);
    hash *= kFnv1aPrime;
    return hash;
  }

  [[nodiscard]] static std::uint64_t fnv1a_hash(const char* text) noexcept {
    if (text == nullptr) {
      return 0u;
    }
    std::uint64_t hash = kFnv1aOffset;
    for (const char* cursor = text; *cursor != '\0'; ++cursor) {
      hash = fnv1a_step(hash, static_cast<std::uint8_t>(static_cast<unsigned char>(*cursor)));
    }
    return hash;
  }

  [[nodiscard]] static std::uint64_t combine_hashes(std::uint64_t module_hash,
                                                    std::uint64_t symbol_hash) noexcept {
    std::uint64_t hash = kFnv1aOffset;
    for (std::size_t i = 0; i < 8u; ++i) {
      const std::uint8_t byte =
          static_cast<std::uint8_t>((module_hash >> static_cast<unsigned>(i * 8u)) & 0xFFull);
      hash = fnv1a_step(hash, byte);
    }
    for (std::size_t i = 0; i < 8u; ++i) {
      const std::uint8_t byte =
          static_cast<std::uint8_t>((symbol_hash >> static_cast<unsigned>(i * 8u)) & 0xFFull);
      hash = fnv1a_step(hash, byte);
    }
    return hash;
  }

  [[nodiscard]] void* lookup_symbol_locked(std::uint64_t symbol_key) noexcept {
    for (const SymbolCacheEntry& symbol : symbols_) {
      if (symbol.occupied && symbol.cache_key == symbol_key) {
        return symbol.address;
      }
    }
    return nullptr;
  }

  void cache_symbol_locked(std::uint64_t symbol_key, void* address) noexcept {
    std::size_t first_free = kMaxSymbolCache;
    for (std::size_t i = 0; i < symbols_.size(); ++i) {
      SymbolCacheEntry& symbol = symbols_[i];
      if (symbol.occupied && symbol.cache_key == symbol_key) {
        symbol.address = address;
        return;
      }
      if (!symbol.occupied && first_free == kMaxSymbolCache) {
        first_free = i;
      }
    }

    if (first_free != kMaxSymbolCache) {
      symbols_[first_free] = SymbolCacheEntry{symbol_key, address, true};
      return;
    }

    SymbolCacheEntry& victim = symbols_[static_cast<std::size_t>(symbol_key % symbols_.size())];
    victim.cache_key = symbol_key;
    victim.address = address;
    victim.occupied = true;
  }

  [[nodiscard]] LibraryLoader* ensure_module_locked(std::uint64_t module_hash,
                                                    const char* module_name) noexcept {
    for (ModuleCacheEntry& module : modules_) {
      if (module.occupied && module.module_hash == module_hash && module.loader.valid()) {
        return &module.loader;
      }
    }

    std::optional<LibraryLoader> opened = LibraryLoader::open(module_name);
    if (!opened.has_value()) {
      opened = LibraryLoader::open_self();
      if (!opened.has_value()) {
        return nullptr;
      }
    }

    std::size_t slot = kMaxModuleCache;
    for (std::size_t i = 0; i < modules_.size(); ++i) {
      if (!modules_[i].occupied) {
        slot = i;
        break;
      }
    }
    if (slot == kMaxModuleCache) {
      slot = static_cast<std::size_t>(module_hash % modules_.size());
      modules_[slot].loader.reset();
    }

    ModuleCacheEntry& entry = modules_[slot];
    entry.loader = std::move(*opened);
    entry.module_hash = module_hash;
    entry.occupied = true;
    return &entry.loader;
  }

  mutable SpinLock mutex_{};
  std::array<SymbolCacheEntry, kMaxSymbolCache> symbols_{};
  std::array<ModuleCacheEntry, kMaxModuleCache> modules_{};
};

}  // namespace eippf::runtime

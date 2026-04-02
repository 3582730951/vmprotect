#pragma once

#include <optional>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace eippf::runtime {

class LibraryLoader final {
 public:
#if defined(_WIN32)
  using native_handle_type = HMODULE;
#else
  using native_handle_type = void*;
#endif

  LibraryLoader() noexcept = default;
  LibraryLoader(native_handle_type handle, bool owned) noexcept : handle_(handle), owned_(owned) {}

  LibraryLoader(const LibraryLoader&) = delete;
  LibraryLoader& operator=(const LibraryLoader&) = delete;

  LibraryLoader(LibraryLoader&& other) noexcept { move_from(other); }

  LibraryLoader& operator=(LibraryLoader&& other) noexcept {
    if (this != &other) {
      reset();
      move_from(other);
    }
    return *this;
  }

  ~LibraryLoader() { reset(); }

  static std::optional<LibraryLoader> open(const char* library_path) noexcept {
    if (library_path == nullptr || *library_path == '\0') {
      return std::nullopt;
    }

#if defined(_WIN32)
    HMODULE mod = ::LoadLibraryA(library_path);
    if (mod == nullptr) {
      return std::nullopt;
    }
    return LibraryLoader(mod, true);
#else
    void* mod = ::dlopen(library_path, RTLD_NOW | RTLD_LOCAL);
    if (mod == nullptr) {
      return std::nullopt;
    }
    return LibraryLoader(mod, true);
#endif
  }

  static std::optional<LibraryLoader> open_self() noexcept {
#if defined(_WIN32)
    HMODULE mod = ::GetModuleHandleA(nullptr);
    if (mod == nullptr) {
      return std::nullopt;
    }
    return LibraryLoader(mod, false);
#else
    void* mod = ::dlopen(nullptr, RTLD_NOW | RTLD_LOCAL);
    if (mod == nullptr) {
      return std::nullopt;
    }
    return LibraryLoader(mod, true);
#endif
  }

  [[nodiscard]] bool valid() const noexcept { return handle_ != nullptr; }
  [[nodiscard]] native_handle_type native_handle() const noexcept { return handle_; }

  std::optional<void*> resolve(const char* symbol_name) const noexcept {
    if (handle_ == nullptr || symbol_name == nullptr || *symbol_name == '\0') {
      return std::nullopt;
    }

#if defined(_WIN32)
    FARPROC symbol = ::GetProcAddress(handle_, symbol_name);
    if (symbol == nullptr) {
      return std::nullopt;
    }
    return reinterpret_cast<void*>(symbol);
#else
    ::dlerror();
    void* symbol = ::dlsym(handle_, symbol_name);
    if (symbol == nullptr) {
      (void)::dlerror();
      return std::nullopt;
    }
    return symbol;
#endif
  }

  void reset() noexcept {
    if (handle_ == nullptr || !owned_) {
      handle_ = nullptr;
      owned_ = false;
      return;
    }

#if defined(_WIN32)
    (void)::FreeLibrary(handle_);
#else
    (void)::dlclose(handle_);
#endif
    handle_ = nullptr;
    owned_ = false;
  }

 private:
  void move_from(LibraryLoader& other) noexcept {
    handle_ = other.handle_;
    owned_ = other.owned_;
    other.handle_ = nullptr;
    other.owned_ = false;
  }

  native_handle_type handle_ = nullptr;
  bool owned_ = false;
};

}  // namespace eippf::runtime


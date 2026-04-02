#pragma once

#include <cstddef>
#include <cstdint>

namespace eippf::bootstrap::hal::windows {

constexpr std::uint32_t kFnv1aOffset = 2166136261u;
constexpr std::uint32_t kFnv1aPrime = 16777619u;
constexpr std::uint64_t kFnv1aOffset64 = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime64 = 1099511628211ull;

constexpr std::uint16_t kImageDosSignature = 0x5A4Du;
constexpr std::uint32_t kImageNtSignature = 0x00004550u;
constexpr std::uint16_t kImageNtOptionalHdr32Magic = 0x10Bu;
constexpr std::uint16_t kImageNtOptionalHdr64Magic = 0x20Bu;
constexpr std::size_t kImageDirectoryEntryExport = 0u;

constexpr std::uint8_t ascii_to_lower(std::uint8_t value) noexcept {
  return (value >= static_cast<std::uint8_t>('A') && value <= static_cast<std::uint8_t>('Z'))
             ? static_cast<std::uint8_t>(value + 0x20u)
             : value;
}

constexpr std::uint32_t hash_ascii_literal(const char* text) noexcept {
  std::uint32_t hash = kFnv1aOffset;
  if (text == nullptr) {
    return hash;
  }

  for (std::size_t i = 0; text[i] != '\0'; ++i) {
    hash ^= static_cast<std::uint32_t>(ascii_to_lower(static_cast<std::uint8_t>(text[i])));
    hash *= kFnv1aPrime;
  }
  return hash;
}

inline std::uint32_t hash_ascii_ci(const char* text) noexcept {
  std::uint32_t hash = kFnv1aOffset;
  if (text == nullptr) {
    return hash;
  }
  for (std::size_t i = 0; text[i] != '\0'; ++i) {
    hash ^= static_cast<std::uint32_t>(ascii_to_lower(static_cast<std::uint8_t>(text[i])));
    hash *= kFnv1aPrime;
  }
  return hash;
}

inline std::uint64_t hash_ascii_ci64(const char* text) noexcept {
  std::uint64_t hash = kFnv1aOffset64;
  if (text == nullptr) {
    return hash;
  }
  for (std::size_t i = 0; text[i] != '\0'; ++i) {
    hash ^= static_cast<std::uint64_t>(ascii_to_lower(static_cast<std::uint8_t>(text[i])));
    hash *= kFnv1aPrime64;
  }
  return hash;
}

inline std::uint32_t hash_wide_ci(const wchar_t* text, std::size_t char_count) noexcept {
  std::uint32_t hash = kFnv1aOffset;
  if (text == nullptr) {
    return hash;
  }

  for (std::size_t i = 0; i < char_count; ++i) {
    const std::uint32_t ch = static_cast<std::uint32_t>(text[i]);
    const std::uint8_t low = ascii_to_lower(static_cast<std::uint8_t>(ch & 0xFFu));
    hash ^= static_cast<std::uint32_t>(low);
    hash *= kFnv1aPrime;
  }
  return hash;
}

struct LIST_ENTRY {
  LIST_ENTRY* Flink;
  LIST_ENTRY* Blink;
};

struct UNICODE_STRING {
  std::uint16_t Length;
  std::uint16_t MaximumLength;
  wchar_t* Buffer;
};

struct PEB_LDR_DATA {
  std::uint32_t Length;
  std::uint8_t Initialized;
  std::uint8_t Reserved1[3];
  void* SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  void* DllBase;
  void* EntryPoint;
  std::uint32_t SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
};

struct PEB {
  std::uint8_t InheritedAddressSpace;
  std::uint8_t ReadImageFileExecOptions;
  std::uint8_t BeingDebugged;
  std::uint8_t BitField;
  void* Mutant;
  void* ImageBaseAddress;
  PEB_LDR_DATA* Ldr;
};

struct IMAGE_DOS_HEADER {
  std::uint16_t e_magic;
  std::uint16_t e_cblp;
  std::uint16_t e_cp;
  std::uint16_t e_crlc;
  std::uint16_t e_cparhdr;
  std::uint16_t e_minalloc;
  std::uint16_t e_maxalloc;
  std::uint16_t e_ss;
  std::uint16_t e_sp;
  std::uint16_t e_csum;
  std::uint16_t e_ip;
  std::uint16_t e_cs;
  std::uint16_t e_lfarlc;
  std::uint16_t e_ovno;
  std::uint16_t e_res[4];
  std::uint16_t e_oemid;
  std::uint16_t e_oeminfo;
  std::uint16_t e_res2[10];
  std::int32_t e_lfanew;
};

struct IMAGE_FILE_HEADER {
  std::uint16_t Machine;
  std::uint16_t NumberOfSections;
  std::uint32_t TimeDateStamp;
  std::uint32_t PointerToSymbolTable;
  std::uint32_t NumberOfSymbols;
  std::uint16_t SizeOfOptionalHeader;
  std::uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
  std::uint32_t VirtualAddress;
  std::uint32_t Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
  std::uint16_t Magic;
  std::uint8_t MajorLinkerVersion;
  std::uint8_t MinorLinkerVersion;
  std::uint32_t SizeOfCode;
  std::uint32_t SizeOfInitializedData;
  std::uint32_t SizeOfUninitializedData;
  std::uint32_t AddressOfEntryPoint;
  std::uint32_t BaseOfCode;
  std::uint32_t BaseOfData;
  std::uint32_t ImageBase;
  std::uint32_t SectionAlignment;
  std::uint32_t FileAlignment;
  std::uint16_t MajorOperatingSystemVersion;
  std::uint16_t MinorOperatingSystemVersion;
  std::uint16_t MajorImageVersion;
  std::uint16_t MinorImageVersion;
  std::uint16_t MajorSubsystemVersion;
  std::uint16_t MinorSubsystemVersion;
  std::uint32_t Win32VersionValue;
  std::uint32_t SizeOfImage;
  std::uint32_t SizeOfHeaders;
  std::uint32_t CheckSum;
  std::uint16_t Subsystem;
  std::uint16_t DllCharacteristics;
  std::uint32_t SizeOfStackReserve;
  std::uint32_t SizeOfStackCommit;
  std::uint32_t SizeOfHeapReserve;
  std::uint32_t SizeOfHeapCommit;
  std::uint32_t LoaderFlags;
  std::uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_OPTIONAL_HEADER64 {
  std::uint16_t Magic;
  std::uint8_t MajorLinkerVersion;
  std::uint8_t MinorLinkerVersion;
  std::uint32_t SizeOfCode;
  std::uint32_t SizeOfInitializedData;
  std::uint32_t SizeOfUninitializedData;
  std::uint32_t AddressOfEntryPoint;
  std::uint32_t BaseOfCode;
  std::uint64_t ImageBase;
  std::uint32_t SectionAlignment;
  std::uint32_t FileAlignment;
  std::uint16_t MajorOperatingSystemVersion;
  std::uint16_t MinorOperatingSystemVersion;
  std::uint16_t MajorImageVersion;
  std::uint16_t MinorImageVersion;
  std::uint16_t MajorSubsystemVersion;
  std::uint16_t MinorSubsystemVersion;
  std::uint32_t Win32VersionValue;
  std::uint32_t SizeOfImage;
  std::uint32_t SizeOfHeaders;
  std::uint32_t CheckSum;
  std::uint16_t Subsystem;
  std::uint16_t DllCharacteristics;
  std::uint64_t SizeOfStackReserve;
  std::uint64_t SizeOfStackCommit;
  std::uint64_t SizeOfHeapReserve;
  std::uint64_t SizeOfHeapCommit;
  std::uint32_t LoaderFlags;
  std::uint32_t NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS32 {
  std::uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
  std::uint32_t Signature;
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_EXPORT_DIRECTORY {
  std::uint32_t Characteristics;
  std::uint32_t TimeDateStamp;
  std::uint16_t MajorVersion;
  std::uint16_t MinorVersion;
  std::uint32_t Name;
  std::uint32_t Base;
  std::uint32_t NumberOfFunctions;
  std::uint32_t NumberOfNames;
  std::uint32_t AddressOfFunctions;
  std::uint32_t AddressOfNames;
  std::uint32_t AddressOfNameOrdinals;
};

template <typename T>
inline T* rva_to_ptr(std::uintptr_t image_base, std::uint32_t rva) noexcept {
  return reinterpret_cast<T*>(image_base + static_cast<std::uintptr_t>(rva));
}

#if defined(_MSC_VER)
extern "C" std::uint64_t __readgsqword(unsigned long);
extern "C" std::uint32_t __readfsdword(unsigned long);
#pragma intrinsic(__readgsqword)
#pragma intrinsic(__readfsdword)
#endif

inline PEB* get_peb() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
#if defined(_MSC_VER)
  return reinterpret_cast<PEB*>(static_cast<std::uintptr_t>(__readgsqword(0x60)));
#else
  std::uintptr_t peb_ptr = 0;
  __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb_ptr));
  return reinterpret_cast<PEB*>(peb_ptr);
#endif
#elif defined(_M_IX86) || defined(__i386__)
#if defined(_MSC_VER)
  return reinterpret_cast<PEB*>(static_cast<std::uintptr_t>(__readfsdword(0x30)));
#else
  std::uintptr_t peb_ptr = 0;
  __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb_ptr));
  return reinterpret_cast<PEB*>(peb_ptr);
#endif
#else
  return nullptr;
#endif
}

inline void* get_module_base(std::uint32_t module_hash) {
  PEB* peb = get_peb();
  if (peb == nullptr || peb->Ldr == nullptr) {
    return nullptr;
  }

  LIST_ENTRY* const list_head = &peb->Ldr->InMemoryOrderModuleList;
  LIST_ENTRY* current = list_head->Flink;

  for (std::size_t guard = 0; current != nullptr && current != list_head && guard < 1024;
       ++guard, current = current->Flink) {
    auto* entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(
        reinterpret_cast<std::uintptr_t>(current) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

    if (entry->BaseDllName.Buffer == nullptr || entry->BaseDllName.Length == 0) {
      continue;
    }

    const std::size_t name_len = static_cast<std::size_t>(entry->BaseDllName.Length) / sizeof(wchar_t);
    if (hash_wide_ci(entry->BaseDllName.Buffer, name_len) == module_hash) {
      return entry->DllBase;
    }
  }

  return nullptr;
}

inline void* get_export_address(void* module_base, std::uint64_t func_hash) {
  if (module_base == nullptr) {
    return nullptr;
  }

  const std::uintptr_t image_base = reinterpret_cast<std::uintptr_t>(module_base);
  auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
  if (dos == nullptr || dos->e_magic != kImageDosSignature || dos->e_lfanew <= 0) {
    return nullptr;
  }

  const std::uintptr_t nt_base = image_base + static_cast<std::uintptr_t>(dos->e_lfanew);
  const std::uint32_t signature = *reinterpret_cast<const std::uint32_t*>(nt_base);
  if (signature != kImageNtSignature) {
    return nullptr;
  }

  std::uint32_t export_rva = 0;
  std::uint32_t export_size = 0;

  const auto* file_header = reinterpret_cast<const IMAGE_FILE_HEADER*>(nt_base + sizeof(std::uint32_t));
  const auto* optional_header_magic =
      reinterpret_cast<const std::uint16_t*>(reinterpret_cast<std::uintptr_t>(file_header) +
                                             sizeof(IMAGE_FILE_HEADER));

  if (*optional_header_magic == kImageNtOptionalHdr64Magic) {
    const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt_base);
    if (nt64->OptionalHeader.NumberOfRvaAndSizes <= kImageDirectoryEntryExport) {
      return nullptr;
    }
    export_rva = nt64->OptionalHeader.DataDirectory[kImageDirectoryEntryExport].VirtualAddress;
    export_size = nt64->OptionalHeader.DataDirectory[kImageDirectoryEntryExport].Size;
  } else if (*optional_header_magic == kImageNtOptionalHdr32Magic) {
    const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(nt_base);
    if (nt32->OptionalHeader.NumberOfRvaAndSizes <= kImageDirectoryEntryExport) {
      return nullptr;
    }
    export_rva = nt32->OptionalHeader.DataDirectory[kImageDirectoryEntryExport].VirtualAddress;
    export_size = nt32->OptionalHeader.DataDirectory[kImageDirectoryEntryExport].Size;
  } else {
    return nullptr;
  }

  if (export_rva == 0 || export_size == 0) {
    return nullptr;
  }

  const auto* export_dir = rva_to_ptr<const IMAGE_EXPORT_DIRECTORY>(image_base, export_rva);
  if (export_dir == nullptr || export_dir->NumberOfNames == 0 || export_dir->NumberOfFunctions == 0) {
    return nullptr;
  }

  const auto* name_rvas = rva_to_ptr<const std::uint32_t>(image_base, export_dir->AddressOfNames);
  const auto* ordinals =
      rva_to_ptr<const std::uint16_t>(image_base, export_dir->AddressOfNameOrdinals);
  const auto* function_rvas =
      rva_to_ptr<const std::uint32_t>(image_base, export_dir->AddressOfFunctions);

  if (name_rvas == nullptr || ordinals == nullptr || function_rvas == nullptr) {
    return nullptr;
  }

  for (std::uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
    const auto* export_name = rva_to_ptr<const char>(image_base, name_rvas[i]);
    if (export_name == nullptr) {
      continue;
    }

    if (hash_ascii_ci64(export_name) != func_hash) {
      continue;
    }

    const std::uint16_t ordinal = ordinals[i];
    if (ordinal >= export_dir->NumberOfFunctions) {
      return nullptr;
    }

    const std::uint32_t function_rva = function_rvas[ordinal];
    if (function_rva == 0) {
      return nullptr;
    }

    const std::uint32_t export_end = export_rva + export_size;
    if (function_rva >= export_rva && function_rva < export_end) {
      return nullptr;
    }

    return rva_to_ptr<void>(image_base, function_rva);
  }

  return nullptr;
}

}  // namespace eippf::bootstrap::hal::windows

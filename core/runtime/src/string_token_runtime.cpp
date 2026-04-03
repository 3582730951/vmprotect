#include "runtime/string_token_runtime.hpp"

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace {

std::uint8_t stream_mask(std::uint8_t key, std::size_t index) noexcept {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 37u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

}  // namespace

extern "C" void eippf_string_token_decode(std::uint8_t* dest, const std::uint8_t* src,
                                          std::size_t size, std::uint8_t key) {
  if (dest == nullptr || src == nullptr || size == 0u) {
    return;
  }

  for (std::size_t i = 0; i < size; ++i) {
    dest[i] = static_cast<std::uint8_t>(src[i] ^ stream_mask(key, i));
  }
}

extern "C" void eippf_string_token_wipe(std::uint8_t* data, std::size_t size) {
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

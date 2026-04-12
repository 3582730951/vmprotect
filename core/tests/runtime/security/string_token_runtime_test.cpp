#include "runtime/string_token_runtime.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>

namespace {

std::uint8_t stream_mask(std::uint8_t key, std::size_t index) {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 37u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_decode_success() {
  constexpr std::array<std::uint8_t, 8> plain = {
      static_cast<std::uint8_t>('s'), static_cast<std::uint8_t>('e'), static_cast<std::uint8_t>('c'),
      static_cast<std::uint8_t>('r'), static_cast<std::uint8_t>('e'), static_cast<std::uint8_t>('t'),
      static_cast<std::uint8_t>('!'), static_cast<std::uint8_t>('\0')};
  constexpr std::uint8_t key = 0x5Du;

  std::array<std::uint8_t, plain.size()> encoded{};
  for (std::size_t i = 0; i < plain.size(); ++i) {
    encoded[i] = static_cast<std::uint8_t>(plain[i] ^ stream_mask(key, i));
  }

  std::array<std::uint8_t, plain.size()> decoded{};
  eippf_sd0(decoded.data(), encoded.data(), decoded.size(), key);

  return expect(decoded == plain, "decode helper should restore plaintext bytes");
}

bool test_wipe_clears_buffer() {
  std::array<std::uint8_t, 16> buffer{};
  for (std::size_t i = 0; i < buffer.size(); ++i) {
    buffer[i] = static_cast<std::uint8_t>(i + 1u);
  }

  eippf_sw0(buffer.data(), buffer.size());

  for (std::uint8_t value : buffer) {
    if (value != 0u) {
      return expect(false, "wipe helper should zero every byte");
    }
  }
  return true;
}

bool test_empty_and_boundary_inputs() {
  std::array<std::uint8_t, 4> src = {0xAAu, 0xBBu, 0xCCu, 0xDDu};
  std::array<std::uint8_t, 4> dest = {0x11u, 0x22u, 0x33u, 0x44u};
  const std::array<std::uint8_t, 4> baseline = dest;

  eippf_sd0(nullptr, src.data(), src.size(), 0x31u);
  eippf_sd0(dest.data(), nullptr, src.size(), 0x31u);
  eippf_sd0(dest.data(), src.data(), 0u, 0x31u);
  eippf_sw0(nullptr, src.size());
  eippf_sw0(dest.data(), 0u);

  return expect(dest == baseline, "empty/boundary helper inputs must not corrupt destination bytes");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_decode_success() && ok;
  ok = test_wipe_clears_buffer() && ok;
  ok = test_empty_and_boundary_inputs() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] string_token_runtime_test\n";
  return 0;
}

#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace eippf::runtime::security {

inline void secure_zero(void* buffer, std::size_t size) noexcept {
  if (buffer == nullptr || size == 0u) {
    return;
  }

  auto* bytes = static_cast<volatile std::uint8_t*>(buffer);
  for (std::size_t i = 0; i < size; ++i) {
    bytes[i] = 0u;
  }
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

template <std::size_t N>
class DecryptedBuffer final {
 public:
  explicit DecryptedBuffer(std::array<char, N> data) noexcept : data_(data) {}

  DecryptedBuffer(const DecryptedBuffer&) = delete;
  DecryptedBuffer& operator=(const DecryptedBuffer&) = delete;

  DecryptedBuffer(DecryptedBuffer&& other) noexcept : data_(other.data_) {
    other.wipe();
  }

  DecryptedBuffer& operator=(DecryptedBuffer&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    wipe();
    data_ = other.data_;
    other.wipe();
    return *this;
  }

  ~DecryptedBuffer() { wipe(); }

  [[nodiscard]] const char* c_str() const noexcept { return data_.data(); }
  [[nodiscard]] char* data() noexcept { return data_.data(); }
  [[nodiscard]] const std::array<char, N>& raw() const noexcept { return data_; }
  [[nodiscard]] std::size_t size() const noexcept { return N > 0u ? (N - 1u) : 0u; }

  void wipe() noexcept { secure_zero(data_.data(), data_.size()); }

 private:
  std::array<char, N> data_{};
};

template <std::uint8_t Key, std::size_t N>
class ConstexprObfuscatedString final {
 public:
  constexpr explicit ConstexprObfuscatedString(const char (&literal)[N]) noexcept
      : encrypted_(encrypt(literal, std::make_index_sequence<N>{})) {}

  [[nodiscard]] DecryptedBuffer<N> decrypt() const noexcept {
    std::array<char, N> plain{};
    for (std::size_t i = 0; i < N; ++i) {
      plain[i] = static_cast<char>(encrypted_[i] ^ key_at(i));
    }
    return DecryptedBuffer<N>(plain);
  }

  [[nodiscard]] constexpr const std::array<std::uint8_t, N>& encrypted_bytes() const noexcept {
    return encrypted_;
  }

 private:
  template <std::size_t... I>
  [[nodiscard]] static constexpr std::array<std::uint8_t, N> encrypt(
      const char (&literal)[N], std::index_sequence<I...>) noexcept {
    return {static_cast<std::uint8_t>(literal[I] ^ key_at(I))...};
  }

  [[nodiscard]] static constexpr std::uint8_t key_at(std::size_t index) noexcept {
    return static_cast<std::uint8_t>(Key ^ static_cast<std::uint8_t>(index * 17u + 31u));
  }

  std::array<std::uint8_t, N> encrypted_{};
};

template <std::uint8_t Key, std::size_t N>
[[nodiscard]] constexpr auto make_obfuscated_string(const char (&literal)[N]) noexcept {
  return ConstexprObfuscatedString<Key, N>(literal);
}

}  // namespace eippf::runtime::security

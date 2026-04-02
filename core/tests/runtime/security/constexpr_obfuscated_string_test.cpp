#include "runtime/constexpr_obfuscated_string.hpp"

#include <cstring>
#include <iostream>

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_decrypt_roundtrip() {
  static constexpr auto kDbPassword =
      eippf::runtime::security::make_obfuscated_string<0x5Au>("ProdDB#Pass_2026!");

  auto plain = kDbPassword.decrypt();
  return expect(std::strcmp(plain.c_str(), "ProdDB#Pass_2026!") == 0,
                "decrypted string must match original literal");
}

bool test_ciphertext_differs_from_plaintext() {
  static constexpr auto kApiKey =
      eippf::runtime::security::make_obfuscated_string<0xA7u>("API_KEY_XYZ_123456");
  constexpr auto cipher = kApiKey.encrypted_bytes();
  constexpr const char plain[] = "API_KEY_XYZ_123456";

  bool at_least_one_diff = false;
  for (std::size_t i = 0; i + 1u < cipher.size(); ++i) {
    if (cipher[i] != static_cast<std::uint8_t>(plain[i])) {
      at_least_one_diff = true;
      break;
    }
  }

  return expect(at_least_one_diff, "ciphertext bytes should differ from plaintext bytes");
}

bool test_wipe_clears_plain_buffer() {
  static constexpr auto kSecret =
      eippf::runtime::security::make_obfuscated_string<0x3Cu>("SENSITIVE_VALUE");
  auto plain = kSecret.decrypt();
  plain.wipe();

  for (const char ch : plain.raw()) {
    if (ch != '\0') {
      return expect(false, "wipe() must zero every byte");
    }
  }
  return true;
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_decrypt_roundtrip() && ok;
  ok = test_ciphertext_differs_from_plaintext() && ok;
  ok = test_wipe_clears_plain_buffer() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] constexpr_obfuscated_string_test\n";
  return 0;
}

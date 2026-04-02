#include "runtime/constexpr_obfuscated_string.hpp"
#include "runtime/dynamic_api_resolver.hpp"

#include <cstddef>
#include <iostream>

namespace {

using Resolver = eippf::runtime::DynamicAPIResolver<64u, 4u>;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_success_path() {
#if defined(_WIN32) || defined(_WIN64)
  constexpr auto kRuntimeLib = eippf::runtime::security::make_obfuscated_string<0x11u>("msvcrt.dll");
#elif defined(__APPLE__) && defined(__MACH__)
  constexpr auto kRuntimeLib =
      eippf::runtime::security::make_obfuscated_string<0x11u>("libSystem.B.dylib");
#else
  constexpr auto kRuntimeLib = eippf::runtime::security::make_obfuscated_string<0x11u>("libc.so.6");
#endif
  constexpr auto kStrlen = eippf::runtime::security::make_obfuscated_string<0x12u>("strlen");
  using StrlenFn = std::size_t (*)(const char*);

  Resolver resolver;
  const StrlenFn strlen_fn = resolver.resolve<StrlenFn>(kRuntimeLib, kStrlen);
  if (!expect(strlen_fn != nullptr, "resolver should resolve strlen")) {
    return false;
  }

  return expect(strlen_fn("hft") == 3u, "resolved strlen should execute");
}

bool test_failure_path() {
#if defined(_WIN32) || defined(_WIN64)
  constexpr auto kRuntimeLib = eippf::runtime::security::make_obfuscated_string<0x13u>("msvcrt.dll");
#elif defined(__APPLE__) && defined(__MACH__)
  constexpr auto kRuntimeLib =
      eippf::runtime::security::make_obfuscated_string<0x13u>("libSystem.B.dylib");
#else
  constexpr auto kRuntimeLib = eippf::runtime::security::make_obfuscated_string<0x13u>("libc.so.6");
#endif
  constexpr auto kMissingSymbol =
      eippf::runtime::security::make_obfuscated_string<0x14u>("__eippf_missing_symbol__");
  using MissingFn = int (*)();

  Resolver resolver;
  const MissingFn missing_fn = resolver.resolve<MissingFn>(kRuntimeLib, kMissingSymbol);
  return expect(missing_fn == nullptr, "resolver should return nullptr for unknown symbol");
}

bool test_edge_security_path() {
#if defined(_WIN32) || defined(_WIN64)
  constexpr auto kRuntimeLib = eippf::runtime::security::make_obfuscated_string<0x15u>("msvcrt.dll");
#elif defined(__APPLE__) && defined(__MACH__)
  constexpr auto kRuntimeLib =
      eippf::runtime::security::make_obfuscated_string<0x15u>("libSystem.B.dylib");
#else
  constexpr auto kRuntimeLib = eippf::runtime::security::make_obfuscated_string<0x15u>("libc.so.6");
#endif
  constexpr auto kStrlen = eippf::runtime::security::make_obfuscated_string<0x16u>("strlen");
  using StrlenFn = std::size_t (*)(const char*);

  Resolver resolver;
  const StrlenFn first = resolver.resolve<StrlenFn>(kRuntimeLib, kStrlen);
  const StrlenFn second = resolver.resolve<StrlenFn>(kRuntimeLib, kStrlen);
  if (!expect(first != nullptr && second != nullptr, "cached resolver must return valid symbol")) {
    return false;
  }
  if (!expect(first == second, "cached resolver should return same function pointer")) {
    return false;
  }

  resolver.wipe();
  return expect(resolver.cached_symbol_count_for_testing() == 0u,
                "wipe should clear cached symbol entries");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_success_path() && ok;
  ok = test_failure_path() && ok;
  ok = test_edge_security_path() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] dynamic_api_resolver_test\n";
  return 0;
}

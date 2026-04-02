#include "runtime/dynamic_api_resolver.hpp"
#include "runtime/memory_hal.hpp"

#include <cstdint>
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
  Resolver resolver;
  eippf::runtime::MemoryHAL::Region region =
      eippf::runtime::MemoryHAL::allocate_rw(resolver, 4096u);
  if (!expect(region.valid(), "allocate_rw should return a valid region")) {
    return false;
  }

  auto* bytes = static_cast<std::uint8_t*>(region.base);
  bytes[0] = 0xAAu;
  bytes[1] = 0x55u;

  if (!expect(eippf::runtime::MemoryHAL::protect_rx(resolver, region),
              "protect_rx should switch region to RX")) {
    eippf::runtime::MemoryHAL::release(resolver, region);
    return false;
  }

  if (!expect(eippf::runtime::MemoryHAL::protect_rw(resolver, region),
              "protect_rw should switch region back to RW")) {
    eippf::runtime::MemoryHAL::release(resolver, region);
    return false;
  }

  eippf::runtime::MemoryHAL::release(resolver, region);
  return expect(!region.valid(), "release should invalidate region handle");
}

bool test_failure_path() {
  Resolver resolver;
  const eippf::runtime::MemoryHAL::Region region =
      eippf::runtime::MemoryHAL::allocate_rw(resolver, 0u);
  return expect(!region.valid(), "allocate_rw(0) should fail deterministically");
}

bool test_edge_security_path() {
  Resolver resolver;
  eippf::runtime::MemoryHAL::Region invalid{};
  eippf::runtime::MemoryHAL::release(resolver, invalid);
  if (!expect(!invalid.valid(), "release on invalid region should be no-op")) {
    return false;
  }

  return expect(!eippf::runtime::MemoryHAL::protect_rx(resolver, invalid),
                "protect_rx should reject invalid regions");
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
  std::cout << "[PASS] memory_hal_test\n";
  return 0;
}

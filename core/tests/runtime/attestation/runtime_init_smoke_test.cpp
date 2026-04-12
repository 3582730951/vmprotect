#include <cstdint>
#include <iostream>

extern "C" void* eippf_ra0(std::uint64_t hash) noexcept;

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

}  // namespace

int main() {
  if (!expect(eippf_ra0(0u) == nullptr, "zero hash must resolve to nullptr")) {
    return 1;
  }
  std::cout << "[PASS] runtime_init_smoke_test\n";
  return 0;
}

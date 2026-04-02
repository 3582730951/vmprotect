#include <array>
#include <cstdint>
#include <iostream>

namespace {

// 该函数演示“流程图 -> 状态机”代码生成目标：
// - 只有一个 while(true)
// - 每个节点映射为 case
// - 通过 state 变量表达任意跳转（分支/回边/终止）
std::uint64_t fibonacci_state_machine(std::uint32_t n) {
  std::uint64_t prev = 0u;
  std::uint64_t curr = 1u;
  std::uint64_t next = 0u;
  std::uint32_t index = 0u;
  int state = 0;

  while (true) {
    switch (state) {
      case 0:
        if (n == 0u) {
          state = 100;
        } else if (n == 1u) {
          state = 101;
        } else {
          index = 2u;
          state = 10;
        }
        break;
      case 10:
        state = (index <= n) ? 20 : 102;
        break;
      case 20:
        next = prev + curr;
        state = 30;
        break;
      case 30:
        prev = curr;
        state = 40;
        break;
      case 40:
        curr = next;
        state = 50;
        break;
      case 50:
        ++index;
        state = 10;
        break;
      case 100:
        return 0u;
      case 101:
        return 1u;
      case 102:
        return curr;
      default:
        return 0u;
    }
  }
}

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

}  // namespace

int main() {
  constexpr std::array<std::uint64_t, 11> kExpected = {
      0u, 1u, 1u, 2u, 3u, 5u, 8u, 13u, 21u, 34u, 55u,
  };

  for (std::uint32_t i = 0u; i < kExpected.size(); ++i) {
    const std::uint64_t value = fibonacci_state_machine(i);
    if (!expect(value == kExpected[i], "state-machine fibonacci mismatch")) {
      return 1;
    }
  }

  std::cout << "[PASS] state_machine_codegen_demo_test\n";
  return 0;
}

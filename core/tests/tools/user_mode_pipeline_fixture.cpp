#include <iostream>
#include <string_view>

namespace {

constexpr std::string_view kFixtureString = "user_mode_pipeline_fixture";

int add_values(int lhs, int rhs) {
  return lhs + rhs;
}

}  // namespace

int main() {
  const int sum = add_values(7, 5);
  std::cout << kFixtureString << ":" << sum << '\n';
  return sum == 12 ? 0 : 1;
}

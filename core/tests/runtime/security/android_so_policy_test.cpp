#include "runtime/android_so_policy.hpp"

#include <iostream>

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

eippf::runtime::AndroidSoPolicyInput make_compliant_input() {
  eippf::runtime::AndroidSoPolicyInput input{};
  input.jni_export_surface_ok = true;
  input.lexical_residual_strings_ok = true;
  input.hook_check_ok = true;
  input.anti_debug_check_ok = true;
  return input;
}

bool test_success_path() {
  const auto result = eippf::runtime::evaluate_android_so_policy(make_compliant_input());
  if (!expect(result.jni_export_surface_ok, "JNI export surface should pass")) {
    return false;
  }
  if (!expect(result.lexical_residual_strings_ok, "lexical residual strings should pass")) {
    return false;
  }
  if (!expect(result.hook_check_ok, "hook check should pass")) {
    return false;
  }
  if (!expect(result.anti_debug_check_ok, "anti-debug check should pass")) {
    return false;
  }
  return expect(result.verdict_allow, "all checks passing must allow Android .so baseline");
}

bool test_jni_violation_failure() {
  auto input = make_compliant_input();
  input.jni_export_surface_ok = false;
  const auto result = eippf::runtime::evaluate_android_so_policy(input);
  if (!expect(!result.jni_export_surface_ok, "JNI violation must be reflected in result")) {
    return false;
  }
  return expect(!result.verdict_allow, "JNI violation must fail baseline verdict");
}

bool test_lexical_violation_failure() {
  auto input = make_compliant_input();
  input.lexical_residual_strings_ok = false;
  const auto result = eippf::runtime::evaluate_android_so_policy(input);
  if (!expect(!result.lexical_residual_strings_ok, "lexical violation must be reflected in result")) {
    return false;
  }
  return expect(!result.verdict_allow, "lexical violation must fail baseline verdict");
}

bool test_hook_violation_failure() {
  auto input = make_compliant_input();
  input.hook_check_ok = false;
  const auto result = eippf::runtime::evaluate_android_so_policy(input);
  if (!expect(!result.hook_check_ok, "hook violation must be reflected in result")) {
    return false;
  }
  return expect(!result.verdict_allow, "hook violation must fail baseline verdict");
}

bool test_anti_debug_violation_failure() {
  auto input = make_compliant_input();
  input.anti_debug_check_ok = false;
  const auto result = eippf::runtime::evaluate_android_so_policy(input);
  if (!expect(!result.anti_debug_check_ok, "anti-debug violation must be reflected in result")) {
    return false;
  }
  return expect(!result.verdict_allow, "anti-debug violation must fail baseline verdict");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_success_path() && ok;
  ok = test_jni_violation_failure() && ok;
  ok = test_lexical_violation_failure() && ok;
  ok = test_hook_violation_failure() && ok;
  ok = test_anti_debug_violation_failure() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] android_so_policy_test\n";
  return 0;
}

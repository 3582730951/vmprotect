#include "runtime/android_so_policy.hpp"
#include "runtime/environment_attestation.hpp"

#include <iostream>
#include <string>

namespace {

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_android_so_baseline_path_is_auditable() {
  eippf::runtime::AndroidSoPolicyInput input{};
  input.jni_export_surface_ok = true;
  input.lexical_residual_strings_ok = true;
  input.hook_check_ok = true;
  input.anti_debug_check_ok = true;

  const auto result = eippf::runtime::EnvironmentAttestation::evaluate_android_so_baseline(input);
  if (!expect(result.verdict_allow, "baseline-compliant Android .so sample must be allowed")) {
    return false;
  }

  const std::string audit = eippf::runtime::build_android_so_policy_audit_record(result);
  if (!expect(audit.find("\"scope\": \"android_so_baseline\"") != std::string::npos,
              "audit payload must contain android_so_baseline scope")) {
    return false;
  }
  return expect(audit.find("\"verdict_allow\": true") != std::string::npos,
                "audit payload must expose allow verdict");
}

bool test_android_so_violation_is_fail_closed() {
  eippf::runtime::AndroidSoPolicyInput input{};
  input.jni_export_surface_ok = true;
  input.lexical_residual_strings_ok = false;
  input.hook_check_ok = true;
  input.anti_debug_check_ok = true;

  const auto result = eippf::runtime::EnvironmentAttestation::evaluate_android_so_baseline(input);
  if (!expect(!result.verdict_allow, "any Android .so baseline violation must fail-closed")) {
    return false;
  }
  if (!expect(!result.lexical_residual_strings_ok, "violating lexical check must remain visible")) {
    return false;
  }

  const std::string audit = eippf::runtime::build_android_so_policy_audit_record(result);
  return expect(audit.find("\"verdict_allow\": false") != std::string::npos,
                "audit payload must expose fail-closed verdict");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_android_so_baseline_path_is_auditable() && ok;
  ok = test_android_so_violation_is_fail_closed() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] android_so_pipeline_smoke_test\n";
  return 0;
}

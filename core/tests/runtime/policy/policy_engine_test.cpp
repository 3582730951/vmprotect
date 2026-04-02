#include "runtime/policy_engine.hpp"

#include <iostream>
#include <vector>

namespace {

using eippf::runtime::policy::BudgetConfig;
using eippf::runtime::policy::ErrorCode;
using eippf::runtime::policy::FunctionProfile;
using eippf::runtime::policy::HotClass;
using eippf::runtime::policy::NormalizationStats;
using eippf::runtime::policy::ProtectionStrategy;
using eippf::runtime::policy::WorkloadSample;
using eippf::runtime::policy::evaluate_budget;
using eippf::runtime::policy::route_function;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_success_hot_critical_route() {
  const FunctionProfile profile{
      .function_name = "critical_hot_fn",
      .calls_per_sec = 8000.0,
      .cycles_share = 0.10,
      .p95_us = 150.0,
      .branch_miss_rate = 0.08,
      .is_critical = true,
      .has_drm_flatten = false,
      .has_drm_jit = false,
  };
  const NormalizationStats stats{
      .min_calls_per_sec = 1.0,
      .max_calls_per_sec = 9000.0,
      .min_p95_us = 5.0,
      .max_p95_us = 200.0,
      .min_branch_miss_rate = 0.0,
      .max_branch_miss_rate = 0.20,
  };

  const auto routed = route_function(profile, stats, false);
  if (!expect(routed.ok(), "hot critical route should succeed")) {
    return false;
  }
  if (!expect(routed.value().hot_class == HotClass::kHot, "hot class should be Hot")) {
    return false;
  }
  if (!expect(routed.value().strategy ==
                  ProtectionStrategy::kJitEnclaveCffFullBcfStandard,
              "hot critical must route to JIT_ENCLAVE+CFF_FULL+BCF_STANDARD")) {
    return false;
  }
  return expect(routed.value().predicted_overhead > 0.0, "predicted overhead must be positive");
}

bool test_failure_invalid_profile_range() {
  const FunctionProfile profile{
      .function_name = "invalid_fn",
      .calls_per_sec = 100.0,
      .cycles_share = -0.01,
      .p95_us = 20.0,
      .branch_miss_rate = 0.1,
      .is_critical = false,
      .has_drm_flatten = false,
      .has_drm_jit = false,
  };
  const NormalizationStats stats{
      .min_calls_per_sec = 0.0,
      .max_calls_per_sec = 1000.0,
      .min_p95_us = 1.0,
      .max_p95_us = 120.0,
      .min_branch_miss_rate = 0.0,
      .max_branch_miss_rate = 0.2,
  };

  const auto routed = route_function(profile, stats, false);
  if (!expect(!routed.ok(), "invalid profile should fail")) {
    return false;
  }
  return expect(routed.error() == ErrorCode::kInvalidNumericRange,
                "invalid profile should return kInvalidNumericRange");
}

bool test_failure_empty_function_name() {
  const FunctionProfile profile{
      .function_name = "",
      .calls_per_sec = 10.0,
      .cycles_share = 0.01,
      .p95_us = 10.0,
      .branch_miss_rate = 0.01,
      .is_critical = false,
      .has_drm_flatten = false,
      .has_drm_jit = false,
  };
  const NormalizationStats stats{
      .min_calls_per_sec = 0.0,
      .max_calls_per_sec = 1000.0,
      .min_p95_us = 1.0,
      .max_p95_us = 120.0,
      .min_branch_miss_rate = 0.0,
      .max_branch_miss_rate = 0.2,
  };

  const auto routed = route_function(profile, stats, false);
  if (!expect(!routed.ok(), "empty function name must fail")) {
    return false;
  }
  return expect(routed.error() == ErrorCode::kInvalidProfile,
                "empty function name should map to kInvalidProfile");
}

bool test_security_edge_critical_never_none() {
  const FunctionProfile profile{
      .function_name = "critical_cold_fn",
      .calls_per_sec = 3.0,
      .cycles_share = 0.001,
      .p95_us = 3.0,
      .branch_miss_rate = 0.0,
      .is_critical = true,
      .has_drm_flatten = false,
      .has_drm_jit = false,
  };
  const NormalizationStats stats{
      .min_calls_per_sec = 0.0,
      .max_calls_per_sec = 1000.0,
      .min_p95_us = 1.0,
      .max_p95_us = 100.0,
      .min_branch_miss_rate = 0.0,
      .max_branch_miss_rate = 0.2,
  };

  const auto routed = route_function(profile, stats, false);
  if (!expect(routed.ok(), "critical cold route should still succeed")) {
    return false;
  }
  return expect(routed.value().strategy == ProtectionStrategy::kVmStrongCffLite,
                "critical cold cannot downgrade to NONE");
}

bool test_budget_gate_success_and_failure() {
  const BudgetConfig config{
      .target_budget = 0.10,
      .critical_cluster_overhead_limit = 0.15,
  };

  const std::vector<WorkloadSample> pass_samples{
      WorkloadSample{.qps = 100.0,
                     .predicted_overhead = 0.05,
                     .measured_overhead = 0.07,
                     .critical_cluster_p95_overhead = 0.12},
      WorkloadSample{.qps = 50.0,
                     .predicted_overhead = 0.06,
                     .measured_overhead = 0.08,
                     .critical_cluster_p95_overhead = 0.13},
  };
  const auto pass_budget = evaluate_budget(pass_samples, config);
  if (!expect(pass_budget.ok(), "budget in range should pass")) {
    return false;
  }

  const std::vector<WorkloadSample> fail_samples{
      WorkloadSample{.qps = 10.0,
                     .predicted_overhead = 0.20,
                     .measured_overhead = 0.21,
                     .critical_cluster_p95_overhead = 0.18},
  };
  const auto fail_budget = evaluate_budget(fail_samples, config);
  if (!expect(!fail_budget.ok(), "budget overrun should fail")) {
    return false;
  }
  if (!expect(fail_budget.error() == ErrorCode::kBudgetExceeded,
              "budget overrun should return kBudgetExceeded")) {
    return false;
  }

  const std::vector<WorkloadSample> invalid_samples{
      WorkloadSample{.qps = 1.0,
                     .predicted_overhead = 1.20,
                     .measured_overhead = 0.02,
                     .critical_cluster_p95_overhead = 0.01},
  };
  const auto invalid_budget = evaluate_budget(invalid_samples, config);
  if (!expect(!invalid_budget.ok(), "overhead > 1.0 must be rejected")) {
    return false;
  }
  return expect(invalid_budget.error() == ErrorCode::kInvalidNumericRange,
                "invalid overhead ratio should return kInvalidNumericRange");
}

}  // namespace

int main() {
  bool success = true;
  success = test_success_hot_critical_route() && success;
  success = test_failure_invalid_profile_range() && success;
  success = test_failure_empty_function_name() && success;
  success = test_security_edge_critical_never_none() && success;
  success = test_budget_gate_success_and_failure() && success;

  if (!success) {
    return 1;
  }
  std::cout << "[PASS] policy_engine_test\n";
  return 0;
}

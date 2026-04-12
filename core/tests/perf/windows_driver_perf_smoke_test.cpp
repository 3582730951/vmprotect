#include "runtime/backend_policy.hpp"
#include "runtime_backend_perf_test_common.hpp"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>

namespace {

using eippf::contracts::ProtectionTargetKind;
using eippf::contracts::RuntimeBackendKind;
namespace perf = eippf::tests::perf;

constexpr double kHotPathBudgetPct = 10.0;
constexpr double kOverallBudgetPct = 10.0;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool run_correctness_guard(ProtectionTargetKind compared_target) {
  const auto dispatch = eippf::runtime::backend::dispatch_for_target(compared_target);
  if (!expect(dispatch.backend == RuntimeBackendKind::kKernelSafeAot,
              "compared target backend must be kKernelSafeAot")) {
    return false;
  }
  if (!expect(!dispatch.allow_jit, "compared target must disable jit")) {
    return false;
  }
  if (!expect(!dispatch.allow_runtime_executable_pages,
              "compared target must disable runtime executable pages")) {
    return false;
  }
  return expect(eippf::runtime::backend::target_kind_requires_sign_after_mutate(compared_target),
                "compared target must require sign-after-mutate");
}

}  // namespace

int main() {
  constexpr ProtectionTargetKind kBaselineTarget = ProtectionTargetKind::kDesktopNative;
  constexpr ProtectionTargetKind kComparedTarget = ProtectionTargetKind::kWindowsDriver;

  if (!run_correctness_guard(kComparedTarget)) {
    return 1;
  }

  volatile std::uint64_t sink = 0u;
  const perf::MeasurementPair hot_path_pair =
      perf::measure_median_pair_ns(kBaselineTarget, kComparedTarget, sink, perf::measure_hot_path_ns);
  const perf::MeasurementPair overall_pair =
      perf::measure_median_pair_ns(kBaselineTarget, kComparedTarget, sink, perf::measure_overall_ns);

  const double hot_path_overhead_pct = hot_path_pair.overhead_pct;
  const double overall_overhead_pct = overall_pair.overhead_pct;

  const bool baseline_ok = hot_path_overhead_pct >= 0.0 && overall_overhead_pct >= 0.0;
  const bool within_budget = baseline_ok && hot_path_overhead_pct <= kHotPathBudgetPct &&
                             overall_overhead_pct <= kOverallBudgetPct;

  std::cout << std::fixed << std::setprecision(3) << "lane=windows_driver"
            << " hot_path_baseline_ns=" << hot_path_pair.baseline_ns
            << " hot_path_compared_ns=" << hot_path_pair.compared_ns
            << " hot_path_overhead_pct=" << hot_path_overhead_pct
            << " overall_baseline_ns=" << overall_pair.baseline_ns
            << " overall_compared_ns=" << overall_pair.compared_ns
            << " overall_overhead_pct=" << overall_overhead_pct
            << " status=" << (within_budget ? "PASS" : "FAIL") << '\n';

  if (sink == std::numeric_limits<std::uint64_t>::max()) {
    std::cerr << "[INFO] sink_guard\n";
  }

  return within_budget ? 0 : 1;
}

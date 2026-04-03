#include "runtime/backend_policy.hpp"

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>

namespace {

using eippf::contracts::ProtectionTargetKind;
using eippf::contracts::RuntimeBackendKind;
using eippf::runtime::backend::Policy;
using eippf::runtime::backend::PolicyError;

constexpr std::uint64_t kHotPathIterations = 2000000u;
constexpr std::uint64_t kOverallIterations = 1000000u;
constexpr int kRuns = 5;
constexpr double kHotPathBudgetPct = 10.0;
constexpr double kOverallBudgetPct = 10.0;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

std::uint64_t measure_hot_path_ns(ProtectionTargetKind target, volatile std::uint64_t& sink) {
  const auto start = std::chrono::steady_clock::now();
  for (std::uint64_t i = 0; i < kHotPathIterations; ++i) {
    const auto dispatch = eippf::runtime::backend::dispatch_for_target(target);
    sink = sink + static_cast<std::uint64_t>(dispatch.allow_jit);
    sink = sink + static_cast<std::uint64_t>(dispatch.allow_runtime_executable_pages);
    sink = sink + static_cast<std::uint64_t>(dispatch.requires_sign_after_mutate);
    sink = sink + static_cast<std::uint64_t>(dispatch.backend);
  }
  const auto end = std::chrono::steady_clock::now();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

std::uint64_t measure_overall_ns(ProtectionTargetKind target, volatile std::uint64_t& sink) {
  const auto start = std::chrono::steady_clock::now();
  for (std::uint64_t i = 0; i < kOverallIterations; ++i) {
    const Policy policy = eippf::runtime::backend::default_policy_for_target(target);
    const PolicyError validate = eippf::runtime::backend::validate_policy(policy);
    const bool sign_after_mutate =
        eippf::runtime::backend::target_kind_requires_sign_after_mutate(target);
    sink = sink + static_cast<std::uint64_t>(validate);
    sink = sink + static_cast<std::uint64_t>(sign_after_mutate);
    sink = sink + static_cast<std::uint64_t>(policy.allow_runtime_executable_pages);
  }
  const auto end = std::chrono::steady_clock::now();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

std::uint64_t measure_best_hot_path_ns(ProtectionTargetKind target, volatile std::uint64_t& sink) {
  std::uint64_t best = std::numeric_limits<std::uint64_t>::max();
  for (int run = 0; run < kRuns; ++run) {
    const std::uint64_t elapsed = measure_hot_path_ns(target, sink);
    if (elapsed < best) {
      best = elapsed;
    }
  }
  return best;
}

std::uint64_t measure_best_overall_ns(ProtectionTargetKind target, volatile std::uint64_t& sink) {
  std::uint64_t best = std::numeric_limits<std::uint64_t>::max();
  for (int run = 0; run < kRuns; ++run) {
    const std::uint64_t elapsed = measure_overall_ns(target, sink);
    if (elapsed < best) {
      best = elapsed;
    }
  }
  return best;
}

double compute_overhead_pct(std::uint64_t baseline_ns, std::uint64_t compared_ns) {
  if (baseline_ns == 0u) {
    return -1.0;
  }
  if (compared_ns <= baseline_ns) {
    return 0.0;
  }
  const double delta = static_cast<double>(compared_ns - baseline_ns);
  return (delta * 100.0) / static_cast<double>(baseline_ns);
}

bool run_correctness_guard(ProtectionTargetKind compared_target) {
  const auto dispatch = eippf::runtime::backend::dispatch_for_target(compared_target);
  if (!expect(dispatch.backend == RuntimeBackendKind::kIosSafeAot,
              "compared target backend must be kIosSafeAot")) {
    return false;
  }
  if (!expect(!dispatch.allow_jit, "compared target must disable jit")) {
    return false;
  }
  if (!expect(!dispatch.allow_runtime_executable_pages,
              "compared target must disable runtime executable pages")) {
    return false;
  }
  return expect(!eippf::runtime::backend::target_kind_requires_sign_after_mutate(compared_target),
                "compared target must keep sign-after-mutate disabled in policy");
}

}  // namespace

int main() {
  constexpr ProtectionTargetKind kBaselineTarget = ProtectionTargetKind::kDesktopNative;
  constexpr ProtectionTargetKind kComparedTarget = ProtectionTargetKind::kIosAppStore;

  if (!run_correctness_guard(kComparedTarget)) {
    return 1;
  }

  volatile std::uint64_t sink = 0u;
  const std::uint64_t hot_path_baseline_ns = measure_best_hot_path_ns(kBaselineTarget, sink);
  const std::uint64_t hot_path_compared_ns = measure_best_hot_path_ns(kComparedTarget, sink);
  const std::uint64_t overall_baseline_ns = measure_best_overall_ns(kBaselineTarget, sink);
  const std::uint64_t overall_compared_ns = measure_best_overall_ns(kComparedTarget, sink);

  const double hot_path_overhead_pct =
      compute_overhead_pct(hot_path_baseline_ns, hot_path_compared_ns);
  const double overall_overhead_pct =
      compute_overhead_pct(overall_baseline_ns, overall_compared_ns);

  const bool baseline_ok = hot_path_overhead_pct >= 0.0 && overall_overhead_pct >= 0.0;
  const bool within_budget = baseline_ok && hot_path_overhead_pct <= kHotPathBudgetPct &&
                             overall_overhead_pct <= kOverallBudgetPct;

  std::cout << std::fixed << std::setprecision(3) << "lane=ios_safe"
            << " hot_path_baseline_ns=" << hot_path_baseline_ns
            << " hot_path_compared_ns=" << hot_path_compared_ns
            << " hot_path_overhead_pct=" << hot_path_overhead_pct
            << " overall_baseline_ns=" << overall_baseline_ns
            << " overall_compared_ns=" << overall_compared_ns
            << " overall_overhead_pct=" << overall_overhead_pct
            << " status=" << (within_budget ? "PASS" : "FAIL") << '\n';

  if (sink == std::numeric_limits<std::uint64_t>::max()) {
    std::cerr << "[INFO] sink_guard\n";
  }

  return within_budget ? 0 : 1;
}

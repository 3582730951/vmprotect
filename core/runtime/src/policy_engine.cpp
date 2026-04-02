#include "runtime/policy_engine.hpp"

#include <algorithm>
#include <cmath>

namespace eippf::runtime::policy {

namespace {

double clamp_unit_interval(double value) noexcept {
  if (value < 0.0) {
    return 0.0;
  }
  if (value > 1.0) {
    return 1.0;
  }
  return value;
}

bool is_finite_non_negative(double value) noexcept {
  return std::isfinite(value) && value >= 0.0;
}

bool is_finite_probability(double value) noexcept {
  return is_finite_non_negative(value) && value <= 1.0;
}

bool is_finite_overhead_ratio(double value) noexcept {
  return is_finite_non_negative(value) && value <= 1.0;
}

double normalize_min_max(double value, double min_value, double max_value) noexcept {
  if (!std::isfinite(value) || !std::isfinite(min_value) || !std::isfinite(max_value)) {
    return 0.0;
  }
  if (max_value <= min_value) {
    return 0.0;
  }
  return clamp_unit_interval((value - min_value) / (max_value - min_value));
}

bool has_valid_profile_ranges(const FunctionProfile& profile) noexcept {
  return is_finite_non_negative(profile.calls_per_sec) &&
         is_finite_probability(profile.cycles_share) &&
         is_finite_non_negative(profile.p95_us) &&
         is_finite_probability(profile.branch_miss_rate);
}

bool has_valid_normalization_ranges(const NormalizationStats& stats) noexcept {
  const bool calls_range_valid =
      std::isfinite(stats.min_calls_per_sec) &&
      std::isfinite(stats.max_calls_per_sec) &&
      stats.max_calls_per_sec >= stats.min_calls_per_sec;
  const bool p95_range_valid =
      std::isfinite(stats.min_p95_us) &&
      std::isfinite(stats.max_p95_us) &&
      stats.max_p95_us >= stats.min_p95_us;
  const bool branch_range_valid =
      std::isfinite(stats.min_branch_miss_rate) &&
      std::isfinite(stats.max_branch_miss_rate) &&
      stats.max_branch_miss_rate >= stats.min_branch_miss_rate;
  return calls_range_valid && p95_range_valid && branch_range_valid;
}

HotClass classify_hotness(double heat_score, double cycles_share) noexcept {
  if (heat_score >= 0.70 || cycles_share >= 0.02) {
    return HotClass::kHot;
  }
  if (heat_score >= 0.40) {
    return HotClass::kWarm;
  }
  return HotClass::kCold;
}

ProtectionStrategy choose_strategy(const FunctionProfile& profile, HotClass hot_class) noexcept {
  if (profile.has_drm_jit) {
    return ProtectionStrategy::kJitEnclaveCffFullBcfStandard;
  }

  if (hot_class == HotClass::kHot && profile.is_critical) {
    return ProtectionStrategy::kJitEnclaveCffFullBcfStandard;
  }
  if (hot_class == HotClass::kHot && !profile.is_critical) {
    return ProtectionStrategy::kCffFullBcfStandard;
  }
  if (profile.is_critical) {
    return ProtectionStrategy::kVmStrongCffLite;
  }
  if (profile.has_drm_flatten) {
    return ProtectionStrategy::kCffLite;
  }
  return ProtectionStrategy::kNone;
}

double estimate_strategy_overhead(ProtectionStrategy strategy, double heat_score) noexcept {
  const double clamped_heat = clamp_unit_interval(heat_score);
  switch (strategy) {
    case ProtectionStrategy::kNone:
      return 0.0;
    case ProtectionStrategy::kCffLite:
      return 0.012 + (0.008 * clamped_heat);
    case ProtectionStrategy::kCffFullBcfStandard:
      return 0.028 + (0.020 * clamped_heat);
    case ProtectionStrategy::kVmStrongCffLite:
      return 0.035 + (0.030 * clamped_heat);
    case ProtectionStrategy::kJitEnclaveCffFullBcfStandard:
      return 0.045 + (0.040 * clamped_heat);
  }
  return 0.0;
}

bool exceeds_budget_limits(const BudgetReport& report, const BudgetConfig& config) noexcept {
  return report.weighted_predicted_budget > config.target_budget ||
         report.weighted_measured_budget > config.target_budget ||
         report.max_critical_cluster_overhead > config.critical_cluster_overhead_limit;
}

}  // namespace

Result<RoutingDecision> route_function(const FunctionProfile& profile,
                                       const NormalizationStats& normalization_stats,
                                       bool cold_start_mode) noexcept {
  if (profile.function_name.empty()) {
    return Result<RoutingDecision>::failure(ErrorCode::kInvalidProfile);
  }
  if (!has_valid_profile_ranges(profile) || !has_valid_normalization_ranges(normalization_stats)) {
    return Result<RoutingDecision>::failure(ErrorCode::kInvalidNumericRange);
  }

  const double calls_norm = cold_start_mode
                                ? 0.0
                                : normalize_min_max(profile.calls_per_sec,
                                                    normalization_stats.min_calls_per_sec,
                                                    normalization_stats.max_calls_per_sec);
  const double p95_norm = normalize_min_max(profile.p95_us, normalization_stats.min_p95_us,
                                            normalization_stats.max_p95_us);
  const double branch_norm =
      cold_start_mode
          ? 0.0
          : normalize_min_max(profile.branch_miss_rate,
                              normalization_stats.min_branch_miss_rate,
                              normalization_stats.max_branch_miss_rate);

  const double heat_score = (0.45 * profile.cycles_share) + (0.25 * calls_norm) +
                            (0.20 * p95_norm) + (0.10 * branch_norm);
  const HotClass hot_class = classify_hotness(heat_score, profile.cycles_share);
  const ProtectionStrategy strategy = choose_strategy(profile, hot_class);

  if (profile.is_critical && strategy == ProtectionStrategy::kNone) {
    return Result<RoutingDecision>::failure(ErrorCode::kCriticalDowngradeRejected);
  }
  if (hot_class == HotClass::kHot && strategy == ProtectionStrategy::kNone) {
    return Result<RoutingDecision>::failure(ErrorCode::kCriticalDowngradeRejected);
  }

  RoutingDecision decision{};
  decision.hot_class = hot_class;
  decision.strategy = strategy;
  decision.heat_score = clamp_unit_interval(heat_score);
  decision.predicted_overhead = estimate_strategy_overhead(strategy, decision.heat_score);
  return Result<RoutingDecision>::success(decision);
}

Result<BudgetReport> evaluate_budget(const std::vector<WorkloadSample>& samples,
                                     const BudgetConfig& config) noexcept {
  if (samples.empty() || !is_finite_probability(config.target_budget) ||
      !is_finite_probability(config.critical_cluster_overhead_limit)) {
    return Result<BudgetReport>::failure(ErrorCode::kInvalidProfile);
  }

  double qps_sum = 0.0;
  double weighted_predicted_sum = 0.0;
  double weighted_measured_sum = 0.0;
  double max_critical_cluster_overhead = 0.0;

  for (const WorkloadSample& sample : samples) {
    if (!is_finite_non_negative(sample.qps) ||
        !is_finite_overhead_ratio(sample.predicted_overhead) ||
        !is_finite_overhead_ratio(sample.measured_overhead) ||
        !is_finite_overhead_ratio(sample.critical_cluster_p95_overhead)) {
      return Result<BudgetReport>::failure(ErrorCode::kInvalidNumericRange);
    }

    qps_sum += sample.qps;
    weighted_predicted_sum += sample.qps * sample.predicted_overhead;
    weighted_measured_sum += sample.qps * sample.measured_overhead;
    max_critical_cluster_overhead =
        std::max(max_critical_cluster_overhead, sample.critical_cluster_p95_overhead);
  }

  if (qps_sum <= 0.0) {
    return Result<BudgetReport>::failure(ErrorCode::kInvalidProfile);
  }

  BudgetReport report{};
  report.weighted_predicted_budget = weighted_predicted_sum / qps_sum;
  report.weighted_measured_budget = weighted_measured_sum / qps_sum;
  report.max_critical_cluster_overhead = max_critical_cluster_overhead;
  report.within_budget = !exceeds_budget_limits(report, config);

  if (!report.within_budget) {
    return Result<BudgetReport>::failure(ErrorCode::kBudgetExceeded);
  }
  return Result<BudgetReport>::success(report);
}

const char* strategy_name(ProtectionStrategy strategy) noexcept {
  switch (strategy) {
    case ProtectionStrategy::kNone:
      return "NONE";
    case ProtectionStrategy::kCffLite:
      return "CFF_LITE";
    case ProtectionStrategy::kCffFullBcfStandard:
      return "CFF_FULL_BCF_STANDARD";
    case ProtectionStrategy::kVmStrongCffLite:
      return "VM_STRONG_CFF_LITE";
    case ProtectionStrategy::kJitEnclaveCffFullBcfStandard:
      return "JIT_ENCLAVE_CFF_FULL_BCF_STANDARD";
  }
  return "UNKNOWN";
}

}  // namespace eippf::runtime::policy

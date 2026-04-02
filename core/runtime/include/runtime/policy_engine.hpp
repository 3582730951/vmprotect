#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace eippf::runtime::policy {

enum class ErrorCode : std::uint8_t {
  kOk = 0u,
  kInvalidProfile = 1u,
  kInvalidNumericRange = 2u,
  kCriticalDowngradeRejected = 3u,
  kBudgetExceeded = 4u,
};

template <typename T>
class Result final {
 public:
  static Result success(T value) noexcept { return Result(std::move(value)); }

  static Result failure(ErrorCode error) noexcept { return Result(error); }

  [[nodiscard]] bool ok() const noexcept { return value_.has_value(); }

  [[nodiscard]] const T& value() const noexcept { return value_.value(); }

  [[nodiscard]] T& value() noexcept { return value_.value(); }

  [[nodiscard]] ErrorCode error() const noexcept { return error_; }

 private:
  explicit Result(T value) noexcept : value_(std::move(value)), error_(ErrorCode::kOk) {}

  explicit Result(ErrorCode error) noexcept : value_(std::nullopt), error_(error) {}

  std::optional<T> value_;
  ErrorCode error_ = ErrorCode::kInvalidProfile;
};

enum class HotClass : std::uint8_t {
  kCold = 0u,
  kWarm = 1u,
  kHot = 2u,
};

enum class ProtectionStrategy : std::uint8_t {
  kNone = 0u,
  kCffLite = 1u,
  kCffFullBcfStandard = 2u,
  kVmStrongCffLite = 3u,
  kJitEnclaveCffFullBcfStandard = 4u,
};

struct FunctionProfile final {
  std::string function_name;
  double calls_per_sec = 0.0;
  double cycles_share = 0.0;
  double p95_us = 0.0;
  double branch_miss_rate = 0.0;
  bool is_critical = false;
  bool has_drm_flatten = false;
  bool has_drm_jit = false;
};

struct NormalizationStats final {
  double min_calls_per_sec = 0.0;
  double max_calls_per_sec = 0.0;
  double min_p95_us = 0.0;
  double max_p95_us = 0.0;
  double min_branch_miss_rate = 0.0;
  double max_branch_miss_rate = 0.0;
};

struct RoutingDecision final {
  HotClass hot_class = HotClass::kCold;
  ProtectionStrategy strategy = ProtectionStrategy::kNone;
  double heat_score = 0.0;
  double predicted_overhead = 0.0;
};

struct WorkloadSample final {
  double qps = 0.0;
  double predicted_overhead = 0.0;
  double measured_overhead = 0.0;
  double critical_cluster_p95_overhead = 0.0;
};

struct BudgetConfig final {
  double target_budget = 0.10;
  double critical_cluster_overhead_limit = 0.15;
};

struct BudgetReport final {
  double weighted_predicted_budget = 0.0;
  double weighted_measured_budget = 0.0;
  double max_critical_cluster_overhead = 0.0;
  bool within_budget = false;
};

[[nodiscard]] Result<RoutingDecision> route_function(
    const FunctionProfile& profile,
    const NormalizationStats& normalization_stats,
    bool cold_start_mode) noexcept;

[[nodiscard]] Result<BudgetReport> evaluate_budget(
    const std::vector<WorkloadSample>& samples,
    const BudgetConfig& config) noexcept;

[[nodiscard]] const char* strategy_name(ProtectionStrategy strategy) noexcept;

}  // namespace eippf::runtime::policy

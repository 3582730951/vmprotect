#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <type_traits>

#include "runtime/backend_policy.hpp"

namespace eippf::tests::perf {

namespace {

#if defined(_MSC_VER)
#define EIPPF_PERF_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define EIPPF_PERF_NOINLINE __attribute__((noinline))
#else
#define EIPPF_PERF_NOINLINE
#endif

}  // namespace

using eippf::contracts::ProtectionTargetKind;
using eippf::runtime::backend::Policy;
using eippf::runtime::backend::PolicyError;

constexpr std::uint64_t kHotPathIterations = 2000000u;
constexpr std::uint64_t kOverallIterations = 10000000u;
constexpr int kWarmupRuns = 2;
constexpr std::size_t kMeasurementRuns = 7u;

struct MeasurementPair final {
  std::uint64_t baseline_ns = 0u;
  std::uint64_t compared_ns = 0u;
  double overhead_pct = 0.0;
};

inline double compute_overhead_pct(std::uint64_t baseline_ns, std::uint64_t compared_ns) {
  if (baseline_ns == 0u) {
    return -1.0;
  }
  if (compared_ns <= baseline_ns) {
    return 0.0;
  }
  const double delta = static_cast<double>(compared_ns - baseline_ns);
  return (delta * 100.0) / static_cast<double>(baseline_ns);
}

inline ProtectionTargetKind runtime_materialize_target(ProtectionTargetKind target) noexcept {
  volatile const auto raw =
      static_cast<std::underlying_type_t<ProtectionTargetKind>>(target);
  return static_cast<ProtectionTargetKind>(raw);
}

EIPPF_PERF_NOINLINE inline std::uint64_t measure_hot_path_ns(ProtectionTargetKind target,
                                                             volatile std::uint64_t& sink) {
  const ProtectionTargetKind runtime_target = runtime_materialize_target(target);
  const auto start = std::chrono::steady_clock::now();
  for (std::uint64_t i = 0; i < kHotPathIterations; ++i) {
    const auto dispatch = eippf::runtime::backend::dispatch_for_target(runtime_target);
    sink = sink + static_cast<std::uint64_t>(dispatch.allow_jit);
    sink = sink + static_cast<std::uint64_t>(dispatch.allow_runtime_executable_pages);
    sink = sink + static_cast<std::uint64_t>(dispatch.requires_sign_after_mutate);
    sink = sink + static_cast<std::uint64_t>(dispatch.backend);
  }
  const auto end = std::chrono::steady_clock::now();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

EIPPF_PERF_NOINLINE inline std::uint64_t measure_overall_ns(ProtectionTargetKind target,
                                                            volatile std::uint64_t& sink) {
  const ProtectionTargetKind runtime_target = runtime_materialize_target(target);
  const auto start = std::chrono::steady_clock::now();
  for (std::uint64_t i = 0; i < kOverallIterations; ++i) {
    const Policy policy = eippf::runtime::backend::default_policy_for_target(runtime_target);
    const PolicyError validate = eippf::runtime::backend::validate_policy(policy);
    const bool sign_after_mutate =
        eippf::runtime::backend::target_kind_requires_sign_after_mutate(runtime_target);
    sink = sink + static_cast<std::uint64_t>(validate);
    sink = sink + static_cast<std::uint64_t>(sign_after_mutate);
    sink = sink + static_cast<std::uint64_t>(policy.allow_runtime_executable_pages);
  }
  const auto end = std::chrono::steady_clock::now();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

template <typename MeasureFn>
MeasurementPair measure_median_pair_ns(ProtectionTargetKind baseline_target,
                                       ProtectionTargetKind compared_target,
                                       volatile std::uint64_t& sink,
                                       MeasureFn measure_fn) {
  for (int run = 0; run < kWarmupRuns; ++run) {
    (void)measure_fn(baseline_target, sink);
    (void)measure_fn(compared_target, sink);
  }

  std::array<std::uint64_t, kMeasurementRuns> baseline_samples{};
  std::array<std::uint64_t, kMeasurementRuns> compared_samples{};
  std::array<double, kMeasurementRuns> overhead_samples{};
  for (std::size_t run = 0; run < kMeasurementRuns; ++run) {
    std::uint64_t baseline_ns = 0u;
    std::uint64_t compared_ns = 0u;
    if ((run % 2u) == 0u) {
      baseline_ns = measure_fn(baseline_target, sink);
      compared_ns = measure_fn(compared_target, sink);
    } else {
      compared_ns = measure_fn(compared_target, sink);
      baseline_ns = measure_fn(baseline_target, sink);
    }

    baseline_samples[run] = baseline_ns;
    compared_samples[run] = compared_ns;
    overhead_samples[run] = compute_overhead_pct(baseline_ns, compared_ns);
  }

  std::sort(baseline_samples.begin(), baseline_samples.end());
  std::sort(compared_samples.begin(), compared_samples.end());
  std::sort(overhead_samples.begin(), overhead_samples.end());
  const std::size_t median_index = kMeasurementRuns / 2u;
  return MeasurementPair{
      .baseline_ns = baseline_samples[median_index],
      .compared_ns = compared_samples[median_index],
      .overhead_pct = overhead_samples[median_index],
  };
}

}  // namespace eippf::tests::perf

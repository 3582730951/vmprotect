#pragma once

#include <string>
#include <vector>

namespace eippf::contracts {

struct RedteamSampleResult final {
  std::string artifact_id;
  std::string platform;
  std::string format;
  std::string protection_profile;
  bool static_leak_pass = false;
  bool dynamic_probe_pass = false;
  bool runtime_dump_pass = false;
  bool signature_policy_pass = false;
  bool perf_budget_pass = false;
  double perf_delta_pct = 100.0;
  std::vector<std::string> failure_reasons;
  std::vector<std::string> evidence_paths;
  std::string final_verdict;
};

struct RedteamReport final {
  unsigned schema_version = 0u;
  std::string generated_at_utc;
  std::vector<RedteamSampleResult> samples;
};

[[nodiscard]] inline bool validate_redteam_sample_baseline(
    const RedteamSampleResult& sample) noexcept {
  if (sample.artifact_id.empty() || sample.platform.empty() || sample.format.empty() ||
      sample.protection_profile.empty()) {
    return false;
  }
  if (sample.perf_delta_pct < 0.0) {
    return false;
  }
  const bool all_hard_gates = sample.static_leak_pass && sample.dynamic_probe_pass &&
                              sample.runtime_dump_pass && sample.signature_policy_pass &&
                              sample.perf_budget_pass;
  if (sample.final_verdict != "pass" && sample.final_verdict != "fail") {
    return false;
  }
  if (sample.final_verdict == "pass" && !all_hard_gates) {
    return false;
  }
  if (sample.perf_budget_pass && sample.perf_delta_pct > 10.0) {
    return false;
  }
  if (!sample.perf_budget_pass && sample.perf_delta_pct <= 10.0) {
    return false;
  }
  return true;
}

[[nodiscard]] inline bool validate_redteam_report_baseline(
    const RedteamReport& report) noexcept {
  if (report.schema_version != 1u || report.generated_at_utc.empty() || report.samples.empty()) {
    return false;
  }
  for (const RedteamSampleResult& sample : report.samples) {
    if (!validate_redteam_sample_baseline(sample)) {
      return false;
    }
  }
  return true;
}

}  // namespace eippf::contracts

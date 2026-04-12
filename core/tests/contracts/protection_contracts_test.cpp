#include <iostream>
#include <string>

#include "contracts/protection_contracts.hpp"
#include "contracts/redteam_report_contracts.hpp"

namespace {

using eippf::contracts::ArtifactKind;
using eippf::contracts::MutationProfileKind;
using eippf::contracts::ProtectionManifestV2;
using eippf::contracts::ProtectionTargetKind;
using eippf::contracts::RedteamReport;
using eippf::contracts::RedteamSampleResult;
using eippf::contracts::ReviewStatus;
using eippf::contracts::RuntimeBackendKind;
using eippf::contracts::StrikeReasonCode;

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

}  // namespace

int main() {
  ProtectionManifestV2 ios_manifest{};
  ios_manifest.target_kind = ProtectionTargetKind::kIosAppStore;
  ios_manifest.backend_kind = RuntimeBackendKind::kIosSafeAot;
  ios_manifest.artifact_kind = ArtifactKind::kMachO;
  ios_manifest.attestation_profile = "ios.safe";
  ios_manifest.audit_policy = "strict";

  if (!expect(eippf::contracts::validate_manifest_baseline(ios_manifest),
              "ios manifest baseline should pass")) {
    return 1;
  }

  ios_manifest.allow_jit = true;
  if (!expect(!eippf::contracts::validate_manifest_baseline(ios_manifest),
              "ios manifest must reject jit")) {
    return 1;
  }

  if (!expect(eippf::contracts::target_requires_signed_artifact(
                  ProtectionTargetKind::kWindowsDriver),
              "windows driver should require signature")) {
    return 1;
  }

  if (!expect(eippf::contracts::target_allows_jit(ProtectionTargetKind::kDesktopNative),
              "desktop native should allow jit by policy")) {
    return 1;
  }

  if (!expect(!eippf::contracts::target_allows_jit(ProtectionTargetKind::kIosAppStore),
              "ios appstore should forbid jit")) {
    return 1;
  }
  if (!expect(eippf::contracts::target_forbids_jit(ProtectionTargetKind::kUnknown),
              "unknown target should forbid jit")) {
    return 1;
  }
  if (!expect(!eippf::contracts::target_allows_jit(ProtectionTargetKind::kUnknown),
              "unknown target should not allow jit")) {
    return 1;
  }

  if (!expect(eippf::contracts::target_forbids_jit(ProtectionTargetKind::kAndroidDex),
              "android dex should forbid jit")) {
    return 1;
  }
  if (!expect(eippf::contracts::target_forbids_jit(ProtectionTargetKind::kShellEphemeral),
              "shell ephemeral should forbid jit")) {
    return 1;
  }
  if (!expect(!eippf::contracts::target_allows_jit(ProtectionTargetKind::kAndroidDex),
              "android dex should not allow jit")) {
    return 1;
  }
  if (!expect(!eippf::contracts::target_allows_jit(ProtectionTargetKind::kShellEphemeral),
              "shell ephemeral should not allow jit")) {
    return 1;
  }

  if (!expect(eippf::contracts::mutation_profile_for_target_artifact(
                  ProtectionTargetKind::kDesktopNative, ArtifactKind::kPe) ==
                  MutationProfileKind::kPeUserMode,
              "desktop native + pe should map to pe_user_mode")) {
    return 1;
  }
  if (!expect(eippf::contracts::mutation_profile_for_target_artifact(
                  ProtectionTargetKind::kDesktopNative, ArtifactKind::kElf) ==
                  MutationProfileKind::kElfUserMode,
              "desktop native + elf should map to elf_user_mode")) {
    return 1;
  }
  if (!expect(eippf::contracts::mutation_profile_for_target(ProtectionTargetKind::kDesktopNative) ==
                  MutationProfileKind::kUnknown,
              "desktop native default mutation profile should be unknown")) {
    return 1;
  }
  if (!expect(eippf::contracts::mutation_profile_for_target_artifact(
                  ProtectionTargetKind::kDesktopNative, ArtifactKind::kMachO) ==
                  MutationProfileKind::kUnknown,
              "desktop native + macho should map to unknown")) {
    return 1;
  }

  const eippf::contracts::StrikeLedgerEntry strike = eippf::contracts::make_strike_entry(
      "agent-reviewer", "track-security", StrikeReasonCode::kRepeatRegression, "evidence-42",
      2u);
  if (!expect(strike.strike_count == 3u, "strike count should increment")) {
    return 1;
  }
  if (!expect(strike.requires_reassignment, "third strike should require reassignment")) {
    return 1;
  }

  if (!expect(std::string(eippf::contracts::to_string(ReviewStatus::kConditionalPass)) ==
                  "conditional_pass",
              "review status string mapping should be stable")) {
    return 1;
  }

  RedteamSampleResult redteam_sample{};
  redteam_sample.artifact_id = "linux_elf";
  redteam_sample.platform = "linux";
  redteam_sample.format = "elf";
  redteam_sample.protection_profile = "desktop_native_strict";
  redteam_sample.static_leak_pass = true;
  redteam_sample.dynamic_probe_pass = true;
  redteam_sample.runtime_dump_pass = true;
  redteam_sample.signature_policy_pass = true;
  redteam_sample.perf_budget_pass = true;
  redteam_sample.perf_delta_pct = 4.0;
  redteam_sample.final_verdict = "pass";

  if (!expect(eippf::contracts::validate_redteam_sample_baseline(redteam_sample),
              "redteam sample baseline should pass")) {
    return 1;
  }

  redteam_sample.perf_delta_pct = 12.0;
  redteam_sample.perf_budget_pass = false;
  redteam_sample.final_verdict = "fail";
  if (!expect(eippf::contracts::validate_redteam_sample_baseline(redteam_sample),
              "redteam sample should accept a valid failure report above perf budget")) {
    return 1;
  }

  redteam_sample.perf_budget_pass = true;
  if (!expect(!eippf::contracts::validate_redteam_sample_baseline(redteam_sample),
              "redteam sample must reject perf pass with perf delta above budget")) {
    return 1;
  }

  redteam_sample.perf_delta_pct = 4.0;
  redteam_sample.perf_budget_pass = true;
  redteam_sample.dynamic_probe_pass = false;
  redteam_sample.final_verdict = "pass";
  if (!expect(!eippf::contracts::validate_redteam_sample_baseline(redteam_sample),
              "redteam sample must reject pass verdict with failed dynamic probe")) {
    return 1;
  }

  RedteamSampleResult valid_report_sample{};
  valid_report_sample.artifact_id = "linux_elf";
  valid_report_sample.platform = "linux";
  valid_report_sample.format = "elf";
  valid_report_sample.protection_profile = "desktop_native_strict";
  valid_report_sample.static_leak_pass = true;
  valid_report_sample.dynamic_probe_pass = true;
  valid_report_sample.runtime_dump_pass = true;
  valid_report_sample.signature_policy_pass = true;
  valid_report_sample.perf_budget_pass = true;
  valid_report_sample.perf_delta_pct = 4.0;
  valid_report_sample.final_verdict = "pass";

  RedteamReport report{};
  report.schema_version = 1u;
  report.generated_at_utc = "2026-04-12T00:00:00+00:00";
  report.samples.push_back(valid_report_sample);
  if (!expect(eippf::contracts::validate_redteam_report_baseline(report),
              "redteam report baseline should accept populated report")) {
    return 1;
  }

  return 0;
}

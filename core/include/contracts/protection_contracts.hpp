#pragma once

#include <cstdint>
#include <string>

namespace eippf::contracts {

enum class ProtectionTargetKind : std::uint8_t {
  kUnknown = 0u,
  kDesktopNative = 1u,
  kAndroidSo = 2u,
  kAndroidDex = 3u,
  kIosAppStore = 4u,
  kWindowsDriver = 5u,
  kLinuxKernelModule = 6u,
  kAndroidKernelModule = 7u,
  kShellEphemeral = 8u,
};

enum class RuntimeBackendKind : std::uint8_t {
  kUnknown = 0u,
  kDesktopInterpreter = 1u,
  kDesktopJit = 2u,
  kIosSafeAot = 3u,
  kKernelSafeAot = 4u,
  kDexLoaderVm = 5u,
  kShellLauncher = 6u,
};

enum class ArtifactKind : std::uint8_t {
  kUnknown = 0u,
  kPe = 1u,
  kElf = 2u,
  kMachO = 3u,
  kDex = 4u,
  kShellBundle = 5u,
  kWindowsDriverSys = 6u,
  kLinuxKernelModuleKo = 7u,
};

enum class ReviewStatus : std::uint8_t {
  kUnknown = 0u,
  kPass = 1u,
  kConditionalPass = 2u,
  kFail = 3u,
};

struct ProtectionManifestV2 final {
  std::uint32_t schema_version = 2u;
  ProtectionTargetKind target_kind = ProtectionTargetKind::kUnknown;
  RuntimeBackendKind backend_kind = RuntimeBackendKind::kUnknown;
  ArtifactKind artifact_kind = ArtifactKind::kUnknown;
  bool allow_jit = false;
  bool allow_runtime_executable_pages = false;
  bool allow_persistent_plaintext = false;
  bool require_fail_closed = true;
  std::uint32_t plaintext_ttl_ms = 0u;
  std::string signing_profile;
  std::string attestation_profile;
  std::string audit_policy;
};

struct ArtifactAuditReportV1 final {
  std::uint32_t schema_version = 1u;
  ArtifactKind artifact_kind = ArtifactKind::kUnknown;
  bool imports_minimized = false;
  bool symbols_sanitized = false;
  bool string_anchor_scan_passed = false;
  bool section_permission_scan_passed = false;
  bool signature_state_passed = false;
  std::uint32_t suspicious_string_hits = 0u;
  std::uint32_t writable_executable_segments = 0u;
};

struct EvidencePackV1 final {
  std::uint32_t schema_version = 1u;
  std::string commit_sha;
  std::string toolchain_fingerprint;
  std::string build_log_path;
  std::string test_log_path;
  std::string artifact_hash_path;
  bool independent_reproduction = false;
  bool perf_gate_passed = false;
  bool security_gate_passed = false;
};

enum class StrikeReasonCode : std::uint8_t {
  kMissingEvidence = 0u,
  kPlatformConstraintViolation = 1u,
  kFailOpen = 2u,
  kOwnershipViolation = 3u,
  kTestGateBypass = 4u,
  kRepeatRegression = 5u,
};

struct StrikeLedgerEntry final {
  std::string agent_id;
  std::string track;
  StrikeReasonCode reason_code = StrikeReasonCode::kMissingEvidence;
  std::string evidence_ref;
  std::uint32_t strike_count = 0u;
  bool requires_reassignment = false;
};

[[nodiscard]] inline bool is_kernel_target(ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kWindowsDriver ||
         target == ProtectionTargetKind::kLinuxKernelModule ||
         target == ProtectionTargetKind::kAndroidKernelModule;
}

[[nodiscard]] inline bool target_forbids_jit(ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kIosAppStore || is_kernel_target(target);
}

[[nodiscard]] inline bool target_allows_jit(ProtectionTargetKind target) noexcept {
  return !target_forbids_jit(target);
}

[[nodiscard]] inline bool target_forbids_persistent_plaintext(
    ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kIosAppStore ||
         target == ProtectionTargetKind::kAndroidDex ||
         target == ProtectionTargetKind::kShellEphemeral || is_kernel_target(target);
}

[[nodiscard]] inline bool target_allows_persistent_plaintext(
    ProtectionTargetKind target) noexcept {
  return !target_forbids_persistent_plaintext(target);
}

[[nodiscard]] inline bool target_requires_signed_artifact(ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kIosAppStore || is_kernel_target(target);
}

[[nodiscard]] inline RuntimeBackendKind default_backend_for_target(
    ProtectionTargetKind target) noexcept {
  switch (target) {
    case ProtectionTargetKind::kDesktopNative:
    case ProtectionTargetKind::kAndroidSo:
      return RuntimeBackendKind::kDesktopJit;
    case ProtectionTargetKind::kIosAppStore:
      return RuntimeBackendKind::kIosSafeAot;
    case ProtectionTargetKind::kWindowsDriver:
    case ProtectionTargetKind::kLinuxKernelModule:
    case ProtectionTargetKind::kAndroidKernelModule:
      return RuntimeBackendKind::kKernelSafeAot;
    case ProtectionTargetKind::kAndroidDex:
      return RuntimeBackendKind::kDexLoaderVm;
    case ProtectionTargetKind::kShellEphemeral:
      return RuntimeBackendKind::kShellLauncher;
    case ProtectionTargetKind::kUnknown:
      return RuntimeBackendKind::kUnknown;
  }
  return RuntimeBackendKind::kUnknown;
}

[[nodiscard]] inline bool manifest_requires_runtime_page_control(
    const ProtectionManifestV2& manifest) noexcept {
  return manifest.allow_runtime_executable_pages || manifest.allow_jit;
}

[[nodiscard]] inline bool validate_manifest_baseline(const ProtectionManifestV2& manifest) noexcept {
  if (manifest.schema_version != 2u) {
    return false;
  }
  if (manifest.target_kind == ProtectionTargetKind::kUnknown ||
      manifest.backend_kind == RuntimeBackendKind::kUnknown ||
      manifest.artifact_kind == ArtifactKind::kUnknown) {
    return false;
  }
  if (target_forbids_jit(manifest.target_kind) && manifest.allow_jit) {
    return false;
  }
  if (target_forbids_persistent_plaintext(manifest.target_kind) &&
      manifest.allow_persistent_plaintext) {
    return false;
  }
  if (!manifest.require_fail_closed) {
    return false;
  }
  return true;
}

[[nodiscard]] inline StrikeLedgerEntry make_strike_entry(
    const std::string& agent_id, const std::string& track, StrikeReasonCode reason_code,
    const std::string& evidence_ref, std::uint32_t previous_strikes) {
  StrikeLedgerEntry entry{};
  entry.agent_id = agent_id;
  entry.track = track;
  entry.reason_code = reason_code;
  entry.evidence_ref = evidence_ref;
  entry.strike_count = previous_strikes + 1u;
  entry.requires_reassignment = entry.strike_count >= 3u;
  return entry;
}

[[nodiscard]] inline const char* to_string(ProtectionTargetKind target) noexcept {
  switch (target) {
    case ProtectionTargetKind::kDesktopNative:
      return "desktop_native";
    case ProtectionTargetKind::kAndroidSo:
      return "android_so";
    case ProtectionTargetKind::kAndroidDex:
      return "android_dex";
    case ProtectionTargetKind::kIosAppStore:
      return "ios_appstore";
    case ProtectionTargetKind::kWindowsDriver:
      return "windows_driver";
    case ProtectionTargetKind::kLinuxKernelModule:
      return "linux_kernel_module";
    case ProtectionTargetKind::kAndroidKernelModule:
      return "android_kernel_module";
    case ProtectionTargetKind::kShellEphemeral:
      return "shell_ephemeral";
    case ProtectionTargetKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

[[nodiscard]] inline const char* to_string(RuntimeBackendKind backend) noexcept {
  switch (backend) {
    case RuntimeBackendKind::kDesktopInterpreter:
      return "desktop_interpreter";
    case RuntimeBackendKind::kDesktopJit:
      return "desktop_jit";
    case RuntimeBackendKind::kIosSafeAot:
      return "ios_safe_aot";
    case RuntimeBackendKind::kKernelSafeAot:
      return "kernel_safe_aot";
    case RuntimeBackendKind::kDexLoaderVm:
      return "dex_loader_vm";
    case RuntimeBackendKind::kShellLauncher:
      return "shell_launcher";
    case RuntimeBackendKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

[[nodiscard]] inline const char* to_string(ArtifactKind kind) noexcept {
  switch (kind) {
    case ArtifactKind::kPe:
      return "pe";
    case ArtifactKind::kElf:
      return "elf";
    case ArtifactKind::kMachO:
      return "macho";
    case ArtifactKind::kDex:
      return "dex";
    case ArtifactKind::kShellBundle:
      return "shell_bundle";
    case ArtifactKind::kWindowsDriverSys:
      return "windows_driver_sys";
    case ArtifactKind::kLinuxKernelModuleKo:
      return "linux_kernel_module_ko";
    case ArtifactKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

[[nodiscard]] inline const char* to_string(ReviewStatus status) noexcept {
  switch (status) {
    case ReviewStatus::kPass:
      return "pass";
    case ReviewStatus::kConditionalPass:
      return "conditional_pass";
    case ReviewStatus::kFail:
      return "fail";
    case ReviewStatus::kUnknown:
      return "unknown";
  }
  return "unknown";
}

}  // namespace eippf::contracts

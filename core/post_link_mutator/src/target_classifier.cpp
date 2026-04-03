#include "post_link_mutator/target_classifier.hpp"

#include <cctype>
#include <string>

namespace eippf::post_link_mutator {
namespace {

using eippf::contracts::ArtifactKind;
using eippf::contracts::ProtectionTargetKind;

[[nodiscard]] std::string to_lower_ascii(std::string_view text) {
  std::string lowered;
  lowered.reserve(text.size());
  for (const char ch : text) {
    lowered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return lowered;
}

[[nodiscard]] bool contains_token(std::string_view text, std::string_view token) {
  return text.find(token) != std::string_view::npos;
}

}  // namespace

std::optional<ProtectionTargetKind> parse_target_kind_hint(std::string_view target_kind) {
  const std::string lowered = to_lower_ascii(target_kind);
  if (lowered == "desktop_native") {
    return ProtectionTargetKind::kDesktopNative;
  }
  if (lowered == "android_so") {
    return ProtectionTargetKind::kAndroidSo;
  }
  if (lowered == "android_dex" || lowered == "android_dex_research") {
    return ProtectionTargetKind::kAndroidDex;
  }
  if (lowered == "ios_appstore") {
    return ProtectionTargetKind::kIosAppStore;
  }
  if (lowered == "windows_driver") {
    return ProtectionTargetKind::kWindowsDriver;
  }
  if (lowered == "linux_kernel_module") {
    return ProtectionTargetKind::kLinuxKernelModule;
  }
  if (lowered == "android_kernel_module") {
    return ProtectionTargetKind::kAndroidKernelModule;
  }
  if (lowered == "shell_ephemeral") {
    return ProtectionTargetKind::kShellEphemeral;
  }
  return std::nullopt;
}

ProtectionTargetKind classify_target_kind(std::string_view target_label,
                                          std::string_view explicit_target_kind,
                                          ArtifactKind base_artifact_kind) {
  if (!explicit_target_kind.empty()) {
    const std::optional<ProtectionTargetKind> parsed = parse_target_kind_hint(explicit_target_kind);
    if (!parsed.has_value()) {
      return ProtectionTargetKind::kUnknown;
    }
    return *parsed;
  }

  const std::string lowered = to_lower_ascii(target_label);
  if (contains_token(lowered, "windows_driver") || contains_token(lowered, "driver_sys") ||
      contains_token(lowered, ".sys")) {
    return ProtectionTargetKind::kWindowsDriver;
  }
  if ((contains_token(lowered, "android") && contains_token(lowered, ".ko")) ||
      contains_token(lowered, "android_kernel_module")) {
    return ProtectionTargetKind::kAndroidKernelModule;
  }
  if (contains_token(lowered, "linux_kernel_module") || contains_token(lowered, "kernel_module") ||
      contains_token(lowered, ".ko")) {
    return ProtectionTargetKind::kLinuxKernelModule;
  }
  if (contains_token(lowered, "ios")) {
    return ProtectionTargetKind::kIosAppStore;
  }
  if (contains_token(lowered, "dex")) {
    return ProtectionTargetKind::kAndroidDex;
  }
  if (contains_token(lowered, "shell") || contains_token(lowered, "script") ||
      contains_token(lowered, ".sh")) {
    return ProtectionTargetKind::kShellEphemeral;
  }
  if (contains_token(lowered, "android")) {
    return ProtectionTargetKind::kAndroidSo;
  }

  switch (base_artifact_kind) {
    case ArtifactKind::kMachO:
      return ProtectionTargetKind::kIosAppStore;
    case ArtifactKind::kPe:
    case ArtifactKind::kElf:
      return ProtectionTargetKind::kDesktopNative;
    case ArtifactKind::kDex:
    case ArtifactKind::kShellBundle:
    case ArtifactKind::kWindowsDriverSys:
    case ArtifactKind::kLinuxKernelModuleKo:
    case ArtifactKind::kUnknown:
      return ProtectionTargetKind::kUnknown;
  }
  return ProtectionTargetKind::kUnknown;
}

bool target_kind_matches_artifact_kind(ProtectionTargetKind target_kind, ArtifactKind artifact_kind) {
  switch (target_kind) {
    case ProtectionTargetKind::kDesktopNative:
      return artifact_kind == ArtifactKind::kPe || artifact_kind == ArtifactKind::kElf;
    case ProtectionTargetKind::kAndroidSo:
      return artifact_kind == ArtifactKind::kElf;
    case ProtectionTargetKind::kIosAppStore:
      return artifact_kind == ArtifactKind::kMachO;
    case ProtectionTargetKind::kWindowsDriver:
      return artifact_kind == ArtifactKind::kPe;
    case ProtectionTargetKind::kLinuxKernelModule:
    case ProtectionTargetKind::kAndroidKernelModule:
      return artifact_kind == ArtifactKind::kElf;
    case ProtectionTargetKind::kAndroidDex:
      return artifact_kind == ArtifactKind::kDex;
    case ProtectionTargetKind::kShellEphemeral:
      return artifact_kind == ArtifactKind::kShellBundle;
    case ProtectionTargetKind::kUnknown:
      return false;
  }
  return false;
}

ArtifactKind classify_artifact_kind(ArtifactKind base_artifact_kind, ProtectionTargetKind target_kind) {
  if (target_kind == ProtectionTargetKind::kWindowsDriver) {
    return ArtifactKind::kWindowsDriverSys;
  }
  if (target_kind == ProtectionTargetKind::kLinuxKernelModule ||
      target_kind == ProtectionTargetKind::kAndroidKernelModule) {
    return ArtifactKind::kLinuxKernelModuleKo;
  }
  return base_artifact_kind;
}

}  // namespace eippf::post_link_mutator

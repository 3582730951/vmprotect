#include <iostream>
#include <string_view>

#include "contracts/protection_contracts.hpp"
#include "post_link_mutator/target_classifier.hpp"

namespace {

using eippf::contracts::ArtifactKind;
using eippf::contracts::ProtectionTargetKind;

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

}  // namespace

int main() {
  bool ok = true;

  const ProtectionTargetKind success_kind = eippf::post_link_mutator::classify_target_kind(
      "ios_release.dylib", "ios_appstore", ArtifactKind::kMachO);
  ok = expect(success_kind == ProtectionTargetKind::kIosAppStore,
              "success path: ios_appstore hint should classify as ios_appstore") &&
       ok;
  ok = expect(
           eippf::post_link_mutator::target_kind_matches_artifact_kind(success_kind, ArtifactKind::kMachO),
           "success path: ios_appstore should match macho") &&
       ok;

  const ProtectionTargetKind failure_kind = eippf::post_link_mutator::classify_target_kind(
      "invalid_hint_target", "not_a_real_target_kind", ArtifactKind::kElf);
  ok = expect(failure_kind == ProtectionTargetKind::kUnknown,
              "failure path: invalid hint must fail closed to unknown") &&
       ok;
  ok = expect(
           !eippf::post_link_mutator::target_kind_matches_artifact_kind(failure_kind, ArtifactKind::kElf),
           "failure path: unknown target kind must not match artifact") &&
       ok;

  const ProtectionTargetKind edge_kind = eippf::post_link_mutator::classify_target_kind(
      "android_kernel_module.ko", "", ArtifactKind::kElf);
  ok = expect(edge_kind == ProtectionTargetKind::kAndroidKernelModule,
              "security-edge: android + .ko should classify as android_kernel_module") &&
       ok;
  ok = expect(
           eippf::post_link_mutator::target_kind_matches_artifact_kind(edge_kind, ArtifactKind::kElf),
           "security-edge: android_kernel_module should only accept elf artifact") &&
       ok;
  ok = expect(eippf::post_link_mutator::classify_artifact_kind(ArtifactKind::kElf, edge_kind) ==
                  ArtifactKind::kLinuxKernelModuleKo,
              "security-edge: android_kernel_module should map manifest artifact to linux_kernel_module_ko") &&
       ok;

  return ok ? 0 : 1;
}

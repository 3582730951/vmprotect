#include "runtime/backend_policy.hpp"

namespace eippf::runtime::backend {

namespace {

using contracts::ProtectionTargetKind;
using contracts::RuntimeBackendKind;

[[nodiscard]] bool is_unknown_target(ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kUnknown;
}

[[nodiscard]] bool is_unknown_backend(RuntimeBackendKind backend) noexcept {
  return backend == RuntimeBackendKind::kUnknown;
}

}  // namespace

Policy default_policy_for_target(ProtectionTargetKind target) noexcept {
  switch (target) {
    case ProtectionTargetKind::kDesktopNative:
    case ProtectionTargetKind::kAndroidSo:
      return Policy{
          .target = target,
          .backend = RuntimeBackendKind::kDesktopJit,
          .allow_jit = true,
          .allow_runtime_executable_pages = true,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .plaintext_ttl_ms = 50u,
      };
    case ProtectionTargetKind::kIosAppStore:
      return Policy{
          .target = target,
          .backend = RuntimeBackendKind::kIosSafeAot,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .plaintext_ttl_ms = 0u,
      };
    case ProtectionTargetKind::kWindowsDriver:
    case ProtectionTargetKind::kLinuxKernelModule:
    case ProtectionTargetKind::kAndroidKernelModule:
      return Policy{
          .target = target,
          .backend = RuntimeBackendKind::kKernelSafeAot,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .plaintext_ttl_ms = 0u,
      };
    case ProtectionTargetKind::kAndroidDex:
      return Policy{
          .target = target,
          .backend = RuntimeBackendKind::kDexLoaderVm,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .plaintext_ttl_ms = 25u,
      };
    case ProtectionTargetKind::kShellEphemeral:
      return Policy{
          .target = target,
          .backend = RuntimeBackendKind::kShellLauncher,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .plaintext_ttl_ms = 25u,
      };
    case ProtectionTargetKind::kUnknown:
      return Policy{};
  }
  return Policy{};
}

bool target_forbids_jit(ProtectionTargetKind target) noexcept {
  return contracts::target_forbids_jit(target);
}

bool target_forbids_runtime_executable_pages(ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kIosAppStore || contracts::is_kernel_target(target);
}

bool target_forbids_persistent_plaintext(ProtectionTargetKind target) noexcept {
  return contracts::target_forbids_persistent_plaintext(target);
}

bool backend_matches_target(RuntimeBackendKind backend, ProtectionTargetKind target) noexcept {
  switch (backend) {
    case RuntimeBackendKind::kDesktopInterpreter:
    case RuntimeBackendKind::kDesktopJit:
      return target == ProtectionTargetKind::kDesktopNative ||
             target == ProtectionTargetKind::kAndroidSo;
    case RuntimeBackendKind::kIosSafeAot:
      return target == ProtectionTargetKind::kIosAppStore;
    case RuntimeBackendKind::kKernelSafeAot:
      return contracts::is_kernel_target(target);
    case RuntimeBackendKind::kDexLoaderVm:
      return target == ProtectionTargetKind::kAndroidDex;
    case RuntimeBackendKind::kShellLauncher:
      return target == ProtectionTargetKind::kShellEphemeral;
    case RuntimeBackendKind::kUnknown:
      return false;
  }
  return false;
}

PolicyError validate_policy(const Policy& policy) noexcept {
  if (is_unknown_target(policy.target)) {
    return PolicyError::kUnknownTarget;
  }
  if (is_unknown_backend(policy.backend)) {
    return PolicyError::kUnknownBackend;
  }
  if (!backend_matches_target(policy.backend, policy.target)) {
    return PolicyError::kBackendTargetMismatch;
  }
  if (eippf::runtime::backend::target_forbids_jit(policy.target) && policy.allow_jit) {
    return PolicyError::kJitForbidden;
  }
  if (eippf::runtime::backend::target_forbids_runtime_executable_pages(policy.target) &&
      policy.allow_runtime_executable_pages) {
    return PolicyError::kRuntimeExecutablePagesForbidden;
  }
  if (eippf::runtime::backend::target_forbids_persistent_plaintext(policy.target) &&
      policy.allow_persistent_plaintext) {
    return PolicyError::kPersistentPlaintextForbidden;
  }
  if (!policy.require_fail_closed) {
    return PolicyError::kFailClosedRequired;
  }
  if (policy.allow_persistent_plaintext && policy.plaintext_ttl_ms == 0u) {
    return PolicyError::kInvalidPlaintextTtl;
  }
  return PolicyError::kOk;
}

const char* policy_error_name(PolicyError error) noexcept {
  switch (error) {
    case PolicyError::kOk:
      return "OK";
    case PolicyError::kUnknownTarget:
      return "UNKNOWN_TARGET";
    case PolicyError::kUnknownBackend:
      return "UNKNOWN_BACKEND";
    case PolicyError::kBackendTargetMismatch:
      return "BACKEND_TARGET_MISMATCH";
    case PolicyError::kJitForbidden:
      return "JIT_FORBIDDEN";
    case PolicyError::kRuntimeExecutablePagesForbidden:
      return "RUNTIME_EXECUTABLE_PAGES_FORBIDDEN";
    case PolicyError::kPersistentPlaintextForbidden:
      return "PERSISTENT_PLAINTEXT_FORBIDDEN";
    case PolicyError::kFailClosedRequired:
      return "FAIL_CLOSED_REQUIRED";
    case PolicyError::kInvalidPlaintextTtl:
      return "INVALID_PLAINTEXT_TTL";
  }
  return "UNKNOWN_ERROR";
}

}  // namespace eippf::runtime::backend

#include "runtime/backend_policy.hpp"

namespace eippf::runtime::backend {

namespace {

using contracts::ProtectionTargetKind;
using contracts::RuntimeBackendKind;
using contracts::RuntimeLaneKind;

[[nodiscard]] bool is_unknown_target(ProtectionTargetKind target) noexcept {
  return target == ProtectionTargetKind::kUnknown;
}

[[nodiscard]] bool is_unknown_backend(RuntimeBackendKind backend) noexcept {
  return backend == RuntimeBackendKind::kUnknown;
}

[[nodiscard]] std::uint32_t default_plaintext_ttl_ms(ProtectionTargetKind target) noexcept {
  switch (target) {
    case ProtectionTargetKind::kDesktopNative:
    case ProtectionTargetKind::kAndroidSo:
      return 50u;
    case ProtectionTargetKind::kAndroidDex:
    case ProtectionTargetKind::kShellEphemeral:
      return 25u;
    case ProtectionTargetKind::kIosAppStore:
    case ProtectionTargetKind::kWindowsDriver:
    case ProtectionTargetKind::kLinuxKernelModule:
    case ProtectionTargetKind::kAndroidKernelModule:
    case ProtectionTargetKind::kUnknown:
      return 0u;
  }
  return 0u;
}

}  // namespace

RuntimeBackendDispatch dispatch_for_target(ProtectionTargetKind target) noexcept {
  switch (target) {
    case ProtectionTargetKind::kDesktopNative:
    case ProtectionTargetKind::kAndroidSo:
      return RuntimeBackendDispatch{
          .target = target,
          .lane = RuntimeLaneKind::kDesktopUserMode,
          .backend = RuntimeBackendKind::kDesktopJit,
          .allow_jit = true,
          .allow_runtime_executable_pages = true,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .requires_sign_after_mutate = false,
      };
    case ProtectionTargetKind::kIosAppStore:
      return RuntimeBackendDispatch{
          .target = target,
          .lane = RuntimeLaneKind::kIosSafe,
          .backend = RuntimeBackendKind::kIosSafeAot,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .requires_sign_after_mutate = false,
      };
    case ProtectionTargetKind::kWindowsDriver:
    case ProtectionTargetKind::kLinuxKernelModule:
    case ProtectionTargetKind::kAndroidKernelModule:
      return RuntimeBackendDispatch{
          .target = target,
          .lane = RuntimeLaneKind::kKernelSafe,
          .backend = RuntimeBackendKind::kKernelSafeAot,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .requires_sign_after_mutate = true,
      };
    case ProtectionTargetKind::kAndroidDex:
      return RuntimeBackendDispatch{
          .target = target,
          .lane = RuntimeLaneKind::kDexLoaderVm,
          .backend = RuntimeBackendKind::kDexLoaderVm,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .requires_sign_after_mutate = false,
      };
    case ProtectionTargetKind::kShellEphemeral:
      return RuntimeBackendDispatch{
          .target = target,
          .lane = RuntimeLaneKind::kShellLauncher,
          .backend = RuntimeBackendKind::kShellLauncher,
          .allow_jit = false,
          .allow_runtime_executable_pages = false,
          .allow_persistent_plaintext = false,
          .require_fail_closed = true,
          .requires_sign_after_mutate = false,
      };
    case ProtectionTargetKind::kUnknown:
      return RuntimeBackendDispatch{};
  }
  return RuntimeBackendDispatch{};
}

Policy default_policy_for_target(ProtectionTargetKind target) noexcept {
  const RuntimeBackendDispatch dispatch = dispatch_for_target(target);
  return Policy{
      .target = dispatch.target,
      .backend = dispatch.backend,
      .allow_jit = dispatch.allow_jit,
      .allow_runtime_executable_pages = dispatch.allow_runtime_executable_pages,
      .allow_persistent_plaintext = dispatch.allow_persistent_plaintext,
      .require_fail_closed = dispatch.require_fail_closed,
      .plaintext_ttl_ms = default_plaintext_ttl_ms(target),
  };
}

bool target_forbids_jit(ProtectionTargetKind target) noexcept {
  return contracts::target_forbids_jit(target);
}

bool target_forbids_runtime_executable_pages(ProtectionTargetKind target) noexcept {
  if (is_unknown_target(target)) {
    return true;
  }
  return !dispatch_for_target(target).allow_runtime_executable_pages;
}

bool target_forbids_persistent_plaintext(ProtectionTargetKind target) noexcept {
  return contracts::target_forbids_persistent_plaintext(target);
}

bool backend_matches_target(RuntimeBackendKind backend, ProtectionTargetKind target) noexcept {
  if (is_unknown_target(target) || is_unknown_backend(backend)) {
    return false;
  }
  const RuntimeBackendDispatch dispatch = dispatch_for_target(target);
  return dispatch.backend == backend;
}

bool target_kind_supports_desktop_jit(ProtectionTargetKind target) noexcept {
  const RuntimeBackendDispatch dispatch = dispatch_for_target(target);
  return dispatch.backend == RuntimeBackendKind::kDesktopJit && dispatch.allow_jit;
}

bool target_kind_requires_sign_after_mutate(ProtectionTargetKind target) noexcept {
  return dispatch_for_target(target).requires_sign_after_mutate;
}

PolicyError validate_policy(const Policy& policy) noexcept {
  if (is_unknown_target(policy.target)) {
    return PolicyError::kUnknownTarget;
  }
  if (is_unknown_backend(policy.backend)) {
    return PolicyError::kUnknownBackend;
  }
  const RuntimeBackendDispatch dispatch = dispatch_for_target(policy.target);
  if (dispatch.backend == RuntimeBackendKind::kUnknown) {
    return PolicyError::kUnknownTarget;
  }
  if (policy.backend != dispatch.backend) {
    return PolicyError::kBackendTargetMismatch;
  }
  if (policy.allow_jit != dispatch.allow_jit) {
    if (policy.allow_jit && !dispatch.allow_jit) {
      return PolicyError::kJitForbidden;
    }
    return PolicyError::kBackendTargetMismatch;
  }
  if (policy.allow_runtime_executable_pages != dispatch.allow_runtime_executable_pages) {
    if (policy.allow_runtime_executable_pages && !dispatch.allow_runtime_executable_pages) {
      return PolicyError::kRuntimeExecutablePagesForbidden;
    }
    return PolicyError::kBackendTargetMismatch;
  }
  if (policy.allow_persistent_plaintext != dispatch.allow_persistent_plaintext) {
    if (policy.allow_persistent_plaintext && !dispatch.allow_persistent_plaintext) {
      return PolicyError::kPersistentPlaintextForbidden;
    }
    return PolicyError::kBackendTargetMismatch;
  }
  if (policy.require_fail_closed != dispatch.require_fail_closed) {
    if (!policy.require_fail_closed) {
      return PolicyError::kFailClosedRequired;
    }
    return PolicyError::kBackendTargetMismatch;
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

#include "runtime/memory_hal.hpp"
#include "runtime/secure_ir_engine.hpp"

#include <cstdint>
#include <iostream>

namespace {

using Engine = eippf::runtime::ir::SecureIREngine;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

Engine::Program make_valid_program() {
  return Engine::Program{
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 7},
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 5},
      Engine::Instruction{Engine::OpCode::kAdd, 0},
      Engine::Instruction{Engine::OpCode::kRet, 0},
  };
}

bool test_target_disables_runtime_dynamic_code() {
  using eippf::contracts::ProtectionTargetKind;
  const ProtectionTargetKind configured = eippf::runtime::MemoryHAL::configured_target_kind();

#if defined(EIPPF_EXPECT_IOS_APPSTORE)
  if (!expect(configured == ProtectionTargetKind::kIosAppStore,
              "expected ios app store runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_WINDOWS_DRIVER)
  if (!expect(configured == ProtectionTargetKind::kWindowsDriver,
              "expected windows driver runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_LINUX_KERNEL_MODULE)
  if (!expect(configured == ProtectionTargetKind::kLinuxKernelModule,
              "expected linux kernel module runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_ANDROID_KERNEL_MODULE)
  if (!expect(configured == ProtectionTargetKind::kAndroidKernelModule,
              "expected android kernel module runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_ANDROID_DEX)
  if (!expect(configured == ProtectionTargetKind::kAndroidDex,
              "expected android dex runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_SHELL_EPHEMERAL)
  if (!expect(configured == ProtectionTargetKind::kShellEphemeral,
              "expected shell ephemeral runtime target")) {
    return false;
  }
#elif defined(EIPPF_EXPECT_UNKNOWN_TARGET)
  if (!expect(configured == ProtectionTargetKind::kUnknown,
              "expected unknown runtime target")) {
    return false;
  }
#else
  return expect(false, "missing expected runtime target macro");
#endif

  return expect(!eippf::runtime::MemoryHAL::runtime_dynamic_code_allowed(),
                "safe backend should disable SecureIREngine JIT execution");
}

bool test_compile_fails_closed() {
  Engine engine;
  const Engine::CompileResult compiled = engine.compile(make_valid_program());
  if (!expect(!compiled.ok(), "compile should fail closed when runtime code is forbidden")) {
    return false;
  }
  if (!expect(compiled.error == Engine::ErrorCode::kMemoryProtectFailed,
              "safe backend should surface memory protection failure")) {
    return false;
  }
  if (!expect(compiled.gate_code == Engine::GateCode::kJitRouteForbiddenForTarget,
              "safe backend should set jit_route_forbidden_for_target gate code")) {
    return false;
  }
  return expect(compiled.error_message_hash != 0u,
                "failed compile should still emit an audit hash");
}

bool test_execute_mitigates() {
  Engine engine;
  const Engine::CompileResult compiled = engine.compile(make_valid_program());
  const std::int64_t result = engine.execute(compiled);
  return expect(result == 0, "safe backend should mitigate instead of executing jitted code");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_target_disables_runtime_dynamic_code() && ok;
  ok = test_compile_fails_closed() && ok;
  ok = test_execute_mitigates() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] secure_ir_engine_safe_backend_test\n";
  return 0;
}

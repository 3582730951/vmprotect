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

Engine::Program make_program() {
  return Engine::Program{
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 3},
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 4},
      Engine::Instruction{Engine::OpCode::kAdd, 0},
      Engine::Instruction{Engine::OpCode::kRet, 0},
  };
}

}  // namespace

int main() {
  Engine engine;
  const Engine::CompileResult compiled = engine.compile(make_program());
  if (!expect(!compiled.ok(), "hardened safe target should block SecureIREngine compile")) {
    return 1;
  }
  if (!expect(compiled.error == Engine::ErrorCode::kMemoryProtectFailed,
              "compile should fail closed with kMemoryProtectFailed")) {
    return 1;
  }
  if (!expect(compiled.error_message_hash != 0u,
              "failed compile should still emit an audit hash")) {
    return 1;
  }

  if (!expect(engine.execute(compiled) == 0,
              "execute should mitigate instead of running compiled code")) {
    return 1;
  }

  std::cout << "[PASS] hardened_target_secure_ir_engine_test\n";
  return 0;
}

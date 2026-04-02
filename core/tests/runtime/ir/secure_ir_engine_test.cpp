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

bool test_compile_and_execute_success() {
  Engine::Program program{
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 7},
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 5},
      Engine::Instruction{Engine::OpCode::kAdd, 0},
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 3},
      Engine::Instruction{Engine::OpCode::kMul, 0},
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 4},
      Engine::Instruction{Engine::OpCode::kSub, 0},
      Engine::Instruction{Engine::OpCode::kRet, 0},
  };

  Engine engine;
  const Engine::CompileResult compiled = engine.compile(program);
  if (!expect(compiled.ok(), "expected compile() success for valid IR program")) {
    return false;
  }

  const std::int64_t result = engine.execute(compiled);
  if (!expect(result == 32, "expected jitted result ((7+5)*3-4) == 32")) {
    return false;
  }

  return expect(compiled.opcode_trace_hash != 0u && compiled.debug_symbol_hash != 0u,
                "expected non-zero audit hashes");
}

bool test_stack_underflow_failure() {
  Engine::Program bad_program{
      Engine::Instruction{Engine::OpCode::kAdd, 0},
      Engine::Instruction{Engine::OpCode::kRet, 0},
  };

  Engine engine;
  const Engine::CompileResult compiled = engine.compile(bad_program);
  if (!expect(!compiled.ok(), "expected compile() failure for stack underflow program")) {
    return false;
  }

  if (!expect(compiled.error == Engine::ErrorCode::kStackUnderflow,
              "expected kStackUnderflow error")) {
    return false;
  }

  return expect(compiled.error_message_hash != 0u, "expected non-zero error message hash");
}

bool test_missing_return_failure() {
  Engine::Program bad_program{
      Engine::Instruction{Engine::OpCode::kLoadImmI64, 42},
  };

  Engine engine;
  const Engine::CompileResult compiled = engine.compile(bad_program);
  if (!expect(!compiled.ok(), "expected compile() failure when return opcode is missing")) {
    return false;
  }

  return expect(compiled.error == Engine::ErrorCode::kMissingReturn,
                "expected kMissingReturn error");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_compile_and_execute_success() && ok;
  ok = test_stack_underflow_failure() && ok;
  ok = test_missing_return_failure() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] secure_ir_engine_test\n";
  return 0;
}

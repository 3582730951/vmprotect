#include "passes/IATMinimizationPass.hpp"

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

namespace {

constexpr const char* kResolverName = "eippf_ra0";

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

struct Fixture final {
  std::unique_ptr<llvm::Module> module;
  llvm::Function* main_function = nullptr;
  llvm::Function* puts_function = nullptr;
  llvm::Function* helper_function = nullptr;
};

Fixture build_fixture(llvm::LLVMContext& context) {
  Fixture fixture{};
  fixture.module = std::make_unique<llvm::Module>("iat_minimization_fixture", context);
  fixture.module->setTargetTriple("x86_64-pc-linux-gnu");

  auto* i32_ty = llvm::Type::getInt32Ty(context);
  auto* i8_ptr_ty = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));

  auto* puts_ty = llvm::FunctionType::get(i32_ty, {i8_ptr_ty}, false);
  fixture.puts_function = llvm::Function::Create(
      puts_ty, llvm::GlobalValue::ExternalLinkage, "puts", fixture.module.get());

  auto* helper_ty = llvm::FunctionType::get(i32_ty, false);
  fixture.helper_function = llvm::Function::Create(
      helper_ty, llvm::GlobalValue::ExternalLinkage, "eippf_rg0", fixture.module.get());

  auto* main_ty = llvm::FunctionType::get(i32_ty, false);
  fixture.main_function = llvm::Function::Create(
      main_ty, llvm::GlobalValue::ExternalLinkage, "main", fixture.module.get());
  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", fixture.main_function);
  llvm::IRBuilder<> builder(entry);

  auto* message = builder.CreateGlobalStringPtr("iat-minimization");
  builder.CreateCall(fixture.helper_function, {});
  builder.CreateCall(fixture.puts_function, {message});
  builder.CreateRet(builder.getInt32(0));

  return fixture;
}

bool verify_module_ok(const llvm::Module& module) {
  std::string verifier_message;
  llvm::raw_string_ostream verifier_stream(verifier_message);
  const bool broken = llvm::verifyModule(module, &verifier_stream);
  verifier_stream.flush();
  if (!broken) {
    return true;
  }
  std::cerr << "[FAIL] verifier failed\n";
  if (!verifier_message.empty()) {
    std::cerr << verifier_message;
  }
  return false;
}

std::size_t count_calls_to(const llvm::Module& module, llvm::StringRef callee_name) {
  std::size_t count = 0u;
  for (const llvm::Function& function : module) {
    for (const llvm::BasicBlock& block : function) {
      for (const llvm::Instruction& instruction : block) {
        const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call == nullptr) {
          continue;
        }
        const llvm::Function* callee = call->getCalledFunction();
        if (callee != nullptr && callee->getName() == callee_name) {
          ++count;
        }
      }
    }
  }
  return count;
}

bool test_iat_minimization_only_rewrites_runtime_supported_imports() {
  llvm::LLVMContext context;
  Fixture fixture = build_fixture(context);

  eippf::passes::IATMinimizationPass pass;
  llvm::ModuleAnalysisManager analysis_manager;
  const llvm::PreservedAnalyses preserved = pass.run(*fixture.module, analysis_manager);
  if (!expect(!preserved.areAllPreserved(), "iat minimization should rewrite supported imports")) {
    return false;
  }

  if (!expect(fixture.module->getFunction(kResolverName) != nullptr,
              "resolver declaration must be materialized")) {
    return false;
  }
  if (!expect(fixture.module->getFunction("puts") == nullptr,
              "supported import should be erased after rewrite")) {
    return false;
  }
  if (!expect(fixture.module->getFunction("eippf_rg0") != nullptr,
              "unsupported project helper must stay as direct external declaration")) {
    return false;
  }
  if (!expect(count_calls_to(*fixture.module, kResolverName) == 1u,
              "only one supported import should be rewritten to resolver")) {
    return false;
  }

  return verify_module_ok(*fixture.module);
}

}  // namespace

int main() {
  if (!test_iat_minimization_only_rewrites_runtime_supported_imports()) {
    return 1;
  }
  return 0;
}

#include "passes/StringProtectionPass.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Casting.h"

namespace {

constexpr const char* kAppliedMarker = "__eippf_inline_string_protect_applied";
constexpr const char* kDisallowedMarker = "__eippf_string_disallowed_detected";

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

struct ModuleFixture final {
  std::unique_ptr<llvm::Module> module;
  llvm::GlobalVariable* string_global = nullptr;
  llvm::Function* use_function = nullptr;
};

ModuleFixture build_fixture(llvm::LLVMContext& context, const std::string& literal) {
  ModuleFixture fixture{};
  fixture.module = std::make_unique<llvm::Module>("string_protection_fixture", context);

  auto* i8_ty = llvm::Type::getInt8Ty(context);
  auto* i32_ty = llvm::Type::getInt32Ty(context);
  auto* i8_ptr_ty = llvm::PointerType::getUnqual(i8_ty);

  auto* sink_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {i8_ptr_ty}, false);
  llvm::FunctionCallee sink = fixture.module->getOrInsertFunction("sink", sink_ty);

  llvm::Constant* string_initializer = llvm::ConstantDataArray::getString(context, literal, true);
  fixture.string_global = new llvm::GlobalVariable(*fixture.module, string_initializer->getType(), true,
                                                   llvm::GlobalValue::PrivateLinkage,
                                                   string_initializer, ".str");
  fixture.string_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  fixture.string_global->setAlignment(llvm::Align(1));

  auto* function_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
  fixture.use_function = llvm::Function::Create(function_ty, llvm::GlobalValue::ExternalLinkage,
                                                "use_string", fixture.module.get());
  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", fixture.use_function);
  llvm::IRBuilder<> builder(entry);

  llvm::Constant* zero = llvm::ConstantInt::get(i32_ty, 0);
  const std::array<llvm::Constant*, 2> gep_indices{zero, zero};
  const llvm::ArrayRef<llvm::Constant*> gep_index_ref(gep_indices);
  llvm::Constant* string_ptr = llvm::ConstantExpr::getInBoundsGetElementPtr(
      string_initializer->getType(), fixture.string_global, gep_index_ref);
  builder.CreateCall(sink, {string_ptr});
  builder.CreateRetVoid();

  return fixture;
}

bool run_pass(llvm::Module& module) {
  eippf::passes::StringProtectionPass pass;
  llvm::ModuleAnalysisManager analysis_manager;
  const llvm::PreservedAnalyses preserved = pass.run(module, analysis_manager);
  return !preserved.areAllPreserved();
}

bool has_callee(const llvm::Function& function, llvm::StringRef name) {
  for (const llvm::Instruction& instruction : llvm::instructions(function)) {
    const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
    if (call == nullptr) {
      continue;
    }
    const llvm::Function* callee = call->getCalledFunction();
    if (callee != nullptr && callee->getName() == name) {
      return true;
    }
  }
  return false;
}

bool call_to_sink_uses_dynamic_buffer(const llvm::Function& function) {
  for (const llvm::Instruction& instruction : llvm::instructions(function)) {
    const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
    if (call == nullptr) {
      continue;
    }
    const llvm::Function* callee = call->getCalledFunction();
    if (callee == nullptr || callee->getName() != "sink") {
      continue;
    }
    llvm::Value* arg = call->getArgOperand(0);
    if (llvm::isa<llvm::Constant>(arg)) {
      return false;
    }
  }
  return true;
}

bool test_normal_candidate_rewrite_success() {
  llvm::LLVMContext context;
  ModuleFixture fixture = build_fixture(context, "hello_mainline");
  const bool changed = run_pass(*fixture.module);
  if (!expect(changed, "pass should report changes for normal string candidate")) {
    return false;
  }

  auto* encrypted = llvm::dyn_cast<llvm::ConstantDataSequential>(fixture.string_global->getInitializer());
  if (!expect(encrypted != nullptr, "rewritten global should remain byte-array constant data")) {
    return false;
  }

  const std::string plain = std::string("hello_mainline") + '\0';
  if (!expect(encrypted->getRawDataValues() != plain,
              "rewritten candidate initializer must not keep plaintext bytes")) {
    return false;
  }

  if (!expect(fixture.module->getNamedGlobal(kAppliedMarker) != nullptr,
              "pass applied marker should be emitted")) {
    return false;
  }

  if (!expect(has_callee(*fixture.use_function, "eippf_string_token_decode"),
              "decode helper call should be injected")) {
    return false;
  }
  return expect(has_callee(*fixture.use_function, "eippf_string_token_wipe"),
                "wipe helper call should be injected");
}

bool test_sample_anchor_literals_are_rewritten() {
  constexpr std::array<const char*, 3> kSampleAnchors = {
      "EIPPF_SAMPLE_ANCHOR_WINDOWS_DLL",
      "EIPPF_SAMPLE_ANCHOR_LINUX_SO",
      "EIPPF_SAMPLE_ANCHOR_ANDROID_SO",
  };

  for (const char* anchor : kSampleAnchors) {
    llvm::LLVMContext context;
    ModuleFixture fixture = build_fixture(context, anchor);
    if (!expect(run_pass(*fixture.module),
                "sample anchor literal should be rewritten by string protection pass")) {
      return false;
    }

    auto* encrypted = llvm::dyn_cast<llvm::ConstantDataSequential>(fixture.string_global->getInitializer());
    if (!expect(encrypted != nullptr, "sample anchor candidate should keep byte-array constant form")) {
      return false;
    }

    const std::string plain = std::string(anchor) + '\0';
    if (!expect(encrypted->getRawDataValues() != plain,
                "sample anchor literal must not remain plaintext after rewrite")) {
      return false;
    }
    if (!expect(has_callee(*fixture.use_function, "eippf_string_token_decode"),
                "sample anchor rewrite should inject decode helper call")) {
      return false;
    }
    if (!expect(fixture.module->getNamedGlobal(kDisallowedMarker) == nullptr,
                "sample anchor rewrite should not be tagged as disallowed lexical anchor")) {
      return false;
    }
  }

  return true;
}

bool test_tutorial_anchor_is_disallowed() {
  llvm::LLVMContext context;
  ModuleFixture fixture = build_fixture(context, "tutorial_anchor_here");
  const bool changed = run_pass(*fixture.module);
  if (!expect(changed, "disallowed lexical candidate should be observably marked")) {
    return false;
  }

  auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(fixture.string_global->getInitializer());
  if (!expect(data != nullptr, "disallowed candidate should keep original constant data form")) {
    return false;
  }

  const std::string expected = std::string("tutorial_anchor_here") + '\0';
  if (!expect(data->getRawDataValues() == expected,
              "disallowed candidate must remain in original plaintext initializer")) {
    return false;
  }

  if (!expect(fixture.module->getNamedGlobal(kDisallowedMarker) != nullptr,
              "disallowed marker should be emitted")) {
    return false;
  }

  return expect(!has_callee(*fixture.use_function, "eippf_string_token_decode"),
                "disallowed candidate should not inject decode helper call");
}

bool test_rewrite_avoids_long_lived_plaintext_semantics() {
  llvm::LLVMContext context;
  ModuleFixture fixture = build_fixture(context, "sensitive_runtime_secret");
  if (!expect(run_pass(*fixture.module), "rewrite should happen for sensitive literal")) {
    return false;
  }

  if (!expect(call_to_sink_uses_dynamic_buffer(*fixture.use_function),
              "rewritten sink call should no longer use constant/global plaintext operand")) {
    return false;
  }

  return expect(has_callee(*fixture.use_function, "eippf_string_token_wipe"),
                "rewritten function should wipe decoded buffer before exit");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_normal_candidate_rewrite_success() && ok;
  ok = test_sample_anchor_literals_are_rewritten() && ok;
  ok = test_tutorial_anchor_is_disallowed() && ok;
  ok = test_rewrite_avoids_long_lived_plaintext_semantics() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] string_protection_pass_test\n";
  return 0;
}

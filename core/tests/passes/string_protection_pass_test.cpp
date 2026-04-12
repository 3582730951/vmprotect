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
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

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

struct EntryDominanceFixture final {
  std::unique_ptr<llvm::Module> module;
  llvm::GlobalVariable* string_global = nullptr;
  llvm::Function* use_function = nullptr;
};

struct DualUseFixture final {
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

EntryDominanceFixture build_entry_dominance_fixture(llvm::LLVMContext& context,
                                                    const std::string& literal) {
  EntryDominanceFixture fixture{};
  fixture.module = std::make_unique<llvm::Module>("string_protection_entry_dominance_fixture", context);

  auto* i8_ty = llvm::Type::getInt8Ty(context);
  auto* i32_ty = llvm::Type::getInt32Ty(context);
  auto* i64_ty = llvm::Type::getInt64Ty(context);

  llvm::Constant* string_initializer = llvm::ConstantDataArray::getString(context, literal, true);
  fixture.string_global = new llvm::GlobalVariable(*fixture.module, string_initializer->getType(), true,
                                                   llvm::GlobalValue::PrivateLinkage,
                                                   string_initializer, ".entry.str");
  fixture.string_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  fixture.string_global->setAlignment(llvm::Align(1));

  auto* function_ty = llvm::FunctionType::get(i32_ty, false);
  fixture.use_function = llvm::Function::Create(function_ty, llvm::GlobalValue::ExternalLinkage,
                                                "entry_dominance_user", fixture.module.get());
  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", fixture.use_function);
  llvm::IRBuilder<> builder(entry);

  llvm::AllocaInst* index_slot = builder.CreateAlloca(i32_ty, nullptr, "idx.slot");
  index_slot->setAlignment(llvm::Align(4));
  builder.CreateStore(builder.getInt32(9), index_slot);
  llvm::Value* index_i32 = builder.CreateLoad(i32_ty, index_slot, "idx.load");
  llvm::Value* index_i64 = builder.CreateSExt(index_i32, i64_ty, "idx.ext");

  llvm::Value* base_ptr = builder.CreateInBoundsGEP(
      string_initializer->getType(), fixture.string_global,
      {builder.getInt64(0), builder.getInt64(0)}, "str.base");
  llvm::Value* char_ptr = builder.CreateInBoundsGEP(i8_ty, base_ptr, index_i64, "str.char.ptr");
  llvm::Value* char_value = builder.CreateLoad(i8_ty, char_ptr, "str.char.load");
  llvm::Value* char_i32 = builder.CreateSExt(char_value, i32_ty, "str.char.i32");
  builder.CreateRet(char_i32);

  return fixture;
}

DualUseFixture build_dual_use_fixture(llvm::LLVMContext& context, const std::string& literal) {
  DualUseFixture fixture{};
  fixture.module = std::make_unique<llvm::Module>("string_protection_dual_use_fixture", context);

  auto* i8_ty = llvm::Type::getInt8Ty(context);
  auto* i32_ty = llvm::Type::getInt32Ty(context);
  auto* i8_ptr_ty = llvm::PointerType::getUnqual(i8_ty);

  auto* sink_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context), {i8_ptr_ty}, false);
  llvm::FunctionCallee sink = fixture.module->getOrInsertFunction("sink", sink_ty);
  auto* barrier_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
  llvm::FunctionCallee barrier = fixture.module->getOrInsertFunction("barrier", barrier_ty);

  llvm::Constant* string_initializer = llvm::ConstantDataArray::getString(context, literal, true);
  fixture.string_global = new llvm::GlobalVariable(*fixture.module, string_initializer->getType(), true,
                                                   llvm::GlobalValue::PrivateLinkage,
                                                   string_initializer, ".dual.str");
  fixture.string_global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  fixture.string_global->setAlignment(llvm::Align(1));

  auto* function_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(context), false);
  fixture.use_function = llvm::Function::Create(function_ty, llvm::GlobalValue::ExternalLinkage,
                                                "dual_use_string", fixture.module.get());
  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", fixture.use_function);
  llvm::IRBuilder<> builder(entry);

  llvm::Constant* zero = llvm::ConstantInt::get(i32_ty, 0);
  const std::array<llvm::Constant*, 2> gep_indices{zero, zero};
  const llvm::ArrayRef<llvm::Constant*> gep_index_ref(gep_indices);
  llvm::Constant* string_ptr = llvm::ConstantExpr::getInBoundsGetElementPtr(
      string_initializer->getType(), fixture.string_global, gep_index_ref);
  builder.CreateCall(sink, {string_ptr});
  builder.CreateCall(barrier, {});
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

bool verify_module_ok(const llvm::Module& module, const char* context) {
  std::string verifier_message;
  llvm::raw_string_ostream verifier_stream(verifier_message);
  const bool broken = llvm::verifyModule(module, &verifier_stream);
  verifier_stream.flush();
  if (!broken) {
    return true;
  }
  std::cerr << "[FAIL] verifier failed in " << context << '\n';
  if (!verifier_message.empty()) {
    std::cerr << verifier_message;
  }
  return false;
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

std::size_t count_callee_calls(const llvm::Function& function, llvm::StringRef name) {
  std::size_t count = 0u;
  for (const llvm::Instruction& instruction : llvm::instructions(function)) {
    const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
    if (call == nullptr) {
      continue;
    }
    const llvm::Function* callee = call->getCalledFunction();
    if (callee != nullptr && callee->getName() == name) {
      ++count;
    }
  }
  return count;
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

  if (!expect(has_callee(*fixture.use_function, "eippf_sd0"),
              "decode helper call should be injected")) {
    return false;
  }
  return expect(has_callee(*fixture.use_function, "eippf_sw0"),
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
    if (!expect(has_callee(*fixture.use_function, "eippf_sd0"),
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

  return expect(!has_callee(*fixture.use_function, "eippf_sd0"),
                "disallowed candidate should not inject decode helper call");
}

bool test_reverse_tool_markers_are_disallowed() {
  constexpr std::array<const char*, 3> kReverseMarkers = {
      "IDA Pro marker",
      "Cheat Engine marker",
      "Frida gadget marker",
  };

  for (const char* marker : kReverseMarkers) {
    llvm::LLVMContext context;
    ModuleFixture fixture = build_fixture(context, marker);
    const bool changed = run_pass(*fixture.module);
    if (!expect(changed, "reverse-tool lexical candidate should be observably marked")) {
      return false;
    }

    auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(fixture.string_global->getInitializer());
    if (!expect(data != nullptr, "reverse-tool candidate should keep original constant data form")) {
      return false;
    }

    const std::string expected = std::string(marker) + '\0';
    if (!expect(data->getRawDataValues() == expected,
                "reverse-tool candidate must remain in original plaintext initializer")) {
      return false;
    }

    if (!expect(fixture.module->getNamedGlobal(kDisallowedMarker) != nullptr,
                "reverse-tool marker should emit disallowed marker")) {
      return false;
    }

    if (!expect(!has_callee(*fixture.use_function, "eippf_sd0"),
                "reverse-tool candidate should not inject decode helper call")) {
      return false;
    }
  }

  return true;
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

  return expect(has_callee(*fixture.use_function, "eippf_sw0"),
                "rewritten function should wipe decoded buffer before exit");
}

bool test_entry_block_dominance_regression() {
  llvm::LLVMContext context;
  EntryDominanceFixture fixture =
      build_entry_dominance_fixture(context, "entry_block_dominance_literal");
  if (!expect(run_pass(*fixture.module),
              "entry-block dominance fixture should be rewritten by string protection pass")) {
    return false;
  }
  if (!expect(verify_module_ok(*fixture.module, "entry_block_dominance_regression"),
              "rewritten entry-block dominance fixture must pass verifier")) {
    return false;
  }
  if (!expect(has_callee(*fixture.use_function, "eippf_sd0"),
              "entry-block dominance fixture should inject decode helper call")) {
    return false;
  }
  return expect(has_callee(*fixture.use_function, "eippf_sw0"),
                "entry-block dominance fixture should inject wipe helper call");
}

bool test_repeated_uses_decode_on_demand() {
  llvm::LLVMContext context;
  DualUseFixture fixture = build_dual_use_fixture(context, "decode_twice");
  if (!expect(run_pass(*fixture.module), "dual-use fixture should be rewritten")) {
    return false;
  }
  if (!expect(verify_module_ok(*fixture.module, "repeated_uses_decode_on_demand"),
              "dual-use fixture must pass verifier")) {
    return false;
  }
  if (!expect(count_callee_calls(*fixture.use_function, "eippf_sd0") == 2u,
              "dual-use fixture should decode once per use site")) {
    return false;
  }
  return expect(count_callee_calls(*fixture.use_function, "eippf_sw0") == 2u,
                "dual-use fixture should wipe once per use site");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_normal_candidate_rewrite_success() && ok;
  ok = test_sample_anchor_literals_are_rewritten() && ok;
  ok = test_tutorial_anchor_is_disallowed() && ok;
  ok = test_reverse_tool_markers_are_disallowed() && ok;
  ok = test_rewrite_avoids_long_lived_plaintext_semantics() && ok;
  ok = test_entry_block_dominance_regression() && ok;
  ok = test_repeated_uses_decode_on_demand() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] string_protection_pass_test\n";
  return 0;
}

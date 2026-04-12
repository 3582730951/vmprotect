#include "passes/ProtectionSuitePassPlugin.hpp"

#include <array>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

namespace {

constexpr const char* kRouteAttribute = "eippf.route";
constexpr const char* kStringMarker = "__eippf_inline_string_protect_applied";
constexpr const char* kMbaMarker = "__eippf_mba_obfuscation_applied";
constexpr const char* kResolverName = "eippf_ra0";
constexpr const char* kJitEntryPoint = "eippf_je0";
constexpr const char* kJitInjectedAttr = "eippf.jit.enclave.injected";
constexpr const char* kVmInjectedAttr = "eippf.vm.shell.injected";
constexpr const char* kVmFailClosedAttr = "eippf.vm.fail_closed";

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

struct Fixture final {
  std::unique_ptr<llvm::Module> module;
  llvm::GlobalVariable* string_global = nullptr;
  llvm::Function* main_function = nullptr;
  llvm::Function* jit_target = nullptr;
  llvm::Function* vm_target = nullptr;
  llvm::Function* flatten_target = nullptr;
};

llvm::GlobalVariable* create_string_global(llvm::Module& module,
                                           llvm::StringRef literal,
                                           llvm::StringRef name) {
  llvm::Constant* initializer =
      llvm::ConstantDataArray::getString(module.getContext(), literal, true);
  auto* global = new llvm::GlobalVariable(module, initializer->getType(), true,
                                          llvm::GlobalValue::PrivateLinkage,
                                          initializer, name);
  global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  global->setAlignment(llvm::Align(1));
  return global;
}

llvm::Constant* global_string_ptr(llvm::GlobalVariable& global) {
  llvm::LLVMContext& context = global.getContext();
  auto* i32_ty = llvm::Type::getInt32Ty(context);
  llvm::Constant* zero = llvm::ConstantInt::get(i32_ty, 0);
  const std::array<llvm::Constant*, 2> gep_indices{zero, zero};
  const llvm::ArrayRef<llvm::Constant*> gep_index_ref(gep_indices);
  return llvm::ConstantExpr::getInBoundsGetElementPtr(
      global.getValueType(), &global, gep_index_ref);
}

void append_annotation(llvm::Module& module, llvm::Function& function, llvm::StringRef text) {
  llvm::LLVMContext& context = module.getContext();
  auto* i8_ptr_ty = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  auto* i32_ty = llvm::Type::getInt32Ty(context);
  auto* entry_ty = llvm::StructType::get(i8_ptr_ty, i8_ptr_ty, i8_ptr_ty, i32_ty, i8_ptr_ty);

  llvm::GlobalVariable* annotation_text = create_string_global(module, text, ".ann.text");
  llvm::GlobalVariable* annotation_file = create_string_global(module, "suite_test.cpp", ".ann.file");

  llvm::Constant* function_ptr =
      llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(&function, i8_ptr_ty);
  llvm::Constant* text_ptr = llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(
      global_string_ptr(*annotation_text), i8_ptr_ty);
  llvm::Constant* file_ptr = llvm::ConstantExpr::getPointerBitCastOrAddrSpaceCast(
      global_string_ptr(*annotation_file), i8_ptr_ty);
  llvm::Constant* line = llvm::ConstantInt::get(i32_ty, 1);
  llvm::Constant* extra = llvm::ConstantPointerNull::get(i8_ptr_ty);
  llvm::Constant* new_entry =
      llvm::ConstantStruct::get(entry_ty, {function_ptr, text_ptr, file_ptr, line, extra});

  llvm::SmallVector<llvm::Constant*, 8> entries;
  if (llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations")) {
    auto* existing = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
    if (existing != nullptr) {
      for (llvm::Value* operand : existing->operands()) {
        auto* entry = llvm::dyn_cast<llvm::Constant>(operand);
        if (entry != nullptr) {
          entries.push_back(entry);
        }
      }
    }
    annotations->eraseFromParent();
  }

  entries.push_back(new_entry);
  auto* array_ty = llvm::ArrayType::get(entry_ty, entries.size());
  auto* annotations = new llvm::GlobalVariable(
      module, array_ty, false, llvm::GlobalValue::AppendingLinkage,
      llvm::ConstantArray::get(array_ty, entries), "llvm.global.annotations");
  annotations->setSection("llvm.metadata");
}

Fixture build_fixture(llvm::LLVMContext& context) {
  Fixture fixture{};
  fixture.module = std::make_unique<llvm::Module>("protection_suite_fixture", context);

  auto* i32_ty = llvm::Type::getInt32Ty(context);
  fixture.string_global = create_string_global(*fixture.module, "default_suite_string", ".str");

  auto* puts_ty = llvm::FunctionType::get(i32_ty, {llvm::PointerType::getUnqual(
                                                        llvm::Type::getInt8Ty(context))},
                                          false);
  llvm::FunctionCallee puts = fixture.module->getOrInsertFunction("puts", puts_ty);

  auto* main_ty = llvm::FunctionType::get(i32_ty, false);
  fixture.main_function = llvm::Function::Create(
      main_ty, llvm::GlobalValue::ExternalLinkage, "main", fixture.module.get());
  fixture.main_function->addFnAttr(kRouteAttribute, "vm");
  llvm::BasicBlock* main_entry = llvm::BasicBlock::Create(context, "entry", fixture.main_function);
  llvm::IRBuilder<> main_builder(main_entry);
  main_builder.CreateCall(puts, {global_string_ptr(*fixture.string_global)});
  main_builder.CreateRet(main_builder.getInt32(0));

  auto* unary_ty = llvm::FunctionType::get(i32_ty, {i32_ty}, false);

  fixture.jit_target = llvm::Function::Create(
      unary_ty, llvm::GlobalValue::ExternalLinkage, "jit_target", fixture.module.get());
  fixture.jit_target->arg_begin()->setName("value");
  llvm::BasicBlock* jit_entry = llvm::BasicBlock::Create(context, "entry", fixture.jit_target);
  llvm::IRBuilder<> jit_builder(jit_entry);
  llvm::Value* jit_result =
      jit_builder.CreateAdd(fixture.jit_target->getArg(0), jit_builder.getInt32(1), "jit.ret");
  jit_builder.CreateRet(jit_result);

  fixture.vm_target = llvm::Function::Create(
      unary_ty, llvm::GlobalValue::ExternalLinkage, "vm_target", fixture.module.get());
  fixture.vm_target->arg_begin()->setName("value");
  llvm::BasicBlock* vm_entry = llvm::BasicBlock::Create(context, "entry", fixture.vm_target);
  llvm::IRBuilder<> vm_builder(vm_entry);
  llvm::Value* vm_result =
      vm_builder.CreateSub(fixture.vm_target->getArg(0), vm_builder.getInt32(1), "vm.ret");
  vm_builder.CreateRet(vm_result);

  fixture.flatten_target = llvm::Function::Create(
      unary_ty, llvm::GlobalValue::ExternalLinkage, "flatten_target", fixture.module.get());
  fixture.flatten_target->arg_begin()->setName("value");
  llvm::BasicBlock* flatten_entry =
      llvm::BasicBlock::Create(context, "entry", fixture.flatten_target);
  llvm::BasicBlock* flatten_positive =
      llvm::BasicBlock::Create(context, "positive", fixture.flatten_target);
  llvm::BasicBlock* flatten_negative =
      llvm::BasicBlock::Create(context, "negative", fixture.flatten_target);

  llvm::IRBuilder<> flatten_entry_builder(flatten_entry);
  llvm::Value* flatten_condition = flatten_entry_builder.CreateICmpSGT(
      fixture.flatten_target->getArg(0), flatten_entry_builder.getInt32(0), "is_positive");
  flatten_entry_builder.CreateCondBr(flatten_condition, flatten_positive, flatten_negative);

  llvm::IRBuilder<> flatten_positive_builder(flatten_positive);
  llvm::Value* flatten_add = flatten_positive_builder.CreateAdd(
      fixture.flatten_target->getArg(0), flatten_positive_builder.getInt32(4), "pos.ret");
  flatten_positive_builder.CreateRet(flatten_add);

  llvm::IRBuilder<> flatten_negative_builder(flatten_negative);
  llvm::Value* flatten_sub = flatten_negative_builder.CreateSub(
      fixture.flatten_target->getArg(0), flatten_negative_builder.getInt32(4), "neg.ret");
  flatten_negative_builder.CreateRet(flatten_sub);

  append_annotation(*fixture.module, *fixture.jit_target, "drm_jit_target");
  append_annotation(*fixture.module, *fixture.vm_target, "drm_critical_ip");
  append_annotation(*fixture.module, *fixture.flatten_target, "drm_flatten");

  return fixture;
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

bool has_basic_block_named(const llvm::Function& function, llvm::StringRef name) {
  for (const llvm::BasicBlock& block : function) {
    if (block.getName() == name) {
      return true;
    }
  }
  return false;
}

bool has_call_to(const llvm::Module& module, llvm::StringRef callee_name) {
  for (const llvm::Function& function : module) {
    for (const llvm::Instruction& instruction : llvm::instructions(function)) {
      const auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
      if (call == nullptr) {
        continue;
      }
      const llvm::Function* callee = call->getCalledFunction();
      if (callee != nullptr && callee->getName() == callee_name) {
        return true;
      }
    }
  }
  return false;
}

bool has_route(const llvm::Function& function, llvm::StringRef expected_route) {
  const llvm::Attribute route_attribute = function.getFnAttribute(kRouteAttribute);
  return route_attribute.isValid() && route_attribute.isStringAttribute() &&
         route_attribute.getValueAsString() == expected_route;
}

void run_protection_suite(llvm::Module& module) {
  llvm::PassBuilder pass_builder;
  eippf::passes::register_protection_suite_pipeline(pass_builder);

  llvm::LoopAnalysisManager loop_analysis_manager;
  llvm::FunctionAnalysisManager function_analysis_manager;
  llvm::CGSCCAnalysisManager cgscc_analysis_manager;
  llvm::ModuleAnalysisManager module_analysis_manager;

  pass_builder.registerLoopAnalyses(loop_analysis_manager);
  pass_builder.registerFunctionAnalyses(function_analysis_manager);
  pass_builder.registerCGSCCAnalyses(cgscc_analysis_manager);
  pass_builder.registerModuleAnalyses(module_analysis_manager);
  pass_builder.crossRegisterProxies(loop_analysis_manager,
                                    function_analysis_manager,
                                    cgscc_analysis_manager,
                                    module_analysis_manager);

  llvm::ModulePassManager module_pass_manager;
  if (llvm::Error parse_error =
          pass_builder.parsePassPipeline(module_pass_manager, "eippf-protection-suite-default")) {
    std::string error_message;
    llvm::raw_string_ostream error_stream(error_message);
    llvm::handleAllErrors(std::move(parse_error), [&](const llvm::ErrorInfoBase& error_info) {
      error_info.log(error_stream);
    });
    error_stream.flush();
    std::cerr << "[FAIL] unable to parse suite pipeline token";
    if (!error_message.empty()) {
      std::cerr << ": " << error_message;
    }
    std::cerr << '\n';
    std::abort();
  }
  module_pass_manager.run(module, module_analysis_manager);
}

bool test_default_suite_registers_mainline_without_jit_or_vm() {
  if (!expect(eippf::passes::kDefaultProtectionSuitePasses.size() == 5u,
              "suite manifest should contain five default passes")) {
    return false;
  }

  constexpr std::array<std::string_view, 5> kExpectedPasses = {
      "ProtectionAnchor",
      "StringProtection",
      "IATMinimization",
      "MBAObfuscation",
      "CFFObfuscation",
  };
  if (!expect(eippf::passes::kDefaultProtectionSuitePasses == kExpectedPasses,
              "suite manifest order should match the intended mainline")) {
    return false;
  }
  if (!expect(eippf::passes::kDefaultProtectionSuiteSummary ==
                  "ProtectionAnchor,StringProtection,IATMinimization,MBAObfuscation,CFFObfuscation",
              "suite summary string should stay in sync with the mainline order")) {
    return false;
  }

  llvm::LLVMContext context;
  Fixture fixture = build_fixture(context);
  run_protection_suite(*fixture.module);

  auto* encrypted =
      llvm::dyn_cast<llvm::ConstantDataSequential>(fixture.string_global->getInitializer());
  if (!expect(encrypted != nullptr, "string initializer should remain constant data")) {
    return false;
  }

  const std::string plaintext = std::string("default_suite_string") + '\0';
  if (!expect(encrypted->getRawDataValues() != plaintext,
              "string protection must rewrite global string initializers in the default suite")) {
    return false;
  }

  if (!expect(fixture.module->getNamedGlobal(kStringMarker) != nullptr,
              "default suite should emit the string protection marker")) {
    return false;
  }

  if (!expect(fixture.module->getNamedGlobal(kMbaMarker) != nullptr,
              "default suite should emit the MBA applied marker")) {
    return false;
  }

  if (!expect(fixture.module->getFunction("puts") == nullptr,
              "IAT minimization should erase the original direct external declaration")) {
    return false;
  }

  if (!expect(fixture.module->getFunction(kResolverName) != nullptr,
              "default suite should materialize the resolver declaration")) {
    return false;
  }

  if (!expect(has_call_to(*fixture.module, kResolverName),
              "default suite should introduce resolver calls for external targets")) {
    return false;
  }

  if (!expect(has_route(*fixture.jit_target, "jit"),
              "protection anchor should tag JIT-target functions with route=jit")) {
    return false;
  }

  if (!expect(has_route(*fixture.vm_target, "vm"),
              "protection anchor should tag VM-target functions with route=vm")) {
    return false;
  }

  if (!expect(has_route(*fixture.flatten_target, "cff"),
              "protection anchor should tag flatten-target functions with route=cff")) {
    return false;
  }

  if (!expect(has_basic_block_named(*fixture.flatten_target, "eippf.cff.dispatcher"),
              "default suite should still run the CFF pass")) {
    return false;
  }

  if (!expect(fixture.module->getFunction(kJitEntryPoint) == nullptr,
              "default suite must not introduce the legacy JIT enclave entrypoint")) {
    return false;
  }

  if (!expect(!fixture.jit_target->hasFnAttribute(kJitInjectedAttr),
              "default suite must not run JITEnclavePass on JIT-routed functions")) {
    return false;
  }

  if (!expect(!fixture.vm_target->hasFnAttribute(kVmInjectedAttr),
              "default suite must not run SelectiveVMPass on VM-routed functions")) {
    return false;
  }

  if (!expect(!fixture.vm_target->hasFnAttribute(kVmFailClosedAttr),
              "default suite must not inject legacy VM fail-closed attributes")) {
    return false;
  }

  return verify_module_ok(*fixture.module,
                          "test_default_suite_registers_mainline_without_jit_or_vm");
}

}  // namespace

int main() {
  if (!test_default_suite_registers_mainline_without_jit_or_vm()) {
    return 1;
  }
  return 0;
}

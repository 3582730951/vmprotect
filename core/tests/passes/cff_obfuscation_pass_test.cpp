#include "passes/CFFObfuscationPass.hpp"

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

namespace {

constexpr const char* kStringEncryptionMarker = "__eippf_strenc_done";
constexpr const char* kDecryptHelperName = "__eippf_xor_decrypt";
constexpr const char* kRouteAttribute = "eippf.route";

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

Fixture build_fixture(llvm::LLVMContext& context) {
  Fixture fixture{};
  fixture.module = std::make_unique<llvm::Module>("cff_obfuscation_fixture", context);

  auto* i32_ty = llvm::Type::getInt32Ty(context);
  fixture.string_global = create_string_global(*fixture.module, "cff_must_not_touch_me", ".str");

  auto* main_ty = llvm::FunctionType::get(i32_ty, false);
  llvm::Function* main_function = llvm::Function::Create(
      main_ty, llvm::GlobalValue::ExternalLinkage, "main", fixture.module.get());
  main_function->addFnAttr(kRouteAttribute, "vm");
  llvm::BasicBlock* main_entry = llvm::BasicBlock::Create(context, "entry", main_function);
  llvm::IRBuilder<> main_builder(main_entry);
  main_builder.CreateRet(main_builder.getInt32(0));

  auto* flatten_ty = llvm::FunctionType::get(i32_ty, {i32_ty}, false);
  fixture.flatten_target = llvm::Function::Create(
      flatten_ty, llvm::GlobalValue::ExternalLinkage, "flatten_target", fixture.module.get());
  fixture.flatten_target->addFnAttr(kRouteAttribute, "cff");
  fixture.flatten_target->arg_begin()->setName("value");

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", fixture.flatten_target);
  llvm::BasicBlock* positive = llvm::BasicBlock::Create(context, "positive", fixture.flatten_target);
  llvm::BasicBlock* negative = llvm::BasicBlock::Create(context, "negative", fixture.flatten_target);

  llvm::IRBuilder<> entry_builder(entry);
  llvm::Value* condition = entry_builder.CreateICmpSGT(
      fixture.flatten_target->getArg(0), entry_builder.getInt32(0), "is_positive");
  entry_builder.CreateCondBr(condition, positive, negative);

  llvm::IRBuilder<> positive_builder(positive);
  llvm::Value* add_value = positive_builder.CreateAdd(
      fixture.flatten_target->getArg(0), positive_builder.getInt32(1), "plus_one");
  positive_builder.CreateRet(add_value);

  llvm::IRBuilder<> negative_builder(negative);
  llvm::Value* sub_value = negative_builder.CreateSub(
      fixture.flatten_target->getArg(0), negative_builder.getInt32(1), "minus_one");
  negative_builder.CreateRet(sub_value);

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

bool test_cff_rewrites_cfg_without_touching_global_strings() {
  llvm::LLVMContext context;
  Fixture fixture = build_fixture(context);

  eippf::passes::CFFObfuscationPass pass;
  llvm::ModuleAnalysisManager analysis_manager;
  const llvm::PreservedAnalyses preserved = pass.run(*fixture.module, analysis_manager);
  if (!expect(!preserved.areAllPreserved(),
              "CFF pass should rewrite the explicitly routed flatten target")) {
    return false;
  }

  if (!expect(has_basic_block_named(*fixture.flatten_target, "eippf.cff.dispatcher"),
              "flatten target should contain dispatcher block after CFF rewrite")) {
    return false;
  }

  auto* string_data =
      llvm::dyn_cast<llvm::ConstantDataSequential>(fixture.string_global->getInitializer());
  if (!expect(string_data != nullptr, "string global should keep constant data initializer")) {
    return false;
  }

  const std::string expected_plaintext = std::string("cff_must_not_touch_me") + '\0';
  if (!expect(string_data->getRawDataValues() == expected_plaintext,
              "CFF pass must not rewrite global string initializers")) {
    return false;
  }

  if (!expect(fixture.module->getFunction(kDecryptHelperName) == nullptr,
              "CFF pass must not synthesize its legacy string decrypt helper")) {
    return false;
  }

  if (!expect(fixture.module->getNamedGlobal(kStringEncryptionMarker) == nullptr,
              "CFF pass must not emit legacy string encryption marker")) {
    return false;
  }

  return verify_module_ok(*fixture.module, "test_cff_rewrites_cfg_without_touching_global_strings");
}

}  // namespace

int main() {
  if (!test_cff_rewrites_cfg_without_touching_global_strings()) {
    return 1;
  }
  return 0;
}

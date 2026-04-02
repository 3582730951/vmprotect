#include "passes/IATMinimizationPass.hpp"

#include <cstdint>

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

namespace {

constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;
constexpr llvm::StringLiteral kResolverFunctionName("eippf_resolve_api");

struct RewriteSite {
  llvm::CallBase* call_base = nullptr;
  llvm::Function* direct_callee = nullptr;
  std::uint64_t api_hash = 0u;
};

std::uint64_t fnv1a_hash(llvm::StringRef text) {
  std::uint64_t hash = kFnv1aOffset;
  for (const char ch : text) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= kFnv1aPrime;
  }
  return hash;
}

bool is_supported_direct_external_target(llvm::CallBase& call_base, llvm::Function*& direct_callee) {
  llvm::Value* called_operand = call_base.getCalledOperand();
  if (called_operand == nullptr) {
    return false;
  }

  llvm::Value* stripped_target = called_operand->stripPointerCasts();
  auto* callee = llvm::dyn_cast<llvm::Function>(stripped_target);
  if (callee == nullptr) {
    return false;
  }
  if (!callee->isDeclaration() || callee->isIntrinsic()) {
    return false;
  }
  if (callee->getName().startswith("llvm.")) {
    return false;
  }
  if (callee->hasLocalLinkage() || callee->getName() == kResolverFunctionName) {
    return false;
  }

  direct_callee = callee;
  return true;
}

llvm::SmallVector<RewriteSite, 64> collect_rewrite_sites(llvm::Module& module) {
  llvm::SmallVector<RewriteSite, 64> sites;

  for (llvm::Function& function : module) {
    if (function.isDeclaration()) {
      continue;
    }

    for (llvm::BasicBlock& block : function) {
      for (llvm::Instruction& instruction : block) {
        if (!llvm::isa<llvm::CallInst>(instruction) && !llvm::isa<llvm::InvokeInst>(instruction)) {
          continue;
        }

        auto* call_base = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call_base == nullptr) {
          continue;
        }

        llvm::Function* callee = nullptr;
        if (!is_supported_direct_external_target(*call_base, callee)) {
          continue;
        }

        RewriteSite site{};
        site.call_base = call_base;
        site.direct_callee = callee;
        site.api_hash = fnv1a_hash(callee->getName());
        sites.push_back(site);
      }
    }
  }

  return sites;
}

llvm::FunctionCallee get_or_insert_resolver(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* void_ptr_type = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  auto* resolver_type =
      llvm::FunctionType::get(void_ptr_type, {llvm::Type::getInt64Ty(context)}, false);
  llvm::FunctionCallee resolver = module.getOrInsertFunction(kResolverFunctionName, resolver_type);

  auto* resolver_function =
      llvm::dyn_cast<llvm::Function>(resolver.getCallee()->stripPointerCasts());
  if (resolver_function != nullptr) {
    resolver_function->setCallingConv(llvm::CallingConv::C);
    resolver_function->addFnAttr(llvm::Attribute::NoUnwind);
  }

  return resolver;
}

void emit_fail_closed_guard(llvm::CallBase& call_base, llvm::Value* resolved_ptr) {
  auto* pointer_type = llvm::dyn_cast<llvm::PointerType>(resolved_ptr->getType());
  if (pointer_type == nullptr) {
    return;
  }

  llvm::IRBuilder<> guard_builder(&call_base);
  llvm::Value* is_null = guard_builder.CreateICmpEQ(
      resolved_ptr, llvm::ConstantPointerNull::get(pointer_type), "eippf.api.null");

  llvm::Instruction* trap_terminator =
      llvm::SplitBlockAndInsertIfThen(is_null, &call_base, true);
  llvm::IRBuilder<> trap_builder(trap_terminator);
  llvm::Function* trap =
      llvm::Intrinsic::getDeclaration(call_base.getModule(), llvm::Intrinsic::trap);
  trap_builder.CreateCall(trap);
}

bool rewrite_call_site(const RewriteSite& site, llvm::FunctionCallee resolver) {
  if (site.call_base == nullptr) {
    return false;
  }

  llvm::IRBuilder<> builder(site.call_base);
  llvm::Value* hash_value = llvm::ConstantInt::get(
      llvm::Type::getInt64Ty(site.call_base->getContext()), site.api_hash);
  auto* resolver_call = builder.CreateCall(resolver, {hash_value}, "eippf.api.raw");
  resolver_call->setCallingConv(llvm::CallingConv::C);
  resolver_call->addFnAttr(llvm::Attribute::NoUnwind);
  resolver_call->setDebugLoc(site.call_base->getDebugLoc());
  emit_fail_closed_guard(*site.call_base, resolver_call);

  llvm::Value* replacement_callee = resolver_call;
  llvm::Type* expected_callee_type = site.call_base->getCalledOperand()->getType();
  if (replacement_callee->getType() != expected_callee_type) {
    if (!expected_callee_type->isPointerTy()) {
      return false;
    }
    replacement_callee = builder.CreateBitCast(replacement_callee, expected_callee_type, "eippf.api.fnptr");
  }

  site.call_base->setCalledOperand(replacement_callee);
  return true;
}

bool erase_unused_external_declarations(llvm::SmallPtrSetImpl<llvm::Function*>& rewritten_callees) {
  llvm::SmallVector<llvm::Function*, 16> dead_declarations;
  for (llvm::Function* function : rewritten_callees) {
    if (function == nullptr) {
      continue;
    }
    if (!function->isDeclaration() || function->isIntrinsic()) {
      continue;
    }
    if (!function->use_empty()) {
      continue;
    }
    dead_declarations.push_back(function);
  }

  for (llvm::Function* function : dead_declarations) {
    function->eraseFromParent();
  }
  return !dead_declarations.empty();
}

}  // namespace

namespace eippf::passes {

llvm::PreservedAnalyses IATMinimizationPass::run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
  llvm::SmallVector<RewriteSite, 64> sites = collect_rewrite_sites(module);
  if (sites.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  llvm::FunctionCallee resolver = get_or_insert_resolver(module);
  llvm::SmallPtrSet<llvm::Function*, 32> rewritten_callees;

  bool changed = false;
  for (const RewriteSite& site : sites) {
    changed = rewrite_call_site(site, resolver) || changed;
    rewritten_callees.insert(site.direct_callee);
  }

  changed = erase_unused_external_declarations(rewritten_callees) || changed;
  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

void register_iat_minimization_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerOptimizerLastEPCallback(
      [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
        module_pm.addPass(IATMinimizationPass{});
      });

  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-iat-minimization") {
          module_pm.addPass(IATMinimizationPass{});
          return true;
        }
        return false;
      });
}

}  // namespace eippf::passes

#ifdef EIPPF_IAT_MINIMIZATION_STANDALONE_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFIATMinimizationPass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) { eippf::passes::register_iat_minimization_pipeline(pass_builder); }};
}
#endif

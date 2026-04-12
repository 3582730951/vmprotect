#include "passes/ProtectionAnchorPass.hpp"

#include <cstdint>
#include <string>

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"

namespace {

constexpr llvm::StringLiteral kCriticalAnnotation("drm_critical_ip");
constexpr llvm::StringLiteral kJitTargetAnnotation("drm_jit_target");
constexpr llvm::StringLiteral kFlattenAnnotation("drm_flatten");

constexpr llvm::StringLiteral kRouteAttribute("eippf.route");
constexpr llvm::StringLiteral kRouteJit("jit");
constexpr llvm::StringLiteral kRouteVm("vm");
constexpr llvm::StringLiteral kRouteCff("cff");

constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;

enum class RoutePriority : std::uint8_t {
  kNone = 0u,
  kCff = 1u,
  kVm = 2u,
  kJit = 3u,
};

struct RouteSelection final {
  RoutePriority priority = RoutePriority::kNone;
  llvm::StringRef route;
};

std::uint64_t fnv1a_append(std::uint64_t seed, llvm::StringRef text) {
  std::uint64_t hash = seed;
  for (const char ch : text) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= kFnv1aPrime;
  }
  return hash;
}

std::string make_obfuscated_name(const llvm::Module& module, const llvm::Function& function) {
  std::uint64_t hash = kFnv1aOffset;
  hash = fnv1a_append(hash, module.getModuleIdentifier());
  hash = fnv1a_append(hash, function.getName());
  return "eippf_fn_" + llvm::utohexstr(hash);
}

llvm::StringRef extract_annotation_text(llvm::Constant* annotation_operand) {
  llvm::Constant* cursor = annotation_operand;

  while (auto* constant_expression = llvm::dyn_cast<llvm::ConstantExpr>(cursor)) {
    if (constant_expression->getNumOperands() == 0u) {
      break;
    }
    cursor = llvm::dyn_cast<llvm::Constant>(constant_expression->getOperand(0));
    if (cursor == nullptr) {
      return {};
    }
  }

  auto* global = llvm::dyn_cast<llvm::GlobalVariable>(cursor);
  if (global == nullptr || !global->hasInitializer()) {
    return {};
  }

  auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(global->getInitializer());
  if (data == nullptr || !data->isString()) {
    return {};
  }
  return data->getAsCString();
}

RouteSelection route_from_annotation(llvm::StringRef annotation) {
  if (annotation == kJitTargetAnnotation) {
    return RouteSelection{RoutePriority::kJit, kRouteJit};
  }
  if (annotation == kCriticalAnnotation) {
    return RouteSelection{RoutePriority::kVm, kRouteVm};
  }
  if (annotation == kFlattenAnnotation) {
    return RouteSelection{RoutePriority::kCff, kRouteCff};
  }
  return {};
}

llvm::DenseMap<llvm::Function*, RouteSelection> collect_route_targets(llvm::Module& module) {
  llvm::DenseMap<llvm::Function*, RouteSelection> route_targets;

  llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr || !annotations->hasInitializer()) {
    return route_targets;
  }

  auto* annotation_array = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (annotation_array == nullptr) {
    return route_targets;
  }

  for (llvm::Value* entry_value : annotation_array->operands()) {
    auto* entry_struct = llvm::dyn_cast<llvm::ConstantStruct>(entry_value);
    if (entry_struct == nullptr || entry_struct->getNumOperands() < 2u) {
      continue;
    }

    llvm::Value* function_operand = entry_struct->getOperand(0)->stripPointerCasts();
    auto* function = llvm::dyn_cast<llvm::Function>(function_operand);
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    auto* annotation_operand = llvm::dyn_cast<llvm::Constant>(entry_struct->getOperand(1));
    if (annotation_operand == nullptr) {
      continue;
    }

    const RouteSelection candidate = route_from_annotation(extract_annotation_text(annotation_operand));
    if (candidate.priority == RoutePriority::kNone) {
      continue;
    }

    auto existing_it = route_targets.find(function);
    if (existing_it == route_targets.end() ||
        static_cast<unsigned>(candidate.priority) >
            static_cast<unsigned>(existing_it->second.priority)) {
      route_targets[function] = candidate;
    }
  }

  return route_targets;
}

bool can_rename_local_symbol(const llvm::Function& function) {
  if (function.isDeclaration()) {
    return false;
  }
  if (!function.hasLocalLinkage()) {
    return false;
  }
  if (function.getName() == "main") {
    return false;
  }
  if (function.getName().starts_with("llvm.")) {
    return false;
  }
  return true;
}

bool apply_anchor_to_function(llvm::Module& module, llvm::Function& function,
                              const RouteSelection& selection) {
  bool changed = false;

  const llvm::Attribute route_attribute = function.getFnAttribute(kRouteAttribute);
  if (!route_attribute.isValid() || !route_attribute.isStringAttribute() ||
      route_attribute.getValueAsString() != selection.route) {
    function.removeFnAttr(kRouteAttribute);
    function.addFnAttr(kRouteAttribute, selection.route);
    changed = true;
  }

  if (!function.hasFnAttribute(llvm::Attribute::NoInline)) {
    function.addFnAttr(llvm::Attribute::NoInline);
    changed = true;
  }
  if (!function.hasFnAttribute(llvm::Attribute::OptimizeNone)) {
    function.addFnAttr(llvm::Attribute::OptimizeNone);
    changed = true;
  }
  if (function.hasFnAttribute(llvm::Attribute::AlwaysInline)) {
    function.removeFnAttr(llvm::Attribute::AlwaysInline);
    changed = true;
  }

  if (!can_rename_local_symbol(function)) {
    return changed;
  }

  const std::string obfuscated_name = make_obfuscated_name(module, function);
  if (function.getName() != obfuscated_name) {
    function.setName(obfuscated_name);
    changed = true;
  }

  return changed;
}

}  // namespace

namespace eippf::passes {

llvm::PreservedAnalyses ProtectionAnchorPass::run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
  llvm::DenseMap<llvm::Function*, RouteSelection> route_targets = collect_route_targets(module);
  if (route_targets.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  bool changed = false;
  for (auto& entry : route_targets) {
    llvm::Function* function = entry.first;
    if (function == nullptr) {
      continue;
    }
    changed = apply_anchor_to_function(module, *function, entry.second) || changed;
  }

  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

void register_protection_anchor_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerPipelineStartEPCallback(
      [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
        module_pm.addPass(ProtectionAnchorPass{});
      });

  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-protection-anchor") {
          module_pm.addPass(ProtectionAnchorPass{});
          return true;
        }
        return false;
      });
}

}  // namespace eippf::passes

#ifdef EIPPF_PROTECTION_ANCHOR_STANDALONE_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFProtectionAnchorPass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) {
        eippf::passes::register_protection_anchor_pipeline(pass_builder);
      }};
}
#endif

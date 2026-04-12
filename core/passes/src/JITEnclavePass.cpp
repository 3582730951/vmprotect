#include "passes/JITEnclavePass.hpp"

#include <cstdint>
#include <string>

#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#if defined(__has_include)
#if __has_include("llvm/TargetParser/Triple.h")
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#else
#include "llvm/ADT/Triple.h"
#endif

namespace {

constexpr llvm::StringLiteral kJitTargetAnnotation("drm_jit_target");
constexpr llvm::StringLiteral kRouteAttribute("eippf.route");
constexpr llvm::StringLiteral kRouteJit("jit");
constexpr llvm::StringLiteral kJitEntryPointName("eippf_je0");
constexpr llvm::StringLiteral kJitInjectedAttr("eippf.jit.enclave.injected");
constexpr llvm::StringLiteral kGateCodeJitRouteForbidden("jit_route_forbidden_for_target");
constexpr std::uint8_t kDummyPayloadKey = 0x5Au;

llvm::cl::opt<std::string> kTargetKindOpt(
    "eippf-target-kind",
    llvm::cl::desc("EIPPF protection target kind"),
    llvm::cl::value_desc("target_kind"),
    llvm::cl::init("unknown"));

llvm::StringRef extract_annotation_text(llvm::Constant* annotation_operand) {
  llvm::Constant* cursor = annotation_operand;

  while (auto* ce = llvm::dyn_cast<llvm::ConstantExpr>(cursor)) {
    if (ce->getNumOperands() == 0u) {
      break;
    }
    cursor = llvm::dyn_cast<llvm::Constant>(ce->getOperand(0));
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

llvm::SmallPtrSet<llvm::Function*, 32> collect_jit_targets(llvm::Module& module) {
  llvm::SmallPtrSet<llvm::Function*, 32> targets;

  for (llvm::Function& function : module) {
    const llvm::Attribute route_attribute = function.getFnAttribute(kRouteAttribute);
    if (!route_attribute.isValid() || !route_attribute.isStringAttribute()) {
      continue;
    }
    if (route_attribute.getValueAsString() == kRouteJit && !function.isDeclaration()) {
      targets.insert(&function);
    }
  }

  llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr || !annotations->hasInitializer()) {
    return targets;
  }

  auto* annotation_array = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (annotation_array == nullptr) {
    return targets;
  }

  for (llvm::Value* entry_value : annotation_array->operands()) {
    auto* entry_struct = llvm::dyn_cast<llvm::ConstantStruct>(entry_value);
    if (entry_struct == nullptr || entry_struct->getNumOperands() < 2u) {
      continue;
    }

    llvm::Value* fn_value = entry_struct->getOperand(0)->stripPointerCasts();
    auto* function = llvm::dyn_cast<llvm::Function>(fn_value);
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    auto* annotation_operand = llvm::dyn_cast<llvm::Constant>(entry_struct->getOperand(1));
    if (annotation_operand == nullptr) {
      continue;
    }

    const llvm::Attribute route_attribute = function->getFnAttribute(kRouteAttribute);
    if (route_attribute.isValid() && route_attribute.isStringAttribute() &&
        route_attribute.getValueAsString() != kRouteJit) {
      continue;
    }

    if (extract_annotation_text(annotation_operand) == kJitTargetAnnotation) {
      targets.insert(function);
    }
  }

  return targets;
}

llvm::SmallVector<std::uint8_t, 8> build_dummy_plain_payload(const llvm::Module& module) {
  llvm::SmallVector<std::uint8_t, 8> plain_payload;
  llvm::Triple triple(module.getTargetTriple());

  if (triple.isAArch64()) {
    plain_payload.push_back(0xC0u);
    plain_payload.push_back(0x03u);
    plain_payload.push_back(0x5Fu);
    plain_payload.push_back(0xD6u);  // ret
    return plain_payload;
  }
  if (triple.isARM()) {
    plain_payload.push_back(0x1Eu);
    plain_payload.push_back(0xFFu);
    plain_payload.push_back(0x2Fu);
    plain_payload.push_back(0xE1u);  // bx lr
    return plain_payload;
  }

  plain_payload.push_back(0xC3u);  // x86/x64 ret
  return plain_payload;
}

llvm::GlobalVariable* create_dummy_encrypted_payload(llvm::Module& module,
                                                     const llvm::Function& function) {
  llvm::SmallVector<std::uint8_t, 8> encrypted_payload = build_dummy_plain_payload(module);
  for (std::uint8_t& byte : encrypted_payload) {
    byte = static_cast<std::uint8_t>(byte ^ kDummyPayloadKey);
  }

  llvm::Constant* initializer = llvm::ConstantDataArray::get(module.getContext(), encrypted_payload);
  const std::string global_name = ("eippf.jit.payload." + function.getName()).str();

  auto* payload = new llvm::GlobalVariable(module, initializer->getType(), true,
                                           llvm::GlobalValue::PrivateLinkage, initializer, global_name);
  payload->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  payload->setAlignment(llvm::Align(1));
  return payload;
}

llvm::FunctionCallee get_or_insert_jit_entry(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  llvm::Type* size_ty = module.getDataLayout().getIntPtrType(context);
  auto* enclave_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(context), {i8_ptr_ty, size_ty, llvm::Type::getInt8Ty(context)}, false);
  llvm::FunctionCallee enclave_entry = module.getOrInsertFunction(kJitEntryPointName, enclave_type);

  auto* enclave_function =
      llvm::dyn_cast<llvm::Function>(enclave_entry.getCallee()->stripPointerCasts());
  if (enclave_function != nullptr) {
    enclave_function->setCallingConv(llvm::CallingConv::C);
    enclave_function->addFnAttr(llvm::Attribute::NoUnwind);
  }

  return enclave_entry;
}

bool rewrite_function_body_to_jit_enclave(llvm::Function& function, llvm::FunctionCallee enclave_entry) {
  if (function.isDeclaration() || function.hasFnAttribute(kJitInjectedAttr)) {
    return false;
  }

  llvm::Module* module = function.getParent();
  if (module == nullptr) {
    return false;
  }

  llvm::GlobalVariable* payload = create_dummy_encrypted_payload(*module, function);
  auto* payload_array_ty = llvm::cast<llvm::ArrayType>(payload->getValueType());

  llvm::SmallVector<llvm::BasicBlock*, 8> old_blocks;
  old_blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) {
    old_blocks.push_back(&block);
  }

  for (llvm::BasicBlock* block : old_blocks) {
    block->dropAllReferences();
  }
  for (llvm::BasicBlock* block : old_blocks) {
    block->eraseFromParent();
  }

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(function.getContext(), "eippf.jit.entry", &function);
  llvm::IRBuilder<> builder(entry);

  llvm::Value* payload_ptr = builder.CreateInBoundsGEP(
      payload_array_ty, payload, {builder.getInt64(0), builder.getInt64(0)}, "eippf.jit.payload.ptr");

  auto* size_int_ty = llvm::cast<llvm::IntegerType>(enclave_entry.getFunctionType()->getParamType(1));

  const std::uint64_t payload_size = static_cast<std::uint64_t>(payload_array_ty->getNumElements());
  llvm::Value* size_value = llvm::ConstantInt::get(size_int_ty, payload_size);
  llvm::Value* key_value = builder.getInt8(kDummyPayloadKey);

  llvm::CallInst* enclave_call =
      builder.CreateCall(enclave_entry, {payload_ptr, size_value, key_value});
  enclave_call->setCallingConv(llvm::CallingConv::C);
  enclave_call->addFnAttr(llvm::Attribute::NoUnwind);

  if (function.getReturnType()->isVoidTy()) {
    builder.CreateRetVoid();
  } else {
    builder.CreateRet(llvm::Constant::getNullValue(function.getReturnType()));
  }

  function.addFnAttr(kJitInjectedAttr);
  return true;
}

}  // namespace

namespace eippf::passes {

JITEnclavePass::TargetKind JITEnclavePass::parse_target_kind_option() noexcept {
  const llvm::StringRef raw_kind(kTargetKindOpt);
  if (raw_kind.empty()) {
    return TargetKind::kUnknown;
  }
  return llvm::StringSwitch<TargetKind>(raw_kind.lower())
      .Case("desktop_native", TargetKind::kDesktopNative)
      .Case("android_so", TargetKind::kAndroidSo)
      .Case("ios_appstore", TargetKind::kIosAppStore)
      .Case("windows_driver", TargetKind::kWindowsDriver)
      .Case("linux_kernel_module", TargetKind::kLinuxKernelModule)
      .Case("android_kernel_module", TargetKind::kAndroidKernelModule)
      .Case("android_dex", TargetKind::kAndroidDex)
      .Case("shell_ephemeral", TargetKind::kShellEphemeral)
      .Case("unknown", TargetKind::kUnknown)
      .Default(TargetKind::kUnknown);
}

bool JITEnclavePass::is_desktop_target_kind(TargetKind kind) noexcept {
  return kind == TargetKind::kDesktopNative;
}

const char* JITEnclavePass::target_kind_name_for_diagnostic(TargetKind kind) noexcept {
  switch (kind) {
    case TargetKind::kDesktopNative:
      return "desktop_native";
    case TargetKind::kAndroidSo:
      return "android_so";
    case TargetKind::kIosAppStore:
      return "ios_appstore";
    case TargetKind::kWindowsDriver:
      return "windows_driver";
    case TargetKind::kLinuxKernelModule:
      return "linux_kernel_module";
    case TargetKind::kAndroidKernelModule:
      return "android_kernel_module";
    case TargetKind::kAndroidDex:
      return "android_dex";
    case TargetKind::kShellEphemeral:
      return "shell_ephemeral";
    case TargetKind::kUnknown:
      return "unknown";
  }
  return "unknown";
}

llvm::PreservedAnalyses JITEnclavePass::run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
  llvm::SmallPtrSet<llvm::Function*, 32> jit_targets = collect_jit_targets(module);
  if (jit_targets.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  const TargetKind target_kind = parse_target_kind_option();
  if (!is_desktop_target_kind(target_kind)) {
    module.getContext().emitError(
        (llvm::Twine(kGateCodeJitRouteForbidden) + ": target_kind=" +
         target_kind_name_for_diagnostic(target_kind))
            .str());
    return llvm::PreservedAnalyses::all();
  }

  llvm::FunctionCallee enclave_entry = get_or_insert_jit_entry(module);
  bool changed = false;
  for (llvm::Function* function : jit_targets) {
    if (function == nullptr) {
      continue;
    }
    changed = rewrite_function_body_to_jit_enclave(*function, enclave_entry) || changed;
  }

  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

void register_jit_enclave_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerOptimizerLastEPCallback(
      [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
        module_pm.addPass(JITEnclavePass{});
      });

  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-jit-enclave") {
          module_pm.addPass(JITEnclavePass{});
          return true;
        }
        return false;
      });
}

}  // namespace eippf::passes

#ifdef EIPPF_JIT_ENCLAVE_STANDALONE_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFJITEnclavePass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) { eippf::passes::register_jit_enclave_pipeline(pass_builder); }};
}
#endif

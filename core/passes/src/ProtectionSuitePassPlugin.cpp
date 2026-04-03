#include "passes/CFFObfuscationPass.hpp"
#include "passes/JITEnclavePass.hpp"
#include "passes/ProtectionAnchorPass.hpp"
#include "passes/SelectiveVMPass.hpp"
#include "passes/StringProtectionPass.hpp"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFProtectionSuitePass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) {
        eippf::passes::register_protection_anchor_pipeline(pass_builder);
        eippf::passes::register_selective_vm_pipeline(pass_builder);
        eippf::passes::register_jit_enclave_pipeline(pass_builder);
        eippf::passes::register_cff_obfuscation_pipeline(pass_builder);
        eippf::passes::register_string_protection_pipeline(pass_builder);
      }};
}

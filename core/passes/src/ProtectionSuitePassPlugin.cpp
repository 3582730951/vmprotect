#include "passes/CFFObfuscationPass.hpp"
#include "passes/IATMinimizationPass.hpp"
#include "passes/MBAObfuscationPass.hpp"
#include "passes/ProtectionAnchorPass.hpp"
#include "passes/ProtectionSuitePassPlugin.hpp"
#include "passes/StringProtectionPass.hpp"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

namespace eippf::passes {

void append_default_protection_suite(llvm::ModulePassManager& module_pass_manager) {
  module_pass_manager.addPass(ProtectionAnchorPass{});
  module_pass_manager.addPass(StringProtectionPass{});
  module_pass_manager.addPass(IATMinimizationPass{});
  module_pass_manager.addPass(MBAObfuscationPass{});
  module_pass_manager.addPass(CFFObfuscationPass{});
}

void register_protection_suite_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-protection-suite-default") {
          append_default_protection_suite(module_pm);
          return true;
        }
        return false;
      });

  register_protection_anchor_pipeline(pass_builder);
  register_string_protection_pipeline(pass_builder);
  register_iat_minimization_pipeline(pass_builder);
  register_mba_obfuscation_pipeline(pass_builder);
  register_cff_obfuscation_pipeline(pass_builder);
}

}  // namespace eippf::passes

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFProtectionSuitePass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) {
        eippf::passes::register_protection_suite_pipeline(pass_builder);
      }};
}

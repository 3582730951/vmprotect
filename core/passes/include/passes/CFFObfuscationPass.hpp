#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class CFFObfuscationPass : public llvm::PassInfoMixin<CFFObfuscationPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_cff_obfuscation_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

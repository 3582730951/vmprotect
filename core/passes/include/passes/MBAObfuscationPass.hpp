#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class MBAObfuscationPass : public llvm::PassInfoMixin<MBAObfuscationPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_mba_obfuscation_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

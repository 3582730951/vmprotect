#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class IATMinimizationPass : public llvm::PassInfoMixin<IATMinimizationPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_iat_minimization_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

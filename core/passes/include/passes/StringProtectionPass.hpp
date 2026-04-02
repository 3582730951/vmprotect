#pragma once

#include "llvm/IR/PassManager.h"

namespace eippf::passes {

class StringProtectionPass : public llvm::PassInfoMixin<StringProtectionPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

}  // namespace eippf::passes


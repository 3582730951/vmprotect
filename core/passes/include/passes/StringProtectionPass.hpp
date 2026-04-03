#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class StringProtectionPass : public llvm::PassInfoMixin<StringProtectionPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_string_protection_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

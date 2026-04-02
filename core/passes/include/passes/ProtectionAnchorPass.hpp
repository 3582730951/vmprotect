#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class ProtectionAnchorPass : public llvm::PassInfoMixin<ProtectionAnchorPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_protection_anchor_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

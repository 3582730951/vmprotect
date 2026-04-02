#pragma once

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class JITEnclavePass : public llvm::PassInfoMixin<JITEnclavePass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_jit_enclave_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

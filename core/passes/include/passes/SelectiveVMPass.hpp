#pragma once

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class SelectiveVMFunctionPass : public llvm::PassInfoMixin<SelectiveVMFunctionPass> {
 public:
  explicit SelectiveVMFunctionPass(
      const llvm::SmallPtrSetImpl<llvm::Function*>& annotated_functions) noexcept;

  llvm::PreservedAnalyses run(llvm::Function& function,
                              llvm::FunctionAnalysisManager& analysis_manager);

 private:
  const llvm::SmallPtrSetImpl<llvm::Function*>& annotated_functions_;
};

class SelectiveVMPass : public llvm::PassInfoMixin<SelectiveVMPass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);
};

void register_selective_vm_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

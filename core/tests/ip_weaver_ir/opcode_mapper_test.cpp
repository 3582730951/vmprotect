#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>

#include "ip_weaver_ir/heuristic_profiler.hpp"
#include "ip_weaver_ir/opcode_mapper.hpp"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

namespace {

llvm::Function* build_sample_function(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::IRBuilder<> builder(context);

  auto* function_type = llvm::FunctionType::get(
      builder.getInt32Ty(), {builder.getInt32Ty(), builder.getInt32Ty()}, false);
  auto* function = llvm::Function::Create(
      function_type, llvm::Function::ExternalLinkage, "sample", module);

  auto args_it = function->arg_begin();
  llvm::Value* lhs = args_it++;
  lhs->setName("lhs");
  llvm::Value* rhs = args_it++;
  rhs->setName("rhs");

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", function);
  builder.SetInsertPoint(entry);

  llvm::Value* sum = builder.CreateAdd(lhs, rhs, "sum");
  llvm::Value* cmp = builder.CreateICmpSGT(sum, llvm::ConstantInt::get(builder.getInt32Ty(), 0), "cmp");
  llvm::BasicBlock* then_block = llvm::BasicBlock::Create(context, "then", function);
  llvm::BasicBlock* else_block = llvm::BasicBlock::Create(context, "else", function);
  builder.CreateCondBr(cmp, then_block, else_block);

  builder.SetInsertPoint(then_block);
  builder.CreateRet(sum);

  builder.SetInsertPoint(else_block);
  llvm::Value* neg = builder.CreateSub(llvm::ConstantInt::get(builder.getInt32Ty(), 0), sum, "neg");
  builder.CreateRet(neg);

  assert(!llvm::verifyFunction(*function, &llvm::errs()));
  return function;
}

}  // namespace

int main() {
  llvm::LLVMContext context;
  llvm::Module module("opcode_mapper_test", context);
  llvm::Function* function = build_sample_function(module);
  assert(function != nullptr);

  llvm::Instruction* add_inst = nullptr;
  llvm::Instruction* cmp_inst = nullptr;
  llvm::Instruction* ret_inst = nullptr;

  for (llvm::BasicBlock& block : *function) {
    for (llvm::Instruction& instruction : block) {
      if (instruction.getOpcode() == llvm::Instruction::Add) {
        add_inst = &instruction;
      } else if (instruction.getOpcode() == llvm::Instruction::ICmp) {
        cmp_inst = &instruction;
      } else if (instruction.getOpcode() == llvm::Instruction::Ret) {
        ret_inst = &instruction;
      }
    }
  }

  assert(add_inst != nullptr);
  assert(cmp_inst != nullptr);
  assert(ret_inst != nullptr);

  const std::optional<eippf::ip_weaver_ir::MappedOpcode> add_mapping =
      eippf::ip_weaver_ir::map_instruction(*add_inst);
  assert(add_mapping.has_value());
  assert(add_mapping->opcode == eippf::runtime::pir::OpCode::kAddI);
  assert(!add_mapping->condition.has_value());

  const std::optional<eippf::ip_weaver_ir::MappedOpcode> cmp_mapping =
      eippf::ip_weaver_ir::map_instruction(*cmp_inst);
  assert(cmp_mapping.has_value());
  assert(cmp_mapping->opcode == eippf::runtime::pir::OpCode::kCmpI);
  assert(cmp_mapping->condition.has_value());
  assert(*cmp_mapping->condition == eippf::runtime::pir::ConditionCode::kGt);

  const std::optional<eippf::ip_weaver_ir::MappedOpcode> ret_mapping =
      eippf::ip_weaver_ir::map_instruction(*ret_inst);
  assert(!ret_mapping.has_value());

  eippf::ip_weaver_ir::ProfileConfig config{};
  config.hot_threshold = 0u;
  eippf::ip_weaver_ir::HeuristicProfiler profiler(config);

  function->setMetadata("eippf.hotness",
                        llvm::MDNode::get(context, llvm::MDString::get(context, "cold")));
  const eippf::ip_weaver_ir::FunctionTemperature temperature = profiler.classify(*function);
  assert(temperature == eippf::ip_weaver_ir::FunctionTemperature::kCold);

  std::cout << "opcode_mapper_test: pass\n";
  return 0;
}

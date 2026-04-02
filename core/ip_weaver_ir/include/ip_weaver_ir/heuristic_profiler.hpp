#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"

namespace eippf::ip_weaver_ir {

enum class FunctionTemperature : std::uint8_t {
  kCold = 0u,
  kHot = 1u,
};

struct ProfileConfig final {
  std::uint32_t hot_threshold = 48u;
  std::uint32_t arithmetic_weight = 3u;
  std::uint32_t compare_weight = 2u;
  std::uint32_t branch_weight = 2u;
  std::uint32_t loop_weight = 8u;
  std::uint32_t memory_weight = 1u;
  std::uint32_t call_weight = 2u;
};

struct FunctionMetrics final {
  std::uint32_t basic_block_count = 0u;
  std::uint32_t instruction_count = 0u;
  std::uint32_t arithmetic_ops = 0u;
  std::uint32_t compare_ops = 0u;
  std::uint32_t conditional_branches = 0u;
  std::uint32_t loop_back_edges = 0u;
  std::uint32_t memory_ops = 0u;
  std::uint32_t call_sites = 0u;
};

[[nodiscard]] inline std::optional<FunctionTemperature> read_hotness_metadata(
    const llvm::Function& function) {
  const llvm::MDNode* md = function.getMetadata("eippf.hotness");
  if (md == nullptr || md->getNumOperands() == 0u) {
    return std::nullopt;
  }

  const llvm::Metadata* operand = md->getOperand(0).get();
  const auto* text = llvm::dyn_cast<llvm::MDString>(operand);
  if (text == nullptr) {
    return std::nullopt;
  }

  const llvm::StringRef value = text->getString();
  if (value.equals_insensitive("hot")) {
    return FunctionTemperature::kHot;
  }
  if (value.equals_insensitive("cold")) {
    return FunctionTemperature::kCold;
  }
  return std::nullopt;
}

class HeuristicProfiler final {
 public:
  explicit HeuristicProfiler(ProfileConfig config = {}) : config_(config) {}

  [[nodiscard]] FunctionMetrics collect_metrics(const llvm::Function& function) const {
    FunctionMetrics metrics{};
    if (function.isDeclaration()) {
      return metrics;
    }

    llvm::DenseMap<const llvm::BasicBlock*, std::uint32_t> block_index;
    std::uint32_t next_index = 0u;
    for (const llvm::BasicBlock& block : function) {
      block_index[&block] = next_index;
      ++next_index;
      ++metrics.basic_block_count;
    }

    for (const llvm::BasicBlock& block : function) {
      const std::uint32_t current_index = block_index.lookup(&block);
      for (const llvm::Instruction& instruction : block) {
        ++metrics.instruction_count;
        switch (instruction.getOpcode()) {
          case llvm::Instruction::Add:
          case llvm::Instruction::Sub:
          case llvm::Instruction::Mul:
          case llvm::Instruction::UDiv:
          case llvm::Instruction::SDiv:
          case llvm::Instruction::URem:
          case llvm::Instruction::SRem:
          case llvm::Instruction::FAdd:
          case llvm::Instruction::FSub:
          case llvm::Instruction::FMul:
          case llvm::Instruction::FDiv:
            ++metrics.arithmetic_ops;
            break;
          case llvm::Instruction::ICmp:
          case llvm::Instruction::FCmp:
            ++metrics.compare_ops;
            break;
          case llvm::Instruction::Load:
          case llvm::Instruction::Store:
          case llvm::Instruction::AtomicCmpXchg:
          case llvm::Instruction::AtomicRMW:
            ++metrics.memory_ops;
            break;
          case llvm::Instruction::Call:
          case llvm::Instruction::Invoke:
          case llvm::Instruction::CallBr:
            ++metrics.call_sites;
            break;
          default:
            break;
        }
      }

      const llvm::Instruction* terminator = block.getTerminator();
      if (const auto* branch = llvm::dyn_cast<llvm::BranchInst>(terminator);
          branch != nullptr && branch->isConditional()) {
        ++metrics.conditional_branches;
      }
      if (llvm::isa<llvm::SwitchInst>(terminator)) {
        ++metrics.conditional_branches;
      }

      for (const llvm::BasicBlock* successor : llvm::successors(&block)) {
        const std::uint32_t successor_index = block_index.lookup(successor);
        if (successor_index <= current_index) {
          ++metrics.loop_back_edges;
        }
      }
    }

    return metrics;
  }

  [[nodiscard]] FunctionTemperature classify(const llvm::Function& function) const {
    if (const std::optional<FunctionTemperature> metadata = read_hotness_metadata(function);
        metadata.has_value()) {
      return *metadata;
    }

    const FunctionMetrics metrics = collect_metrics(function);
    const std::uint32_t score =
        (metrics.arithmetic_ops * config_.arithmetic_weight) +
        (metrics.compare_ops * config_.compare_weight) +
        (metrics.conditional_branches * config_.branch_weight) +
        (metrics.loop_back_edges * config_.loop_weight) +
        (metrics.memory_ops * config_.memory_weight) +
        (metrics.call_sites * config_.call_weight);

    return score >= config_.hot_threshold ? FunctionTemperature::kHot : FunctionTemperature::kCold;
  }

 private:
  ProfileConfig config_{};
};

[[nodiscard]] inline const char* to_string(FunctionTemperature temperature) {
  return temperature == FunctionTemperature::kHot ? "hot" : "cold";
}

}  // namespace eippf::ip_weaver_ir

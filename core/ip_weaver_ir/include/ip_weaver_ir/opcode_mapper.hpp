#pragma once

#include <cstdint>
#include <optional>

#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "runtime/proprietary_isa.hpp"

namespace eippf::ip_weaver_ir {

namespace pir = eippf::runtime::pir;

struct MappedOpcode final {
  pir::OpCode opcode = pir::OpCode::kNop;
  std::optional<pir::ConditionCode> condition{};
};

[[nodiscard]] inline const char* opcode_name(pir::OpCode opcode) {
  switch (opcode) {
    case pir::OpCode::kAddI:
      return "kAddI";
    case pir::OpCode::kSubI:
      return "kSubI";
    case pir::OpCode::kMulI:
      return "kMulI";
    case pir::OpCode::kDivSI:
      return "kDivSI";
    case pir::OpCode::kDivUI:
      return "kDivUI";
    case pir::OpCode::kRemSI:
      return "kRemSI";
    case pir::OpCode::kRemUI:
      return "kRemUI";
    case pir::OpCode::kAddF:
      return "kAddF";
    case pir::OpCode::kSubF:
      return "kSubF";
    case pir::OpCode::kMulF:
      return "kMulF";
    case pir::OpCode::kDivF:
      return "kDivF";
    case pir::OpCode::kCmpI:
      return "kCmpI";
    case pir::OpCode::kCmpF:
      return "kCmpF";
    default:
      return "kNop";
  }
}

[[nodiscard]] inline const char* condition_name(pir::ConditionCode code) {
  switch (code) {
    case pir::ConditionCode::kEq:
      return "kEq";
    case pir::ConditionCode::kNe:
      return "kNe";
    case pir::ConditionCode::kLt:
      return "kLt";
    case pir::ConditionCode::kLe:
      return "kLe";
    case pir::ConditionCode::kGt:
      return "kGt";
    case pir::ConditionCode::kGe:
      return "kGe";
    case pir::ConditionCode::kUlt:
      return "kUlt";
    case pir::ConditionCode::kUle:
      return "kUle";
    case pir::ConditionCode::kUgt:
      return "kUgt";
    case pir::ConditionCode::kUge:
      return "kUge";
    default:
      return "kEq";
  }
}

[[nodiscard]] inline std::optional<pir::ConditionCode> map_icmp_predicate(
    llvm::CmpInst::Predicate predicate) {
  switch (predicate) {
    case llvm::CmpInst::ICMP_EQ:
      return pir::ConditionCode::kEq;
    case llvm::CmpInst::ICMP_NE:
      return pir::ConditionCode::kNe;
    case llvm::CmpInst::ICMP_SLT:
      return pir::ConditionCode::kLt;
    case llvm::CmpInst::ICMP_SLE:
      return pir::ConditionCode::kLe;
    case llvm::CmpInst::ICMP_SGT:
      return pir::ConditionCode::kGt;
    case llvm::CmpInst::ICMP_SGE:
      return pir::ConditionCode::kGe;
    case llvm::CmpInst::ICMP_ULT:
      return pir::ConditionCode::kUlt;
    case llvm::CmpInst::ICMP_ULE:
      return pir::ConditionCode::kUle;
    case llvm::CmpInst::ICMP_UGT:
      return pir::ConditionCode::kUgt;
    case llvm::CmpInst::ICMP_UGE:
      return pir::ConditionCode::kUge;
    default:
      return std::nullopt;
  }
}

[[nodiscard]] inline std::optional<MappedOpcode> map_instruction(
    const llvm::Instruction& instruction) {
  switch (instruction.getOpcode()) {
    case llvm::Instruction::Add:
      return MappedOpcode{pir::OpCode::kAddI, std::nullopt};
    case llvm::Instruction::Sub:
      return MappedOpcode{pir::OpCode::kSubI, std::nullopt};
    case llvm::Instruction::Mul:
      return MappedOpcode{pir::OpCode::kMulI, std::nullopt};
    case llvm::Instruction::UDiv:
      return MappedOpcode{pir::OpCode::kDivUI, std::nullopt};
    case llvm::Instruction::SDiv:
      return MappedOpcode{pir::OpCode::kDivSI, std::nullopt};
    case llvm::Instruction::URem:
      return MappedOpcode{pir::OpCode::kRemUI, std::nullopt};
    case llvm::Instruction::SRem:
      return MappedOpcode{pir::OpCode::kRemSI, std::nullopt};
    case llvm::Instruction::FAdd:
      return MappedOpcode{pir::OpCode::kAddF, std::nullopt};
    case llvm::Instruction::FSub:
      return MappedOpcode{pir::OpCode::kSubF, std::nullopt};
    case llvm::Instruction::FMul:
      return MappedOpcode{pir::OpCode::kMulF, std::nullopt};
    case llvm::Instruction::FDiv:
      return MappedOpcode{pir::OpCode::kDivF, std::nullopt};
    case llvm::Instruction::ICmp: {
      const auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(&instruction);
      if (icmp == nullptr) {
        return std::nullopt;
      }
      const std::optional<pir::ConditionCode> condition = map_icmp_predicate(icmp->getPredicate());
      if (!condition.has_value()) {
        return std::nullopt;
      }
      return MappedOpcode{pir::OpCode::kCmpI, condition};
    }
    case llvm::Instruction::FCmp:
      return MappedOpcode{pir::OpCode::kCmpF, std::nullopt};
    default:
      return std::nullopt;
  }
}

}  // namespace eippf::ip_weaver_ir

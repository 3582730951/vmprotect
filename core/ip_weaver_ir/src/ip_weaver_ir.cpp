#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <iterator>
#include <optional>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include "runtime/proprietary_isa.hpp"
#include "llvm/ADT/APFloat.h"
#include "llvm/ADT/APInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/LowerInvoke.h"
#include "llvm/Transforms/Utils/Mem2Reg.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar/CorrelatedValuePropagation.h"
#include "llvm/Transforms/Scalar/DCE.h"
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/Scalar/MemCpyOptimizer.h"
#include "llvm/Transforms/Scalar/Reassociate.h"
#include "llvm/Transforms/Scalar/SROA.h"
#include "llvm/Transforms/Scalar/SimplifyCFG.h"

namespace {

namespace pir = eippf::runtime::pir;

llvm::cl::OptionCategory kIpWeaverIrCategory("ip_weaver_ir options");

llvm::cl::opt<std::string> kInputPath(
    "input",
    llvm::cl::desc("Input LLVM bitcode (.bc) path."),
    llvm::cl::Required,
    llvm::cl::cat(kIpWeaverIrCategory));

llvm::cl::opt<std::string> kOutputPath(
    "output",
    llvm::cl::desc("Output transformed LLVM bitcode (.bc) path."),
    llvm::cl::Required,
    llvm::cl::cat(kIpWeaverIrCategory));

llvm::cl::opt<std::string> kProtectPrefix(
    "protect-prefix",
    llvm::cl::desc("Auto-protect function name prefix."),
    llvm::cl::init("protected_"),
    llvm::cl::cat(kIpWeaverIrCategory));

llvm::cl::opt<bool> kProtectAllFunctions(
    "protect-all-functions",
    llvm::cl::desc("Protect all eligible functions (ignores annotations/prefix filter)."),
    llvm::cl::init(false),
    llvm::cl::cat(kIpWeaverIrCategory));

llvm::cl::opt<std::string> kRustCrateName(
    "rust-crate-name",
    llvm::cl::desc("Rust crate name hint used to scope protect-all to current crate symbols."),
    llvm::cl::init(""),
    llvm::cl::cat(kIpWeaverIrCategory));

llvm::cl::opt<std::uint8_t> kDefaultXorKey(
    "xor-key",
    llvm::cl::desc("Base XOR key used for encrypted globals and VM blobs."),
    llvm::cl::init(0x5Au),
    llvm::cl::cat(kIpWeaverIrCategory));

llvm::cl::opt<std::string> kTargetTriple(
    "target-triple",
    llvm::cl::desc("Target triple forwarded by wrapper for cross-compilation."),
    llvm::cl::init(""),
    llvm::cl::cat(kIpWeaverIrCategory));

constexpr llvm::StringLiteral kRunTemplateSymbol("eippf_generated_run_template");
constexpr llvm::StringLiteral kRunTemplateCheckedSymbol("eippf_generated_run_template_checked");
constexpr llvm::StringLiteral kVmBlobPrefix("__eippf_vmblob.");
constexpr llvm::StringLiteral kStringDecFlagPrefix("__eippf_strdec_flag.");
constexpr llvm::StringLiteral kDispatchTableSymbol("__eippf_dispatch_table");
constexpr llvm::StringLiteral kIntegrityTableSymbol("__eippf_integrity_table");
constexpr llvm::StringLiteral kAnnDrmFlatten("drm_flatten");
constexpr llvm::StringLiteral kAnnDrmCriticalIp("drm_critical_ip");
constexpr llvm::StringLiteral kAnnHftSecureRule("hft_secure_rule");
constexpr llvm::StringLiteral kAnnVmTarget("drm_vm_target");

struct ProtectedFunctionInfo final {
  llvm::Function* function = nullptr;
  llvm::GlobalVariable* encrypted_blob = nullptr;
  llvm::GlobalVariable* vm_call_table = nullptr;
  std::uint64_t blob_size = 0u;
  std::uint32_t vm_call_count = 0u;
  std::uint8_t key = 0u;
  bool vm_compatible = false;
};

struct VmBytecodeBuildResult final {
  std::vector<std::uint8_t> bytecode;
  std::vector<llvm::Function*> vm_call_targets;
  bool fully_supported = true;
  std::string first_error;
};

struct Vm2Instruction final {
  std::uint16_t opcode = 0u;
  std::uint16_t flags = 0u;
  std::uint32_t dst = 0u;
  std::uint32_t src0 = 0u;
  std::uint32_t src1 = 0u;
  std::int64_t imm = 0;
  std::uint64_t aux = 0u;
};

constexpr std::uint32_t kVm2InvalidSlot = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint16_t kVm2Version = 2u;
constexpr std::uint16_t kVm2LabelFlag = 0x1u;
constexpr std::uint16_t kVm2PhiImmediateFlag = 0x1u;
constexpr std::uint16_t kVm2CastUnsignedFlag = 0x1u;
constexpr std::uint16_t kVm2CastSignedFlag = 0x2u;
constexpr std::uint16_t kVm2CastSIToFPFlag = 0x10u;
constexpr std::uint16_t kVm2CastUIToFPFlag = 0x11u;
constexpr std::uint16_t kVm2CastFPToSIFlag = 0x12u;
constexpr std::uint16_t kVm2CastFPToUIFlag = 0x13u;
constexpr std::uint16_t kVm2CastFPTruncFlag = 0x14u;
constexpr std::uint16_t kVm2CastFPExtFlag = 0x15u;
constexpr std::uint64_t kVm2CallArg0IsSlotBaseFlag = 0x1ull;

enum : std::uint16_t {
  kVm2FCmpOEq = 0u,
  kVm2FCmpONe = 1u,
  kVm2FCmpOLt = 2u,
  kVm2FCmpOLe = 3u,
  kVm2FCmpOGt = 4u,
  kVm2FCmpOGe = 5u,
  kVm2FCmpUEq = 6u,
  kVm2FCmpUNe = 7u,
  kVm2FCmpULt = 8u,
  kVm2FCmpULe = 9u,
  kVm2FCmpUGt = 10u,
  kVm2FCmpUGe = 11u,
  kVm2FCmpOrd = 12u,
  kVm2FCmpUno = 13u,
  kVm2FCmpTrue = 14u,
  kVm2FCmpFalse = 15u,
};

struct EncryptedStringInfo final {
  llvm::GlobalVariable* global = nullptr;
  std::uint64_t size = 0u;
  std::uint8_t key = 0u;
  llvm::GlobalVariable* decrypt_flag = nullptr;
};

struct DispatchTableInfo final {
  llvm::GlobalVariable* table = nullptr;
  llvm::GlobalVariable* integrity_table = nullptr;
  llvm::DenseMap<llvm::Function*, std::uint32_t> function_index;
  std::uint32_t runtime_index = 0u;
  std::uint32_t entry_count = 0u;
  std::uint64_t secret_key = 0u;
};

void mark_strict_vm_failure(llvm::Module& module,
                            llvm::ArrayRef<std::string> function_names) {
  llvm::NamedMDNode* md = module.getOrInsertNamedMetadata("eippf.vm.unsupported");
  if (md == nullptr) {
    return;
  }
  for (const std::string& function_name : function_names) {
    llvm::MDString* name = llvm::MDString::get(module.getContext(), function_name);
    llvm::MDNode* node = llvm::MDNode::get(module.getContext(), name);
    md->addOperand(node);
  }
}

[[nodiscard]] std::uint64_t fnv1a64(llvm::StringRef text) {
  std::uint64_t hash = 14695981039346656037ull;
  for (char ch : text) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= 1099511628211ull;
  }
  return hash;
}

[[nodiscard]] std::uint8_t derive_poly_key(llvm::StringRef seed, std::uint8_t base_key) {
  const std::uint64_t h = fnv1a64(seed);
  std::uint8_t derived = static_cast<std::uint8_t>((h & 0xFFu) ^ base_key);
  if (derived == 0u) {
    derived = static_cast<std::uint8_t>(base_key ^ 0xA5u);
    if (derived == 0u) {
      derived = 0xA5u;
    }
  }
  return derived;
}

[[nodiscard]] std::uint64_t heartbeat_mix_key(std::uint64_t secret_key, std::uint32_t index) {
  return secret_key ^ (0x9E3779B97F4A7C15ull * (static_cast<std::uint64_t>(index) + 1ull));
}

[[nodiscard]] bool is_supported_scalar_type(const llvm::Type* type) {
  if (type == nullptr) {
    return false;
  }
  return type->isIntegerTy() || type->isFloatingPointTy() || type->isPointerTy() ||
         type->isVoidTy();
}

[[nodiscard]] bool supports_vm_stub_signature(const llvm::Function& function) {
  if (function.isVarArg()) {
    return false;
  }
  if (!is_supported_scalar_type(function.getReturnType())) {
    return false;
  }
  for (const llvm::Argument& argument : function.args()) {
    if (!is_supported_scalar_type(argument.getType())) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] bool is_supported_vm_operand(const llvm::Value* value,
                                           const llvm::Function& function) {
  if (value == nullptr) {
    return false;
  }
  if (llvm::isa<llvm::Argument>(value) || llvm::isa<llvm::ConstantInt>(value)) {
    return true;
  }
  const auto* inst = llvm::dyn_cast<llvm::Instruction>(value);
  if (inst == nullptr) {
    return false;
  }
  return inst->getFunction() == &function;
}

[[maybe_unused]] [[nodiscard]] bool supports_vm_bridge_mvp_lowering(const llvm::Function& function) {
  if (function.arg_size() > 2u || function.size() != 1u) {
    return false;
  }

  llvm::DenseMap<const llvm::Argument*, std::uint32_t> arg_use_count;
  bool saw_binary = false;
  bool saw_return = false;

  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& instruction : block) {
      if (llvm::isa<llvm::DbgInfoIntrinsic>(instruction)) {
        continue;
      }

      if (const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
        saw_binary = true;
        switch (binary->getOpcode()) {
          case llvm::Instruction::Add:
          case llvm::Instruction::Sub:
          case llvm::Instruction::Mul:
            break;
          default:
            return false;
        }

        for (std::uint32_t i = 0u; i < 2u; ++i) {
          const llvm::Value* operand = binary->getOperand(i);
          if (!is_supported_vm_operand(operand, function)) {
            return false;
          }
          if (const auto* arg = llvm::dyn_cast<llvm::Argument>(operand)) {
            ++arg_use_count[arg];
          }
        }

        if (binary->getOpcode() == llvm::Instruction::Sub) {
          const llvm::Value* lhs = binary->getOperand(0);
          const llvm::Value* rhs = binary->getOperand(1);
          const bool lhs_is_const = llvm::isa<llvm::ConstantInt>(lhs);
          const bool rhs_is_const = llvm::isa<llvm::ConstantInt>(rhs);
          if (lhs_is_const && !rhs_is_const) {
            return false;
          }
          const auto* lhs_arg = llvm::dyn_cast<llvm::Argument>(lhs);
          const auto* rhs_arg = llvm::dyn_cast<llvm::Argument>(rhs);
          if (lhs_arg != nullptr && rhs_arg != nullptr && lhs_arg->getArgNo() > rhs_arg->getArgNo()) {
            return false;
          }
        }
        continue;
      }

      if (const auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
        saw_return = true;
        if (ret->getNumOperands() > 1u) {
          return false;
        }
        if (ret->getNumOperands() == 1u) {
          const llvm::Value* ret_value = ret->getReturnValue();
          if (!is_supported_vm_operand(ret_value, function)) {
            return false;
          }
          if (const auto* arg = llvm::dyn_cast<llvm::Argument>(ret_value)) {
            ++arg_use_count[arg];
          }
        }
        continue;
      }

      if (instruction.isTerminator()) {
        return false;
      }
      return false;
    }
  }

  if (!saw_return) {
    return false;
  }

  for (const auto& [arg, use_count] : arg_use_count) {
    (void)arg;
    if (use_count > 1u) {
      return false;
    }
  }
  return saw_binary || !function.getReturnType()->isVoidTy();
}

[[nodiscard]] llvm::StringRef extract_annotation_text(llvm::Constant* annotation_operand) {
  llvm::Constant* cursor = annotation_operand;
  while (auto* constant_expression = llvm::dyn_cast<llvm::ConstantExpr>(cursor)) {
    if (constant_expression->getNumOperands() == 0u) {
      break;
    }
    cursor = llvm::dyn_cast<llvm::Constant>(constant_expression->getOperand(0));
    if (cursor == nullptr) {
      return {};
    }
  }

  auto* global = llvm::dyn_cast<llvm::GlobalVariable>(cursor);
  if (global == nullptr || !global->hasInitializer()) {
    return {};
  }

  auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(global->getInitializer());
  if (data == nullptr || !data->isString()) {
    return {};
  }

  return data->getAsCString();
}

void collect_annotated_functions(llvm::Module& module,
                                 llvm::SmallPtrSetImpl<llvm::Function*>& out) {
  llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr || !annotations->hasInitializer()) {
    return;
  }

  auto* annotation_array = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (annotation_array == nullptr) {
    return;
  }

  for (llvm::Value* entry_value : annotation_array->operands()) {
    auto* entry_struct = llvm::dyn_cast<llvm::ConstantStruct>(entry_value);
    if (entry_struct == nullptr || entry_struct->getNumOperands() < 2u) {
      continue;
    }

    llvm::Value* function_operand = entry_struct->getOperand(0)->stripPointerCasts();
    auto* function = llvm::dyn_cast<llvm::Function>(function_operand);
    if (function == nullptr) {
      continue;
    }

    auto* annotation_operand = llvm::dyn_cast<llvm::Constant>(entry_struct->getOperand(1));
    if (annotation_operand == nullptr) {
      continue;
    }

    const llvm::StringRef annotation = extract_annotation_text(annotation_operand);
    if (annotation == kAnnDrmFlatten || annotation == kAnnDrmCriticalIp ||
        annotation == kAnnHftSecureRule || annotation == kAnnVmTarget) {
      out.insert(function);
    }
  }
}

[[nodiscard]] bool should_protect_function(const llvm::Function& function,
                                           const llvm::SmallPtrSetImpl<llvm::Function*>& annotated,
                                           llvm::StringRef protect_prefix,
                                           bool protect_all_functions,
                                           llvm::StringRef rust_crate_name) {
  if (function.isDeclaration() || function.isIntrinsic() || function.empty()) {
    return false;
  }
  if (function.getName() == kRunTemplateSymbol ||
      function.getName() == kRunTemplateCheckedSymbol) {
    return false;
  }
  if (function.getName().startswith("__eippf_")) {
    return false;
  }
  // Entry/runtime symbols must remain stable for platform startup/runtime ABI.
  if (function.getName() == "main" || function.getName() == "_start" ||
      function.getName().startswith("__rust_") ||
      function.getName().startswith("rust_") ||
      function.getName().contains("lang_start") ||
      function.getName().contains("eh_personality")) {
    return false;
  }
  if (!supports_vm_stub_signature(function)) {
    return false;
  }
  if (protect_all_functions) {
    if (!rust_crate_name.empty()) {
      const llvm::StringRef name = function.getName();
      const bool rust_mangled = name.startswith("_ZN") || name.startswith("_RN") ||
                                name.startswith("_R");
      if (rust_mangled && name.contains("main17h")) {
        return false;
      }
      const bool rust_runtime_like =
          name.startswith("_ZN3std") || name.startswith("_ZN4core") ||
          name.startswith("_ZN5alloc") || name.startswith("_RNvNtCs") ||
          name.contains("lang_start") || name.contains("backtrace") ||
          name.contains("panicking");
      if (rust_runtime_like) {
        return false;
      }
      if (rust_mangled && !name.contains(rust_crate_name)) {
        return false;
      }
    }
    return true;
  }
  if (annotated.contains(&function)) {
    return true;
  }
  return !protect_prefix.empty() && function.getName().startswith(protect_prefix);
}

void append_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
  output.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFFu));
}

void append_u8(std::vector<std::uint8_t>& output, std::uint8_t value) {
  output.push_back(value);
}

void append_i64(std::vector<std::uint8_t>& output, std::int64_t value) {
  const std::uint64_t bits = static_cast<std::uint64_t>(value);
  for (std::size_t i = 0; i < sizeof(std::int64_t); ++i) {
    output.push_back(static_cast<std::uint8_t>((bits >> (8u * i)) & 0xFFu));
  }
}

void append_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
  for (std::size_t i = 0; i < sizeof(std::uint32_t); ++i) {
    output.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
  }
}

void append_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
  for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
    output.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
  }
}

[[nodiscard]] bool try_append_load_imm_from_value(const llvm::Value* value,
                                                  std::vector<std::uint8_t>& out) {
  auto append_imm_bits = [&](std::uint64_t bits) {
    append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64));
    append_i64(out, static_cast<std::int64_t>(bits));
  };

  if (llvm::isa<llvm::ConstantPointerNull>(value)) {
    append_imm_bits(0u);
    return true;
  }

  if (const auto* constant_int = llvm::dyn_cast<llvm::ConstantInt>(value)) {
    if (constant_int->getBitWidth() > 64u) {
      return false;
    }
    const llvm::APInt bits = constant_int->getValue().zextOrTrunc(64u);
    append_imm_bits(bits.getZExtValue());
    return true;
  }

  if (const auto* constant_fp = llvm::dyn_cast<llvm::ConstantFP>(value)) {
    llvm::APInt bits = constant_fp->getValueAPF().bitcastToAPInt();
    if (bits.getBitWidth() > 64u) {
      return false;
    }
    bits = bits.zextOrTrunc(64u);
    append_imm_bits(bits.getZExtValue());
    return true;
  }

  if (const auto* constant_expr = llvm::dyn_cast<llvm::ConstantExpr>(value)) {
    switch (constant_expr->getOpcode()) {
      case llvm::Instruction::BitCast:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::IntToPtr:
      case llvm::Instruction::AddrSpaceCast:
        return try_append_load_imm_from_value(constant_expr->getOperand(0), out);
      default:
        return false;
    }
  }

  return false;
}

[[nodiscard]] std::optional<pir::ConditionCode> map_icmp_condition(llvm::CmpInst::Predicate predicate) {
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

[[nodiscard]] std::optional<std::uint16_t> map_fcmp_condition(llvm::CmpInst::Predicate predicate) {
  switch (predicate) {
    case llvm::CmpInst::FCMP_OEQ:
      return kVm2FCmpOEq;
    case llvm::CmpInst::FCMP_ONE:
      return kVm2FCmpONe;
    case llvm::CmpInst::FCMP_OLT:
      return kVm2FCmpOLt;
    case llvm::CmpInst::FCMP_OLE:
      return kVm2FCmpOLe;
    case llvm::CmpInst::FCMP_OGT:
      return kVm2FCmpOGt;
    case llvm::CmpInst::FCMP_OGE:
      return kVm2FCmpOGe;
    case llvm::CmpInst::FCMP_UEQ:
      return kVm2FCmpUEq;
    case llvm::CmpInst::FCMP_UNE:
      return kVm2FCmpUNe;
    case llvm::CmpInst::FCMP_ULT:
      return kVm2FCmpULt;
    case llvm::CmpInst::FCMP_ULE:
      return kVm2FCmpULe;
    case llvm::CmpInst::FCMP_UGT:
      return kVm2FCmpUGt;
    case llvm::CmpInst::FCMP_UGE:
      return kVm2FCmpUGe;
    case llvm::CmpInst::FCMP_ORD:
      return kVm2FCmpOrd;
    case llvm::CmpInst::FCMP_UNO:
      return kVm2FCmpUno;
    case llvm::CmpInst::FCMP_TRUE:
      return kVm2FCmpTrue;
    case llvm::CmpInst::FCMP_FALSE:
      return kVm2FCmpFalse;
    default:
      return std::nullopt;
  }
}

[[maybe_unused]] [[nodiscard]] bool encode_instruction(const llvm::Instruction& instruction,
                                                       std::vector<std::uint8_t>& out) {
  switch (instruction.getOpcode()) {
    case llvm::Instruction::Add: {
      const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary != nullptr) {
        if (!try_append_load_imm_from_value(binary->getOperand(1), out)) {
          (void)try_append_load_imm_from_value(binary->getOperand(0), out);
        }
      }
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kAddI));
      return true;
    }
    case llvm::Instruction::Sub: {
      const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary != nullptr) {
        // Preserve stack order: only support rhs immediate for subtraction.
        (void)try_append_load_imm_from_value(binary->getOperand(1), out);
      }
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kSubI));
      return true;
    }
    case llvm::Instruction::Mul: {
      const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (binary != nullptr) {
        if (!try_append_load_imm_from_value(binary->getOperand(1), out)) {
          (void)try_append_load_imm_from_value(binary->getOperand(0), out);
        }
      }
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kMulI));
      return true;
    }
    case llvm::Instruction::UDiv:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kDivUI));
      return true;
    case llvm::Instruction::SDiv:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kDivSI));
      return true;
    case llvm::Instruction::URem:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kRemUI));
      return true;
    case llvm::Instruction::SRem:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kRemSI));
      return true;
    case llvm::Instruction::And:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kAnd));
      return true;
    case llvm::Instruction::Or:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kOr));
      return true;
    case llvm::Instruction::Xor:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kXor));
      return true;
    case llvm::Instruction::Shl:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kShl));
      return true;
    case llvm::Instruction::LShr:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kLShr));
      return true;
    case llvm::Instruction::AShr:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kAShr));
      return true;
    case llvm::Instruction::FAdd:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kAddF));
      return true;
    case llvm::Instruction::FSub:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kSubF));
      return true;
    case llvm::Instruction::FMul:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kMulF));
      return true;
    case llvm::Instruction::FDiv:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kDivF));
      return true;
    case llvm::Instruction::ICmp: {
      const auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(&instruction);
      if (icmp == nullptr) {
        return false;
      }
      const std::optional<pir::ConditionCode> cond = map_icmp_condition(icmp->getPredicate());
      if (!cond.has_value()) {
        return false;
      }
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kCmpI));
      append_u8(out, static_cast<std::uint8_t>(*cond));
      return true;
    }
    case llvm::Instruction::FCmp:
      append_u16(out, static_cast<std::uint16_t>(pir::OpCode::kCmpF));
      return true;
    case llvm::Instruction::Ret: {
      const auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction);
      if (ret != nullptr && ret->getNumOperands() == 1u) {
        (void)try_append_load_imm_from_value(ret->getReturnValue(), out);
      }
      return true;
    }
    default:
      return false;
  }
}

[[nodiscard]] VmBytecodeBuildResult build_vm_bytecode(const llvm::Function& function) {
  VmBytecodeBuildResult result{};
  std::vector<Vm2Instruction> instructions;
  instructions.reserve(static_cast<std::size_t>(function.getInstructionCount()) * 2u + 16u);

  llvm::DenseMap<const llvm::BasicBlock*, std::uint32_t> block_ids;
  llvm::DenseMap<const llvm::Value*, std::uint32_t> slot_ids;
  llvm::DenseMap<const llvm::Value*, std::uint32_t> stack_slots;
  llvm::DenseMap<const llvm::Value*, llvm::DenseMap<std::int64_t, std::uint32_t>> stack_offset_slots;
  llvm::DenseMap<const llvm::Function*, std::uint32_t> vm_call_indices;
  std::vector<llvm::Function*> vm_call_targets;
  std::uint32_t next_slot = 0u;
  std::uint32_t next_block_id = 0u;
  const llvm::DataLayout* data_layout = nullptr;
  if (const llvm::Module* module = function.getParent()) {
    data_layout = &module->getDataLayout();
  }

  for (const llvm::BasicBlock& block : function) {
    block_ids[&block] = next_block_id++;
  }

  for (const llvm::Argument& arg : function.args()) {
    slot_ids[&arg] = next_slot++;
  }
  for (const llvm::BasicBlock& block : function) {
    for (const llvm::Instruction& inst : block) {
      if (llvm::isa<llvm::AllocaInst>(inst)) {
        const std::uint32_t slot = next_slot++;
        stack_slots[&inst] = slot;
        stack_offset_slots[&inst][0] = slot;
        continue;
      }
      if (!inst.getType()->isVoidTy()) {
        slot_ids[&inst] = next_slot++;
      }
    }
  }

  std::function<bool(const llvm::Value*, std::int64_t&)> try_extract_constant_bits;
  try_extract_constant_bits = [&](const llvm::Value* value, std::int64_t& out_bits) -> bool {
    if (llvm::isa<llvm::ConstantPointerNull>(value)) {
      out_bits = 0;
      return true;
    }
    if (const auto* ci = llvm::dyn_cast<llvm::ConstantInt>(value)) {
      if (ci->getBitWidth() > 64u) {
        return false;
      }
      out_bits = static_cast<std::int64_t>(ci->getValue().zextOrTrunc(64u).getZExtValue());
      return true;
    }
    if (const auto* cf = llvm::dyn_cast<llvm::ConstantFP>(value)) {
      llvm::APInt bits = cf->getValueAPF().bitcastToAPInt();
      if (bits.getBitWidth() > 64u) {
        return false;
      }
      out_bits = static_cast<std::int64_t>(bits.zextOrTrunc(64u).getZExtValue());
      return true;
    }
    if (const auto* expr = llvm::dyn_cast<llvm::ConstantExpr>(value)) {
      switch (expr->getOpcode()) {
        case llvm::Instruction::BitCast:
        case llvm::Instruction::PtrToInt:
        case llvm::Instruction::IntToPtr:
        case llvm::Instruction::AddrSpaceCast:
          return try_extract_constant_bits(expr->getOperand(0), out_bits);
        default:
          return false;
      }
    }
    return false;
  };

  auto push_inst = [&](Vm2Instruction inst) {
    instructions.push_back(inst);
  };

  auto get_or_insert_vm_call_target = [&](llvm::Function* callee) -> std::optional<std::uint32_t> {
    if (callee == nullptr) {
      return std::nullopt;
    }
    auto it = vm_call_indices.find(callee);
    if (it != vm_call_indices.end()) {
      return it->second;
    }
    const std::uint32_t index = static_cast<std::uint32_t>(vm_call_targets.size());
    vm_call_targets.push_back(callee);
    vm_call_indices[callee] = index;
    return index;
  };

  auto mark_unsupported = [&](const llvm::Instruction* inst, llvm::StringRef reason) {
    result.fully_supported = false;
    if (!result.first_error.empty()) {
      return;
    }
    result.first_error = reason.str();
    if (inst != nullptr) {
      result.first_error.append(" [opcode=");
      result.first_error.append(inst->getOpcodeName());
      result.first_error.push_back(']');
    }
  };

  auto get_or_emit_slot = [&](const llvm::Value* value,
                              std::vector<Vm2Instruction>& stream) -> std::optional<std::uint32_t> {
    auto stack_it = stack_slots.find(value);
    if (stack_it != stack_slots.end()) {
      return stack_it->second;
    }
    auto it = slot_ids.find(value);
    if (it != slot_ids.end()) {
      return it->second;
    }
    std::int64_t imm_bits = 0;
    if (!try_extract_constant_bits(value, imm_bits)) {
      return std::nullopt;
    }
    // Constants must be materialized at each use site. Reusing a slot initialized
    // in a different control-flow branch can read uninitialized values.
    const std::uint32_t slot = next_slot++;
    Vm2Instruction load{};
    load.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
    load.flags = 64u;
    load.dst = slot;
    load.src0 = kVm2InvalidSlot;
    load.src1 = kVm2InvalidSlot;
    load.imm = imm_bits;
    load.aux = 0u;
    stream.push_back(load);
    return slot;
  };

  auto integer_bit_width = [](const llvm::Type* ty) -> std::uint16_t {
    if (ty == nullptr) {
      return 64u;
    }
    if (ty->isIntegerTy()) {
      const unsigned bw = ty->getIntegerBitWidth();
      if (bw == 0u) {
        return 1u;
      }
      return static_cast<std::uint16_t>(bw > 64u ? 64u : bw);
    }
    return 64u;
  };

  std::function<std::optional<std::uint32_t>(const llvm::Value*)> resolve_stack_slot;
  resolve_stack_slot = [&](const llvm::Value* value) -> std::optional<std::uint32_t> {
    if (value == nullptr) {
      return std::nullopt;
    }
    value = value->stripPointerCasts();
    auto it = stack_slots.find(value);
    if (it != stack_slots.end()) {
      return it->second;
    }

    auto resolve_with_offset = [&](const llvm::Value* base, std::int64_t offset) -> std::optional<std::uint32_t> {
      if (base == nullptr) {
        return std::nullopt;
      }
      base = base->stripPointerCasts();

      auto base_it = stack_slots.find(base);
      if (base_it == stack_slots.end()) {
        return std::nullopt;
      }

      llvm::DenseMap<std::int64_t, std::uint32_t>& offsets = stack_offset_slots[base];
      auto off_it = offsets.find(offset);
      if (off_it != offsets.end()) {
        return off_it->second;
      }

      const std::uint32_t new_slot = next_slot++;
      offsets[offset] = new_slot;
      return new_slot;
    };

    const auto* gep_operator = llvm::dyn_cast<llvm::GEPOperator>(value);
    if (gep_operator != nullptr) {
      llvm::APInt offset_bits(64u, 0u, true);
      if (data_layout == nullptr || !gep_operator->accumulateConstantOffset(*data_layout, offset_bits)) {
        return std::nullopt;
      }
      if (offset_bits.getBitWidth() > 64u) {
        offset_bits = offset_bits.sextOrTrunc(64u);
      }
      const std::int64_t byte_offset = offset_bits.getSExtValue();
      return resolve_with_offset(gep_operator->getPointerOperand(), byte_offset);
    }

    if (const auto* expr = llvm::dyn_cast<llvm::ConstantExpr>(value)) {
      if (expr->getNumOperands() == 0u) {
        return std::nullopt;
      }
      if (expr->getOpcode() == llvm::Instruction::BitCast ||
          expr->getOpcode() == llvm::Instruction::AddrSpaceCast) {
        return resolve_stack_slot(expr->getOperand(0));
      }
    }
    return std::nullopt;
  };

  auto try_decode_constant_array_elements =
      [&](const llvm::GlobalVariable* global,
          std::vector<std::int64_t>& out_elements,
          std::uint16_t& out_element_bits) -> bool {
    if (global == nullptr || !global->hasInitializer()) {
      return false;
    }
    const llvm::Constant* initializer = global->getInitializer();
    if (initializer == nullptr) {
      return false;
    }

    auto decode_element = [&](const llvm::Constant* constant, std::int64_t& out_bits) -> bool {
      return try_extract_constant_bits(constant, out_bits);
    };

    if (const auto* cds = llvm::dyn_cast<llvm::ConstantDataSequential>(initializer)) {
      if (cds->isString()) {
        return false;
      }
      out_element_bits = integer_bit_width(cds->getElementType());
      out_elements.reserve(cds->getNumElements());
      for (unsigned i = 0; i < cds->getNumElements(); ++i) {
        std::int64_t bits = 0;
        if (!decode_element(cds->getElementAsConstant(i), bits)) {
          return false;
        }
        out_elements.push_back(bits);
      }
      return !out_elements.empty();
    }

    const auto* array = llvm::dyn_cast<llvm::ConstantArray>(initializer);
    if (array == nullptr || array->getNumOperands() == 0u) {
      return false;
    }
    const llvm::Type* elem_ty = array->getType()->getElementType();
    out_element_bits = integer_bit_width(elem_ty);
    out_elements.reserve(array->getNumOperands());
    for (const llvm::Use& operand : array->operands()) {
      const auto* constant = llvm::dyn_cast<llvm::Constant>(operand.get());
      std::int64_t bits = 0;
      if (constant == nullptr || !decode_element(constant, bits)) {
        return false;
      }
      out_elements.push_back(bits);
    }
    return !out_elements.empty();
  };

  auto try_emit_const_global_array_load =
      [&](const llvm::LoadInst* load) -> bool {
    if (load == nullptr) {
      return false;
    }

    const llvm::Value* pointer_value = load->getPointerOperand()->stripPointerCasts();
    const auto* gep = llvm::dyn_cast<llvm::GEPOperator>(pointer_value);
    if (gep == nullptr || gep->getNumIndices() == 0u) {
      return false;
    }

    const llvm::GlobalVariable* global =
        llvm::dyn_cast<llvm::GlobalVariable>(gep->getPointerOperand()->stripPointerCasts());
    if (global == nullptr) {
      return false;
    }

    std::vector<std::int64_t> elements;
    std::uint16_t element_bits = 64u;
    if (!try_decode_constant_array_elements(global, elements, element_bits)) {
      return false;
    }

    const llvm::Value* index_value = nullptr;
    if (gep->getNumIndices() == 1u) {
      index_value = gep->idx_begin()->get();
    } else if (gep->getNumIndices() == 2u) {
      auto it = gep->idx_begin();
      const auto* first = llvm::dyn_cast<llvm::ConstantInt>(it->get());
      if (first == nullptr || !first->isZero()) {
        return false;
      }
      ++it;
      index_value = it->get();
    } else {
      return false;
    }
    if (index_value == nullptr) {
      return false;
    }

    const std::uint32_t dst_slot = slot_ids.lookup(load);
    const std::uint16_t dst_bits = integer_bit_width(load->getType());

    std::int64_t constant_index_bits = 0;
    if (try_extract_constant_bits(index_value, constant_index_bits)) {
      std::int64_t resolved = 0;
      if (constant_index_bits >= 0) {
        const std::uint64_t idx = static_cast<std::uint64_t>(constant_index_bits);
        if (idx < elements.size()) {
          resolved = elements[idx];
        }
      }
      Vm2Instruction load_const{};
      load_const.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
      load_const.flags = dst_bits;
      load_const.dst = dst_slot;
      load_const.src0 = kVm2InvalidSlot;
      load_const.src1 = kVm2InvalidSlot;
      load_const.imm = resolved;
      load_const.aux = 0u;
      push_inst(load_const);
      return true;
    }

    auto idx_slot = get_or_emit_slot(index_value, instructions);
    if (!idx_slot.has_value()) {
      return false;
    }

    Vm2Instruction init_load{};
    init_load.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
    init_load.flags = dst_bits;
    init_load.dst = dst_slot;
    init_load.src0 = kVm2InvalidSlot;
    init_load.src1 = kVm2InvalidSlot;
    init_load.imm = elements[0];
    init_load.aux = 0u;
    push_inst(init_load);

    for (std::size_t i = 1; i < elements.size(); ++i) {
      const std::uint32_t idx_const_slot = next_slot++;
      Vm2Instruction idx_const{};
      idx_const.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
      idx_const.flags = 64u;
      idx_const.dst = idx_const_slot;
      idx_const.src0 = kVm2InvalidSlot;
      idx_const.src1 = kVm2InvalidSlot;
      idx_const.imm = static_cast<std::int64_t>(i);
      idx_const.aux = 0u;
      push_inst(idx_const);

      const std::uint32_t cmp_slot = next_slot++;
      Vm2Instruction cmp{};
      cmp.opcode = static_cast<std::uint16_t>(pir::OpCode::kCmpI);
      cmp.flags = static_cast<std::uint16_t>(pir::ConditionCode::kEq);
      cmp.dst = cmp_slot;
      cmp.src0 = *idx_slot;
      cmp.src1 = idx_const_slot;
      cmp.imm = 0;
      cmp.aux = 64u;
      push_inst(cmp);

      const std::uint32_t val_slot = next_slot++;
      Vm2Instruction value_load{};
      value_load.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
      value_load.flags = dst_bits;
      value_load.dst = val_slot;
      value_load.src0 = kVm2InvalidSlot;
      value_load.src1 = kVm2InvalidSlot;
      value_load.imm = elements[i];
      value_load.aux = 0u;
      push_inst(value_load);

      Vm2Instruction sel{};
      sel.opcode = static_cast<std::uint16_t>(pir::OpCode::kSelect);
      sel.flags = 0u;
      sel.dst = dst_slot;
      sel.src0 = cmp_slot;
      sel.src1 = val_slot;
      sel.imm = 0;
      sel.aux = dst_slot;
      push_inst(sel);
    }

    return true;
  };

  for (const llvm::BasicBlock& block : function) {
    Vm2Instruction label{};
    label.opcode = static_cast<std::uint16_t>(pir::OpCode::kNop);
    label.flags = kVm2LabelFlag;
    label.dst = kVm2InvalidSlot;
    label.src0 = kVm2InvalidSlot;
    label.src1 = kVm2InvalidSlot;
    label.imm = static_cast<std::int64_t>(block_ids.lookup(&block));
    label.aux = 0u;
    push_inst(label);

    for (const llvm::Instruction& inst : block) {
      const auto* phi = llvm::dyn_cast<llvm::PHINode>(&inst);
      if (phi == nullptr) {
        continue;
      }
      const std::uint32_t dst_slot = slot_ids.lookup(phi);
      for (unsigned i = 0; i < phi->getNumIncomingValues(); ++i) {
        const llvm::Value* incoming_value = phi->getIncomingValue(i);
        const llvm::BasicBlock* pred = phi->getIncomingBlock(i);
        Vm2Instruction phi_move{};
        phi_move.opcode = static_cast<std::uint16_t>(pir::OpCode::kPhiMove);
        phi_move.flags = 0u;
        phi_move.dst = dst_slot;
        phi_move.src0 = kVm2InvalidSlot;
        phi_move.src1 = kVm2InvalidSlot;
        phi_move.imm = 0;
        phi_move.aux = pred != nullptr ? block_ids.lookup(pred) : 0u;

        std::int64_t imm_bits = 0;
        if (try_extract_constant_bits(incoming_value, imm_bits)) {
          phi_move.flags |= kVm2PhiImmediateFlag;
          phi_move.imm = imm_bits;
          push_inst(phi_move);
          continue;
        }

        auto incoming_slot = get_or_emit_slot(incoming_value, instructions);
        if (!incoming_slot.has_value()) {
          mark_unsupported(&inst, "phi incoming value cannot be lowered");
          Vm2Instruction trap{};
          trap.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
          trap.dst = kVm2InvalidSlot;
          trap.src0 = kVm2InvalidSlot;
          trap.src1 = kVm2InvalidSlot;
          push_inst(trap);
          continue;
        }
        phi_move.src0 = *incoming_slot;
        push_inst(phi_move);
      }
    }

    for (const llvm::Instruction& inst : block) {
      if (llvm::isa<llvm::PHINode>(inst) || llvm::isa<llvm::DbgInfoIntrinsic>(inst)) {
        continue;
      }
      if (const auto* intrinsic = llvm::dyn_cast<llvm::IntrinsicInst>(&inst)) {
        switch (intrinsic->getIntrinsicID()) {
          case llvm::Intrinsic::lifetime_start:
          case llvm::Intrinsic::lifetime_end:
          case llvm::Intrinsic::invariant_start:
          case llvm::Intrinsic::invariant_end:
          case llvm::Intrinsic::assume:
            continue;
          default:
            break;
        }
      }

      if (llvm::isa<llvm::AllocaInst>(inst)) {
        continue;
      }

      if (const auto* gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(&inst)) {
        if (auto resolved = resolve_stack_slot(gep_inst); resolved.has_value()) {
          slot_ids[&inst] = *resolved;
        }
        continue;
      }

      if (const auto* br = llvm::dyn_cast<llvm::BranchInst>(&inst)) {
        Vm2Instruction branch_inst{};
        branch_inst.dst = kVm2InvalidSlot;
        branch_inst.src0 = kVm2InvalidSlot;
        branch_inst.src1 = kVm2InvalidSlot;
        if (br->isUnconditional()) {
          branch_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kJmp);
          branch_inst.imm = static_cast<std::int64_t>(block_ids.lookup(br->getSuccessor(0)));
          branch_inst.aux = 0u;
          push_inst(branch_inst);
          continue;
        }
        auto cond_slot = get_or_emit_slot(br->getCondition(), instructions);
        if (!cond_slot.has_value()) {
          mark_unsupported(&inst, "branch condition cannot be lowered");
          branch_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
          push_inst(branch_inst);
          continue;
        }
        branch_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kJcc);
        branch_inst.src0 = *cond_slot;
        branch_inst.imm = static_cast<std::int64_t>(block_ids.lookup(br->getSuccessor(0)));
        branch_inst.aux = block_ids.lookup(br->getSuccessor(1));
        push_inst(branch_inst);
        continue;
      }

      if (const auto* switch_inst = llvm::dyn_cast<llvm::SwitchInst>(&inst)) {
        auto cond_slot = get_or_emit_slot(switch_inst->getCondition(), instructions);
        if (!cond_slot.has_value()) {
          mark_unsupported(&inst, "switch condition cannot be lowered");
          Vm2Instruction trap{};
          trap.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
          trap.dst = kVm2InvalidSlot;
          trap.src0 = kVm2InvalidSlot;
          trap.src1 = kVm2InvalidSlot;
          push_inst(trap);
          continue;
        }

        const llvm::Type* cond_ty = switch_inst->getCondition()->getType();
        const std::uint16_t cond_width = integer_bit_width(cond_ty);

        llvm::SmallVector<std::uint32_t, 16> compare_labels;
        const unsigned case_count = switch_inst->getNumCases();
        if (case_count > 1u) {
          compare_labels.reserve(case_count - 1u);
          for (unsigned i = 0u; i < case_count - 1u; ++i) {
            compare_labels.push_back(next_block_id++);
          }
        }

        const std::uint32_t cmp_slot = next_slot++;
        unsigned case_index = 0u;
        for (const auto& case_handle : switch_inst->cases()) {
          if (case_index > 0u) {
            Vm2Instruction cmp_label{};
            cmp_label.opcode = static_cast<std::uint16_t>(pir::OpCode::kNop);
            cmp_label.flags = kVm2LabelFlag;
            cmp_label.dst = kVm2InvalidSlot;
            cmp_label.src0 = kVm2InvalidSlot;
            cmp_label.src1 = kVm2InvalidSlot;
            cmp_label.imm = static_cast<std::int64_t>(compare_labels[case_index - 1u]);
            cmp_label.aux = 0u;
            push_inst(cmp_label);
          }

          auto case_slot = get_or_emit_slot(case_handle.getCaseValue(), instructions);
          if (!case_slot.has_value()) {
            mark_unsupported(&inst, "switch case value cannot be lowered");
            Vm2Instruction trap{};
            trap.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
            trap.dst = kVm2InvalidSlot;
            trap.src0 = kVm2InvalidSlot;
            trap.src1 = kVm2InvalidSlot;
            push_inst(trap);
            break;
          }

          Vm2Instruction cmp_inst{};
          cmp_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kCmpI);
          cmp_inst.flags = static_cast<std::uint16_t>(pir::ConditionCode::kEq);
          cmp_inst.dst = cmp_slot;
          cmp_inst.src0 = *cond_slot;
          cmp_inst.src1 = *case_slot;
          cmp_inst.imm = 0;
          cmp_inst.aux = cond_width;
          push_inst(cmp_inst);

          Vm2Instruction branch_inst{};
          branch_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kJcc);
          branch_inst.flags = 0u;
          branch_inst.dst = kVm2InvalidSlot;
          branch_inst.src0 = cmp_slot;
          branch_inst.src1 = kVm2InvalidSlot;
          branch_inst.imm =
              static_cast<std::int64_t>(block_ids.lookup(case_handle.getCaseSuccessor()));
          if (case_index + 1u < case_count) {
            branch_inst.aux = compare_labels[case_index];
          } else {
            branch_inst.aux = block_ids.lookup(switch_inst->getDefaultDest());
          }
          push_inst(branch_inst);
          ++case_index;
        }

        if (case_count == 0u) {
          Vm2Instruction jmp_default{};
          jmp_default.opcode = static_cast<std::uint16_t>(pir::OpCode::kJmp);
          jmp_default.flags = 0u;
          jmp_default.dst = kVm2InvalidSlot;
          jmp_default.src0 = kVm2InvalidSlot;
          jmp_default.src1 = kVm2InvalidSlot;
          jmp_default.imm =
              static_cast<std::int64_t>(block_ids.lookup(switch_inst->getDefaultDest()));
          jmp_default.aux = 0u;
          push_inst(jmp_default);
        }
        continue;
      }

      if (const auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&inst)) {
        Vm2Instruction ret_inst{};
        ret_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kRet);
        ret_inst.dst = kVm2InvalidSlot;
        ret_inst.src0 = kVm2InvalidSlot;
        ret_inst.src1 = kVm2InvalidSlot;
        ret_inst.imm = 0;
        ret_inst.aux = 0u;
        if (ret->getNumOperands() == 1u) {
          auto ret_slot = get_or_emit_slot(ret->getReturnValue(), instructions);
          if (ret_slot.has_value()) {
            ret_inst.src0 = *ret_slot;
          } else {
            mark_unsupported(&inst, "return value cannot be lowered");
            ret_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
          }
        }
        push_inst(ret_inst);
        continue;
      }

      if (const auto* load = llvm::dyn_cast<llvm::LoadInst>(&inst)) {
        if (try_emit_const_global_array_load(load)) {
          continue;
        }

        Vm2Instruction load_inst{};
        load_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMov);
        load_inst.flags = kVm2CastUnsignedFlag;
        load_inst.dst = slot_ids.lookup(load);
        load_inst.src1 = kVm2InvalidSlot;
        load_inst.imm = 0;
        load_inst.aux = (static_cast<std::uint64_t>(integer_bit_width(load->getType())) << 32u) |
                        integer_bit_width(load->getType());
        auto src_slot = resolve_stack_slot(load->getPointerOperand());
        if (!src_slot.has_value()) {
          mark_unsupported(&inst, "load pointer is not VM stack-addressable");
          Vm2Instruction trap{};
          trap.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
          trap.dst = kVm2InvalidSlot;
          trap.src0 = kVm2InvalidSlot;
          trap.src1 = kVm2InvalidSlot;
          push_inst(trap);
        } else {
          load_inst.src0 = *src_slot;
          push_inst(load_inst);
        }
        continue;
      }

      if (const auto* store = llvm::dyn_cast<llvm::StoreInst>(&inst)) {
        Vm2Instruction store_inst{};
        store_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMov);
        store_inst.flags = kVm2CastUnsignedFlag;
        store_inst.dst = kVm2InvalidSlot;
        store_inst.src1 = kVm2InvalidSlot;
        store_inst.imm = 0;
        const llvm::Type* stored_ty = store->getValueOperand()->getType();
        const std::uint16_t bw = integer_bit_width(stored_ty);
        store_inst.aux = (static_cast<std::uint64_t>(bw) << 32u) | bw;
        auto dst_slot = resolve_stack_slot(store->getPointerOperand());
        auto src_slot = get_or_emit_slot(store->getValueOperand(), instructions);
        if (!dst_slot.has_value() || !src_slot.has_value()) {
          mark_unsupported(&inst, "store operands are not VM-lowerable");
          Vm2Instruction trap{};
          trap.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
          trap.dst = kVm2InvalidSlot;
          trap.src0 = kVm2InvalidSlot;
          trap.src1 = kVm2InvalidSlot;
          push_inst(trap);
        } else {
          store_inst.dst = *dst_slot;
          store_inst.src0 = *src_slot;
          push_inst(store_inst);
        }
        continue;
      }

      Vm2Instruction vm_inst{};
      vm_inst.dst = inst.getType()->isVoidTy() ? kVm2InvalidSlot : slot_ids.lookup(&inst);
      vm_inst.src0 = kVm2InvalidSlot;
      vm_inst.src1 = kVm2InvalidSlot;
      vm_inst.imm = 0;
      vm_inst.aux = 0u;

      bool supported = true;
      if (const auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&inst)) {
        auto lhs = get_or_emit_slot(binary->getOperand(0), instructions);
        auto rhs = get_or_emit_slot(binary->getOperand(1), instructions);
        if (!lhs.has_value() || !rhs.has_value()) {
          supported = false;
        } else {
          vm_inst.src0 = *lhs;
          vm_inst.src1 = *rhs;
          vm_inst.flags = integer_bit_width(binary->getType());
          switch (binary->getOpcode()) {
            case llvm::Instruction::Add:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kAddI);
              break;
            case llvm::Instruction::Sub:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kSubI);
              break;
            case llvm::Instruction::Mul:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMulI);
              break;
            case llvm::Instruction::UDiv:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kDivUI);
              break;
            case llvm::Instruction::SDiv:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kDivSI);
              break;
            case llvm::Instruction::URem:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kRemUI);
              break;
            case llvm::Instruction::SRem:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kRemSI);
              break;
            case llvm::Instruction::And:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kAnd);
              break;
            case llvm::Instruction::Or:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kOr);
              break;
            case llvm::Instruction::Xor:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kXor);
              break;
            case llvm::Instruction::Shl:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kShl);
              break;
            case llvm::Instruction::LShr:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kLShr);
              break;
            case llvm::Instruction::AShr:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kAShr);
              break;
            case llvm::Instruction::FAdd:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kAddF);
              break;
            case llvm::Instruction::FSub:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kSubF);
              break;
            case llvm::Instruction::FMul:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMulF);
              break;
            case llvm::Instruction::FDiv:
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kDivF);
              break;
            default:
              supported = false;
              break;
          }
        }
      } else if (const auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(&inst)) {
        auto lhs = get_or_emit_slot(icmp->getOperand(0), instructions);
        auto rhs = get_or_emit_slot(icmp->getOperand(1), instructions);
        const std::optional<pir::ConditionCode> cond = map_icmp_condition(icmp->getPredicate());
        if (!lhs.has_value() || !rhs.has_value() || !cond.has_value()) {
          supported = false;
        } else {
          vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kCmpI);
          vm_inst.src0 = *lhs;
          vm_inst.src1 = *rhs;
          vm_inst.flags = static_cast<std::uint16_t>(*cond);
          vm_inst.aux = integer_bit_width(icmp->getOperand(0)->getType());
        }
      } else if (const auto* fcmp = llvm::dyn_cast<llvm::FCmpInst>(&inst)) {
        auto lhs = get_or_emit_slot(fcmp->getOperand(0), instructions);
        auto rhs = get_or_emit_slot(fcmp->getOperand(1), instructions);
        const std::optional<std::uint16_t> cond = map_fcmp_condition(fcmp->getPredicate());
        if (!lhs.has_value() || !rhs.has_value() || !cond.has_value()) {
          supported = false;
        } else {
          vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kCmpF);
          vm_inst.src0 = *lhs;
          vm_inst.src1 = *rhs;
          vm_inst.flags = *cond;
          vm_inst.aux = integer_bit_width(fcmp->getOperand(0)->getType());
        }
      } else if (const auto* cast = llvm::dyn_cast<llvm::CastInst>(&inst)) {
        if (cast->getOpcode() == llvm::Instruction::PtrToInt) {
          if (auto ptr_slot = resolve_stack_slot(cast->getOperand(0)); ptr_slot.has_value()) {
            vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
            vm_inst.flags = 64u;
            vm_inst.src0 = kVm2InvalidSlot;
            vm_inst.src1 = kVm2InvalidSlot;
            vm_inst.imm = static_cast<std::int64_t>(*ptr_slot);
            vm_inst.aux = 0u;
          } else {
            auto src = get_or_emit_slot(cast->getOperand(0), instructions);
            if (!src.has_value()) {
              supported = false;
            } else {
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMov);
              vm_inst.src0 = *src;
              const std::uint32_t src_bw = integer_bit_width(cast->getSrcTy());
              const std::uint32_t dst_bw = integer_bit_width(cast->getDestTy());
              vm_inst.aux = (static_cast<std::uint64_t>(src_bw) << 32u) | dst_bw;
              vm_inst.flags = kVm2CastUnsignedFlag;
            }
          }
        } else {
          auto src = get_or_emit_slot(cast->getOperand(0), instructions);
          if (!src.has_value()) {
            supported = false;
          } else {
            vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMov);
            vm_inst.src0 = *src;
            const std::uint32_t src_bw = integer_bit_width(cast->getSrcTy());
            const std::uint32_t dst_bw = integer_bit_width(cast->getDestTy());
            vm_inst.aux = (static_cast<std::uint64_t>(src_bw) << 32u) | dst_bw;
            switch (cast->getOpcode()) {
              case llvm::Instruction::SExt:
                vm_inst.flags = kVm2CastSignedFlag;
                break;
              case llvm::Instruction::ZExt:
              case llvm::Instruction::Trunc:
              case llvm::Instruction::BitCast:
              case llvm::Instruction::IntToPtr:
              case llvm::Instruction::AddrSpaceCast:
                vm_inst.flags = kVm2CastUnsignedFlag;
                break;
              case llvm::Instruction::SIToFP:
                vm_inst.flags = kVm2CastSIToFPFlag;
                break;
              case llvm::Instruction::UIToFP:
                vm_inst.flags = kVm2CastUIToFPFlag;
                break;
              case llvm::Instruction::FPToSI:
                vm_inst.flags = kVm2CastFPToSIFlag;
                break;
              case llvm::Instruction::FPToUI:
                vm_inst.flags = kVm2CastFPToUIFlag;
                break;
              case llvm::Instruction::FPTrunc:
                vm_inst.flags = kVm2CastFPTruncFlag;
                break;
              case llvm::Instruction::FPExt:
                vm_inst.flags = kVm2CastFPExtFlag;
                break;
              default:
                supported = false;
                break;
            }
          }
        }
      } else if (const auto* unary = llvm::dyn_cast<llvm::UnaryOperator>(&inst)) {
        if (unary->getOpcode() != llvm::Instruction::FNeg) {
          supported = false;
        } else {
          auto src = get_or_emit_slot(unary->getOperand(0), instructions);
          llvm::Constant* zero = nullptr;
          if (unary->getType()->isFloatTy()) {
            zero = llvm::ConstantFP::get(unary->getType(), 0.0);
          } else if (unary->getType()->isDoubleTy()) {
            zero = llvm::ConstantFP::get(unary->getType(), 0.0);
          }
          auto zero_slot = zero != nullptr ? get_or_emit_slot(zero, instructions) : std::nullopt;
          if (!src.has_value() || !zero_slot.has_value()) {
            supported = false;
          } else {
            vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kSubF);
            vm_inst.src0 = *zero_slot;
            vm_inst.src1 = *src;
            vm_inst.flags = integer_bit_width(unary->getType());
          }
        }
      } else if (const auto* freeze = llvm::dyn_cast<llvm::FreezeInst>(&inst)) {
        auto src = get_or_emit_slot(freeze->getOperand(0), instructions);
        if (!src.has_value()) {
          supported = false;
        } else {
          vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMov);
          vm_inst.src0 = *src;
          const std::uint32_t bw = integer_bit_width(freeze->getType());
          vm_inst.flags = kVm2CastUnsignedFlag;
          vm_inst.aux = (static_cast<std::uint64_t>(bw) << 32u) | bw;
        }
      } else if (const auto* call = llvm::dyn_cast<llvm::CallInst>(&inst)) {
        llvm::Function* callee = call->getCalledFunction();
        if (call->isInlineAsm() || callee == nullptr) {
          supported = false;
        } else if (!callee->isIntrinsic()) {
          if (call->arg_size() > 2u || call->isMustTailCall() || call->isIndirectCall()) {
            supported = false;
          } else if (!is_supported_scalar_type(call->getType())) {
            supported = false;
          } else {
            auto call_index = get_or_insert_vm_call_target(callee);
            auto arg0 = call->arg_size() > 0u
                            ? get_or_emit_slot(call->getArgOperand(0), instructions)
                            : std::optional<std::uint32_t>(kVm2InvalidSlot);
            auto arg1 = call->arg_size() > 1u
                            ? get_or_emit_slot(call->getArgOperand(1), instructions)
                            : std::optional<std::uint32_t>(kVm2InvalidSlot);
            if (!call_index.has_value() || !arg0.has_value() || !arg1.has_value()) {
              supported = false;
            } else {
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kCall);
              vm_inst.flags = static_cast<std::uint16_t>(call->arg_size());
              vm_inst.src0 = *arg0;
              vm_inst.src1 = *arg1;
              vm_inst.imm = static_cast<std::int64_t>(*call_index);
              vm_inst.aux = callee->getName().startswith("__eippf_vmwrap.")
                                ? kVm2CallArg0IsSlotBaseFlag
                                : 0u;
              if (call->getType()->isVoidTy()) {
                vm_inst.dst = kVm2InvalidSlot;
              }
            }
          }
        } else {
          switch (callee->getIntrinsicID()) {
            case llvm::Intrinsic::fmuladd: {
              if (call->arg_size() != 3u) {
                supported = false;
                break;
              }
              auto lhs = get_or_emit_slot(call->getArgOperand(0), instructions);
              auto rhs = get_or_emit_slot(call->getArgOperand(1), instructions);
              auto addend = get_or_emit_slot(call->getArgOperand(2), instructions);
              if (!lhs.has_value() || !rhs.has_value() || !addend.has_value()) {
                supported = false;
                break;
              }
              const std::uint16_t bw = integer_bit_width(call->getType());
              const std::uint32_t tmp_slot = next_slot++;
              Vm2Instruction mul_inst{};
              mul_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kMulF);
              mul_inst.flags = bw;
              mul_inst.dst = tmp_slot;
              mul_inst.src0 = *lhs;
              mul_inst.src1 = *rhs;
              mul_inst.imm = 0;
              mul_inst.aux = 0u;
              push_inst(mul_inst);

              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kAddF);
              vm_inst.flags = bw;
              vm_inst.src0 = tmp_slot;
              vm_inst.src1 = *addend;
              break;
            }
            case llvm::Intrinsic::fabs: {
              if (call->arg_size() != 1u) {
                supported = false;
                break;
              }
              auto src = get_or_emit_slot(call->getArgOperand(0), instructions);
              if (!src.has_value()) {
                supported = false;
                break;
              }
              vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kAbsF);
              vm_inst.flags = integer_bit_width(call->getType());
              vm_inst.src0 = *src;
              vm_inst.src1 = kVm2InvalidSlot;
              break;
            }
            default:
              supported = false;
              break;
          }
        }
      } else if (const auto* select = llvm::dyn_cast<llvm::SelectInst>(&inst)) {
        auto cond = get_or_emit_slot(select->getCondition(), instructions);
        auto true_slot = get_or_emit_slot(select->getTrueValue(), instructions);
        auto false_slot = get_or_emit_slot(select->getFalseValue(), instructions);
        if (!cond.has_value() || !true_slot.has_value() || !false_slot.has_value()) {
          supported = false;
        } else {
          vm_inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kSelect);
          vm_inst.src0 = *cond;
          vm_inst.src1 = *true_slot;
          vm_inst.aux = *false_slot;
        }
      } else {
        supported = false;
      }

      if (!supported) {
        mark_unsupported(&inst, "instruction is not yet supported by VM lowering");
        Vm2Instruction trap{};
        trap.opcode = static_cast<std::uint16_t>(pir::OpCode::kTrap);
        trap.dst = kVm2InvalidSlot;
        trap.src0 = kVm2InvalidSlot;
        trap.src1 = kVm2InvalidSlot;
        push_inst(trap);
      } else {
        push_inst(vm_inst);
      }
    }
  }

  if (instructions.empty()) {
    Vm2Instruction ret{};
    ret.opcode = static_cast<std::uint16_t>(pir::OpCode::kRet);
    ret.dst = kVm2InvalidSlot;
    ret.src0 = kVm2InvalidSlot;
    ret.src1 = kVm2InvalidSlot;
    instructions.push_back(ret);
  }

  std::vector<std::uint8_t>& out = result.bytecode;
  out.reserve(24u + instructions.size() * 32u);
  out.push_back('E');
  out.push_back('V');
  out.push_back('M');
  out.push_back('2');
  append_u16(out, kVm2Version);
  append_u16(out, 0u);
  append_u32(out, next_slot);
  append_u32(out, static_cast<std::uint32_t>(function.arg_size()));
  append_u32(out, block_ids.lookup(&function.getEntryBlock()));
  append_u32(out, static_cast<std::uint32_t>(instructions.size()));
  for (const Vm2Instruction& inst : instructions) {
    append_u16(out, inst.opcode);
    append_u16(out, inst.flags);
    append_u32(out, inst.dst);
    append_u32(out, inst.src0);
    append_u32(out, inst.src1);
    append_i64(out, inst.imm);
    append_u64(out, inst.aux);
  }
  result.vm_call_targets = std::move(vm_call_targets);
  return result;
}

bool inline_local_callees(llvm::Function& function) {
  if (function.isDeclaration() || function.empty()) {
    return false;
  }
  function.removeFnAttr(llvm::Attribute::NoInline);
  function.removeFnAttr(llvm::Attribute::OptimizeNone);

  auto is_directly_recursive = [](const llvm::Function& candidate) -> bool {
    for (const llvm::BasicBlock& block : candidate) {
      for (const llvm::Instruction& instruction : block) {
        const auto* call_base = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call_base == nullptr) {
          continue;
        }
        if (call_base->isInlineAsm() || call_base->isIndirectCall()) {
          continue;
        }
        if (call_base->getCalledFunction() == &candidate) {
          return true;
        }
      }
    }
    return false;
  };

  bool changed = false;
  bool progress = true;
  std::uint32_t budget = 128u;

  while (progress && budget-- > 0u) {
    progress = false;
    llvm::SmallVector<llvm::CallBase*, 32> call_sites;
    for (llvm::BasicBlock& block : function) {
      for (llvm::Instruction& instruction : block) {
        auto* call_base = llvm::dyn_cast<llvm::CallBase>(&instruction);
        if (call_base == nullptr) {
          continue;
        }
        call_sites.push_back(call_base);
      }
    }

    for (llvm::CallBase* call_site : call_sites) {
      if (call_site == nullptr || call_site->getParent() == nullptr) {
        continue;
      }
      if (call_site->isInlineAsm() || call_site->isIndirectCall()) {
        continue;
      }

      llvm::Function* callee = call_site->getCalledFunction();
      if (callee == nullptr || callee->isDeclaration() || callee->isIntrinsic() ||
          callee == &function) {
        continue;
      }
      // Guard against recursive inline explosion (e.g. fib/dfs style helpers).
      if (is_directly_recursive(*callee)) {
        continue;
      }
      callee->removeFnAttr(llvm::Attribute::NoInline);
      callee->removeFnAttr(llvm::Attribute::OptimizeNone);

      llvm::InlineFunctionInfo inline_info;
      llvm::InlineResult inline_result = llvm::InlineFunction(*call_site, inline_info);
      if (inline_result.isSuccess()) {
        progress = true;
        changed = true;
      } else {
        llvm::errs() << "ip_weaver_ir: inline failure in " << function.getName()
                     << " -> " << callee->getName() << ": "
                     << inline_result.getFailureReason() << "\n";
      }
    }
  }

  return changed;
}

bool canonicalize_for_vm_lowering(llvm::Function& function, llvm::FunctionAnalysisManager& fam) {
  if (function.isDeclaration() || function.empty()) {
    return false;
  }

  function.removeFnAttr(llvm::Attribute::NoInline);
  function.removeFnAttr(llvm::Attribute::OptimizeNone);

  llvm::FunctionPassManager fpm;
  fpm.addPass(llvm::SROAPass());
  fpm.addPass(llvm::PromotePass());
  fpm.addPass(llvm::EarlyCSEPass());
  fpm.addPass(llvm::InstCombinePass());
  fpm.addPass(llvm::MemCpyOptPass());
  fpm.addPass(llvm::CorrelatedValuePropagationPass());
  fpm.addPass(llvm::ReassociatePass());
  fpm.addPass(llvm::LowerInvokePass());
  fpm.addPass(llvm::SimplifyCFGPass());
  fpm.addPass(llvm::DCEPass());

  llvm::PreservedAnalyses pa = fpm.run(function, fam);
  return !pa.areAllPreserved();
}

void xor_encrypt_in_place(std::vector<std::uint8_t>& data, std::uint8_t key) {
  for (std::size_t index = 0; index < data.size(); ++index) {
    const std::uint8_t poly = static_cast<std::uint8_t>(index & 0xFFu);
    data[index] ^= static_cast<std::uint8_t>(key ^ poly);
  }
}

[[nodiscard]] llvm::GlobalVariable* create_blob_global(llvm::Module& module,
                                                        llvm::StringRef function_name,
                                                        llvm::ArrayRef<std::uint8_t> blob) {
  llvm::LLVMContext& context = module.getContext();
  llvm::ArrayType* array_type = llvm::ArrayType::get(llvm::Type::getInt8Ty(context), blob.size());

  llvm::SmallVector<llvm::Constant*, 64> items;
  items.reserve(blob.size());
  for (std::uint8_t byte : blob) {
    items.push_back(llvm::ConstantInt::get(llvm::Type::getInt8Ty(context), byte));
  }
  llvm::Constant* initializer = llvm::ConstantArray::get(array_type, items);

  const std::string symbol = (kVmBlobPrefix + function_name).str();
  auto* global = new llvm::GlobalVariable(
      module,
      array_type,
      true,
      llvm::GlobalValue::InternalLinkage,
      initializer,
      symbol);
  global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  global->setAlignment(llvm::Align(1));
  return global;
}

[[nodiscard]] llvm::GlobalVariable* create_vm_call_table_global(
    llvm::Module& module,
    llvm::StringRef function_name,
    llvm::ArrayRef<llvm::Function*> call_targets) {
  if (call_targets.empty()) {
    return nullptr;
  }

  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i8_ptr_type = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  llvm::ArrayType* table_type = llvm::ArrayType::get(i8_ptr_type, call_targets.size());

  llvm::SmallVector<llvm::Constant*, 16> entries;
  entries.reserve(call_targets.size());
  for (llvm::Function* target : call_targets) {
    if (target == nullptr) {
      entries.push_back(llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(i8_ptr_type)));
      continue;
    }
    entries.push_back(llvm::ConstantExpr::getBitCast(target, i8_ptr_type));
  }

  llvm::Constant* initializer = llvm::ConstantArray::get(table_type, entries);
  const std::string symbol = ("__eippf_vmcalltbl." + function_name).str();
  auto* table = new llvm::GlobalVariable(
      module,
      table_type,
      true,
      llvm::GlobalValue::InternalLinkage,
      initializer,
      symbol);
  table->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  table->setDSOLocal(true);
  table->setAlignment(llvm::Align(sizeof(void*)));
  return table;
}

[[nodiscard]] llvm::Function* get_or_insert_run_template_checked(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i8_ptr = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  llvm::Type* i8_ptr_ptr = llvm::PointerType::getUnqual(i8_ptr);
  llvm::Type* i64_type = llvm::Type::getInt64Ty(context);
  llvm::Type* i32_type = llvm::Type::getInt32Ty(context);
  llvm::Type* i64_ptr = llvm::PointerType::getUnqual(i64_type);
  llvm::FunctionType* fn_type = llvm::FunctionType::get(
      i32_type,
      {i8_ptr, i64_type, i64_ptr, i32_type, i64_ptr, i8_ptr_ptr, i32_type},
      false);
  module.getOrInsertFunction(kRunTemplateCheckedSymbol, fn_type);
  return module.getFunction(kRunTemplateCheckedSymbol);
}

[[nodiscard]] DispatchTableInfo create_dispatch_table(
    llvm::Module& module,
    llvm::Function* runtime_entry,
    llvm::ArrayRef<ProtectedFunctionInfo> protected_functions,
    std::uint8_t xor_key) {
  DispatchTableInfo info;
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i8_ptr_type = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  auto* i8_ptr_ptr_type = llvm::cast<llvm::PointerType>(i8_ptr_type);

  info.secret_key = fnv1a64(module.getName()) ^ (static_cast<std::uint64_t>(xor_key) << 56u) ^
                    0xC3A5C85C97CB3127ull;
  if (info.secret_key == 0u) {
    info.secret_key = 0xA5A5A5A55A5A5A5Aull;
  }

  llvm::SmallVector<llvm::Constant*, 64> entries;
  llvm::SmallVector<llvm::Constant*, 64> integrity_entries;
  entries.reserve(protected_functions.size() + 1u);
  integrity_entries.reserve(protected_functions.size() + 1u);

  auto append_entry = [&](llvm::Constant* ptr_constant, llvm::Function* function_or_null) {
    const std::uint32_t index = static_cast<std::uint32_t>(entries.size());
    entries.push_back(ptr_constant);
    if (function_or_null != nullptr) {
      info.function_index[function_or_null] = index;
    }
    integrity_entries.push_back(ptr_constant);
  };

  if (runtime_entry != nullptr) {
    info.runtime_index = static_cast<std::uint32_t>(entries.size());
    append_entry(llvm::ConstantExpr::getBitCast(runtime_entry, i8_ptr_type), runtime_entry);
  }

  for (const ProtectedFunctionInfo& protected_info : protected_functions) {
    llvm::Function* fn = protected_info.function;
    if (fn == nullptr || info.function_index.find(fn) != info.function_index.end()) {
      continue;
    }
    append_entry(llvm::ConstantExpr::getBitCast(fn, i8_ptr_type), fn);
  }

  if (entries.empty()) {
    append_entry(llvm::ConstantPointerNull::get(i8_ptr_ptr_type), nullptr);
  }

  llvm::ArrayType* table_type = llvm::ArrayType::get(i8_ptr_type, entries.size());
  llvm::Constant* table_initializer = llvm::ConstantArray::get(table_type, entries);
  auto* table = new llvm::GlobalVariable(
      module,
      table_type,
      false,
      llvm::GlobalValue::InternalLinkage,
      table_initializer,
      kDispatchTableSymbol);
  table->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  table->setAlignment(llvm::Align(8));

  llvm::ArrayType* integrity_type = llvm::ArrayType::get(i8_ptr_type, integrity_entries.size());
  llvm::Constant* integrity_initializer = llvm::ConstantArray::get(integrity_type, integrity_entries);
  auto* integrity_table = new llvm::GlobalVariable(
      module,
      integrity_type,
      false,
      llvm::GlobalValue::InternalLinkage,
      integrity_initializer,
      kIntegrityTableSymbol);
  integrity_table->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  integrity_table->setAlignment(llvm::Align(8));

  info.table = table;
  info.integrity_table = integrity_table;
  info.entry_count = static_cast<std::uint32_t>(entries.size());
  return info;
}

[[nodiscard]] llvm::Value* load_dispatch_entry(llvm::IRBuilder<>& builder,
                                               llvm::GlobalVariable* dispatch_table,
                                               std::uint32_t index,
                                               llvm::StringRef value_name) {
  auto* table_type = llvm::dyn_cast<llvm::ArrayType>(dispatch_table->getValueType());
  if (table_type == nullptr) {
    return nullptr;
  }
  llvm::Value* slot = builder.CreateInBoundsGEP(
      table_type,
      dispatch_table,
      {builder.getInt64(0u), builder.getInt64(index)},
      (value_name + ".slot").str());
  llvm::Type* i8_ptr_type = llvm::PointerType::getUnqual(builder.getInt8Ty());
  return builder.CreateLoad(i8_ptr_type, slot, value_name);
}

[[nodiscard]] llvm::Value* load_integrity_entry(llvm::IRBuilder<>& builder,
                                                llvm::GlobalVariable* integrity_table,
                                                std::uint32_t index,
                                                llvm::StringRef value_name) {
  auto* table_type = llvm::dyn_cast<llvm::ArrayType>(integrity_table->getValueType());
  if (table_type == nullptr) {
    return nullptr;
  }
  llvm::Value* slot = builder.CreateInBoundsGEP(
      table_type,
      integrity_table,
      {builder.getInt64(0u), builder.getInt64(index)},
      (value_name + ".slot").str());
  llvm::Type* i8_ptr_type = llvm::PointerType::getUnqual(builder.getInt8Ty());
  return builder.CreateLoad(i8_ptr_type, slot, value_name);
}

[[nodiscard]] llvm::Value* compute_pointer_tag(llvm::IRBuilder<>& builder,
                                               llvm::Value* ptr_value,
                                               std::uint64_t secret_key,
                                               std::uint32_t index) {
  llvm::Value* ptr_as_i64 = builder.CreatePtrToInt(ptr_value, builder.getInt64Ty(), "eippf.hb.ptr.i64");
  llvm::Value* mix = builder.getInt64(heartbeat_mix_key(secret_key, index));
  return builder.CreateXor(ptr_as_i64, mix, "eippf.hb.tag");
}

[[nodiscard]] llvm::Value* cast_value_to_i64(llvm::IRBuilder<>& builder, llvm::Value* value) {
  llvm::Type* i64_type = builder.getInt64Ty();
  llvm::Type* value_type = value->getType();

  if (value_type->isIntegerTy()) {
    return builder.CreateIntCast(value, i64_type, false, "eippf.arg.i64");
  }
  if (value_type->isPointerTy()) {
    return builder.CreatePtrToInt(value, i64_type, "eippf.arg.ptr");
  }
  if (value_type->isFloatTy()) {
    llvm::Value* as_i32 = builder.CreateBitCast(value, builder.getInt32Ty(), "eippf.arg.f32.bits");
    return builder.CreateZExt(as_i32, i64_type, "eippf.arg.f32.i64");
  }
  if (value_type->isDoubleTy()) {
    return builder.CreateBitCast(value, i64_type, "eippf.arg.f64.i64");
  }

  return llvm::ConstantInt::get(i64_type, 0u);
}

[[nodiscard]] llvm::Value* cast_i64_to_return_type(llvm::IRBuilder<>& builder,
                                                    llvm::Value* value,
                                                    llvm::Type* target_type) {
  if (target_type->isVoidTy()) {
    return nullptr;
  }
  if (target_type->isIntegerTy()) {
    return builder.CreateIntCast(value, target_type, false, "eippf.ret.int");
  }
  if (target_type->isPointerTy()) {
    return builder.CreateIntToPtr(value, target_type, "eippf.ret.ptr");
  }
  if (target_type->isFloatTy()) {
    llvm::Value* as_i32 = builder.CreateTrunc(value, builder.getInt32Ty(), "eippf.ret.f32.i32");
    return builder.CreateBitCast(as_i32, target_type, "eippf.ret.f32");
  }
  if (target_type->isDoubleTy()) {
    return builder.CreateBitCast(value, target_type, "eippf.ret.f64");
  }
  return llvm::UndefValue::get(target_type);
}

[[nodiscard]] llvm::Constant* silent_mitigation_value_for_type(llvm::Type* type) {
  if (type->isIntegerTy()) {
    return llvm::ConstantInt::get(type, 0u);
  }
  if (type->isFloatingPointTy()) {
    return llvm::ConstantFP::get(type, 0.0);
  }
  if (type->isPointerTy()) {
    return llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(type));
  }
  return llvm::UndefValue::get(type);
}

[[nodiscard]] llvm::Function* create_vm_hostcall_wrapper(llvm::CallInst& call, llvm::Module& module) {
  llvm::Function* callee = call.getCalledFunction();
  if (callee == nullptr || call.isInlineAsm() || call.isIndirectCall()) {
    return nullptr;
  }
  if (!is_supported_scalar_type(call.getType())) {
    return nullptr;
  }
  llvm::SmallVector<unsigned, 8> dynamic_arg_positions;
  for (unsigned i = 0u; i < call.arg_size(); ++i) {
    llvm::Value* arg = call.getArgOperand(i);
    if (!is_supported_scalar_type(arg->getType())) {
      return nullptr;
    }
    if (!llvm::isa<llvm::Constant>(arg)) {
      dynamic_arg_positions.push_back(i);
    }
  }

  llvm::LLVMContext& context = module.getContext();
  llvm::Type* i64_type = llvm::Type::getInt64Ty(context);
  llvm::FunctionType* wrapper_type = llvm::FunctionType::get(i64_type, {i64_type, i64_type}, false);

  static std::uint64_t wrapper_id = 0u;
  const std::string wrapper_name =
      ("__eippf_vmwrap." + callee->getName() + "." + std::to_string(wrapper_id++)).str();
  llvm::Function* wrapper = llvm::Function::Create(
      wrapper_type, llvm::GlobalValue::InternalLinkage, wrapper_name, module);
  wrapper->setDSOLocal(true);
  wrapper->addFnAttr(llvm::Attribute::NoInline);

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", wrapper);
  llvm::IRBuilder<> builder(entry);

  llvm::SmallVector<llvm::Value*, 4> converted_args;
  converted_args.reserve(call.arg_size());
  auto wrap_arg_it = wrapper->arg_begin();
  llvm::Value* packet_ptr_i64 = &*wrap_arg_it++;
  (void)wrap_arg_it;
  llvm::Value* packet_base = builder.CreateIntToPtr(
      packet_ptr_i64, llvm::PointerType::getUnqual(i64_type), "eippf.vmwrap.packet");
  std::size_t dynamic_cursor = 0u;

  for (unsigned i = 0u; i < call.arg_size(); ++i) {
    if (const auto* constant = llvm::dyn_cast<llvm::Constant>(call.getArgOperand(i))) {
      converted_args.push_back(const_cast<llvm::Constant*>(constant));
      continue;
    }

    llvm::Type* target_type = call.getArgOperand(i)->getType();
    llvm::Value* slot_ptr = builder.CreateInBoundsGEP(
        i64_type,
        packet_base,
        {builder.getInt64(static_cast<std::uint64_t>(dynamic_cursor))},
        "eippf.vmwrap.arg.slot");
    llvm::Value* source = builder.CreateLoad(i64_type, slot_ptr, "eippf.vmwrap.arg.i64");
    ++dynamic_cursor;
    llvm::Value* converted = cast_i64_to_return_type(builder, source, target_type);
    if (converted == nullptr) {
      return nullptr;
    }
    converted_args.push_back(converted);
  }

  llvm::CallInst* inner_call =
      builder.CreateCall(callee->getFunctionType(), callee, converted_args, "eippf.vmwrap.call");
  inner_call->setCallingConv(call.getCallingConv());

  if (call.getType()->isVoidTy()) {
    builder.CreateRet(llvm::ConstantInt::get(i64_type, 0u));
  } else {
    llvm::Value* ret = cast_value_to_i64(builder, inner_call);
    builder.CreateRet(ret);
  }

  return wrapper;
}

bool rewrite_calls_to_vm_wrappers(llvm::Function& function, llvm::Module& module) {
  if (function.isDeclaration() || function.empty()) {
    return false;
  }

  llvm::SmallVector<llvm::CallInst*, 32> candidates;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      auto* call = llvm::dyn_cast<llvm::CallInst>(&instruction);
      if (call == nullptr) {
        continue;
      }
      llvm::Function* callee = call->getCalledFunction();
      if (callee == nullptr || call->isInlineAsm() || call->isIndirectCall()) {
        continue;
      }
      if (callee->isIntrinsic()) {
        continue;
      }
      candidates.push_back(call);
    }
  }

  bool changed = false;
  for (llvm::CallInst* call : candidates) {
    if (call == nullptr || call->getParent() == nullptr) {
      continue;
    }
    llvm::Function* wrapper = create_vm_hostcall_wrapper(*call, module);
    if (wrapper == nullptr) {
      continue;
    }

    llvm::IRBuilder<> builder(call);
    llvm::SmallVector<llvm::Value*, 8> dynamic_args;
    for (unsigned i = 0u; i < call->arg_size(); ++i) {
      llvm::Value* arg = call->getArgOperand(i);
      if (llvm::isa<llvm::Constant>(arg)) {
        continue;
      }
      dynamic_args.push_back(cast_value_to_i64(builder, arg));
    }
    llvm::Value* arg0 = llvm::ConstantInt::get(builder.getInt64Ty(), 0u);
    if (!dynamic_args.empty()) {
      llvm::ArrayType* packet_type =
          llvm::ArrayType::get(builder.getInt64Ty(), static_cast<std::uint64_t>(dynamic_args.size()));
      llvm::AllocaInst* packet = builder.CreateAlloca(packet_type, nullptr, "eippf.vmwrap.packet.alloca");
      for (std::size_t idx = 0u; idx < dynamic_args.size(); ++idx) {
        llvm::Value* slot = builder.CreateInBoundsGEP(
            packet_type,
            packet,
            {builder.getInt64(0u), builder.getInt64(static_cast<std::uint64_t>(idx))},
            "eippf.vmwrap.packet.slot");
        builder.CreateStore(dynamic_args[idx], slot);
      }
      llvm::Value* packet_base = builder.CreateInBoundsGEP(
          packet_type, packet, {builder.getInt64(0u), builder.getInt64(0u)}, "eippf.vmwrap.packet.base");
      arg0 = builder.CreatePtrToInt(packet_base, builder.getInt64Ty(), "eippf.vmwrap.packet.i64");
    }
    llvm::Value* arg1 = llvm::ConstantInt::get(
        builder.getInt64Ty(), static_cast<std::uint64_t>(dynamic_args.size()));
    llvm::CallInst* vm_call = builder.CreateCall(
        wrapper->getFunctionType(), wrapper, {arg0, arg1}, "eippf.vmwrap.ret64");
    vm_call->setCallingConv(llvm::CallingConv::C);

    if (!call->getType()->isVoidTy()) {
      llvm::Value* casted = cast_i64_to_return_type(builder, vm_call, call->getType());
      call->replaceAllUsesWith(casted);
    }
    call->eraseFromParent();
    changed = true;
  }

  return changed;
}

bool lower_function_to_vm_stub(ProtectedFunctionInfo& info,
                               llvm::GlobalVariable* dispatch_table,
                               llvm::GlobalVariable* integrity_table,
                               std::uint32_t runtime_dispatch_index,
                               llvm::FunctionType* run_template_type,
                               std::uint64_t dispatch_secret_key) {
  llvm::Function* function = info.function;
  llvm::GlobalVariable* blob = info.encrypted_blob;
  if (function == nullptr || dispatch_table == nullptr ||
      integrity_table == nullptr) {
    return false;
  }
  if (!function->empty()) {
    function->deleteBody();
  }

  llvm::LLVMContext& context = function->getContext();
  llvm::Type* return_type = function->getReturnType();

  if (!info.vm_compatible || blob == nullptr || info.blob_size == 0u || run_template_type == nullptr) {
    llvm::BasicBlock* mitigate_entry = llvm::BasicBlock::Create(context, "entry", function);
    llvm::IRBuilder<> mitigate_builder(mitigate_entry);
    if (return_type->isVoidTy()) {
      mitigate_builder.CreateRetVoid();
    } else {
      mitigate_builder.CreateRet(silent_mitigation_value_for_type(return_type));
    }

    function->removeFnAttr(llvm::Attribute::AlwaysInline);
    function->addFnAttr(llvm::Attribute::NoInline);
    function->addFnAttr(llvm::Attribute::OptimizeNone);
    function->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::None);
    return true;
  }

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", function);
  llvm::BasicBlock* decode_header = llvm::BasicBlock::Create(context, "eippf.vm.decode.header", function);
  llvm::BasicBlock* decode_body = llvm::BasicBlock::Create(context, "eippf.vm.decode.body", function);
  llvm::BasicBlock* decode_exit = llvm::BasicBlock::Create(context, "eippf.vm.decode.exit", function);

  llvm::IRBuilder<> builder(entry);
  llvm::Type* i8_type = builder.getInt8Ty();
  llvm::Type* i8_ptr_type = llvm::PointerType::getUnqual(i8_type);
  llvm::Type* i8_ptr_ptr_type = llvm::PointerType::getUnqual(i8_ptr_type);
  llvm::Type* i64_type = builder.getInt64Ty();
  llvm::Type* i32_type = builder.getInt32Ty();

  auto* blob_type = llvm::dyn_cast<llvm::ArrayType>(blob->getValueType());
  if (blob_type == nullptr) {
    return false;
  }

  llvm::AllocaInst* decoded_blob = builder.CreateAlloca(blob_type, nullptr, "eippf.vm.decoded");
  llvm::AllocaInst* decode_idx = builder.CreateAlloca(i64_type, nullptr, "eippf.vm.idx");
  builder.CreateStore(llvm::ConstantInt::get(i64_type, 0u), decode_idx);
  builder.CreateBr(decode_header);

  llvm::IRBuilder<> header_builder(decode_header);
  llvm::Value* idx = header_builder.CreateLoad(i64_type, decode_idx, "idx");
  llvm::Value* cond =
      header_builder.CreateICmpULT(idx, llvm::ConstantInt::get(i64_type, info.blob_size), "has_next");
  header_builder.CreateCondBr(cond, decode_body, decode_exit);

  llvm::IRBuilder<> body_builder(decode_body);
  llvm::Value* enc_ptr = body_builder.CreateInBoundsGEP(
      blob_type, blob, {body_builder.getInt64(0u), idx}, "enc_ptr");
  llvm::Value* enc_byte = body_builder.CreateLoad(i8_type, enc_ptr, "enc_byte");
  llvm::Value* poly = body_builder.CreateTrunc(idx, i8_type, "poly");
  llvm::Value* key = body_builder.CreateXor(body_builder.getInt8(info.key), poly, "poly_key");
  llvm::Value* dec_byte = body_builder.CreateXor(enc_byte, key, "dec_byte");
  llvm::Value* dec_ptr = body_builder.CreateInBoundsGEP(
      blob_type, decoded_blob, {body_builder.getInt64(0u), idx}, "dec_ptr");
  body_builder.CreateStore(dec_byte, dec_ptr);
  llvm::Value* next_idx = body_builder.CreateAdd(idx, body_builder.getInt64(1u), "next_idx");
  body_builder.CreateStore(next_idx, decode_idx);
  body_builder.CreateBr(decode_header);

  llvm::IRBuilder<> exit_builder(decode_exit);

  const std::size_t arg_count = function->arg_size();
  llvm::ArrayType* arg_array_type = llvm::ArrayType::get(i64_type, arg_count == 0u ? 1u : arg_count);
  llvm::AllocaInst* arg_array = exit_builder.CreateAlloca(arg_array_type, nullptr, "eippf.vm.args");

  std::size_t arg_index = 0u;
  for (llvm::Argument& argument : function->args()) {
    llvm::Value* casted = cast_value_to_i64(exit_builder, &argument);
    llvm::Value* slot = exit_builder.CreateInBoundsGEP(
        arg_array_type, arg_array,
        {exit_builder.getInt64(0u), exit_builder.getInt64(static_cast<std::uint64_t>(arg_index))},
        "eippf.vm.arg.slot");
    exit_builder.CreateStore(casted, slot);
    ++arg_index;
  }

  llvm::Value* decoded_ptr = exit_builder.CreateInBoundsGEP(
      blob_type, decoded_blob, {exit_builder.getInt64(0u), exit_builder.getInt64(0u)}, "eippf.vm.bytecode");
  llvm::Value* args_ptr = exit_builder.CreateInBoundsGEP(
      arg_array_type, arg_array, {exit_builder.getInt64(0u), exit_builder.getInt64(0u)}, "eippf.vm.args.ptr");
  llvm::AllocaInst* vm_result_slot = exit_builder.CreateAlloca(i64_type, nullptr, "eippf.vm.result.slot");
  exit_builder.CreateStore(llvm::ConstantInt::get(i64_type, 0u), vm_result_slot);

  llvm::Value* vm_call_table_ptr =
      llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(i8_ptr_ptr_type));
  if (info.vm_call_table != nullptr) {
    if (auto* table_type = llvm::dyn_cast<llvm::ArrayType>(info.vm_call_table->getValueType())) {
      vm_call_table_ptr = exit_builder.CreateInBoundsGEP(
          table_type,
          info.vm_call_table,
          {exit_builder.getInt64(0u), exit_builder.getInt64(0u)},
          "eippf.vm.calltbl.ptr");
    }
  }

  llvm::Value* runtime_raw =
      load_dispatch_entry(exit_builder, dispatch_table, runtime_dispatch_index, "eippf.vm.runtime.raw");
  if (runtime_raw == nullptr) {
    return false;
  }
  llvm::Value* expected_ptr =
      load_integrity_entry(exit_builder, integrity_table, runtime_dispatch_index, "eippf.vm.runtime.exp");
  if (expected_ptr == nullptr) {
    return false;
  }
  llvm::Value* observed_tag =
      compute_pointer_tag(exit_builder, runtime_raw, dispatch_secret_key, runtime_dispatch_index);
  llvm::Value* expected_tag =
      compute_pointer_tag(exit_builder, expected_ptr, dispatch_secret_key, runtime_dispatch_index);
  llvm::Value* auth_ok = exit_builder.CreateICmpEQ(expected_tag, observed_tag, "eippf.vm.runtime.auth");

  llvm::BasicBlock* runtime_valid =
      llvm::BasicBlock::Create(context, "eippf.vm.runtime.valid", function);
  llvm::BasicBlock* runtime_invalid =
      llvm::BasicBlock::Create(context, "eippf.vm.runtime.invalid", function);
  llvm::BasicBlock* runtime_vm_ok =
      llvm::BasicBlock::Create(context, "eippf.vm.runtime.ok", function);
  llvm::BasicBlock* runtime_vm_fail =
      llvm::BasicBlock::Create(context, "eippf.vm.runtime.fail", function);

  exit_builder.CreateCondBr(auth_ok, runtime_valid, runtime_invalid);

  llvm::IRBuilder<> valid_builder(runtime_valid);
  llvm::Value* runtime_fn = valid_builder.CreateBitCast(
      runtime_raw, llvm::PointerType::getUnqual(run_template_type), "eippf.vm.runtime.fn");
  llvm::CallInst* runtime_ok = valid_builder.CreateCall(
      run_template_type,
      runtime_fn,
      {decoded_ptr,
       llvm::ConstantInt::get(i64_type, info.blob_size),
       args_ptr,
       llvm::ConstantInt::get(i32_type, static_cast<std::uint32_t>(arg_count)),
       vm_result_slot,
       vm_call_table_ptr,
       llvm::ConstantInt::get(i32_type, info.vm_call_count)},
      "eippf.vm.ok");
  runtime_ok->setCallingConv(llvm::CallingConv::C);
  llvm::Value* vm_ok =
      valid_builder.CreateICmpNE(runtime_ok, llvm::ConstantInt::get(i32_type, 0u), "eippf.vm.ok.flag");
  valid_builder.CreateCondBr(vm_ok, runtime_vm_ok, runtime_vm_fail);

  llvm::IRBuilder<> invalid_builder(runtime_invalid);
  invalid_builder.CreateBr(runtime_vm_fail);

  if (return_type->isVoidTy()) {
    llvm::IRBuilder<> vm_ok_builder(runtime_vm_ok);
    vm_ok_builder.CreateRetVoid();

    llvm::IRBuilder<> vm_fail_builder(runtime_vm_fail);
    vm_fail_builder.CreateRetVoid();
  } else {
    llvm::IRBuilder<> vm_ok_builder(runtime_vm_ok);
    llvm::Value* vm_result = vm_ok_builder.CreateLoad(i64_type, vm_result_slot, "eippf.vm.result");
    llvm::Value* casted_ret = cast_i64_to_return_type(vm_ok_builder, vm_result, return_type);
    vm_ok_builder.CreateRet(casted_ret);

    llvm::IRBuilder<> vm_fail_builder(runtime_vm_fail);
    vm_fail_builder.CreateRet(silent_mitigation_value_for_type(return_type));
  }

  function->removeFnAttr(llvm::Attribute::AlwaysInline);
  function->addFnAttr(llvm::Attribute::NoInline);
  function->addFnAttr(llvm::Attribute::OptimizeNone);
  function->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::None);

  return true;
}

bool rewrite_call_to_dispatch_table(llvm::CallInst* call,
                                    const DispatchTableInfo& dispatch,
                                    std::uint32_t table_index) {
  if (call == nullptr || dispatch.table == nullptr || dispatch.integrity_table == nullptr) {
    return false;
  }
  if (call->isInlineAsm() || call->isMustTailCall()) {
    return false;
  }
  if (call->getFunctionType()->isVarArg()) {
    return false;
  }

  llvm::IRBuilder<> builder(call);
  llvm::Value* raw_target = load_dispatch_entry(builder, dispatch.table, table_index, "eippf.disp.raw");
  if (raw_target == nullptr) {
    return false;
  }

  llvm::Value* expected_ptr =
      load_integrity_entry(builder, dispatch.integrity_table, table_index, "eippf.disp.exp");
  if (expected_ptr == nullptr) {
    return false;
  }
  llvm::Value* observed_tag =
      compute_pointer_tag(builder, raw_target, dispatch.secret_key, table_index);
  llvm::Value* expected_tag =
      compute_pointer_tag(builder, expected_ptr, dispatch.secret_key, table_index);

  llvm::BasicBlock* original_block = call->getParent();
  llvm::Function* parent = original_block != nullptr ? original_block->getParent() : nullptr;
  if (original_block == nullptr || parent == nullptr) {
    return false;
  }

  llvm::BasicBlock* continuation = original_block->splitBasicBlock(call, "eippf.hb.cont");
  llvm::Instruction* old_term = original_block->getTerminator();
  if (old_term == nullptr) {
    return false;
  }
  old_term->eraseFromParent();

  llvm::LLVMContext& context = parent->getContext();
  llvm::BasicBlock* valid_block = llvm::BasicBlock::Create(context, "eippf.hb.valid", parent, continuation);
  llvm::BasicBlock* invalid_block = llvm::BasicBlock::Create(context, "eippf.hb.invalid", parent, continuation);

  llvm::IRBuilder<> guard_builder(original_block);
  llvm::Value* auth_ok = guard_builder.CreateICmpEQ(expected_tag, observed_tag, "eippf.hb.ok");
  guard_builder.CreateCondBr(auth_ok, valid_block, invalid_block);

  llvm::FunctionType* function_type = call->getFunctionType();
  llvm::IRBuilder<> valid_builder(valid_block);
  llvm::Value* target = valid_builder.CreateBitCast(
      raw_target, llvm::PointerType::getUnqual(function_type), "eippf.disp.fn");
  llvm::SmallVector<llvm::Value*, 8> args;
  args.reserve(call->arg_size());
  for (llvm::Use& arg : call->args()) {
    args.push_back(arg.get());
  }
  llvm::CallInst* indirect_call = valid_builder.CreateCall(
      function_type, target, args, call->getType()->isVoidTy() ? "" : "eippf.dispatch.result");
  indirect_call->setCallingConv(call->getCallingConv());
  indirect_call->setTailCallKind(call->getTailCallKind());
  indirect_call->setAttributes(call->getAttributes());
  valid_builder.CreateBr(continuation);

  llvm::IRBuilder<> invalid_builder(invalid_block);
  llvm::Value* invalid_value = nullptr;
  if (!call->getType()->isVoidTy()) {
    invalid_value = silent_mitigation_value_for_type(call->getType());
  }
  invalid_builder.CreateBr(continuation);

  if (!call->getType()->isVoidTy()) {
    llvm::IRBuilder<> cont_builder(&*continuation->begin());
    llvm::PHINode* phi = cont_builder.CreatePHI(call->getType(), 2u, "eippf.hb.phi");
    phi->addIncoming(indirect_call, valid_block);
    phi->addIncoming(invalid_value, invalid_block);
    call->replaceAllUsesWith(phi);
  }

  call->eraseFromParent();
  return true;
}

[[nodiscard]] bool is_heartbeat_candidate_instruction(const llvm::Instruction& inst) {
  if (llvm::isa<llvm::PHINode>(inst) || inst.isTerminator()) {
    return false;
  }
  if (llvm::isa<llvm::BinaryOperator>(inst) || llvm::isa<llvm::ICmpInst>(inst) ||
      llvm::isa<llvm::FCmpInst>(inst)) {
    return true;
  }
  if (llvm::isa<llvm::CallBase>(inst)) {
    return true;
  }
  const llvm::StringRef block_name = inst.getParent() != nullptr ? inst.getParent()->getName() : "";
  return block_name.contains("loop");
}

bool inject_inline_heartbeat_guard(llvm::Instruction* insert_before,
                                   const DispatchTableInfo& dispatch,
                                   std::uint32_t table_index) {
  if (insert_before == nullptr || dispatch.table == nullptr || dispatch.integrity_table == nullptr ||
      table_index >= dispatch.entry_count) {
    return false;
  }

  llvm::BasicBlock* block = insert_before->getParent();
  llvm::Function* function = block != nullptr ? block->getParent() : nullptr;
  if (block == nullptr || function == nullptr || function->isDeclaration() || block->isEHPad()) {
    return false;
  }

  llvm::BasicBlock* continuation = block->splitBasicBlock(insert_before, "eippf.hb.poll.cont");
  llvm::Instruction* old_term = block->getTerminator();
  if (old_term == nullptr) {
    return false;
  }
  old_term->eraseFromParent();

  llvm::BasicBlock* fail_block = llvm::BasicBlock::Create(
      function->getContext(), "eippf.hb.poll.fail", function, continuation);

  llvm::IRBuilder<> guard_builder(block);
  llvm::Value* raw_target =
      load_dispatch_entry(guard_builder, dispatch.table, table_index, "eippf.hb.poll.raw");
  llvm::Value* expected_ptr =
      load_integrity_entry(guard_builder, dispatch.integrity_table, table_index, "eippf.hb.poll.exp");
  if (raw_target == nullptr || expected_ptr == nullptr) {
    return false;
  }
  llvm::Value* observed_tag =
      compute_pointer_tag(guard_builder, raw_target, dispatch.secret_key, table_index);
  llvm::Value* expected_tag =
      compute_pointer_tag(guard_builder, expected_ptr, dispatch.secret_key, table_index);
  llvm::Value* auth_ok =
      guard_builder.CreateICmpEQ(expected_tag, observed_tag, "eippf.hb.poll.ok");
  guard_builder.CreateCondBr(auth_ok, continuation, fail_block);

  llvm::IRBuilder<> fail_builder(fail_block);
  if (function->getReturnType()->isVoidTy()) {
    fail_builder.CreateRetVoid();
  } else {
    fail_builder.CreateRet(silent_mitigation_value_for_type(function->getReturnType()));
  }
  return true;
}

bool inject_distributed_heartbeats(llvm::Function& function,
                                   const DispatchTableInfo& dispatch,
                                   std::uint64_t seed) {
  if (function.isDeclaration() || function.empty() || dispatch.entry_count == 0u) {
    return false;
  }

  llvm::SmallVector<llvm::Instruction*, 128> candidates;
  for (llvm::BasicBlock& block : function) {
    if (block.isEHPad()) {
      continue;
    }
    for (llvm::Instruction& instruction : block) {
      if (is_heartbeat_candidate_instruction(instruction)) {
        candidates.push_back(&instruction);
      }
    }
  }
  if (candidates.empty()) {
    return false;
  }

  llvm::SmallVector<llvm::Instruction*, 64> selected;
  const std::uint64_t fn_seed = seed ^ fnv1a64(function.getName());
  for (std::size_t i = 0; i < candidates.size(); ++i) {
    const std::uint64_t mix =
        fn_seed ^ (0xD6E8FEB86659FD93ull * static_cast<std::uint64_t>(i + 1u));
    const bool should_inject = (i == 0u) || ((mix % 5u) == 0u);
    if (!should_inject) {
      continue;
    }
    selected.push_back(candidates[i]);
  }

  bool changed = false;
  std::uint64_t ordinal = 1u;
  for (auto it = selected.rbegin(); it != selected.rend(); ++it) {
    llvm::Instruction* target = *it;
    if (target == nullptr || target->getParent() == nullptr) {
      ++ordinal;
      continue;
    }
    const std::uint64_t mix = fn_seed ^ (0x9E3779B97F4A7C15ull * ordinal);
    const std::uint32_t index = static_cast<std::uint32_t>(mix % dispatch.entry_count);
    changed = inject_inline_heartbeat_guard(target, dispatch, index) || changed;
    ++ordinal;
  }

  return changed;
}

[[nodiscard]] bool is_encryptable_string_global(const llvm::GlobalVariable& global) {
  if (global.isDeclaration() || !global.hasInitializer()) {
    return false;
  }
  if (global.getName().startswith("llvm.")) {
    return false;
  }
  if (global.getName().startswith(kVmBlobPrefix)) {
    return false;
  }
  if (global.hasSection() && global.getSection() == "llvm.metadata") {
    return false;
  }

  const auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer());
  return data != nullptr && data->isString();
}

[[nodiscard]] llvm::GlobalVariable* create_string_flag(llvm::Module& module,
                                                        llvm::StringRef string_name) {
  const std::string flag_name = (kStringDecFlagPrefix + string_name).str();
  if (llvm::GlobalVariable* existing = module.getNamedGlobal(flag_name)) {
    return existing;
  }

  llvm::Type* i1_type = llvm::Type::getInt1Ty(module.getContext());
  auto* flag = new llvm::GlobalVariable(
      module,
      i1_type,
      false,
      llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::getFalse(module.getContext()),
      flag_name);
  flag->setAlignment(llvm::Align(1));
  return flag;
}

[[nodiscard]] std::vector<EncryptedStringInfo> encrypt_module_strings(llvm::Module& module,
                                                                       std::uint8_t base_key) {
  std::vector<EncryptedStringInfo> encrypted;

  for (llvm::GlobalVariable& global : module.globals()) {
    if (!is_encryptable_string_global(global)) {
      continue;
    }

    auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer());
    if (data == nullptr) {
      continue;
    }

    const llvm::StringRef raw = data->getAsString();
    if (raw.empty()) {
      continue;
    }

    std::uint8_t key = derive_poly_key(global.getName(), base_key);
    std::string transformed;
    transformed.resize(raw.size());
    for (std::size_t index = 0; index < raw.size(); ++index) {
      const std::uint8_t poly = static_cast<std::uint8_t>(index & 0xFFu);
      transformed[index] = static_cast<char>(
          static_cast<std::uint8_t>(raw[index]) ^ static_cast<std::uint8_t>(key ^ poly));
    }

    llvm::Constant* initializer =
        llvm::ConstantDataArray::getString(module.getContext(), transformed, false);
    if (initializer->getType() != global.getValueType()) {
      continue;
    }

    global.setInitializer(initializer);
    global.setConstant(false);

    EncryptedStringInfo info{};
    info.global = &global;
    info.size = static_cast<std::uint64_t>(raw.size());
    info.key = key;
    info.decrypt_flag = create_string_flag(module, global.getName());
    encrypted.push_back(info);
  }

  return encrypted;
}

void collect_instruction_users(llvm::Value* value,
                               llvm::SmallPtrSetImpl<llvm::Value*>& visited,
                               llvm::SmallVectorImpl<llvm::Instruction*>& out) {
  if (value == nullptr || !visited.insert(value).second) {
    return;
  }

  for (llvm::User* user : value->users()) {
    if (auto* instruction = llvm::dyn_cast<llvm::Instruction>(user)) {
      out.push_back(instruction);
      continue;
    }

    if (auto* next = llvm::dyn_cast<llvm::Value>(user)) {
      collect_instruction_users(next, visited, out);
    }
  }
}

void inject_inline_string_decrypt_before_use(const EncryptedStringInfo& info,
                                             llvm::Instruction* use_instruction) {
  if (info.global == nullptr || info.decrypt_flag == nullptr || use_instruction == nullptr) {
    return;
  }

  llvm::BasicBlock* use_block = use_instruction->getParent();
  llvm::Function* function = use_block != nullptr ? use_block->getParent() : nullptr;
  if (use_block == nullptr || function == nullptr || function->isDeclaration() || use_block->isEHPad()) {
    return;
  }

  auto* array_type = llvm::dyn_cast<llvm::ArrayType>(info.global->getValueType());
  if (array_type == nullptr) {
    return;
  }

  llvm::IRBuilder<> guard_builder(use_instruction);
  llvm::LoadInst* flag = guard_builder.CreateLoad(guard_builder.getInt1Ty(), info.decrypt_flag, "eippf.str.flag");
  llvm::Value* should_decrypt = guard_builder.CreateNot(flag, "eippf.str.should_decrypt");

  llvm::Instruction* then_terminator = llvm::SplitBlockAndInsertIfThen(
      should_decrypt,
      use_instruction,
      false);

  llvm::IRBuilder<> decrypt_builder(then_terminator);
  llvm::Type* i8_type = decrypt_builder.getInt8Ty();

  for (std::uint64_t index = 0u; index < info.size; ++index) {
    llvm::Value* ptr = decrypt_builder.CreateInBoundsGEP(
        array_type,
        info.global,
        {decrypt_builder.getInt64(0u), decrypt_builder.getInt64(index)},
        "eippf.str.byte.ptr");
    llvm::Value* loaded = decrypt_builder.CreateLoad(i8_type, ptr, "eippf.str.byte");
    const std::uint8_t poly = static_cast<std::uint8_t>(index & 0xFFu);
    llvm::Value* key = decrypt_builder.getInt8(static_cast<std::uint8_t>(info.key ^ poly));
    llvm::Value* plain = decrypt_builder.CreateXor(loaded, key, "eippf.str.plain");
    decrypt_builder.CreateStore(plain, ptr);
  }

  decrypt_builder.CreateStore(decrypt_builder.getTrue(), info.decrypt_flag);
}

void inline_decrypt_strings_at_use_sites(llvm::Module& /*module*/,
                                         llvm::ArrayRef<EncryptedStringInfo> encrypted_strings) {
  for (const EncryptedStringInfo& info : encrypted_strings) {
    if (info.global == nullptr) {
      continue;
    }

    llvm::SmallVector<llvm::Instruction*, 64> users;
    llvm::SmallPtrSet<llvm::Value*, 32> visited;
    collect_instruction_users(info.global, visited, users);

    llvm::SmallPtrSet<llvm::Instruction*, 32> unique;
    llvm::SmallVector<llvm::Instruction*, 64> filtered;
    for (llvm::Instruction* inst : users) {
      if (inst == nullptr || llvm::isa<llvm::PHINode>(inst)) {
        continue;
      }
      if (!unique.insert(inst).second) {
        continue;
      }
      filtered.push_back(inst);
    }

    std::sort(filtered.begin(), filtered.end(),
              [](const llvm::Instruction* lhs, const llvm::Instruction* rhs) {
                if (lhs->getParent() != rhs->getParent()) {
                  return lhs->getParent() < rhs->getParent();
                }
                return lhs->comesBefore(rhs);
              });

    for (llvm::Instruction* use_inst : filtered) {
      inject_inline_string_decrypt_before_use(info, use_inst);
    }
  }
}

class UltimateIpWeaverPass final : public llvm::PassInfoMixin<UltimateIpWeaverPass> {
 public:
  explicit UltimateIpWeaverPass(std::string protect_prefix,
                                std::uint8_t xor_key,
                                bool protect_all_functions,
                                std::string rust_crate_name)
      : protect_prefix_(std::move(protect_prefix)),
        xor_key_(xor_key),
        protect_all_functions_(protect_all_functions),
        rust_crate_name_(std::move(rust_crate_name)) {}

  llvm::PreservedAnalyses run(llvm::Module& module,
                              llvm::ModuleAnalysisManager& analysis_manager) {
    llvm::FunctionAnalysisManager& fam =
        analysis_manager.getResult<llvm::FunctionAnalysisManagerModuleProxy>(module).getManager();

    llvm::SmallPtrSet<llvm::Function*, 32> annotated;
    collect_annotated_functions(module, annotated);

    llvm::Function* run_template_checked = get_or_insert_run_template_checked(module);
    if (run_template_checked == nullptr) {
      return llvm::PreservedAnalyses::all();
    }

    llvm::SmallVector<ProtectedFunctionInfo, 32> protected_functions;
    llvm::SmallVector<std::string, 16> unsupported_functions;
    for (llvm::Function& function : module) {
      if (!should_protect_function(
              function, annotated, protect_prefix_, protect_all_functions_, rust_crate_name_)) {
        continue;
      }

      (void)canonicalize_for_vm_lowering(function, fam);
      (void)inline_local_callees(function);
      (void)canonicalize_for_vm_lowering(function, fam);
      (void)rewrite_calls_to_vm_wrappers(function, module);
      (void)canonicalize_for_vm_lowering(function, fam);

      VmBytecodeBuildResult bytecode_result = build_vm_bytecode(function);
      if (!bytecode_result.fully_supported) {
        std::string issue = function.getName().str();
        if (!bytecode_result.first_error.empty()) {
          issue.append(" :: ");
          issue.append(bytecode_result.first_error);
        }
        for (llvm::BasicBlock& block : function) {
          for (llvm::Instruction& instruction : block) {
            auto* call = llvm::dyn_cast<llvm::CallBase>(&instruction);
            if (call == nullptr) {
              continue;
            }
            llvm::Function* callee = call->getCalledFunction();
            issue.append(" | call=");
            issue.append(callee != nullptr ? callee->getName().str() : std::string("<indirect>"));
          }
        }
        unsupported_functions.push_back(std::move(issue));
        continue;
      }
      std::vector<std::uint8_t>& bytecode = bytecode_result.bytecode;
      std::uint8_t key = derive_poly_key(function.getName(), xor_key_);
      xor_encrypt_in_place(bytecode, key);

      llvm::GlobalVariable* blob = create_blob_global(module, function.getName(), bytecode);
      if (blob == nullptr) {
        continue;
      }

      ProtectedFunctionInfo info{};
      info.function = &function;
      info.encrypted_blob = blob;
      info.vm_call_table =
          create_vm_call_table_global(module, function.getName(), bytecode_result.vm_call_targets);
      info.blob_size = static_cast<std::uint64_t>(bytecode.size());
      info.vm_call_count = static_cast<std::uint32_t>(bytecode_result.vm_call_targets.size());
      info.key = key;
      info.vm_compatible = bytecode_result.fully_supported;
      protected_functions.push_back(info);
    }

    if (!unsupported_functions.empty()) {
      mark_strict_vm_failure(module, unsupported_functions);
      return llvm::PreservedAnalyses::none();
    }

    bool changed = false;
    DispatchTableInfo dispatch_table =
        create_dispatch_table(module, run_template_checked, protected_functions, xor_key_);
    llvm::FunctionType* run_template_type = run_template_checked->getFunctionType();
    llvm::SmallPtrSet<llvm::Function*, 32> protected_set;

    for (ProtectedFunctionInfo& info : protected_functions) {
      if (!lower_function_to_vm_stub(info,
                                     dispatch_table.table,
                                     dispatch_table.integrity_table,
                                     dispatch_table.runtime_index,
                                     run_template_type,
                                     dispatch_table.secret_key)) {
        continue;
      }
      changed = true;
      protected_set.insert(info.function);
    }

    if (!protected_set.empty() && dispatch_table.table != nullptr) {
      llvm::SmallVector<llvm::CallInst*, 128> call_sites;
      for (llvm::Function& function : module) {
        if (function.isDeclaration()) {
          continue;
        }
        for (llvm::BasicBlock& block : function) {
          for (llvm::Instruction& instruction : block) {
            auto* call = llvm::dyn_cast<llvm::CallInst>(&instruction);
            if (call == nullptr) {
              continue;
            }
            llvm::Function* called = call->getCalledFunction();
            if (called == nullptr) {
              continue;
            }
            if (!protected_set.contains(called)) {
              continue;
            }
            call_sites.push_back(call);
          }
        }
      }

      for (llvm::CallInst* call_site : call_sites) {
        llvm::Function* direct_callee = call_site->getCalledFunction();
        if (direct_callee == nullptr || !protected_set.contains(direct_callee)) {
          continue;
        }
        auto index_it = dispatch_table.function_index.find(direct_callee);
        if (index_it == dispatch_table.function_index.end()) {
          continue;
        }
        changed = rewrite_call_to_dispatch_table(
                      call_site, dispatch_table, index_it->second) ||
                  changed;
      }

      for (ProtectedFunctionInfo& info : protected_functions) {
        if (info.function == nullptr || !protected_set.contains(info.function)) {
          continue;
        }
        changed = inject_distributed_heartbeats(
                      *info.function, dispatch_table, fnv1a64(info.function->getName())) ||
                  changed;
      }

      for (ProtectedFunctionInfo& info : protected_functions) {
        if (info.function == nullptr || !protected_set.contains(info.function)) {
          continue;
        }
        if (info.function->hasLocalLinkage()) {
          info.function->setLinkage(llvm::GlobalValue::InternalLinkage);
          info.function->setDSOLocal(true);
          info.function->setName("");
        }
      }
    }

    const std::vector<EncryptedStringInfo> encrypted_strings =
        encrypt_module_strings(module, xor_key_);
    if (!encrypted_strings.empty()) {
      inline_decrypt_strings_at_use_sites(module, encrypted_strings);
      changed = true;
    }

    for (ProtectedFunctionInfo& info : protected_functions) {
      if (info.encrypted_blob != nullptr) {
        info.encrypted_blob->setName("");
      }
      if (info.vm_call_table != nullptr) {
        info.vm_call_table->setName("");
      }
    }

    return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
  }

 private:
  std::string protect_prefix_;
  std::uint8_t xor_key_ = 0x5Au;
  bool protect_all_functions_ = false;
  std::string rust_crate_name_;
};

}  // namespace

int main(int argc, const char** argv) {
  llvm::InitLLVM init_llvm(argc, argv);
  llvm::cl::ParseCommandLineOptions(
      argc, argv, "ip_weaver_ir: Ultimate IR weaver (VM fusion + CFI + inline decrypt)\n");

  llvm::LLVMContext context;
  std::unique_ptr<llvm::Module> module;

  llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffer_or =
      llvm::MemoryBuffer::getFile(kInputPath);
  if (!buffer_or) {
    llvm::errs() << "ip_weaver_ir: failed to open input file '" << kInputPath
                 << "': " << buffer_or.getError().message() << "\n";
    return 1;
  }

  llvm::Expected<std::unique_ptr<llvm::Module>> module_or_error =
      llvm::parseBitcodeFile(buffer_or.get()->getMemBufferRef(), context);
  if (module_or_error) {
    module = std::move(module_or_error.get());
  } else {
    llvm::SMDiagnostic diagnostic;
    module = llvm::parseIRFile(kInputPath, diagnostic, context);
    if (!module) {
      llvm::errs() << "ip_weaver_ir: parse failed for input '" << kInputPath << "'\n";
      llvm::errs() << llvm::toString(module_or_error.takeError()) << "\n";
      diagnostic.print("ip_weaver_ir", llvm::errs());
      return 1;
    }
  }

  llvm::PassBuilder pass_builder;
  llvm::LoopAnalysisManager loop_analysis_manager;
  llvm::FunctionAnalysisManager function_analysis_manager;
  llvm::CGSCCAnalysisManager cgscc_analysis_manager;
  llvm::ModuleAnalysisManager module_analysis_manager;
  pass_builder.registerLoopAnalyses(loop_analysis_manager);
  pass_builder.registerFunctionAnalyses(function_analysis_manager);
  pass_builder.registerCGSCCAnalyses(cgscc_analysis_manager);
  pass_builder.registerModuleAnalyses(module_analysis_manager);
  pass_builder.crossRegisterProxies(loop_analysis_manager,
                                    function_analysis_manager,
                                    cgscc_analysis_manager,
                                    module_analysis_manager);

  llvm::ModulePassManager module_pass_manager;
  module_pass_manager.addPass(
      UltimateIpWeaverPass(
          kProtectPrefix, kDefaultXorKey, kProtectAllFunctions, kRustCrateName));
  module_pass_manager.run(*module, module_analysis_manager);

  if (llvm::NamedMDNode* unsupported = module->getNamedMetadata("eippf.vm.unsupported")) {
    if (unsupported->getNumOperands() > 0u) {
      llvm::errs() << "ip_weaver_ir: unsupported IR for strict VM-only mode in functions:\n";
      for (unsigned i = 0u; i < unsupported->getNumOperands(); ++i) {
        llvm::MDNode* node = unsupported->getOperand(i);
        if (node == nullptr || node->getNumOperands() == 0u) {
          continue;
        }
        auto* name = llvm::dyn_cast<llvm::MDString>(node->getOperand(0));
        if (name == nullptr) {
          continue;
        }
        llvm::errs() << "  - " << name->getString() << "\n";
      }
      return 2;
    }
  }

  std::error_code error_code;
  llvm::raw_fd_ostream output_stream(kOutputPath, error_code, llvm::sys::fs::OF_None);
  if (error_code) {
    llvm::errs() << "ip_weaver_ir: failed to open output file '" << kOutputPath
                 << "': " << error_code.message() << "\n";
    return 1;
  }

  llvm::WriteBitcodeToFile(*module, output_stream);
  output_stream.flush();
  return 0;
}

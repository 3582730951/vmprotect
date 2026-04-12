#include "passes/MBAObfuscationPass.hpp"

#include <cstddef>
#include <concepts>
#include <cstdint>
#include <random>

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Casting.h"

namespace {

constexpr llvm::StringLiteral kCriticalAnnotation("drm_critical_ip");
constexpr llvm::StringLiteral kRouteAttribute("eippf.route");
constexpr llvm::StringLiteral kAppliedMarkerName("__eippf_mba_obfuscation_applied");
constexpr std::uint64_t kFnv1aOffset = 1469598103934665603ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;
constexpr std::uint32_t kTransformProbabilityPercent = 20u;

std::uint64_t fnv1a_append(std::uint64_t seed, llvm::StringRef text) {
  std::uint64_t hash = seed;
  for (const char character : text) {
    hash ^= static_cast<std::uint8_t>(character);
    hash *= kFnv1aPrime;
  }
  return hash;
}

std::uint64_t derive_function_seed(llvm::StringRef function_name) {
  return fnv1a_append(kFnv1aOffset, function_name);
}

bool roll_probability(std::mt19937_64& rng, std::uint32_t probability_percent) {
  if (probability_percent == 0u) {
    return false;
  }
  if (probability_percent >= 100u) {
    return true;
  }

  std::uniform_int_distribution<std::uint32_t> distribution(0u, 99u);
  return distribution(rng) < probability_percent;
}

std::size_t roll_index(std::mt19937_64& rng, std::size_t upper_bound_exclusive) {
  std::uniform_int_distribution<std::size_t> distribution(
      std::size_t{0}, upper_bound_exclusive - std::size_t{1});
  return distribution(rng);
}

llvm::StringRef extract_annotation_text(llvm::Constant* annotation_operand) {
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

llvm::SmallPtrSet<llvm::Function*, 32> collect_critical_functions(llvm::Module& module) {
  llvm::SmallPtrSet<llvm::Function*, 32> critical_functions;

  llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr || !annotations->hasInitializer()) {
    return critical_functions;
  }

  auto* annotation_array = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (annotation_array == nullptr) {
    return critical_functions;
  }

  for (llvm::Value* entry_value : annotation_array->operands()) {
    auto* entry_struct = llvm::dyn_cast<llvm::ConstantStruct>(entry_value);
    if (entry_struct == nullptr || entry_struct->getNumOperands() < 2u) {
      continue;
    }

    llvm::Value* fn_value = entry_struct->getOperand(0)->stripPointerCasts();
    auto* function = llvm::dyn_cast<llvm::Function>(fn_value);
    if (function == nullptr) {
      continue;
    }

    auto* annotation_operand = llvm::dyn_cast<llvm::Constant>(entry_struct->getOperand(1));
    if (annotation_operand == nullptr) {
      continue;
    }

    if (extract_annotation_text(annotation_operand) == kCriticalAnnotation) {
      critical_functions.insert(function);
    }
  }

  return critical_functions;
}

bool is_supported_mba_opcode(unsigned opcode) {
  switch (opcode) {
    case llvm::Instruction::Add:
    case llvm::Instruction::Sub:
    case llvm::Instruction::And:
    case llvm::Instruction::Or:
    case llvm::Instruction::Xor:
      return true;
    default:
      return false;
  }
}

bool has_wrap_sensitive_semantics(const llvm::BinaryOperator& operation) {
  if (operation.getOpcode() != llvm::Instruction::Add &&
      operation.getOpcode() != llvm::Instruction::Sub) {
    return false;
  }
  return operation.hasNoSignedWrap() || operation.hasNoUnsignedWrap();
}

template <typename T>
concept HasPoisonGeneratingFlags = requires(const T& value) {
  { value.hasPoisonGeneratingFlags() } -> std::convertible_to<bool>;
};

bool has_disjoint_or_semantics(const llvm::BinaryOperator& operation) {
  if (operation.getOpcode() != llvm::Instruction::Or) {
    return false;
  }

  if constexpr (HasPoisonGeneratingFlags<llvm::BinaryOperator>) {
    return operation.hasPoisonGeneratingFlags();
  }
  return false;
}

bool is_supported_integer_type(llvm::Type* type) {
  if (type == nullptr) {
    return false;
  }
  if (type->isIntegerTy()) {
    return true;
  }

  auto* vector_type = llvm::dyn_cast<llvm::VectorType>(type);
  if (vector_type == nullptr) {
    return false;
  }
  return llvm::isa<llvm::IntegerType>(vector_type->getElementType());
}

llvm::Constant* create_integer_constant_one(llvm::Type* type) {
  if (auto* integer_type = llvm::dyn_cast<llvm::IntegerType>(type)) {
    return llvm::ConstantInt::get(integer_type, 1u, false);
  }

  auto* vector_type = llvm::dyn_cast<llvm::VectorType>(type);
  if (vector_type == nullptr) {
    return nullptr;
  }
  auto* element_type = llvm::dyn_cast<llvm::IntegerType>(vector_type->getElementType());
  if (element_type == nullptr) {
    return nullptr;
  }

  llvm::Constant* one_element = llvm::ConstantInt::get(element_type, 1u, false);
  return llvm::ConstantVector::getSplat(vector_type->getElementCount(), one_element);
}

llvm::Value* create_mba_add(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                            std::size_t template_index) {
  if (template_index == 0u) {
    llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "eippf.mba.add.xor");
    llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "eippf.mba.add.and");
    llvm::Value* carry_part = builder.CreateAdd(and_part, and_part, "eippf.mba.add.carry2");
    return builder.CreateAdd(xor_part, carry_part, "eippf.mba.add.final");
  }

  llvm::Value* or_part = builder.CreateOr(lhs, rhs, "eippf.mba.add.or");
  llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "eippf.mba.add.and");
  return builder.CreateAdd(or_part, and_part, "eippf.mba.add.final");
}

llvm::Value* create_mba_sub(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                            std::size_t template_index) {
  llvm::Type* op_type = lhs->getType();

  if (template_index == 0u) {
    llvm::Value* not_rhs = builder.CreateNot(rhs, "eippf.mba.sub.not_rhs");
    llvm::Constant* one = create_integer_constant_one(op_type);
    if (one == nullptr) {
      return nullptr;
    }
    llvm::Value* neg_rhs = builder.CreateAdd(not_rhs, one, "eippf.mba.sub.neg_rhs");
    return builder.CreateAdd(lhs, neg_rhs, "eippf.mba.sub.final");
  }

  llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "eippf.mba.sub.xor");
  llvm::Value* borrow_seed = builder.CreateAnd(builder.CreateNot(lhs, "eippf.mba.sub.not_lhs"), rhs,
                                               "eippf.mba.sub.borrow");
  llvm::Value* borrow_twice = builder.CreateAdd(borrow_seed, borrow_seed, "eippf.mba.sub.borrow2");
  return builder.CreateSub(xor_part, borrow_twice, "eippf.mba.sub.final");
}

llvm::Value* create_mba_and(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                            std::size_t template_index) {
  if (template_index == 0u) {
    llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "eippf.mba.and.xor");
    llvm::Value* or_part = builder.CreateOr(lhs, rhs, "eippf.mba.and.or");
    return builder.CreateXor(xor_part, or_part, "eippf.mba.and.final");
  }

  llvm::Value* stripped_bits = builder.CreateAnd(lhs, builder.CreateNot(rhs, "eippf.mba.and.not_rhs"),
                                                 "eippf.mba.and.strip");
  return builder.CreateSub(lhs, stripped_bits, "eippf.mba.and.final");
}

llvm::Value* create_mba_or(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                           std::size_t template_index) {
  if (template_index == 0u) {
    llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "eippf.mba.or.and");
    llvm::Value* xor_part = builder.CreateXor(lhs, rhs, "eippf.mba.or.xor");
    return builder.CreateXor(and_part, xor_part, "eippf.mba.or.final");
  }

  llvm::Value* add_part = builder.CreateAdd(lhs, rhs, "eippf.mba.or.add");
  llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "eippf.mba.or.and");
  return builder.CreateSub(add_part, and_part, "eippf.mba.or.final");
}

llvm::Value* create_mba_xor(llvm::IRBuilder<>& builder, llvm::Value* lhs, llvm::Value* rhs,
                            std::size_t template_index) {
  if (template_index == 0u) {
    llvm::Value* or_part = builder.CreateOr(lhs, rhs, "eippf.mba.xor.or");
    llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "eippf.mba.xor.and");
    return builder.CreateAnd(or_part, builder.CreateNot(and_part, "eippf.mba.xor.not_and"),
                             "eippf.mba.xor.final");
  }

  llvm::Value* add_part = builder.CreateAdd(lhs, rhs, "eippf.mba.xor.add");
  llvm::Value* and_part = builder.CreateAnd(lhs, rhs, "eippf.mba.xor.and");
  llvm::Value* and_twice = builder.CreateAdd(and_part, and_part, "eippf.mba.xor.and2");
  return builder.CreateSub(add_part, and_twice, "eippf.mba.xor.final");
}

llvm::Value* create_mba_replacement(llvm::BinaryOperator& operation, llvm::IRBuilder<>& builder,
                                    std::mt19937_64& rng) {
  llvm::Value* lhs = operation.getOperand(0);
  llvm::Value* rhs = operation.getOperand(1);
  const std::size_t template_index = roll_index(rng, 2u);

  switch (operation.getOpcode()) {
    case llvm::Instruction::Add:
      return create_mba_add(builder, lhs, rhs, template_index);
    case llvm::Instruction::Sub:
      return create_mba_sub(builder, lhs, rhs, template_index);
    case llvm::Instruction::And:
      return create_mba_and(builder, lhs, rhs, template_index);
    case llvm::Instruction::Or:
      return create_mba_or(builder, lhs, rhs, template_index);
    case llvm::Instruction::Xor:
      return create_mba_xor(builder, lhs, rhs, template_index);
    default:
      return nullptr;
  }
}

bool obfuscate_binary_instructions(llvm::Function& function, std::mt19937_64& rng) {
  llvm::SmallVector<llvm::BinaryOperator*, 64> candidates;

  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      auto* operation = llvm::dyn_cast<llvm::BinaryOperator>(&instruction);
      if (operation == nullptr) {
        continue;
      }
      if (!is_supported_mba_opcode(operation->getOpcode())) {
        continue;
      }
      if (has_wrap_sensitive_semantics(*operation)) {
        continue;
      }
      if (has_disjoint_or_semantics(*operation)) {
        continue;
      }
      if (!is_supported_integer_type(operation->getType())) {
        continue;
      }
      if (!roll_probability(rng, kTransformProbabilityPercent)) {
        continue;
      }
      candidates.push_back(operation);
    }
  }

  bool changed = false;
  for (llvm::BinaryOperator* operation : candidates) {
    if (operation == nullptr || operation->getParent() == nullptr) {
      continue;
    }

    llvm::IRBuilder<> builder(operation);
    llvm::Value* replacement = create_mba_replacement(*operation, builder, rng);
    if (replacement == nullptr) {
      continue;
    }

    operation->replaceAllUsesWith(replacement);
    operation->eraseFromParent();
    changed = true;
  }

  return changed;
}

llvm::Value* normalize_to_i64(llvm::IRBuilder<>& builder, llvm::Value* value) {
  if (value == nullptr) {
    return nullptr;
  }
  if (!value->getType()->isIntegerTy()) {
    return nullptr;
  }

  if (value->getType()->isIntegerTy(64)) {
    return value;
  }

  auto* integer_type = llvm::cast<llvm::IntegerType>(value->getType());
  if (integer_type->getBitWidth() < 64u) {
    return builder.CreateZExt(value, builder.getInt64Ty(), "eippf.mba.opaque.seed.zext");
  }
  return builder.CreateTrunc(value, builder.getInt64Ty(), "eippf.mba.opaque.seed.trunc");
}

llvm::Value* find_integer_seed_in_block(llvm::BasicBlock& block, llvm::IRBuilder<>& builder) {
  for (llvm::Instruction& instruction : block) {
    if (instruction.isTerminator()) {
      break;
    }
    llvm::Value* normalized = normalize_to_i64(builder, &instruction);
    if (normalized != nullptr) {
      return normalized;
    }
  }
  return nullptr;
}

llvm::Value* find_integer_seed_in_arguments(llvm::Function& function, llvm::IRBuilder<>& builder) {
  for (llvm::Argument& argument : function.args()) {
    llvm::Value* normalized = normalize_to_i64(builder, &argument);
    if (normalized != nullptr) {
      return normalized;
    }
  }
  return nullptr;
}

llvm::Value* create_fallback_seed(llvm::Function& function, llvm::IRBuilder<>& builder) {
  llvm::BasicBlock& entry = function.getEntryBlock();
  llvm::IRBuilder<> entry_builder(&*entry.getFirstInsertionPt());
  llvm::AllocaInst* seed_slot = entry_builder.CreateAlloca(entry_builder.getInt8Ty(), nullptr,
                                                            "eippf.mba.seed.slot");
  seed_slot->setAlignment(llvm::Align(1));
  return builder.CreatePtrToInt(seed_slot, builder.getInt64Ty(), "eippf.mba.opaque.seed.ptr");
}

llvm::Value* materialize_opaque_seed(llvm::Function& function, llvm::BasicBlock& source_block,
                                     llvm::IRBuilder<>& builder) {
  llvm::Value* seed = find_integer_seed_in_block(source_block, builder);
  if (seed != nullptr) {
    return seed;
  }

  seed = find_integer_seed_in_arguments(function, builder);
  if (seed != nullptr) {
    return seed;
  }

  return create_fallback_seed(function, builder);
}

bool can_split_for_opaque_predicate(const llvm::BasicBlock& block) {
  if (block.hasAddressTaken() || block.isEHPad()) {
    return false;
  }

  const llvm::Instruction* terminator = block.getTerminator();
  if (terminator == nullptr) {
    return false;
  }
  if (llvm::isa<llvm::UnreachableInst>(terminator)) {
    return false;
  }
  if (!llvm::isa<llvm::BranchInst>(terminator) && !llvm::isa<llvm::SwitchInst>(terminator) &&
      !llvm::isa<llvm::ReturnInst>(terminator)) {
    return false;
  }

  if (llvm::isa<llvm::ReturnInst>(terminator)) {
    const llvm::Instruction* previous = terminator->getPrevNode();
    auto* call = llvm::dyn_cast_or_null<llvm::CallInst>(previous);
    if (call != nullptr && call->isMustTailCall()) {
      return false;
    }
  }

  return true;
}

void emit_fake_junk_trap(llvm::BasicBlock& fake_block, llvm::Value* seed_value,
                         std::mt19937_64& rng) {
  auto* module = fake_block.getParent()->getParent();
  llvm::Function* trap_function = llvm::Intrinsic::getDeclaration(module, llvm::Intrinsic::trap);

  llvm::IRBuilder<> builder(&fake_block);
  llvm::Value* junk0 = builder.CreateMul(seed_value, builder.getInt64(rng() | 1ull),
                                         "eippf.mba.fake.junk.mul");
  llvm::Value* junk1 = builder.CreateXor(junk0, builder.getInt64(rng()), "eippf.mba.fake.junk.xor");
  llvm::Value* junk2 = builder.CreateAdd(junk1, builder.getInt64(0x9E3779B97F4A7C15ull),
                                         "eippf.mba.fake.junk.add");
  llvm::Value* junk3 = builder.CreateAnd(junk2, builder.getInt64(0xFFFFull),
                                         "eippf.mba.fake.junk.mask");
  (void)junk3;

  builder.CreateCall(trap_function);
  builder.CreateUnreachable();
}

bool insert_opaque_predicate(llvm::Function& function, std::mt19937_64& rng) {
  if (!roll_probability(rng, kTransformProbabilityPercent)) {
    return false;
  }

  llvm::SmallVector<llvm::BasicBlock*, 8> candidate_blocks;
  for (llvm::BasicBlock& block : function) {
    if (!can_split_for_opaque_predicate(block)) {
      continue;
    }
    candidate_blocks.push_back(&block);
  }
  if (candidate_blocks.empty()) {
    return false;
  }

  llvm::BasicBlock* source_block = candidate_blocks[roll_index(rng, candidate_blocks.size())];
  llvm::Instruction* split_before = source_block->getTerminator();
  if (split_before == nullptr) {
    return false;
  }

  llvm::BasicBlock* real_block = source_block->splitBasicBlock(split_before, "eippf.mba.real");
  llvm::Instruction* old_terminator = source_block->getTerminator();
  if (old_terminator == nullptr) {
    return false;
  }
  old_terminator->eraseFromParent();

  llvm::BasicBlock* fake_block = llvm::BasicBlock::Create(function.getContext(), "eippf.mba.fake",
                                                           &function, real_block);

  llvm::IRBuilder<> builder(source_block);
  llvm::Value* seed = materialize_opaque_seed(function, *source_block, builder);
  if (seed == nullptr) {
    return false;
  }
  seed = builder.CreateFreeze(seed, "eippf.mba.opaque.seed.freeze");

  llvm::Value* seed_plus_one = builder.CreateAdd(seed, builder.getInt64(1), "eippf.mba.opaque.n1");
  llvm::Value* product = builder.CreateMul(seed, seed_plus_one, "eippf.mba.opaque.prod");
  llvm::Value* parity = builder.CreateAnd(product, builder.getInt64(1), "eippf.mba.opaque.parity");
  llvm::Value* predicate = builder.CreateICmpEQ(parity, builder.getInt64(0), "eippf.mba.opaque.pred");

  builder.CreateCondBr(predicate, real_block, fake_block);
  emit_fake_junk_trap(*fake_block, seed, rng);
  return true;
}

bool should_process_function(const llvm::Function& function,
                             const llvm::SmallPtrSetImpl<llvm::Function*>& critical_functions) {
  const llvm::Attribute route_attribute = function.getFnAttribute(kRouteAttribute);
  if (critical_functions.contains(&function) || function.hasFnAttribute(kCriticalAnnotation)) {
    return true;
  }
  return route_attribute.isValid() && route_attribute.isStringAttribute() &&
         route_attribute.getValueAsString() == "vm";
}

bool mark_pass_applied(llvm::Module& module) {
  if (module.getNamedGlobal(kAppliedMarkerName) != nullptr) {
    return false;
  }

  auto* marker = new llvm::GlobalVariable(
      module, llvm::Type::getInt8Ty(module.getContext()), true, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt8Ty(module.getContext()), 1), kAppliedMarkerName);
  marker->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  marker->setDSOLocal(true);
  return true;
}

}  // namespace

namespace eippf::passes {

llvm::PreservedAnalyses MBAObfuscationPass::run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
  if (module.getNamedGlobal(kAppliedMarkerName) != nullptr) {
    return llvm::PreservedAnalyses::all();
  }

  llvm::SmallPtrSet<llvm::Function*, 32> critical_functions = collect_critical_functions(module);
  bool changed = false;

  for (llvm::Function& function : module) {
    if (function.isDeclaration() || function.empty()) {
      continue;
    }
    if (!should_process_function(function, critical_functions)) {
      continue;
    }

    std::mt19937_64 rng(derive_function_seed(function.getName()));

    changed = obfuscate_binary_instructions(function, rng) || changed;
    changed = insert_opaque_predicate(function, rng) || changed;
  }

  changed = mark_pass_applied(module) || changed;
  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

void register_mba_obfuscation_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerOptimizerLastEPCallback(
      [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
        module_pm.addPass(MBAObfuscationPass{});
      });

  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-mba-obfuscation") {
          module_pm.addPass(MBAObfuscationPass{});
          return true;
        }
        return false;
      });
}

}  // namespace eippf::passes

#ifdef EIPPF_MBA_OBFUSCATION_STANDALONE_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFMBAObfuscationPass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) { eippf::passes::register_mba_obfuscation_pipeline(pass_builder); }};
}
#endif

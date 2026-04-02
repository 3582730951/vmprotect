#include "passes/StringProtectionPass.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Casting.h"

namespace {

constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;
constexpr std::size_t kMaxStackStringSize = 1024u;
constexpr llvm::StringLiteral kAppliedMarkerName("__eippf_inline_string_protect_applied");

struct CandidateInfo {
  llvm::GlobalVariable* global = nullptr;
  std::uint8_t key = 0;
  std::size_t byte_count = 0;
};

struct OperandUseSite {
  llvm::Instruction* instruction = nullptr;
  unsigned operand_index = 0;
  llvm::Value* original_operand = nullptr;
  llvm::BasicBlock* dominance_block = nullptr;
  llvm::BasicBlock* lifetime_block = nullptr;
  bool is_phi = false;
};

struct RuntimeState {
  bool use_heap = false;
  llvm::AllocaInst* active_flag = nullptr;
  llvm::AllocaInst* heap_ptr_slot = nullptr;
  llvm::AllocaInst* stack_array = nullptr;
  llvm::Value* stack_byte_ptr = nullptr;
  llvm::Value* heap_dummy_ptr = nullptr;
  llvm::Value* runtime_base = nullptr;
  llvm::DenseMap<llvm::Value*, llvm::Value*> replacement_cache;
};

std::uint64_t fnv1a_step(std::uint64_t hash, std::uint8_t value) {
  hash ^= static_cast<std::uint64_t>(value);
  hash *= kFnv1aPrime;
  return hash;
}

std::uint64_t fnv1a_append(std::uint64_t seed, llvm::StringRef text) {
  std::uint64_t hash = seed;
  for (char ch : text) {
    hash = fnv1a_step(hash, static_cast<std::uint8_t>(ch));
  }
  return hash;
}

std::uint64_t fnv1a_append_u64(std::uint64_t seed, std::uint64_t value) {
  std::uint64_t hash = seed;
  for (int i = 0; i < 8; ++i) {
    hash = fnv1a_step(hash, static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu));
  }
  return hash;
}

std::uint8_t stream_mask(std::uint8_t key, std::size_t index) {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 37u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

std::uint8_t derive_key(const llvm::Module& module, const llvm::GlobalVariable& global,
                        std::size_t ordinal, std::size_t size) {
  std::uint64_t hash = kFnv1aOffset;
  hash = fnv1a_append(hash, module.getModuleIdentifier());
  hash = fnv1a_append(hash, global.getName());
  hash = fnv1a_append_u64(hash, static_cast<std::uint64_t>(ordinal));
  hash = fnv1a_append_u64(hash, static_cast<std::uint64_t>(size));

  std::uint8_t key = static_cast<std::uint8_t>(
      (hash ^ (hash >> 8) ^ (hash >> 16) ^ (hash >> 24) ^ (hash >> 32) ^ (hash >> 40) ^
       (hash >> 48) ^ (hash >> 56)) &
      0xFFu);
  if (key == 0) {
    key = 0x5Du;
  }
  return key;
}

bool is_string_candidate(const llvm::GlobalVariable& global,
                         const llvm::ConstantDataSequential*& data) {
  if (global.isDeclaration() || !global.hasInitializer()) {
    return false;
  }

  const auto* cds = llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer());
  if (cds == nullptr) {
    return false;
  }
  if (!cds->getElementType()->isIntegerTy(8) || !cds->isCString()) {
    return false;
  }

  data = cds;
  return true;
}

bool has_disallowed_use(llvm::Value* value, llvm::SmallPtrSetImpl<llvm::Value*>& visited,
                        bool& has_terminal_instruction_use) {
  if (!visited.insert(value).second) {
    return false;
  }

  for (llvm::User* user : value->users()) {
    if (llvm::isa<llvm::Instruction>(user)) {
      has_terminal_instruction_use = true;
      continue;
    }

    auto* constant_expr = llvm::dyn_cast<llvm::ConstantExpr>(user);
    if (constant_expr == nullptr) {
      return true;
    }

    switch (constant_expr->getOpcode()) {
      case llvm::Instruction::GetElementPtr:
      case llvm::Instruction::BitCast:
      case llvm::Instruction::AddrSpaceCast:
      case llvm::Instruction::PtrToInt:
      case llvm::Instruction::IntToPtr:
        if (has_disallowed_use(constant_expr, visited, has_terminal_instruction_use)) {
          return true;
        }
        break;
      default:
        return true;
    }
  }

  return false;
}

bool is_eligible_for_rewrite(llvm::GlobalVariable& global) {
  llvm::SmallPtrSet<llvm::Value*, 16> visited;
  bool has_terminal_instruction_use = false;
  const bool disallowed = has_disallowed_use(&global, visited, has_terminal_instruction_use);
  return has_terminal_instruction_use && !disallowed;
}

llvm::DenseMap<llvm::GlobalVariable*, CandidateInfo> collect_and_encrypt_candidates(llvm::Module& module,
                                                                                     bool& changed) {
  llvm::DenseMap<llvm::GlobalVariable*, CandidateInfo> candidates;
  std::size_t ordinal = 0;

  for (llvm::GlobalVariable& global : module.globals()) {
    const llvm::ConstantDataSequential* data = nullptr;
    if (!is_string_candidate(global, data)) {
      continue;
    }
    if (!is_eligible_for_rewrite(global)) {
      continue;
    }

    const llvm::StringRef raw = data->getRawDataValues();
    if (raw.empty()) {
      continue;
    }

    const std::uint8_t key = derive_key(module, global, ordinal, raw.size());
    std::vector<std::uint8_t> encrypted(raw.begin(), raw.end());
    for (std::size_t i = 0; i < encrypted.size(); ++i) {
      encrypted[i] = static_cast<std::uint8_t>(encrypted[i] ^ stream_mask(key, i));
    }

    llvm::Constant* enc_init = llvm::ConstantDataArray::get(
        module.getContext(), llvm::ArrayRef<std::uint8_t>(encrypted.data(), encrypted.size()));
    global.setInitializer(enc_init);
    global.setConstant(true);

    candidates[&global] = CandidateInfo{&global, key, encrypted.size()};
    changed = true;
    ++ordinal;
  }

  return candidates;
}

llvm::GlobalVariable* resolve_candidate_global(
    llvm::Value* value, const llvm::DenseMap<llvm::GlobalVariable*, CandidateInfo>& candidates) {
  if (auto* global = llvm::dyn_cast<llvm::GlobalVariable>(value)) {
    return candidates.find(global) != candidates.end() ? global : nullptr;
  }

  auto* constant_expr = llvm::dyn_cast<llvm::ConstantExpr>(value);
  if (constant_expr == nullptr) {
    return nullptr;
  }

  switch (constant_expr->getOpcode()) {
    case llvm::Instruction::GetElementPtr:
    case llvm::Instruction::BitCast:
    case llvm::Instruction::AddrSpaceCast:
    case llvm::Instruction::PtrToInt:
    case llvm::Instruction::IntToPtr:
      return resolve_candidate_global(constant_expr->getOperand(0), candidates);
    default:
      return nullptr;
  }
}

llvm::DenseMap<llvm::GlobalVariable*, std::vector<OperandUseSite>> collect_use_sites(
    llvm::Function& function, const llvm::DenseMap<llvm::GlobalVariable*, CandidateInfo>& candidates) {
  llvm::DenseMap<llvm::GlobalVariable*, std::vector<OperandUseSite>> uses_by_global;

  for (llvm::Instruction& instruction : llvm::instructions(function)) {
    for (unsigned op_index = 0; op_index < instruction.getNumOperands(); ++op_index) {
      llvm::Value* operand = instruction.getOperand(op_index);
      llvm::GlobalVariable* global = resolve_candidate_global(operand, candidates);
      if (global == nullptr) {
        continue;
      }

      OperandUseSite site{};
      site.instruction = &instruction;
      site.operand_index = op_index;
      site.original_operand = operand;
      site.is_phi = llvm::isa<llvm::PHINode>(instruction);

      if (site.is_phi) {
        auto* phi = llvm::cast<llvm::PHINode>(&instruction);
        site.dominance_block = phi->getIncomingBlock(op_index);
        site.lifetime_block = phi->getParent();
      } else {
        site.dominance_block = instruction.getParent();
        site.lifetime_block = instruction.getParent();
      }

      uses_by_global[global].push_back(site);
    }
  }

  return uses_by_global;
}

llvm::BasicBlock* compute_decrypt_block(llvm::Function& function, llvm::DominatorTree& dt,
                                        const std::vector<OperandUseSite>& uses) {
  llvm::BasicBlock* common = &function.getEntryBlock();
  bool seeded = false;

  for (const OperandUseSite& site : uses) {
    if (site.dominance_block == nullptr) {
      continue;
    }

    if (!seeded) {
      common = site.dominance_block;
      seeded = true;
      continue;
    }

    common = dt.findNearestCommonDominator(common, site.dominance_block);
    if (common == nullptr) {
      return &function.getEntryBlock();
    }
  }

  if (common == nullptr) {
    return &function.getEntryBlock();
  }

  auto strictly_dominates_all = [&](llvm::BasicBlock* candidate) {
    for (const OperandUseSite& site : uses) {
      if (site.dominance_block == nullptr) {
        continue;
      }
      if (site.dominance_block == candidate || !dt.dominates(candidate, site.dominance_block)) {
        return false;
      }
    }
    return true;
  };

  while (!strictly_dominates_all(common)) {
    auto* node = dt.getNode(common);
    if (node == nullptr || node->getIDom() == nullptr) {
      break;
    }
    common = node->getIDom()->getBlock();
  }

  return common == nullptr ? &function.getEntryBlock() : common;
}

llvm::Instruction* choose_decrypt_insertion_point(llvm::BasicBlock* decrypt_block,
                                                  const std::vector<OperandUseSite>& uses) {
  llvm::Instruction* default_ip = &*decrypt_block->getFirstInsertionPt();

  llvm::SmallPtrSet<llvm::Instruction*, 8> local_non_phi_uses;
  for (const OperandUseSite& site : uses) {
    if (site.is_phi || site.instruction == nullptr) {
      continue;
    }
    if (site.instruction->getParent() == decrypt_block) {
      local_non_phi_uses.insert(site.instruction);
    }
  }

  if (local_non_phi_uses.empty()) {
    return default_ip;
  }

  for (llvm::Instruction& instruction : *decrypt_block) {
    if (local_non_phi_uses.contains(&instruction)) {
      return &instruction;
    }
  }

  return default_ip;
}

llvm::FunctionCallee get_malloc_callee(llvm::Module& module) {
  llvm::LLVMContext& ctx = module.getContext();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(ctx));
  llvm::Type* i64_ty = llvm::Type::getInt64Ty(ctx);
  llvm::FunctionType* malloc_ty = llvm::FunctionType::get(i8_ptr_ty, {i64_ty}, false);
  return module.getOrInsertFunction("malloc", malloc_ty);
}

llvm::FunctionCallee get_free_callee(llvm::Module& module) {
  llvm::LLVMContext& ctx = module.getContext();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(ctx));
  llvm::FunctionType* free_ty = llvm::FunctionType::get(llvm::Type::getVoidTy(ctx), {i8_ptr_ty}, false);
  return module.getOrInsertFunction("free", free_ty);
}

llvm::Function* get_trap_function(llvm::Module& module) {
  return llvm::Intrinsic::getDeclaration(&module, llvm::Intrinsic::trap);
}

RuntimeState create_runtime_state(llvm::Function& function, const CandidateInfo& candidate) {
  RuntimeState state;
  state.use_heap = candidate.byte_count > kMaxStackStringSize;

  llvm::Instruction* entry_ip = &*function.getEntryBlock().getFirstInsertionPt();
  llvm::IRBuilder<> entry_builder(entry_ip);

  llvm::Type* i1_ty = entry_builder.getInt1Ty();
  llvm::Type* i8_ty = entry_builder.getInt8Ty();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(i8_ty);

  state.active_flag = entry_builder.CreateAlloca(i1_ty, nullptr,
                                                  candidate.global->getName() + ".eippf.active");
  state.active_flag->setAlignment(llvm::Align(1));
  entry_builder.CreateStore(entry_builder.getFalse(), state.active_flag);

  if (state.use_heap) {
    state.heap_ptr_slot = entry_builder.CreateAlloca(i8_ptr_ty, nullptr,
                                                     candidate.global->getName() + ".eippf.heap.slot");
    state.heap_ptr_slot->setAlignment(llvm::Align(sizeof(void*)));
    entry_builder.CreateStore(llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(i8_ptr_ty)),
                              state.heap_ptr_slot);

    llvm::AllocaInst* dummy =
        entry_builder.CreateAlloca(i8_ty, nullptr, candidate.global->getName() + ".eippf.heap.dummy");
    dummy->setAlignment(llvm::Align(1));
    state.heap_dummy_ptr = dummy;
  } else {
    auto* array_ty = llvm::ArrayType::get(i8_ty, candidate.byte_count);
    state.stack_array = entry_builder.CreateAlloca(array_ty, nullptr,
                                                   candidate.global->getName() + ".eippf.stack.array");
    state.stack_array->setAlignment(llvm::Align(1));

    state.stack_byte_ptr = entry_builder.CreateInBoundsGEP(
        array_ty, state.stack_array, {entry_builder.getInt64(0), entry_builder.getInt64(0)},
        candidate.global->getName() + ".eippf.stack.ptr");
  }

  return state;
}

void emit_inline_decrypt(llvm::IRBuilder<>& builder, const CandidateInfo& candidate,
                         llvm::Value* destination_ptr) {
  llvm::Type* i8_ty = builder.getInt8Ty();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(i8_ty);

  llvm::Value* encrypted_base = builder.CreatePointerCast(candidate.global, i8_ptr_ty, "eippf.enc.base");
  llvm::Value* dst_base = builder.CreatePointerCast(destination_ptr, i8_ptr_ty, "eippf.dec.base");

  for (std::size_t i = 0; i < candidate.byte_count; ++i) {
    llvm::Value* index = builder.getInt64(static_cast<std::uint64_t>(i));
    llvm::Value* src_ptr = builder.CreateInBoundsGEP(i8_ty, encrypted_base, index, "eippf.enc.ptr");
    llvm::Value* dst_ptr = builder.CreateInBoundsGEP(i8_ty, dst_base, index, "eippf.dec.ptr");

    auto* encrypted_byte = builder.CreateLoad(i8_ty, src_ptr, "eippf.enc.byte");
    encrypted_byte->setAlignment(llvm::Align(1));
    encrypted_byte->setVolatile(true);

    llvm::Value* mask = builder.getInt8(stream_mask(candidate.key, i));
    llvm::Value* plain = builder.CreateXor(encrypted_byte, mask, "eippf.dec.byte");

    auto* store = builder.CreateStore(plain, dst_ptr);
    store->setAlignment(llvm::Align(1));
  }
}

llvm::Value* materialize_replacement_operand(llvm::IRBuilder<>& builder, llvm::Value* original,
                                             llvm::Value* runtime_base_i8,
                                             llvm::AllocaInst* stack_array,
                                             llvm::DenseMap<llvm::Value*, llvm::Value*>& cache) {
  if (auto it = cache.find(original); it != cache.end()) {
    return it->second;
  }

  llvm::Value* replacement = nullptr;

  if (auto* global = llvm::dyn_cast<llvm::GlobalVariable>(original)) {
    if (stack_array != nullptr && stack_array->getType() == global->getType()) {
      replacement = stack_array;
    } else {
      replacement = builder.CreatePointerCast(runtime_base_i8, global->getType(), "eippf.buf.global.cast");
    }
  } else if (auto* ce = llvm::dyn_cast<llvm::ConstantExpr>(original)) {
    switch (ce->getOpcode()) {
      case llvm::Instruction::GetElementPtr: {
        llvm::Value* base =
            materialize_replacement_operand(builder, ce->getOperand(0), runtime_base_i8, stack_array, cache);

        llvm::SmallVector<llvm::Value*, 4> indices;
        indices.reserve(ce->getNumOperands() - 1);
        for (unsigned i = 1; i < ce->getNumOperands(); ++i) {
          indices.push_back(const_cast<llvm::Constant*>(ce->getOperand(i)));
        }

        const auto* gep_op = llvm::cast<llvm::GEPOperator>(ce);
        llvm::Value* gep = gep_op->isInBounds()
                               ? builder.CreateInBoundsGEP(gep_op->getSourceElementType(), base, indices,
                                                           "eippf.buf.gep")
                               : builder.CreateGEP(gep_op->getSourceElementType(), base, indices,
                                                   "eippf.buf.gep");
        replacement = (gep->getType() == ce->getType())
                          ? gep
                          : builder.CreatePointerCast(gep, ce->getType(), "eippf.buf.gep.cast");
        break;
      }

      case llvm::Instruction::BitCast:
      case llvm::Instruction::AddrSpaceCast: {
        llvm::Value* base =
            materialize_replacement_operand(builder, ce->getOperand(0), runtime_base_i8, stack_array, cache);
        replacement = builder.CreatePointerCast(base, ce->getType(), "eippf.buf.ptrcast");
        break;
      }

      case llvm::Instruction::PtrToInt: {
        llvm::Value* base =
            materialize_replacement_operand(builder, ce->getOperand(0), runtime_base_i8, stack_array, cache);
        replacement = builder.CreatePtrToInt(base, ce->getType(), "eippf.buf.ptrtoint");
        break;
      }

      case llvm::Instruction::IntToPtr: {
        llvm::Value* base =
            materialize_replacement_operand(builder, ce->getOperand(0), runtime_base_i8, stack_array, cache);
        replacement = builder.CreateIntToPtr(base, ce->getType(), "eippf.buf.inttoptr");
        break;
      }

      default:
        if (ce->getType()->isPointerTy()) {
          replacement = builder.CreatePointerCast(runtime_base_i8, ce->getType(), "eippf.buf.fallback.cast");
        } else {
          replacement = runtime_base_i8;
        }
        break;
    }
  } else {
    if (original->getType()->isPointerTy()) {
      replacement = builder.CreatePointerCast(runtime_base_i8, original->getType(), "eippf.buf.value.cast");
    } else {
      replacement = runtime_base_i8;
    }
  }

  cache[original] = replacement;
  return replacement;
}

void emit_memory_barrier(llvm::IRBuilder<>& builder) {
  llvm::FunctionType* barrier_ty = llvm::FunctionType::get(builder.getVoidTy(), false);
  llvm::InlineAsm* barrier =
      llvm::InlineAsm::get(barrier_ty, "", "~{memory}", true, false, llvm::InlineAsm::AD_ATT);
  builder.CreateCall(barrier);
}

void emit_secure_cleanup(llvm::IRBuilder<>& builder, const CandidateInfo& candidate,
                         const RuntimeState& state, llvm::FunctionCallee free_callee) {
  llvm::Type* i8_ty = builder.getInt8Ty();
  llvm::Type* i8_ptr_ty = llvm::PointerType::getUnqual(i8_ty);

  llvm::Value* active = builder.CreateLoad(builder.getInt1Ty(), state.active_flag, "eippf.cleanup.active");

  if (state.use_heap) {
    llvm::Value* heap_ptr = builder.CreateLoad(i8_ptr_ty, state.heap_ptr_slot, "eippf.cleanup.heap.ptr");
    llvm::Value* memset_ptr =
        builder.CreateSelect(active, heap_ptr, state.heap_dummy_ptr, "eippf.cleanup.memset.ptr");
    llvm::Value* clear_size = builder.CreateSelect(active, builder.getInt64(candidate.byte_count),
                                                   builder.getInt64(0), "eippf.cleanup.size");

    builder.CreateMemSet(memset_ptr, builder.getInt8(0), clear_size, llvm::MaybeAlign(1), true);
    emit_memory_barrier(builder);

    llvm::Value* null_ptr =
        llvm::ConstantPointerNull::get(llvm::cast<llvm::PointerType>(i8_ptr_ty));
    llvm::Value* free_arg = builder.CreateSelect(active, heap_ptr, null_ptr, "eippf.cleanup.free.arg");
    builder.CreateCall(free_callee, {free_arg});
    builder.CreateStore(null_ptr, state.heap_ptr_slot);
  } else {
    llvm::Value* clear_size = builder.CreateSelect(active, builder.getInt64(candidate.byte_count),
                                                   builder.getInt64(0), "eippf.cleanup.size");
    builder.CreateMemSet(state.stack_byte_ptr, builder.getInt8(0), clear_size, llvm::MaybeAlign(1), true);
    emit_memory_barrier(builder);
  }

  builder.CreateStore(builder.getFalse(), state.active_flag);
}

llvm::SmallPtrSet<llvm::Instruction*, 16> collect_cleanup_points(llvm::Function& function,
                                                                 llvm::PostDominatorTree& pdt,
                                                                 const std::vector<OperandUseSite>& uses) {
  llvm::SmallPtrSet<llvm::Instruction*, 16> points;

  llvm::BasicBlock* common_postdom = nullptr;
  for (const OperandUseSite& site : uses) {
    if (site.lifetime_block == nullptr) {
      continue;
    }

    if (common_postdom == nullptr) {
      common_postdom = site.lifetime_block;
    } else {
      common_postdom = pdt.findNearestCommonDominator(common_postdom, site.lifetime_block);
      if (common_postdom == nullptr) {
        break;
      }
    }
  }

  if (common_postdom != nullptr && common_postdom->getTerminator() != nullptr) {
    points.insert(common_postdom->getTerminator());
  }

  for (llvm::BasicBlock& block : function) {
    llvm::Instruction* term = block.getTerminator();
    if (term == nullptr) {
      continue;
    }

    if (llvm::isa<llvm::ReturnInst>(term) || llvm::isa<llvm::ResumeInst>(term) ||
        llvm::isa<llvm::CleanupReturnInst>(term) || llvm::isa<llvm::CatchReturnInst>(term)) {
      points.insert(term);
    }

    bool has_eh = false;
    for (llvm::Instruction& inst : block) {
      if (llvm::isa<llvm::LandingPadInst>(inst) || llvm::isa<llvm::CleanupPadInst>(inst) ||
          llvm::isa<llvm::CatchPadInst>(inst) || llvm::isa<llvm::ResumeInst>(inst)) {
        has_eh = true;
        break;
      }
    }
    if (has_eh) {
      points.insert(term);
    }
  }

  if (points.empty()) {
    for (llvm::BasicBlock& block : function) {
      llvm::Instruction* term = block.getTerminator();
      if (term != nullptr && llvm::isa<llvm::ReturnInst>(term)) {
        points.insert(term);
      }
    }
  }

  return points;
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

llvm::PreservedAnalyses StringProtectionPass::run(llvm::Module& module,
                                                  llvm::ModuleAnalysisManager&) {
  if (module.getNamedGlobal(kAppliedMarkerName) != nullptr) {
    return llvm::PreservedAnalyses::all();
  }

  bool changed = false;
  llvm::DenseMap<llvm::GlobalVariable*, CandidateInfo> candidates =
      collect_and_encrypt_candidates(module, changed);
  if (candidates.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  llvm::FunctionCallee malloc_callee = get_malloc_callee(module);
  llvm::FunctionCallee free_callee = get_free_callee(module);
  llvm::Function* trap_function = get_trap_function(module);

  for (llvm::Function& function : module) {
    if (function.isDeclaration()) {
      continue;
    }

    llvm::DenseMap<llvm::GlobalVariable*, std::vector<OperandUseSite>> use_map =
        collect_use_sites(function, candidates);
    if (use_map.empty()) {
      continue;
    }

    llvm::DominatorTree dt(function);
    llvm::PostDominatorTree pdt(function);

    for (auto& [global, uses] : use_map) {
      if (uses.empty()) {
        continue;
      }

      const CandidateInfo& candidate = candidates[global];
      RuntimeState state = create_runtime_state(function, candidate);

      llvm::BasicBlock* decrypt_block = compute_decrypt_block(function, dt, uses);
      llvm::Instruction* decrypt_ip = choose_decrypt_insertion_point(decrypt_block, uses);
      llvm::IRBuilder<> decrypt_builder(decrypt_ip);

      if (state.use_heap) {
        llvm::Value* alloc_size = decrypt_builder.getInt64(candidate.byte_count);
        llvm::Value* heap_ptr = decrypt_builder.CreateCall(malloc_callee, {alloc_size}, "eippf.heap.ptr");
        auto* heap_ptr_ty = llvm::cast<llvm::PointerType>(heap_ptr->getType());
        llvm::Value* heap_is_null = decrypt_builder.CreateICmpEQ(
            heap_ptr, llvm::ConstantPointerNull::get(heap_ptr_ty), "eippf.heap.is_null");

        llvm::BasicBlock* alloc_check_block = decrypt_builder.GetInsertBlock();
        llvm::Instruction* continue_ip = &*decrypt_builder.GetInsertPoint();
        llvm::BasicBlock* alloc_ok_block =
            alloc_check_block->splitBasicBlock(continue_ip, "eippf.heap.alloc.ok");
        alloc_check_block->getTerminator()->eraseFromParent();

        llvm::BasicBlock* alloc_trap_block = llvm::BasicBlock::Create(
            module.getContext(), "eippf.heap.alloc.trap", &function, alloc_ok_block);
        llvm::IRBuilder<> alloc_check_builder(alloc_check_block);
        alloc_check_builder.CreateCondBr(heap_is_null, alloc_trap_block, alloc_ok_block);

        llvm::IRBuilder<> trap_builder(alloc_trap_block);
        trap_builder.CreateCall(trap_function);
        trap_builder.CreateUnreachable();

        decrypt_builder.SetInsertPoint(&*alloc_ok_block->getFirstInsertionPt());
        decrypt_builder.CreateStore(heap_ptr, state.heap_ptr_slot);
        state.runtime_base = heap_ptr;
      } else {
        state.runtime_base = state.stack_byte_ptr;
      }

      emit_inline_decrypt(decrypt_builder, candidate, state.runtime_base);
      decrypt_builder.CreateStore(decrypt_builder.getTrue(), state.active_flag);

      for (const OperandUseSite& site : uses) {
        llvm::Value* replacement = materialize_replacement_operand(
            decrypt_builder, site.original_operand, state.runtime_base, state.stack_array,
            state.replacement_cache);

        llvm::Type* expected = site.instruction->getOperand(site.operand_index)->getType();
        if (replacement->getType() != expected) {
          if (!expected->isPointerTy()) {
            continue;
          }
          replacement = decrypt_builder.CreatePointerCast(replacement, expected, "eippf.use.fixcast");
        }

        site.instruction->setOperand(site.operand_index, replacement);
        changed = true;
      }

      llvm::SmallPtrSet<llvm::Instruction*, 16> cleanup_points =
          collect_cleanup_points(function, pdt, uses);
      for (llvm::Instruction* point : cleanup_points) {
        if (point == nullptr) {
          continue;
        }
        llvm::IRBuilder<> cleanup_builder(point);
        emit_secure_cleanup(cleanup_builder, candidate, state, free_callee);
        changed = true;
      }
    }
  }

  changed |= mark_pass_applied(module);
  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

}  // namespace eippf::passes

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFStringProtectionPass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) {
        pass_builder.registerPipelineParsingCallback(
            [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
               llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
              if (name == "eippf-string-protect-inline") {
                module_pm.addPass(eippf::passes::StringProtectionPass{});
                return true;
              }
              return false;
            });
      }};
}

#include "passes/CFFObfuscationPass.hpp"

#include <cassert>
#include <cstdint>
#include <string>

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
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
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/Local.h"

namespace {

constexpr llvm::StringLiteral kCriticalAnnotation("drm_critical_ip");
constexpr llvm::StringLiteral kJitTargetAnnotation("drm_jit_target");
constexpr llvm::StringLiteral kFlattenAnnotation("drm_flatten");
constexpr llvm::StringLiteral kRouteAttribute("eippf.route");
constexpr llvm::StringLiteral kRouteCff("cff");
constexpr llvm::StringLiteral kDecryptHelperName("__eippf_xor_decrypt");
constexpr llvm::StringLiteral kStringEncryptionMarker("__eippf_strenc_done");
constexpr std::uint32_t kFlattenGatePercent = 20u;
constexpr std::uint8_t kStringXorKey = 0x5Au;
constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;

struct AnnotationSets {
  llvm::SmallPtrSet<llvm::Function*, 32> critical_functions;
  llvm::SmallPtrSet<llvm::Function*, 32> jit_target_functions;
  llvm::SmallPtrSet<llvm::Function*, 32> flatten_functions;
};

struct EncryptedStringInfo {
  llvm::GlobalVariable* global = nullptr;
  std::uint64_t size = 0u;
};

std::uint64_t fnv1a_append(std::uint64_t seed, llvm::StringRef text) {
  std::uint64_t hash = seed;
  for (const char ch : text) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= kFnv1aPrime;
  }
  return hash;
}

std::uint64_t fnv1a_append_u64(std::uint64_t seed, std::uint64_t value) {
  std::uint64_t hash = seed;
  for (int index = 0; index < 8; ++index) {
    hash ^= static_cast<std::uint8_t>((value >> (index * 8)) & 0xFFu);
    hash *= kFnv1aPrime;
  }
  return hash;
}

std::uint64_t derive_deterministic_gate_hash(const llvm::Module& module,
                                             const llvm::Function& function) {
  std::uint64_t hash = kFnv1aOffset;
  hash = fnv1a_append(hash, module.getModuleIdentifier());
  hash = fnv1a_append(hash, function.getName());
  hash = fnv1a_append_u64(hash, static_cast<std::uint64_t>(function.arg_size()));
  hash = fnv1a_append_u64(hash, static_cast<std::uint64_t>(function.size()));
  return hash;
}

bool passes_deterministic_gate(const llvm::Module& module, const llvm::Function& function) {
  if (kFlattenGatePercent == 0u) {
    return false;
  }
  if (kFlattenGatePercent >= 100u) {
    return true;
  }

  const std::uint64_t hash = derive_deterministic_gate_hash(module, function);
  return (hash % 100u) < kFlattenGatePercent;
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

AnnotationSets collect_annotations(llvm::Module& module) {
  AnnotationSets annotation_sets;

  llvm::GlobalVariable* annotations = module.getNamedGlobal("llvm.global.annotations");
  if (annotations == nullptr || !annotations->hasInitializer()) {
    return annotation_sets;
  }

  auto* annotation_array = llvm::dyn_cast<llvm::ConstantArray>(annotations->getInitializer());
  if (annotation_array == nullptr) {
    return annotation_sets;
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
    if (annotation == kCriticalAnnotation) {
      annotation_sets.critical_functions.insert(function);
    } else if (annotation == kJitTargetAnnotation) {
      annotation_sets.jit_target_functions.insert(function);
    } else if (annotation == kFlattenAnnotation) {
      annotation_sets.flatten_functions.insert(function);
    }
  }

  return annotation_sets;
}

bool has_annotation(const llvm::Function& function,
                    const llvm::SmallPtrSetImpl<llvm::Function*>& annotated_functions,
                    llvm::StringRef attribute_name) {
  return annotated_functions.contains(&function) || function.hasFnAttribute(attribute_name);
}

bool should_attempt_flattening(const llvm::Module& module, const llvm::Function& function,
                               const AnnotationSets& annotation_sets) {
  if (function.isDeclaration() || function.isIntrinsic() || function.empty()) {
    return false;
  }

  if (function.getName() == kDecryptHelperName) {
    return false;
  }

  const llvm::Attribute route_attribute = function.getFnAttribute(kRouteAttribute);
  if (route_attribute.isValid() && route_attribute.isStringAttribute()) {
    return route_attribute.getValueAsString() == kRouteCff;
  }

  if (has_annotation(function, annotation_sets.critical_functions, kCriticalAnnotation) ||
      has_annotation(function, annotation_sets.jit_target_functions, kJitTargetAnnotation)) {
    return false;
  }

  if (has_annotation(function, annotation_sets.flatten_functions, kFlattenAnnotation)) {
    return true;
  }

  return passes_deterministic_gate(module, function);
}

bool supports_flattening(const llvm::SmallVectorImpl<llvm::BasicBlock*>& blocks) {
  for (llvm::BasicBlock* block : blocks) {
    if (block == nullptr || block->hasAddressTaken() || block->isEHPad()) {
      return false;
    }

    llvm::Instruction* terminator = block->getTerminator();
    if (terminator == nullptr) {
      return false;
    }

    if (llvm::isa<llvm::BranchInst>(terminator) || llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    return false;
  }

  return true;
}

bool has_supported_allocas(const llvm::SmallVectorImpl<llvm::BasicBlock*>& blocks) {
  for (llvm::BasicBlock* block : blocks) {
    if (block == nullptr) {
      continue;
    }

    for (llvm::Instruction& instruction : *block) {
      auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
      if (alloca == nullptr) {
        continue;
      }

      if (!llvm::isa<llvm::ConstantInt>(alloca->getArraySize())) {
        return false;
      }
    }
  }

  return true;
}

void hoist_static_allocas_to_bootstrap(
    llvm::BasicBlock* bootstrap, const llvm::SmallVectorImpl<llvm::BasicBlock*>& flatten_blocks) {
  if (bootstrap == nullptr || bootstrap->getTerminator() == nullptr) {
    llvm::report_fatal_error("CFF bootstrap block is invalid during alloca hoisting.");
  }

  llvm::SmallVector<llvm::AllocaInst*, 16> allocas_to_hoist;
  for (llvm::BasicBlock* block : flatten_blocks) {
    if (block == nullptr) {
      continue;
    }

    for (llvm::Instruction& instruction : *block) {
      auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(&instruction);
      if (alloca == nullptr) {
        continue;
      }

      if (!llvm::isa<llvm::ConstantInt>(alloca->getArraySize())) {
        llvm::report_fatal_error("CFF encountered non-constant alloca after precheck.");
      }
      allocas_to_hoist.push_back(alloca);
    }
  }

  llvm::Instruction* insertion_point = bootstrap->getTerminator();
  for (llvm::AllocaInst* alloca : allocas_to_hoist) {
    if (alloca == nullptr || alloca->getParent() == bootstrap) {
      continue;
    }
    alloca->moveBefore(insertion_point);
  }
}

void demote_phi_nodes_to_stack(llvm::Function& function, llvm::Instruction* alloca_insertion_point) {
  if (alloca_insertion_point == nullptr) {
    return;
  }

  llvm::SmallVector<llvm::PHINode*, 32> phi_nodes;
  for (llvm::BasicBlock& block : function) {
    for (llvm::Instruction& instruction : block) {
      auto* phi = llvm::dyn_cast<llvm::PHINode>(&instruction);
      if (phi == nullptr) {
        break;
      }
      phi_nodes.push_back(phi);
    }
  }

  for (llvm::PHINode* phi : phi_nodes) {
    llvm::DemotePHIToStack(phi, alloca_insertion_point);
  }
}

bool rewrite_cfg_to_dispatcher(llvm::Function& function) {
  if (function.empty()) {
    return false;
  }

  llvm::SmallVector<llvm::BasicBlock*, 32> precheck_blocks;
  precheck_blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) {
    precheck_blocks.push_back(&block);
  }

  if (precheck_blocks.empty() || !supports_flattening(precheck_blocks) ||
      !has_supported_allocas(precheck_blocks)) {
    return false;
  }

  auto* module = function.getParent();
  if (module == nullptr) {
    return false;
  }

  llvm::BasicBlock* original_entry = &function.getEntryBlock();
  llvm::BasicBlock* bootstrap = llvm::BasicBlock::Create(function.getContext(), "eippf.cff.bootstrap",
                                                          &function, original_entry);
  llvm::IRBuilder<> bootstrap_init_builder(bootstrap);
  bootstrap_init_builder.CreateBr(original_entry);

  llvm::Instruction* bootstrap_terminator = bootstrap->getTerminator();
  if (bootstrap_terminator == nullptr) {
    llvm::report_fatal_error("CFF bootstrap block has no terminator.");
  }
  demote_phi_nodes_to_stack(function, bootstrap_terminator);

  llvm::SmallVector<llvm::BasicBlock*, 32> flatten_blocks;
  flatten_blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) {
    if (&block == bootstrap) {
      continue;
    }
    flatten_blocks.push_back(&block);
  }

  assert(!flatten_blocks.empty() && supports_flattening(flatten_blocks) &&
         has_supported_allocas(flatten_blocks) &&
         "precheck should guarantee flattening eligibility after bootstrap insertion");
  hoist_static_allocas_to_bootstrap(bootstrap, flatten_blocks);

  llvm::SmallPtrSet<llvm::BasicBlock*, 32> flatten_block_set;
  flatten_block_set.insert(flatten_blocks.begin(), flatten_blocks.end());

  llvm::DenseMap<llvm::BasicBlock*, std::uint32_t> state_id_by_block;
  state_id_by_block.reserve(static_cast<unsigned>(flatten_blocks.size()));
  for (std::uint32_t index = 0; index < flatten_blocks.size(); ++index) {
    state_id_by_block.try_emplace(flatten_blocks[index], index);
  }

  for (llvm::BasicBlock* block : flatten_blocks) {
    auto* branch = llvm::dyn_cast<llvm::BranchInst>(block->getTerminator());
    if (branch == nullptr) {
      continue;
    }
    for (llvm::BasicBlock* successor : branch->successors()) {
      if (!flatten_block_set.contains(successor)) {
        llvm::report_fatal_error("CFF found unmapped branch successor during rewrite.");
      }
    }
  }

  llvm::BasicBlock* dispatcher =
      llvm::BasicBlock::Create(function.getContext(), "eippf.cff.dispatcher", &function);
  llvm::BasicBlock* fallback =
      llvm::BasicBlock::Create(function.getContext(), "eippf.cff.default", &function);

  llvm::IRBuilder<> bootstrap_builder(bootstrap_terminator);
  llvm::Type* state_type = bootstrap_builder.getInt32Ty();
  auto* state_slot = bootstrap_builder.CreateAlloca(state_type, nullptr, "eippf.cff.state");
  state_slot->setAlignment(llvm::Align(4));

  auto entry_state_it = state_id_by_block.find(original_entry);
  assert(entry_state_it != state_id_by_block.end() &&
         "entry block must be part of flattened block set");
  if (entry_state_it == state_id_by_block.end()) {
    llvm::report_fatal_error("CFF entry block state mapping is missing.");
  }

  llvm::StoreInst* entry_state_store = bootstrap_builder.CreateStore(
      llvm::ConstantInt::get(bootstrap_builder.getInt32Ty(), entry_state_it->second), state_slot);
  entry_state_store->setAlignment(llvm::Align(4));

  bootstrap_terminator->eraseFromParent();
  bootstrap_builder.SetInsertPoint(bootstrap);
  bootstrap_builder.CreateBr(dispatcher);

  llvm::IRBuilder<> dispatcher_builder(dispatcher);
  llvm::LoadInst* loaded_state =
      dispatcher_builder.CreateLoad(state_type, state_slot, "eippf.cff.state.load");
  loaded_state->setAlignment(llvm::Align(4));

  llvm::SwitchInst* dispatch_switch = dispatcher_builder.CreateSwitch(
      loaded_state, fallback, static_cast<unsigned>(flatten_blocks.size()));
  for (llvm::BasicBlock* block : flatten_blocks) {
    const std::uint32_t state_id = state_id_by_block.lookup(block);
    dispatch_switch->addCase(llvm::ConstantInt::get(dispatcher_builder.getInt32Ty(), state_id),
                             block);
  }

  llvm::IRBuilder<> fallback_builder(fallback);
  llvm::Function* trap_function = llvm::Intrinsic::getDeclaration(module, llvm::Intrinsic::trap);
  fallback_builder.CreateCall(trap_function);
  fallback_builder.CreateUnreachable();

  for (llvm::BasicBlock* block : flatten_blocks) {
    llvm::Instruction* terminator = block->getTerminator();
    if (terminator == nullptr || llvm::isa<llvm::ReturnInst>(terminator) ||
        llvm::isa<llvm::UnreachableInst>(terminator)) {
      continue;
    }

    auto* branch = llvm::dyn_cast<llvm::BranchInst>(terminator);
    assert(branch != nullptr && "supports_flattening should only allow branch/ret/unreachable");

    llvm::IRBuilder<> builder(branch);
    if (branch->isConditional()) {
      llvm::BasicBlock* true_successor = branch->getSuccessor(0);
      llvm::BasicBlock* false_successor = branch->getSuccessor(1);

      auto true_state_it = state_id_by_block.find(true_successor);
      auto false_state_it = state_id_by_block.find(false_successor);
      assert(true_state_it != state_id_by_block.end() &&
             false_state_it != state_id_by_block.end() &&
             "branch successors should be mapped before rewrite");

      llvm::Value* next_state = builder.CreateSelect(
          branch->getCondition(),
          llvm::ConstantInt::get(builder.getInt32Ty(), true_state_it->second),
          llvm::ConstantInt::get(builder.getInt32Ty(), false_state_it->second),
          "eippf.cff.next_state");
      llvm::StoreInst* next_state_store = builder.CreateStore(next_state, state_slot);
      next_state_store->setAlignment(llvm::Align(4));
    } else {
      llvm::BasicBlock* successor = branch->getSuccessor(0);
      auto successor_state_it = state_id_by_block.find(successor);
      assert(successor_state_it != state_id_by_block.end() &&
             "branch successor should be mapped before rewrite");

      llvm::StoreInst* next_state_store = builder.CreateStore(
          llvm::ConstantInt::get(builder.getInt32Ty(), successor_state_it->second), state_slot);
      next_state_store->setAlignment(llvm::Align(4));
    }

    builder.CreateBr(dispatcher);
    branch->eraseFromParent();
  }

  return true;
}

bool string_encryption_already_applied(const llvm::Module& module) {
  return module.getNamedGlobal(kStringEncryptionMarker) != nullptr;
}

void mark_string_encryption_applied(llvm::Module& module) {
  if (module.getNamedGlobal(kStringEncryptionMarker) != nullptr) {
    return;
  }

  llvm::LLVMContext& context = module.getContext();
  auto* marker = new llvm::GlobalVariable(
      module,
      llvm::Type::getInt8Ty(context),
      true,
      llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::get(llvm::Type::getInt8Ty(context), 1u),
      kStringEncryptionMarker);
  marker->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
}

llvm::Function* get_or_create_xor_decrypt_helper(llvm::Module& module) {
  llvm::LLVMContext& context = module.getContext();
  llvm::Type* void_type = llvm::Type::getVoidTy(context);
  llvm::Type* i8_ptr_type = llvm::PointerType::getUnqual(llvm::Type::getInt8Ty(context));
  llvm::Type* i64_type = llvm::Type::getInt64Ty(context);
  llvm::Type* i8_type = llvm::Type::getInt8Ty(context);

  auto* helper_type = llvm::FunctionType::get(void_type, {i8_ptr_type, i64_type, i8_type}, false);
  if (llvm::Function* existing = module.getFunction(kDecryptHelperName)) {
    if (existing->getFunctionType() != helper_type) {
      return nullptr;
    }
    if (!existing->isDeclaration()) {
      return existing;
    }
    existing->setLinkage(llvm::GlobalValue::InternalLinkage);
  }

  llvm::Function* helper = module.getFunction(kDecryptHelperName);
  if (helper == nullptr) {
    helper = llvm::Function::Create(helper_type, llvm::GlobalValue::InternalLinkage,
                                    kDecryptHelperName, module);
  }
  helper->addFnAttr(llvm::Attribute::NoInline);
  helper->setDoesNotThrow();

  if (!helper->empty()) {
    return helper;
  }

  auto argument_it = helper->arg_begin();
  llvm::Argument* base_ptr = argument_it++;
  llvm::Argument* length = argument_it++;
  llvm::Argument* key = argument_it++;
  base_ptr->setName("base");
  length->setName("len");
  key->setName("key");

  llvm::BasicBlock* entry = llvm::BasicBlock::Create(context, "entry", helper);
  llvm::BasicBlock* loop_header = llvm::BasicBlock::Create(context, "loop.header", helper);
  llvm::BasicBlock* loop_body = llvm::BasicBlock::Create(context, "loop.body", helper);
  llvm::BasicBlock* loop_exit = llvm::BasicBlock::Create(context, "loop.exit", helper);

  llvm::IRBuilder<> entry_builder(entry);
  entry_builder.CreateBr(loop_header);

  llvm::IRBuilder<> header_builder(loop_header);
  llvm::PHINode* index = header_builder.CreatePHI(i64_type, 2u, "idx");
  index->addIncoming(header_builder.getInt64(0u), entry);
  llvm::Value* has_more = header_builder.CreateICmpULT(index, length, "has_more");
  header_builder.CreateCondBr(has_more, loop_body, loop_exit);

  llvm::IRBuilder<> body_builder(loop_body);
  llvm::Value* byte_ptr = body_builder.CreateInBoundsGEP(i8_type, base_ptr, index, "byte_ptr");
  llvm::LoadInst* encoded = body_builder.CreateLoad(i8_type, byte_ptr, "encoded");
  llvm::Value* decoded = body_builder.CreateXor(encoded, key, "decoded");
  body_builder.CreateStore(decoded, byte_ptr);
  llvm::Value* next_index = body_builder.CreateAdd(index, body_builder.getInt64(1u), "next_idx");
  body_builder.CreateBr(loop_header);
  index->addIncoming(next_index, loop_body);

  llvm::IRBuilder<> exit_builder(loop_exit);
  exit_builder.CreateRetVoid();
  return helper;
}

llvm::SmallVector<EncryptedStringInfo, 32> encrypt_global_strings(llvm::Module& module) {
  llvm::SmallVector<EncryptedStringInfo, 32> encrypted_strings;
  for (llvm::GlobalVariable& global : module.globals()) {
    if (global.isDeclaration() || !global.hasInitializer()) {
      continue;
    }
    if (global.getName().startswith("llvm.") || global.getName() == kStringEncryptionMarker) {
      continue;
    }
    if (global.hasSection() && global.getSection() == "llvm.metadata") {
      continue;
    }

    auto* data = llvm::dyn_cast<llvm::ConstantDataSequential>(global.getInitializer());
    if (data == nullptr || !data->isString()) {
      continue;
    }

    const llvm::StringRef raw_bytes = data->getAsString();
    if (raw_bytes.empty()) {
      continue;
    }

    std::string encoded;
    encoded.resize(raw_bytes.size());
    for (std::size_t index = 0; index < raw_bytes.size(); ++index) {
      encoded[index] = static_cast<char>(static_cast<std::uint8_t>(raw_bytes[index]) ^ kStringXorKey);
    }

    auto* encrypted_initializer =
        llvm::ConstantDataArray::getString(module.getContext(), encoded, false);
    if (encrypted_initializer->getType() != global.getValueType()) {
      continue;
    }

    global.setInitializer(encrypted_initializer);
    global.setConstant(false);
    encrypted_strings.push_back(
        EncryptedStringInfo{&global, static_cast<std::uint64_t>(encoded.size())});
  }
  return encrypted_strings;
}

bool inject_string_decryption_calls(llvm::Function& main_function, llvm::Function& decrypt_helper,
                                    const llvm::SmallVectorImpl<EncryptedStringInfo>& strings) {
  if (main_function.isDeclaration() || main_function.empty() || strings.empty()) {
    return false;
  }

  llvm::BasicBlock& entry = main_function.getEntryBlock();
  llvm::BasicBlock::iterator insertion_it = entry.getFirstInsertionPt();
  if (insertion_it == entry.end()) {
    return false;
  }

  llvm::IRBuilder<> builder(&*insertion_it);
  llvm::Type* i64_type = builder.getInt64Ty();
  llvm::Type* i8_type = builder.getInt8Ty();

  bool injected = false;
  for (const EncryptedStringInfo& item : strings) {
    if (item.global == nullptr || item.size == 0u) {
      continue;
    }

    auto* array_type = llvm::dyn_cast<llvm::ArrayType>(item.global->getValueType());
    if (array_type == nullptr) {
      continue;
    }

    llvm::Value* string_base = builder.CreateInBoundsGEP(
        array_type, item.global, {builder.getInt64(0u), builder.getInt64(0u)},
        item.global->getName() + ".base");
    builder.CreateCall(&decrypt_helper,
                       {string_base, llvm::ConstantInt::get(i64_type, item.size),
                        llvm::ConstantInt::get(i8_type, kStringXorKey)});
    injected = true;
  }
  return injected;
}

bool apply_global_string_encryption(llvm::Module& module) {
  if (string_encryption_already_applied(module)) {
    return false;
  }

  llvm::Function* main_function = module.getFunction("main");
  if (main_function == nullptr || main_function->isDeclaration() || main_function->empty()) {
    return false;
  }

  llvm::Function* decrypt_helper = get_or_create_xor_decrypt_helper(module);
  if (decrypt_helper == nullptr) {
    llvm::report_fatal_error("CFF string encryption failed to create decrypt helper.");
  }

  llvm::SmallVector<EncryptedStringInfo, 32> encrypted_strings = encrypt_global_strings(module);
  if (encrypted_strings.empty()) {
    return false;
  }

  if (!inject_string_decryption_calls(*main_function, *decrypt_helper, encrypted_strings)) {
    llvm::report_fatal_error("CFF string encryption failed to inject main decryption calls.");
  }

  mark_string_encryption_applied(module);
  return true;
}

}  // namespace

namespace eippf::passes {

llvm::PreservedAnalyses CFFObfuscationPass::run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
  AnnotationSets annotation_sets = collect_annotations(module);

  bool changed = false;
  for (llvm::Function& function : module) {
    if (!should_attempt_flattening(module, function, annotation_sets)) {
      continue;
    }

    changed = rewrite_cfg_to_dispatcher(function) || changed;
  }

  changed = apply_global_string_encryption(module) || changed;

  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

void register_cff_obfuscation_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerOptimizerLastEPCallback(
      [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
        module_pm.addPass(CFFObfuscationPass{});
      });

  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-cff-obfuscation") {
          module_pm.addPass(CFFObfuscationPass{});
          return true;
        }
        return false;
      });
}

}  // namespace eippf::passes

#ifdef EIPPF_CFF_OBFUSCATION_STANDALONE_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFCFFObfuscationPass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) {
        eippf::passes::register_cff_obfuscation_pipeline(pass_builder);
      }};
}
#endif

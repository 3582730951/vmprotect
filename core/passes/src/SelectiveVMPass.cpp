#include "passes/SelectiveVMPass.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Casting.h"

namespace {

constexpr llvm::StringLiteral kCriticalAnnotation("drm_critical_ip");
constexpr llvm::StringLiteral kRouteAttribute("eippf.route");
constexpr llvm::StringLiteral kRouteVm("vm");
constexpr llvm::StringLiteral kVmInjectedAttr("eippf.vm.shell.injected");
constexpr std::size_t kVmRegisterCount = 64u;
constexpr std::size_t kVmInstructionWidth = 4u;
constexpr std::uint32_t kFnv1aOffset = 2166136261u;
constexpr std::uint32_t kFnv1aPrime = 16777619u;

enum class VmOpcode : std::uint8_t {
  kHalt = 0x00u,
  kAdd = 0x10u,
  kSub = 0x11u,
  kXor = 0x12u,
  kAnd = 0x13u,
  kOr = 0x14u,
  kRet = 0x20u,
};

struct VmInstruction {
  VmOpcode opcode = VmOpcode::kHalt;
  std::uint8_t dst = 0u;
  std::uint8_t src1 = 0u;
  std::uint8_t src2 = 0u;
};

enum class VmRegisterInitKind : std::uint8_t {
  kArgument,
  kImmediate,
};

struct VmRegisterInit {
  std::uint8_t reg = 0u;
  VmRegisterInitKind kind = VmRegisterInitKind::kImmediate;
  llvm::Argument* argument = nullptr;
  std::uint64_t immediate = 0u;
};

struct VmCompileResult {
  llvm::SmallVector<VmInstruction, 32> instructions;
  llvm::SmallVector<VmRegisterInit, 32> register_initializers;
  llvm::SmallVector<llvm::Instruction*, 32> translated_native_instructions;
};

std::uint32_t fnv1a_step(std::uint32_t hash, std::uint8_t value) {
  hash ^= static_cast<std::uint32_t>(value);
  hash *= kFnv1aPrime;
  return hash;
}

std::uint32_t fnv1a_append(std::uint32_t seed, llvm::StringRef text) {
  std::uint32_t hash = seed;
  for (const char ch : text) {
    hash = fnv1a_step(hash, static_cast<std::uint8_t>(ch));
  }
  return hash;
}

std::uint32_t fnv1a_append_u64(std::uint32_t seed, std::uint64_t value) {
  std::uint32_t hash = seed;
  for (int index = 0; index < 8; ++index) {
    const std::uint8_t byte_value =
        static_cast<std::uint8_t>((value >> static_cast<unsigned>(index * 8)) & 0xFFu);
    hash = fnv1a_step(hash, byte_value);
  }
  return hash;
}

std::uint8_t stream_mask(std::uint8_t key, std::size_t index) {
  const std::uint8_t salt =
      static_cast<std::uint8_t>(((index * 37u) + (index >> 1u) + 0x5Bu) & 0xFFu);
  return static_cast<std::uint8_t>(key ^ salt);
}

std::uint8_t derive_vm_key(const llvm::Module& module, const llvm::Function& function) {
  std::uint32_t hash = kFnv1aOffset;
  hash = fnv1a_append(hash, module.getModuleIdentifier());
  hash = fnv1a_append(hash, function.getName());
  hash = fnv1a_append_u64(hash, static_cast<std::uint64_t>(function.arg_size()));
  hash = fnv1a_append_u64(hash, static_cast<std::uint64_t>(function.size()));

  std::uint8_t key =
      static_cast<std::uint8_t>((hash ^ (hash >> 8) ^ (hash >> 16) ^ (hash >> 24)) & 0xFFu);
  if (key == 0u) {
    key = 0xA5u;
  }
  return key;
}

llvm::StringRef extract_annotation_text(llvm::Constant* annotation_operand) {
  llvm::Constant* cursor = annotation_operand;

  while (auto* ce = llvm::dyn_cast<llvm::ConstantExpr>(cursor)) {
    if (ce->getNumOperands() == 0u) {
      break;
    }
    cursor = llvm::dyn_cast<llvm::Constant>(ce->getOperand(0));
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

  for (llvm::Function& function : module) {
    const llvm::Attribute route_attribute = function.getFnAttribute(kRouteAttribute);
    if (!route_attribute.isValid() || !route_attribute.isStringAttribute()) {
      continue;
    }
    if (route_attribute.getValueAsString() == kRouteVm) {
      critical_functions.insert(&function);
    }
  }

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
    if (function == nullptr || function->isDeclaration()) {
      continue;
    }

    auto* annotation_operand = llvm::dyn_cast<llvm::Constant>(entry_struct->getOperand(1));
    if (annotation_operand == nullptr) {
      continue;
    }

    const llvm::Attribute route_attribute = function->getFnAttribute(kRouteAttribute);
    if (route_attribute.isValid() && route_attribute.isStringAttribute() &&
        route_attribute.getValueAsString() != kRouteVm) {
      continue;
    }

    llvm::StringRef annotation_text = extract_annotation_text(annotation_operand);
    if (annotation_text == kCriticalAnnotation) {
      critical_functions.insert(function);
    }
  }

  return critical_functions;
}

std::optional<VmOpcode> map_binary_opcode(unsigned opcode) {
  switch (opcode) {
    case llvm::Instruction::Add:
      return VmOpcode::kAdd;
    case llvm::Instruction::Sub:
      return VmOpcode::kSub;
    case llvm::Instruction::Xor:
      return VmOpcode::kXor;
    case llvm::Instruction::And:
      return VmOpcode::kAnd;
    case llvm::Instruction::Or:
      return VmOpcode::kOr;
    default:
      return std::nullopt;
  }
}

std::optional<VmCompileResult> compile_function_to_vm(llvm::Function& function) {
  if (function.isDeclaration() || function.empty()) {
    return std::nullopt;
  }
  if (function.size() != 1u) {
    return std::nullopt;
  }
  if (!function.getReturnType()->isVoidTy() && !function.getReturnType()->isIntegerTy(64)) {
    return std::nullopt;
  }

  llvm::BasicBlock& block = function.getEntryBlock();
  VmCompileResult result;

  llvm::DenseMap<const llvm::Value*, std::uint8_t> value_to_reg;
  std::uint8_t next_reg = 0u;

  auto allocate_register = [&](const llvm::Value* value) -> std::optional<std::uint8_t> {
    if (auto it = value_to_reg.find(value); it != value_to_reg.end()) {
      return it->second;
    }
    if (next_reg >= static_cast<std::uint8_t>(kVmRegisterCount)) {
      return std::nullopt;
    }

    const std::uint8_t assigned_reg = next_reg;
    ++next_reg;
    value_to_reg.try_emplace(value, assigned_reg);
    return assigned_reg;
  };

  auto bind_value_register = [&](llvm::Value* value) -> std::optional<std::uint8_t> {
    if (auto it = value_to_reg.find(value); it != value_to_reg.end()) {
      return it->second;
    }

    if (auto* argument = llvm::dyn_cast<llvm::Argument>(value)) {
      if (!argument->getType()->isIntegerTy(64)) {
        return std::nullopt;
      }

      std::optional<std::uint8_t> reg = allocate_register(argument);
      if (!reg.has_value()) {
        return std::nullopt;
      }
      result.register_initializers.push_back(
          VmRegisterInit{*reg, VmRegisterInitKind::kArgument, argument, 0u});
      return reg;
    }

    if (auto* constant_int = llvm::dyn_cast<llvm::ConstantInt>(value)) {
      if (!constant_int->getType()->isIntegerTy(64)) {
        return std::nullopt;
      }

      std::optional<std::uint8_t> reg = allocate_register(constant_int);
      if (!reg.has_value()) {
        return std::nullopt;
      }
      result.register_initializers.push_back(
          VmRegisterInit{*reg, VmRegisterInitKind::kImmediate, nullptr, constant_int->getZExtValue()});
      return reg;
    }

    return std::nullopt;
  };

  bool saw_return = false;

  for (llvm::Instruction& instruction : block) {
    if (auto* binary = llvm::dyn_cast<llvm::BinaryOperator>(&instruction)) {
      if (!binary->getType()->isIntegerTy(64)) {
        return std::nullopt;
      }

      std::optional<VmOpcode> vm_opcode = map_binary_opcode(binary->getOpcode());
      if (!vm_opcode.has_value()) {
        return std::nullopt;
      }

      std::optional<std::uint8_t> lhs_reg = bind_value_register(binary->getOperand(0));
      std::optional<std::uint8_t> rhs_reg = bind_value_register(binary->getOperand(1));
      std::optional<std::uint8_t> dst_reg = allocate_register(binary);
      if (!lhs_reg.has_value() || !rhs_reg.has_value() || !dst_reg.has_value()) {
        return std::nullopt;
      }

      result.instructions.push_back(VmInstruction{*vm_opcode, *dst_reg, *lhs_reg, *rhs_reg});
      result.translated_native_instructions.push_back(binary);
      continue;
    }

    if (auto* ret = llvm::dyn_cast<llvm::ReturnInst>(&instruction)) {
      if (saw_return) {
        return std::nullopt;
      }
      saw_return = true;

      std::uint8_t ret_reg = 0u;
      if (llvm::Value* return_value = ret->getReturnValue()) {
        if (!return_value->getType()->isIntegerTy(64)) {
          return std::nullopt;
        }

        std::optional<std::uint8_t> bound_return_reg = bind_value_register(return_value);
        if (!bound_return_reg.has_value()) {
          return std::nullopt;
        }
        ret_reg = *bound_return_reg;
      }

      result.instructions.push_back(VmInstruction{VmOpcode::kRet, ret_reg, 0u, 0u});
      result.translated_native_instructions.push_back(ret);
      continue;
    }

    return std::nullopt;
  }

  if (!saw_return || result.instructions.empty()) {
    return std::nullopt;
  }

  result.instructions.push_back(VmInstruction{VmOpcode::kHalt, 0u, 0u, 0u});
  return result;
}

llvm::SmallVector<std::uint8_t, 128> encode_vm_program(const VmCompileResult& compile_result) {
  llvm::SmallVector<std::uint8_t, 128> bytecode;
  bytecode.reserve(compile_result.instructions.size() * kVmInstructionWidth);

  for (const VmInstruction& instruction : compile_result.instructions) {
    bytecode.push_back(static_cast<std::uint8_t>(instruction.opcode));
    bytecode.push_back(instruction.dst);
    bytecode.push_back(instruction.src1);
    bytecode.push_back(instruction.src2);
  }
  return bytecode;
}

llvm::SmallVector<std::uint8_t, 128> obfuscate_vm_program(llvm::ArrayRef<std::uint8_t> plain_bytecode,
                                                           std::uint8_t stream_key) {
  llvm::SmallVector<std::uint8_t, 128> encrypted;
  encrypted.resize(plain_bytecode.size());

  for (std::size_t index = 0; index < plain_bytecode.size(); ++index) {
    encrypted[index] = static_cast<std::uint8_t>(plain_bytecode[index] ^ stream_mask(stream_key, index));
  }
  return encrypted;
}

llvm::GlobalVariable* create_vm_program_global(llvm::Module& module, const llvm::Function& function,
                                               llvm::ArrayRef<std::uint8_t> encrypted_bytecode) {
  llvm::Constant* initializer = llvm::ConstantDataArray::get(module.getContext(), encrypted_bytecode);
  const std::string global_name = ("eippf.vm.bc." + function.getName()).str();

  auto* global = new llvm::GlobalVariable(module, initializer->getType(), true,
                                          llvm::GlobalValue::PrivateLinkage, initializer, global_name);
  global->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  global->setAlignment(llvm::Align(1));
  return global;
}

llvm::Value* get_vm_register_ptr(llvm::IRBuilder<>& builder, llvm::ArrayType* reg_array_ty,
                                 llvm::Value* vm_regs, llvm::Value* reg_index_i8) {
  llvm::Value* reg_index_i64 =
      builder.CreateZExt(reg_index_i8, builder.getInt64Ty(), "eippf.vm.reg.idx64");
  return builder.CreateInBoundsGEP(reg_array_ty, vm_regs, {builder.getInt64(0), reg_index_i64},
                                   "eippf.vm.reg.ptr");
}

llvm::Value* load_vm_register(llvm::IRBuilder<>& builder, llvm::ArrayType* reg_array_ty,
                              llvm::Value* vm_regs, llvm::Value* reg_index_i8) {
  llvm::Value* reg_ptr = get_vm_register_ptr(builder, reg_array_ty, vm_regs, reg_index_i8);
  llvm::LoadInst* loaded = builder.CreateLoad(builder.getInt64Ty(), reg_ptr, "eippf.vm.reg.load");
  loaded->setAlignment(llvm::Align(8));
  return loaded;
}

void store_vm_register(llvm::IRBuilder<>& builder, llvm::ArrayType* reg_array_ty, llvm::Value* vm_regs,
                       llvm::Value* reg_index_i8, llvm::Value* value) {
  llvm::Value* reg_ptr = get_vm_register_ptr(builder, reg_array_ty, vm_regs, reg_index_i8);
  llvm::StoreInst* stored = builder.CreateStore(value, reg_ptr);
  stored->setAlignment(llvm::Align(8));
}

llvm::Value* decode_vm_byte(llvm::IRBuilder<>& builder, llvm::GlobalVariable& bytecode_global,
                            llvm::Value* byte_index_i64, std::uint8_t stream_key) {
  auto* byte_array_ty = llvm::cast<llvm::ArrayType>(bytecode_global.getValueType());
  llvm::Value* byte_ptr = builder.CreateInBoundsGEP(
      byte_array_ty, &bytecode_global, {builder.getInt64(0), byte_index_i64}, "eippf.vm.bc.ptr");
  llvm::LoadInst* encrypted_byte = builder.CreateLoad(builder.getInt8Ty(), byte_ptr, "eippf.vm.bc.enc");
  encrypted_byte->setAlignment(llvm::Align(1));

  llvm::Value* salt_mul =
      builder.CreateMul(byte_index_i64, builder.getInt64(37), "eippf.vm.bc.salt.mul");
  llvm::Value* salt_shift =
      builder.CreateLShr(byte_index_i64, builder.getInt64(1), "eippf.vm.bc.salt.shift");
  llvm::Value* salt = builder.CreateAdd(salt_mul, salt_shift, "eippf.vm.bc.salt.base");
  salt = builder.CreateAdd(salt, builder.getInt64(0x5B), "eippf.vm.bc.salt.full");
  llvm::Value* salt_i8 = builder.CreateTrunc(salt, builder.getInt8Ty(), "eippf.vm.bc.salt");
  llvm::Value* stream =
      builder.CreateXor(builder.getInt8(stream_key), salt_i8, "eippf.vm.bc.stream");

  return builder.CreateXor(encrypted_byte, stream, "eippf.vm.bc.dec");
}

bool inject_vm_shell(llvm::Function& function, const VmCompileResult& compile_result) {
  if (function.isDeclaration() || function.empty()) {
    return false;
  }
  if (function.hasFnAttribute(kVmInjectedAttr)) {
    return false;
  }

  llvm::Module* module = function.getParent();
  if (module == nullptr) {
    return false;
  }

  llvm::SmallVector<std::uint8_t, 128> plain_bytecode = encode_vm_program(compile_result);
  if (plain_bytecode.empty()) {
    return false;
  }

  const std::uint8_t stream_key = derive_vm_key(*module, function);
  llvm::SmallVector<std::uint8_t, 128> encrypted_bytecode =
      obfuscate_vm_program(plain_bytecode, stream_key);
  llvm::GlobalVariable* vm_program_global =
      create_vm_program_global(*module, function, encrypted_bytecode);

  for (auto it = compile_result.translated_native_instructions.rbegin();
       it != compile_result.translated_native_instructions.rend(); ++it) {
    (*it)->eraseFromParent();
  }

  llvm::BasicBlock& entry = function.getEntryBlock();
  if (entry.getTerminator() != nullptr) {
    entry.getTerminator()->eraseFromParent();
  }

  llvm::LLVMContext& context = function.getContext();
  llvm::IRBuilder<> entry_builder(&entry);

  llvm::Type* i1_ty = entry_builder.getInt1Ty();
  llvm::Type* i64_ty = entry_builder.getInt64Ty();

  auto* reg_array_ty = llvm::ArrayType::get(i64_ty, kVmRegisterCount);
  auto* vm_regs = entry_builder.CreateAlloca(reg_array_ty, nullptr, "eippf.vm.regs");
  vm_regs->setAlignment(llvm::Align(16));

  llvm::Value* regs_base = entry_builder.CreateInBoundsGEP(
      reg_array_ty, vm_regs, {entry_builder.getInt64(0), entry_builder.getInt64(0)},
      "eippf.vm.regs.base");
  entry_builder.CreateMemSet(
      regs_base, entry_builder.getInt8(0),
      static_cast<std::uint64_t>(kVmRegisterCount * sizeof(std::uint64_t)), llvm::MaybeAlign(8),
      false);

  for (const VmRegisterInit& reg_init : compile_result.register_initializers) {
    llvm::Value* reg_index = entry_builder.getInt8(reg_init.reg);
    llvm::Value* init_value = entry_builder.getInt64(reg_init.immediate);

    if (reg_init.kind == VmRegisterInitKind::kArgument) {
      if (reg_init.argument == nullptr) {
        return false;
      }
      init_value = reg_init.argument;
    }

    store_vm_register(entry_builder, reg_array_ty, vm_regs, reg_index, init_value);
  }

  auto* vm_active = entry_builder.CreateAlloca(i1_ty, nullptr, "eippf.vm.active");
  vm_active->setAlignment(llvm::Align(1));
  llvm::StoreInst* active_init = entry_builder.CreateStore(entry_builder.getTrue(), vm_active);
  active_init->setAlignment(llvm::Align(1));

  auto* vm_return = entry_builder.CreateAlloca(i64_ty, nullptr, "eippf.vm.ret");
  vm_return->setAlignment(llvm::Align(8));
  llvm::StoreInst* ret_init = entry_builder.CreateStore(entry_builder.getInt64(0), vm_return);
  ret_init->setAlignment(llvm::Align(8));

  llvm::BasicBlock* vm_loop_cond = llvm::BasicBlock::Create(context, "eippf.vm.loop.cond", &function);
  llvm::BasicBlock* vm_dispatch = llvm::BasicBlock::Create(context, "eippf.vm.dispatch", &function);
  llvm::BasicBlock* vm_op_add = llvm::BasicBlock::Create(context, "eippf.vm.op.add", &function);
  llvm::BasicBlock* vm_op_sub = llvm::BasicBlock::Create(context, "eippf.vm.op.sub", &function);
  llvm::BasicBlock* vm_op_xor = llvm::BasicBlock::Create(context, "eippf.vm.op.xor", &function);
  llvm::BasicBlock* vm_op_and = llvm::BasicBlock::Create(context, "eippf.vm.op.and", &function);
  llvm::BasicBlock* vm_op_or = llvm::BasicBlock::Create(context, "eippf.vm.op.or", &function);
  llvm::BasicBlock* vm_op_ret = llvm::BasicBlock::Create(context, "eippf.vm.op.ret", &function);
  llvm::BasicBlock* vm_op_halt = llvm::BasicBlock::Create(context, "eippf.vm.op.halt", &function);
  llvm::BasicBlock* vm_default = llvm::BasicBlock::Create(context, "eippf.vm.op.default", &function);
  llvm::BasicBlock* vm_latch = llvm::BasicBlock::Create(context, "eippf.vm.loop.latch", &function);
  llvm::BasicBlock* vm_exit = llvm::BasicBlock::Create(context, "eippf.vm.exit", &function);

  entry_builder.CreateBr(vm_loop_cond);

  const std::uint64_t vm_program_length =
      static_cast<std::uint64_t>(compile_result.instructions.size());

  llvm::IRBuilder<> loop_cond_builder(vm_loop_cond);
  auto* vpc_phi = loop_cond_builder.CreatePHI(i64_ty, 2, "eippf.vm.vpc");
  vpc_phi->addIncoming(loop_cond_builder.getInt64(0), &entry);

  llvm::LoadInst* active_flag = loop_cond_builder.CreateLoad(i1_ty, vm_active, "eippf.vm.active.load");
  active_flag->setAlignment(llvm::Align(1));
  llvm::Value* vpc_in_range = loop_cond_builder.CreateICmpULT(
      vpc_phi, loop_cond_builder.getInt64(vm_program_length), "eippf.vm.vpc.in.range");
  llvm::Value* can_dispatch =
      loop_cond_builder.CreateAnd(active_flag, vpc_in_range, "eippf.vm.can.dispatch");
  loop_cond_builder.CreateCondBr(can_dispatch, vm_dispatch, vm_exit);

  llvm::IRBuilder<> dispatch_builder(vm_dispatch);
  llvm::Value* byte_offset = dispatch_builder.CreateMul(
      vpc_phi, dispatch_builder.getInt64(static_cast<std::uint64_t>(kVmInstructionWidth)),
      "eippf.vm.bc.offset");
  llvm::Value* opcode = decode_vm_byte(dispatch_builder, *vm_program_global, byte_offset, stream_key);
  llvm::Value* dst = decode_vm_byte(
      dispatch_builder, *vm_program_global,
      dispatch_builder.CreateAdd(byte_offset, dispatch_builder.getInt64(1), "eippf.vm.bc.offset.dst"),
      stream_key);
  llvm::Value* src1 = decode_vm_byte(
      dispatch_builder, *vm_program_global,
      dispatch_builder.CreateAdd(byte_offset, dispatch_builder.getInt64(2), "eippf.vm.bc.offset.src1"),
      stream_key);
  llvm::Value* src2 = decode_vm_byte(
      dispatch_builder, *vm_program_global,
      dispatch_builder.CreateAdd(byte_offset, dispatch_builder.getInt64(3), "eippf.vm.bc.offset.src2"),
      stream_key);

  llvm::SwitchInst* vm_switch = dispatch_builder.CreateSwitch(opcode, vm_default, 7);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kAdd)), vm_op_add);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kSub)), vm_op_sub);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kXor)), vm_op_xor);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kAnd)), vm_op_and);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kOr)), vm_op_or);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kRet)), vm_op_ret);
  vm_switch->addCase(dispatch_builder.getInt8(static_cast<std::uint8_t>(VmOpcode::kHalt)), vm_op_halt);

  llvm::Value* next_vpc_add = nullptr;
  llvm::Value* next_vpc_sub = nullptr;
  llvm::Value* next_vpc_xor = nullptr;
  llvm::Value* next_vpc_and = nullptr;
  llvm::Value* next_vpc_or = nullptr;
  llvm::Value* next_vpc_ret = nullptr;
  llvm::Value* next_vpc_halt = nullptr;
  llvm::Value* next_vpc_default = nullptr;

  llvm::IRBuilder<> add_builder(vm_op_add);
  llvm::Value* add_lhs = load_vm_register(add_builder, reg_array_ty, vm_regs, src1);
  llvm::Value* add_rhs = load_vm_register(add_builder, reg_array_ty, vm_regs, src2);
  llvm::Value* add_result = add_builder.CreateAdd(add_lhs, add_rhs, "eippf.vm.add");
  store_vm_register(add_builder, reg_array_ty, vm_regs, dst, add_result);
  next_vpc_add = add_builder.CreateAdd(vpc_phi, add_builder.getInt64(1), "eippf.vm.vpc.next.add");
  add_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> sub_builder(vm_op_sub);
  llvm::Value* sub_lhs = load_vm_register(sub_builder, reg_array_ty, vm_regs, src1);
  llvm::Value* sub_rhs = load_vm_register(sub_builder, reg_array_ty, vm_regs, src2);
  llvm::Value* sub_result = sub_builder.CreateSub(sub_lhs, sub_rhs, "eippf.vm.sub");
  store_vm_register(sub_builder, reg_array_ty, vm_regs, dst, sub_result);
  next_vpc_sub = sub_builder.CreateAdd(vpc_phi, sub_builder.getInt64(1), "eippf.vm.vpc.next.sub");
  sub_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> xor_builder(vm_op_xor);
  llvm::Value* xor_lhs = load_vm_register(xor_builder, reg_array_ty, vm_regs, src1);
  llvm::Value* xor_rhs = load_vm_register(xor_builder, reg_array_ty, vm_regs, src2);
  llvm::Value* xor_result = xor_builder.CreateXor(xor_lhs, xor_rhs, "eippf.vm.xor");
  store_vm_register(xor_builder, reg_array_ty, vm_regs, dst, xor_result);
  next_vpc_xor = xor_builder.CreateAdd(vpc_phi, xor_builder.getInt64(1), "eippf.vm.vpc.next.xor");
  xor_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> and_builder(vm_op_and);
  llvm::Value* and_lhs = load_vm_register(and_builder, reg_array_ty, vm_regs, src1);
  llvm::Value* and_rhs = load_vm_register(and_builder, reg_array_ty, vm_regs, src2);
  llvm::Value* and_result = and_builder.CreateAnd(and_lhs, and_rhs, "eippf.vm.and");
  store_vm_register(and_builder, reg_array_ty, vm_regs, dst, and_result);
  next_vpc_and = and_builder.CreateAdd(vpc_phi, and_builder.getInt64(1), "eippf.vm.vpc.next.and");
  and_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> or_builder(vm_op_or);
  llvm::Value* or_lhs = load_vm_register(or_builder, reg_array_ty, vm_regs, src1);
  llvm::Value* or_rhs = load_vm_register(or_builder, reg_array_ty, vm_regs, src2);
  llvm::Value* or_result = or_builder.CreateOr(or_lhs, or_rhs, "eippf.vm.or");
  store_vm_register(or_builder, reg_array_ty, vm_regs, dst, or_result);
  next_vpc_or = or_builder.CreateAdd(vpc_phi, or_builder.getInt64(1), "eippf.vm.vpc.next.or");
  or_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> ret_builder(vm_op_ret);
  if (!function.getReturnType()->isVoidTy()) {
    llvm::Value* ret_value = load_vm_register(ret_builder, reg_array_ty, vm_regs, dst);
    llvm::StoreInst* ret_store = ret_builder.CreateStore(ret_value, vm_return);
    ret_store->setAlignment(llvm::Align(8));
  }
  llvm::StoreInst* ret_active_store = ret_builder.CreateStore(ret_builder.getFalse(), vm_active);
  ret_active_store->setAlignment(llvm::Align(1));
  next_vpc_ret = ret_builder.CreateAdd(vpc_phi, ret_builder.getInt64(1), "eippf.vm.vpc.next.ret");
  ret_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> halt_builder(vm_op_halt);
  llvm::StoreInst* halt_active_store = halt_builder.CreateStore(halt_builder.getFalse(), vm_active);
  halt_active_store->setAlignment(llvm::Align(1));
  next_vpc_halt = halt_builder.CreateAdd(vpc_phi, halt_builder.getInt64(1), "eippf.vm.vpc.next.halt");
  halt_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> default_builder(vm_default);
  llvm::StoreInst* default_active_store =
      default_builder.CreateStore(default_builder.getFalse(), vm_active);
  default_active_store->setAlignment(llvm::Align(1));
  next_vpc_default = vpc_phi;
  default_builder.CreateBr(vm_latch);

  llvm::IRBuilder<> latch_builder(vm_latch);
  auto* next_vpc_phi = latch_builder.CreatePHI(i64_ty, 8, "eippf.vm.vpc.next");
  next_vpc_phi->addIncoming(next_vpc_add, vm_op_add);
  next_vpc_phi->addIncoming(next_vpc_sub, vm_op_sub);
  next_vpc_phi->addIncoming(next_vpc_xor, vm_op_xor);
  next_vpc_phi->addIncoming(next_vpc_and, vm_op_and);
  next_vpc_phi->addIncoming(next_vpc_or, vm_op_or);
  next_vpc_phi->addIncoming(next_vpc_ret, vm_op_ret);
  next_vpc_phi->addIncoming(next_vpc_halt, vm_op_halt);
  next_vpc_phi->addIncoming(next_vpc_default, vm_default);
  vpc_phi->addIncoming(next_vpc_phi, vm_latch);
  latch_builder.CreateBr(vm_loop_cond);

  llvm::IRBuilder<> exit_builder(vm_exit);
  if (function.getReturnType()->isVoidTy()) {
    exit_builder.CreateRetVoid();
  } else {
    llvm::LoadInst* ret_value = exit_builder.CreateLoad(i64_ty, vm_return, "eippf.vm.ret.load");
    ret_value->setAlignment(llvm::Align(8));
    exit_builder.CreateRet(ret_value);
  }

  function.addFnAttr(kVmInjectedAttr);
  return true;
}

bool inject_fail_closed_trap(llvm::Function& function) {
  if (function.hasFnAttribute(kVmInjectedAttr)) {
    return false;
  }

  llvm::Module* module = function.getParent();
  if (module == nullptr) {
    return false;
  }

  llvm::Function* trap_function =
      llvm::Intrinsic::getDeclaration(module, llvm::Intrinsic::trap);

  llvm::SmallVector<llvm::BasicBlock*, 8> old_blocks;
  old_blocks.reserve(function.size());
  for (llvm::BasicBlock& block : function) {
    old_blocks.push_back(&block);
  }

  llvm::BasicBlock* fail_closed_block =
      llvm::BasicBlock::Create(function.getContext(), "eippf.vm.fail_closed", &function);
  llvm::IRBuilder<> builder(fail_closed_block);
  builder.CreateCall(trap_function);
  builder.CreateUnreachable();

  for (llvm::BasicBlock* block : old_blocks) {
    if (block == fail_closed_block) {
      continue;
    }
    block->dropAllReferences();
  }
  for (llvm::BasicBlock* block : old_blocks) {
    if (block == fail_closed_block) {
      continue;
    }
    block->eraseFromParent();
  }

  function.addFnAttr(kVmInjectedAttr);
  function.addFnAttr("eippf.vm.fail_closed");
  return true;
}

}  // namespace

namespace eippf::passes {

SelectiveVMFunctionPass::SelectiveVMFunctionPass(
    const llvm::SmallPtrSetImpl<llvm::Function*>& annotated_functions) noexcept
    : annotated_functions_(annotated_functions) {}

llvm::PreservedAnalyses SelectiveVMFunctionPass::run(llvm::Function& function,
                                                     llvm::FunctionAnalysisManager&) {
  if (!annotated_functions_.contains(&function)) {
    return llvm::PreservedAnalyses::all();
  }
  if (function.hasFnAttribute(kVmInjectedAttr)) {
    return llvm::PreservedAnalyses::all();
  }

  std::optional<VmCompileResult> compile_result = compile_function_to_vm(function);
  if (!compile_result.has_value()) {
    const bool changed = inject_fail_closed_trap(function);
    return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
  }

  bool changed = inject_vm_shell(function, *compile_result);
  if (!changed) {
    changed = inject_fail_closed_trap(function);
  }
  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

llvm::PreservedAnalyses SelectiveVMPass::run(llvm::Module& module, llvm::ModuleAnalysisManager&) {
  llvm::SmallPtrSet<llvm::Function*, 32> critical_functions = collect_critical_functions(module);
  if (critical_functions.empty()) {
    return llvm::PreservedAnalyses::all();
  }

  SelectiveVMFunctionPass function_pass(critical_functions);
  llvm::FunctionAnalysisManager function_am;

  bool changed = false;
  for (llvm::Function& function : module) {
    llvm::PreservedAnalyses pa = function_pass.run(function, function_am);
    changed = changed || !pa.areAllPreserved();
  }

  return changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

void register_selective_vm_pipeline(llvm::PassBuilder& pass_builder) {
  pass_builder.registerOptimizerLastEPCallback(
      [](llvm::ModulePassManager& module_pm, llvm::OptimizationLevel) {
        module_pm.addPass(SelectiveVMPass{});
      });

  pass_builder.registerPipelineParsingCallback(
      [](llvm::StringRef name, llvm::ModulePassManager& module_pm,
         llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
        if (name == "eippf-selective-vm") {
          module_pm.addPass(SelectiveVMPass{});
          return true;
        }
        return false;
      });
}

}  // namespace eippf::passes

#ifdef EIPPF_SELECTIVE_VM_STANDALONE_PLUGIN
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "EIPPFSelectiveVMPass",
      LLVM_VERSION_STRING,
      [](llvm::PassBuilder& pass_builder) { eippf::passes::register_selective_vm_pipeline(pass_builder); }};
}
#endif

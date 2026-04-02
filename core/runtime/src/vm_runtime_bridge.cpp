#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include <limits>
#include <unordered_map>
#include <vector>

#include "runtime/proprietary_isa.hpp"
#include "runtime/secure_ir_engine.hpp"

namespace {

namespace pir = eippf::runtime::pir;
using SecureIREngine = eippf::runtime::ir::SecureIREngine;

constexpr std::size_t kMaxBridgeBytecodeLength = 1u << 20;
constexpr std::uint32_t kMaxVm2Slots = 1u << 20;

[[nodiscard]] bool read_u16_le(const std::uint8_t* data,
                               std::size_t length,
                               std::size_t& offset,
                               std::uint16_t& out) noexcept {
  if (data == nullptr || offset + 1u >= length) {
    return false;
  }
  out = static_cast<std::uint16_t>(data[offset]) |
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[offset + 1u]) << 8u);
  offset += 2u;
  return true;
}

[[nodiscard]] bool read_i64_le(const std::uint8_t* data,
                               std::size_t length,
                               std::size_t& offset,
                               std::int64_t& out) noexcept {
  if (data == nullptr || (offset + sizeof(std::int64_t)) > length) {
    return false;
  }
  std::int64_t value = 0;
  for (std::size_t i = 0; i < sizeof(std::int64_t); ++i) {
    value |= static_cast<std::int64_t>(static_cast<std::uint64_t>(data[offset + i]) << (8u * i));
  }
  out = value;
  offset += sizeof(std::int64_t);
  return true;
}

[[nodiscard]] bool read_u32_le(const std::uint8_t* data,
                               std::size_t length,
                               std::size_t& offset,
                               std::uint32_t& out) noexcept {
  if (data == nullptr || (offset + sizeof(std::uint32_t)) > length) {
    return false;
  }
  out = static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1u]) << 8u) |
        (static_cast<std::uint32_t>(data[offset + 2u]) << 16u) |
        (static_cast<std::uint32_t>(data[offset + 3u]) << 24u);
  offset += sizeof(std::uint32_t);
  return true;
}

[[nodiscard]] bool read_u64_le(const std::uint8_t* data,
                               std::size_t length,
                               std::size_t& offset,
                               std::uint64_t& out) noexcept {
  if (data == nullptr || (offset + sizeof(std::uint64_t)) > length) {
    return false;
  }
  out = 0u;
  for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
    out |= (static_cast<std::uint64_t>(data[offset + i]) << (8u * i));
  }
  offset += sizeof(std::uint64_t);
  return true;
}

struct Vm2Instruction final {
  std::uint16_t opcode = 0u;
  std::uint16_t flags = 0u;
  std::uint32_t dst = 0u;
  std::uint32_t src0 = 0u;
  std::uint32_t src1 = 0u;
  std::int64_t imm = 0;
  std::uint64_t aux = 0u;
};

struct Vm2Program final {
  std::uint32_t slot_count = 0u;
  std::uint32_t arg_count = 0u;
  std::uint32_t entry_block = 0u;
  std::vector<Vm2Instruction> instructions;
  std::unordered_map<std::uint32_t, std::size_t> block_pc;
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
constexpr std::size_t kMaxVm2InstructionCount = 1u << 20;
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

[[nodiscard]] bool is_vm2_program(const std::uint8_t* bytecode, std::size_t length) noexcept {
  return bytecode != nullptr && length >= 6u && bytecode[0] == 'E' && bytecode[1] == 'V' &&
         bytecode[2] == 'M' && bytecode[3] == '2';
}

[[nodiscard]] bool parse_vm2_program(const std::uint8_t* bytecode,
                                     std::size_t length,
                                     Vm2Program& out) noexcept {
  out = Vm2Program{};
  if (!is_vm2_program(bytecode, length) || length > kMaxBridgeBytecodeLength) {
    return false;
  }

  std::size_t offset = 4u;
  std::uint16_t version = 0u;
  std::uint16_t reserved = 0u;
  std::uint32_t slot_count = 0u;
  std::uint32_t arg_count = 0u;
  std::uint32_t entry_block = 0u;
  std::uint32_t inst_count = 0u;
  if (!read_u16_le(bytecode, length, offset, version) ||
      !read_u16_le(bytecode, length, offset, reserved) ||
      !read_u32_le(bytecode, length, offset, slot_count) ||
      !read_u32_le(bytecode, length, offset, arg_count) ||
      !read_u32_le(bytecode, length, offset, entry_block) ||
      !read_u32_le(bytecode, length, offset, inst_count)) {
    return false;
  }
  if (reserved != 0u || version != kVm2Version || inst_count > kMaxVm2InstructionCount ||
      slot_count > kMaxVm2Slots) {
    return false;
  }

  out.slot_count = slot_count;
  out.arg_count = arg_count;
  out.entry_block = entry_block;
  out.instructions.reserve(inst_count);

  for (std::uint32_t i = 0; i < inst_count; ++i) {
    Vm2Instruction inst{};
    if (!read_u16_le(bytecode, length, offset, inst.opcode) ||
        !read_u16_le(bytecode, length, offset, inst.flags) ||
        !read_u32_le(bytecode, length, offset, inst.dst) ||
        !read_u32_le(bytecode, length, offset, inst.src0) ||
        !read_u32_le(bytecode, length, offset, inst.src1) ||
        !read_i64_le(bytecode, length, offset, inst.imm) ||
        !read_u64_le(bytecode, length, offset, inst.aux)) {
      return false;
    }
    out.instructions.push_back(inst);
  }
  if (offset != length) {
    return false;
  }

  for (std::size_t pc = 0; pc < out.instructions.size(); ++pc) {
    const Vm2Instruction& inst = out.instructions[pc];
    if (static_cast<pir::OpCode>(inst.opcode) == pir::OpCode::kNop &&
        (inst.flags & kVm2LabelFlag) != 0u) {
      out.block_pc[static_cast<std::uint32_t>(inst.imm)] = pc;
    }
  }
  return !out.instructions.empty();
}

[[nodiscard]] std::uint64_t mask_for_bits(std::uint16_t bits) noexcept {
  if (bits == 0u || bits >= 64u) {
    return ~static_cast<std::uint64_t>(0u);
  }
  return (static_cast<std::uint64_t>(1u) << bits) - 1u;
}

[[nodiscard]] std::int64_t apply_bitwidth(std::int64_t value,
                                          std::uint16_t bits,
                                          bool sign_extend) noexcept {
  const std::uint64_t mask = mask_for_bits(bits);
  std::uint64_t raw = static_cast<std::uint64_t>(value) & mask;
  if (!sign_extend || bits == 0u || bits >= 64u) {
    return static_cast<std::int64_t>(raw);
  }
  const std::uint64_t sign = static_cast<std::uint64_t>(1u) << (bits - 1u);
  if ((raw & sign) != 0u) {
    raw |= ~mask;
  }
  return static_cast<std::int64_t>(raw);
}

[[nodiscard]] double decode_fp_value(std::int64_t raw, std::uint16_t bits) noexcept {
  if (bits <= 32u) {
    const std::uint32_t payload = static_cast<std::uint32_t>(static_cast<std::uint64_t>(raw) & 0xFFFFFFFFu);
    const float fv = std::bit_cast<float>(payload);
    return static_cast<double>(fv);
  }
  const std::uint64_t payload = static_cast<std::uint64_t>(raw);
  return std::bit_cast<double>(payload);
}

[[nodiscard]] std::int64_t encode_fp_value(double value, std::uint16_t bits) noexcept {
  if (bits <= 32u) {
    const float fv = static_cast<float>(value);
    const std::uint32_t payload = std::bit_cast<std::uint32_t>(fv);
    return static_cast<std::int64_t>(payload);
  }
  const std::uint64_t payload = std::bit_cast<std::uint64_t>(value);
  return static_cast<std::int64_t>(payload);
}

[[nodiscard]] bool eval_fcmp(double lhs, double rhs, std::uint16_t predicate) noexcept {
  const bool lhs_nan = std::isnan(lhs);
  const bool rhs_nan = std::isnan(rhs);
  const bool ordered = !(lhs_nan || rhs_nan);
  const bool unordered = !ordered;

  switch (predicate) {
    case kVm2FCmpOEq:
      return ordered && lhs == rhs;
    case kVm2FCmpONe:
      return ordered && lhs != rhs;
    case kVm2FCmpOLt:
      return ordered && lhs < rhs;
    case kVm2FCmpOLe:
      return ordered && lhs <= rhs;
    case kVm2FCmpOGt:
      return ordered && lhs > rhs;
    case kVm2FCmpOGe:
      return ordered && lhs >= rhs;
    case kVm2FCmpUEq:
      return unordered || lhs == rhs;
    case kVm2FCmpUNe:
      return unordered || lhs != rhs;
    case kVm2FCmpULt:
      return unordered || lhs < rhs;
    case kVm2FCmpULe:
      return unordered || lhs <= rhs;
    case kVm2FCmpUGt:
      return unordered || lhs > rhs;
    case kVm2FCmpUGe:
      return unordered || lhs >= rhs;
    case kVm2FCmpOrd:
      return ordered;
    case kVm2FCmpUno:
      return unordered;
    case kVm2FCmpTrue:
      return true;
    case kVm2FCmpFalse:
      return false;
    default:
      return false;
  }
}

[[nodiscard]] bool fp_to_signed_checked(double value, std::uint16_t bits, std::int64_t& out) noexcept {
  if (!std::isfinite(value)) {
    return false;
  }
  const std::uint16_t clamped_bits = bits == 0u ? 64u : bits;
  if (clamped_bits >= 64u) {
    constexpr double kMin = static_cast<double>(std::numeric_limits<std::int64_t>::min());
    constexpr double kMax = static_cast<double>(std::numeric_limits<std::int64_t>::max());
    if (value < kMin || value > kMax) {
      return false;
    }
    out = static_cast<std::int64_t>(value);
    return true;
  }

  const std::int64_t min_value = -(static_cast<std::int64_t>(1) << (clamped_bits - 1u));
  const std::int64_t max_value = (static_cast<std::int64_t>(1) << (clamped_bits - 1u)) - 1;
  if (value < static_cast<double>(min_value) || value > static_cast<double>(max_value)) {
    return false;
  }
  out = static_cast<std::int64_t>(value);
  return true;
}

[[nodiscard]] bool fp_to_unsigned_checked(double value, std::uint16_t bits, std::uint64_t& out) noexcept {
  if (!std::isfinite(value) || value < 0.0) {
    return false;
  }
  const std::uint16_t clamped_bits = bits == 0u ? 64u : bits;
  if (clamped_bits >= 64u) {
    constexpr long double kMax = static_cast<long double>(std::numeric_limits<std::uint64_t>::max());
    if (static_cast<long double>(value) > kMax) {
      return false;
    }
    out = static_cast<std::uint64_t>(value);
    return true;
  }

  const std::uint64_t max_value = (static_cast<std::uint64_t>(1) << clamped_bits) - 1u;
  if (value > static_cast<double>(max_value)) {
    return false;
  }
  out = static_cast<std::uint64_t>(value);
  return true;
}

[[nodiscard]] bool execute_vm2_program(const Vm2Program& program,
                                       const std::int64_t* args,
                                       std::size_t arg_count,
                                       const void* const* vm_call_table,
                                       std::size_t vm_call_count,
                                       std::int64_t& out_result) noexcept {
  if (program.instructions.empty() || program.slot_count > kMaxVm2Slots) {
    return false;
  }

  auto block_it = program.block_pc.find(program.entry_block);
  if (block_it == program.block_pc.end()) {
    return false;
  }

  const std::size_t slot_count = program.slot_count == 0u ? 1u : program.slot_count;
  std::vector<std::int64_t> slots(slot_count, 0);
  const std::size_t init_args = std::min<std::size_t>(
      std::min<std::size_t>(arg_count, static_cast<std::size_t>(program.arg_count)),
      static_cast<std::size_t>(program.slot_count));
  for (std::size_t i = 0; i < init_args; ++i) {
    slots[i] = args != nullptr ? args[i] : 0;
  }

  std::size_t pc = block_it->second;
  std::uint32_t current_block = program.entry_block;
  std::uint32_t pred_block = kVm2InvalidSlot;
  std::size_t step_budget = 10000000u;

  auto slot_value = [&](std::uint32_t id) -> std::int64_t {
    if (id == kVm2InvalidSlot || id >= program.slot_count) {
      return 0;
    }
    return slots[id];
  };
  auto store_slot = [&](std::uint32_t id, std::int64_t value) {
    if (id != kVm2InvalidSlot && id < program.slot_count) {
      slots[id] = value;
    }
  };
  auto jump_to_block = [&](std::uint32_t target) -> bool {
    auto it = program.block_pc.find(target);
    if (it == program.block_pc.end()) {
      return false;
    }
    pred_block = current_block;
    pc = it->second;
    return true;
  };

  auto execute_vm_call = [&](std::uint32_t call_index,
                             std::int64_t arg0,
                             std::int64_t arg1,
                             bool arg0_is_slot_base,
                             std::int64_t& out) -> bool {
    if (vm_call_table == nullptr || call_index >= vm_call_count) {
      return false;
    }
    const void* entry = vm_call_table[call_index];
    if (entry == nullptr) {
      return false;
    }
    using VmCall2Fn = std::int64_t (*)(std::int64_t, std::int64_t);
    const auto fn = reinterpret_cast<VmCall2Fn>(const_cast<void*>(entry));
    std::int64_t wrapped_arg0 = arg0;
    if (arg0_is_slot_base && arg1 > 0) {
      const std::uint64_t base_u64 = static_cast<std::uint64_t>(arg0);
      const std::uint64_t count_u64 = static_cast<std::uint64_t>(arg1);
      const std::uint64_t slots_size_u64 = static_cast<std::uint64_t>(slots.size());
      if (base_u64 >= slots_size_u64 || count_u64 > slots_size_u64 ||
          base_u64 + count_u64 > slots_size_u64) {
        return false;
      }
      std::int64_t* packet_ptr = &slots[static_cast<std::size_t>(base_u64)];
      wrapped_arg0 = static_cast<std::int64_t>(reinterpret_cast<std::intptr_t>(packet_ptr));
    }
    out = fn(wrapped_arg0, arg1);
    return true;
  };

  while (pc < program.instructions.size() && step_budget-- > 0u) {
    const Vm2Instruction& inst = program.instructions[pc];
    const pir::OpCode opcode = static_cast<pir::OpCode>(inst.opcode);
    switch (opcode) {
      case pir::OpCode::kNop:
        if ((inst.flags & kVm2LabelFlag) != 0u) {
          current_block = static_cast<std::uint32_t>(inst.imm);
        }
        ++pc;
        break;
      case pir::OpCode::kPhiMove: {
        if (pred_block == static_cast<std::uint32_t>(inst.aux)) {
          const bool imm = (inst.flags & kVm2PhiImmediateFlag) != 0u;
          store_slot(inst.dst, imm ? inst.imm : slot_value(inst.src0));
        }
        ++pc;
        break;
      }
      case pir::OpCode::kLoadImmI64:
        store_slot(inst.dst, inst.imm);
        ++pc;
        break;
      case pir::OpCode::kMov: {
        std::int64_t source = slot_value(inst.src0);
        const std::uint16_t src_bits = static_cast<std::uint16_t>((inst.aux >> 32u) & 0xFFu);
        const std::uint16_t dst_bits = static_cast<std::uint16_t>(inst.aux & 0xFFu);
        const std::uint16_t mode = inst.flags;
        if (mode == kVm2CastSignedFlag) {
          source = apply_bitwidth(source, src_bits == 0u ? 64u : src_bits, true);
          source = apply_bitwidth(source, dst_bits == 0u ? 64u : dst_bits, false);
        } else if (mode == kVm2CastUnsignedFlag) {
          source = apply_bitwidth(source, dst_bits == 0u ? 64u : dst_bits, false);
        } else if (mode == kVm2CastSIToFPFlag) {
          const std::int64_t signed_value =
              apply_bitwidth(source, src_bits == 0u ? 64u : src_bits, true);
          source = encode_fp_value(static_cast<double>(signed_value), dst_bits == 0u ? 64u : dst_bits);
        } else if (mode == kVm2CastUIToFPFlag) {
          const std::uint64_t unsigned_value = static_cast<std::uint64_t>(
              apply_bitwidth(source, src_bits == 0u ? 64u : src_bits, false));
          source = encode_fp_value(static_cast<double>(unsigned_value), dst_bits == 0u ? 64u : dst_bits);
        } else if (mode == kVm2CastFPToSIFlag) {
          const double as_fp = decode_fp_value(source, src_bits == 0u ? 64u : src_bits);
          std::int64_t converted = 0;
          if (!fp_to_signed_checked(as_fp, dst_bits == 0u ? 64u : dst_bits, converted)) {
            return false;
          }
          source = apply_bitwidth(converted, dst_bits == 0u ? 64u : dst_bits, false);
        } else if (mode == kVm2CastFPToUIFlag) {
          const double as_fp = decode_fp_value(source, src_bits == 0u ? 64u : src_bits);
          std::uint64_t converted = 0u;
          if (!fp_to_unsigned_checked(as_fp, dst_bits == 0u ? 64u : dst_bits, converted)) {
            return false;
          }
          source = apply_bitwidth(static_cast<std::int64_t>(converted), dst_bits == 0u ? 64u : dst_bits, false);
        } else if (mode == kVm2CastFPTruncFlag || mode == kVm2CastFPExtFlag) {
          const double as_fp = decode_fp_value(source, src_bits == 0u ? 64u : src_bits);
          source = encode_fp_value(as_fp, dst_bits == 0u ? 64u : dst_bits);
        }
        store_slot(inst.dst, source);
        ++pc;
        break;
      }
      case pir::OpCode::kAddI:
      case pir::OpCode::kSubI:
      case pir::OpCode::kMulI:
      case pir::OpCode::kDivUI:
      case pir::OpCode::kDivSI:
      case pir::OpCode::kRemUI:
      case pir::OpCode::kRemSI:
      case pir::OpCode::kNegI:
      case pir::OpCode::kAbsI:
      case pir::OpCode::kMinI:
      case pir::OpCode::kMaxI:
      case pir::OpCode::kAnd:
      case pir::OpCode::kOr:
      case pir::OpCode::kXor:
      case pir::OpCode::kNot:
      case pir::OpCode::kShl:
      case pir::OpCode::kLShr:
      case pir::OpCode::kAShr: {
        const std::uint16_t bits = inst.flags == 0u ? 64u : inst.flags;
        const std::uint64_t mask = mask_for_bits(bits);
        std::uint64_t lhs = static_cast<std::uint64_t>(slot_value(inst.src0)) & mask;
        std::uint64_t rhs = static_cast<std::uint64_t>(slot_value(inst.src1)) & mask;
        std::uint64_t result = 0u;
        switch (opcode) {
          case pir::OpCode::kAddI:
            result = lhs + rhs;
            break;
          case pir::OpCode::kSubI:
            result = lhs - rhs;
            break;
          case pir::OpCode::kMulI:
            result = lhs * rhs;
            break;
          case pir::OpCode::kDivUI:
            if (rhs == 0u) {
              return false;
            }
            result = lhs / rhs;
            break;
          case pir::OpCode::kDivSI: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            const std::int64_t sr = apply_bitwidth(static_cast<std::int64_t>(rhs), bits, true);
            if (sr == 0) {
              return false;
            }
            result = static_cast<std::uint64_t>(sl / sr);
            break;
          }
          case pir::OpCode::kRemUI:
            if (rhs == 0u) {
              return false;
            }
            result = lhs % rhs;
            break;
          case pir::OpCode::kRemSI: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            const std::int64_t sr = apply_bitwidth(static_cast<std::int64_t>(rhs), bits, true);
            if (sr == 0) {
              return false;
            }
            result = static_cast<std::uint64_t>(sl % sr);
            break;
          }
          case pir::OpCode::kNegI: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            result = static_cast<std::uint64_t>(-sl);
            break;
          }
          case pir::OpCode::kAbsI: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            result = static_cast<std::uint64_t>(sl < 0 ? -sl : sl);
            break;
          }
          case pir::OpCode::kMinI: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            const std::int64_t sr = apply_bitwidth(static_cast<std::int64_t>(rhs), bits, true);
            result = static_cast<std::uint64_t>(sl < sr ? sl : sr);
            break;
          }
          case pir::OpCode::kMaxI: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            const std::int64_t sr = apply_bitwidth(static_cast<std::int64_t>(rhs), bits, true);
            result = static_cast<std::uint64_t>(sl > sr ? sl : sr);
            break;
          }
          case pir::OpCode::kAnd:
            result = lhs & rhs;
            break;
          case pir::OpCode::kOr:
            result = lhs | rhs;
            break;
          case pir::OpCode::kXor:
            result = lhs ^ rhs;
            break;
          case pir::OpCode::kNot:
            result = ~lhs;
            break;
          case pir::OpCode::kShl:
            result = lhs << static_cast<unsigned>(rhs & 63u);
            break;
          case pir::OpCode::kLShr:
            result = lhs >> static_cast<unsigned>(rhs & 63u);
            break;
          case pir::OpCode::kAShr: {
            const std::int64_t sl = apply_bitwidth(static_cast<std::int64_t>(lhs), bits, true);
            result = static_cast<std::uint64_t>(sl >> static_cast<unsigned>(rhs & 63u));
            break;
          }
          default:
            break;
        }
        result &= mask;
        store_slot(inst.dst, static_cast<std::int64_t>(result));
        ++pc;
        break;
      }
      case pir::OpCode::kAddF:
      case pir::OpCode::kSubF:
      case pir::OpCode::kMulF:
      case pir::OpCode::kDivF:
      case pir::OpCode::kAbsF:
      case pir::OpCode::kMinF:
      case pir::OpCode::kMaxF: {
        const std::uint16_t bits = inst.flags == 0u ? 64u : inst.flags;
        const double lhs = decode_fp_value(slot_value(inst.src0), bits);
        const double rhs = decode_fp_value(slot_value(inst.src1), bits);
        double result = 0.0;
        switch (opcode) {
          case pir::OpCode::kAddF:
            result = lhs + rhs;
            break;
          case pir::OpCode::kSubF:
            result = lhs - rhs;
            break;
          case pir::OpCode::kMulF:
            result = lhs * rhs;
            break;
          case pir::OpCode::kDivF:
            result = lhs / rhs;
            break;
          case pir::OpCode::kAbsF:
            result = std::fabs(lhs);
            break;
          case pir::OpCode::kMinF:
            result = std::fmin(lhs, rhs);
            break;
          case pir::OpCode::kMaxF:
            result = std::fmax(lhs, rhs);
            break;
          default:
            break;
        }
        store_slot(inst.dst, encode_fp_value(result, bits));
        ++pc;
        break;
      }
      case pir::OpCode::kCmpI: {
        const std::uint16_t bits =
            inst.aux == 0u ? 64u : static_cast<std::uint16_t>(inst.aux & 0xFFu);
        const std::uint64_t mask = mask_for_bits(bits);
        const std::uint64_t lhs_u = static_cast<std::uint64_t>(slot_value(inst.src0)) & mask;
        const std::uint64_t rhs_u = static_cast<std::uint64_t>(slot_value(inst.src1)) & mask;
        const std::int64_t lhs_s = apply_bitwidth(static_cast<std::int64_t>(lhs_u), bits, true);
        const std::int64_t rhs_s = apply_bitwidth(static_cast<std::int64_t>(rhs_u), bits, true);
        bool cmp = false;
        switch (static_cast<pir::ConditionCode>(inst.flags & 0xFFu)) {
          case pir::ConditionCode::kEq:
            cmp = lhs_u == rhs_u;
            break;
          case pir::ConditionCode::kNe:
            cmp = lhs_u != rhs_u;
            break;
          case pir::ConditionCode::kLt:
            cmp = lhs_s < rhs_s;
            break;
          case pir::ConditionCode::kLe:
            cmp = lhs_s <= rhs_s;
            break;
          case pir::ConditionCode::kGt:
            cmp = lhs_s > rhs_s;
            break;
          case pir::ConditionCode::kGe:
            cmp = lhs_s >= rhs_s;
            break;
          case pir::ConditionCode::kUlt:
            cmp = lhs_u < rhs_u;
            break;
          case pir::ConditionCode::kUle:
            cmp = lhs_u <= rhs_u;
            break;
          case pir::ConditionCode::kUgt:
            cmp = lhs_u > rhs_u;
            break;
          case pir::ConditionCode::kUge:
            cmp = lhs_u >= rhs_u;
            break;
        }
        store_slot(inst.dst, cmp ? 1 : 0);
        ++pc;
        break;
      }
      case pir::OpCode::kCmpF: {
        const std::uint16_t bits =
            inst.aux == 0u ? 64u : static_cast<std::uint16_t>(inst.aux & 0xFFu);
        const double lhs = decode_fp_value(slot_value(inst.src0), bits);
        const double rhs = decode_fp_value(slot_value(inst.src1), bits);
        const bool cmp = eval_fcmp(lhs, rhs, static_cast<std::uint16_t>(inst.flags & 0xFFu));
        store_slot(inst.dst, cmp ? 1 : 0);
        ++pc;
        break;
      }
      case pir::OpCode::kSelect:
        store_slot(inst.dst, slot_value(inst.src0) != 0 ? slot_value(inst.src1)
                                                         : slot_value(static_cast<std::uint32_t>(inst.aux)));
        ++pc;
        break;
      case pir::OpCode::kCall: {
        if (inst.imm < 0) {
          return false;
        }
        std::int64_t call_result = 0;
        const bool arg0_is_slot_base = (inst.aux & kVm2CallArg0IsSlotBaseFlag) != 0u;
        if (!execute_vm_call(static_cast<std::uint32_t>(inst.imm),
                             slot_value(inst.src0),
                             slot_value(inst.src1),
                             arg0_is_slot_base,
                             call_result)) {
          return false;
        }
        if (inst.dst != kVm2InvalidSlot) {
          store_slot(inst.dst, call_result);
        }
        ++pc;
        break;
      }
      case pir::OpCode::kJmp:
        if (!jump_to_block(static_cast<std::uint32_t>(inst.imm))) {
          return false;
        }
        break;
      case pir::OpCode::kJcc: {
        const std::uint32_t target = slot_value(inst.src0) != 0
                                         ? static_cast<std::uint32_t>(inst.imm)
                                         : static_cast<std::uint32_t>(inst.aux);
        if (!jump_to_block(target)) {
          return false;
        }
        break;
      }
      case pir::OpCode::kRet:
        out_result = inst.src0 == kVm2InvalidSlot ? inst.imm : slot_value(inst.src0);
        return true;
      case pir::OpCode::kTrap:
      case pir::OpCode::kHalt:
        return false;
      default:
        return false;
    }
  }

  return false;
}

void decode_call_arguments(const std::int64_t* raw_args,
                           std::int32_t raw_arg_count,
                           std::int64_t& out_arg0,
                           std::int64_t& out_arg1,
                           std::size_t& out_arg_count) noexcept {
  out_arg0 = 0;
  out_arg1 = 0;
  out_arg_count = 0u;

  if (raw_args == nullptr || raw_arg_count <= 0) {
    return;
  }
  out_arg_count = static_cast<std::size_t>(raw_arg_count);
  out_arg0 = raw_args[0];
  out_arg1 = raw_arg_count > 1 ? raw_args[1] : 0;
}

[[nodiscard]] bool lower_bytecode_to_secure_ir_program(
    const std::uint8_t* bytecode,
    std::size_t length,
    std::int64_t arg0,
    std::int64_t arg1,
    std::size_t arg_count,
    SecureIREngine::Program& out_program) noexcept {
  out_program.clear();

  if (bytecode == nullptr || length < 2u || length > kMaxBridgeBytecodeLength) {
    return false;
  }

  out_program.reserve((length / 2u) + 8u);
  out_program.push_back({SecureIREngine::OpCode::kLoadImmI64, arg0});
  if (arg_count > 1u) {
    out_program.push_back({SecureIREngine::OpCode::kLoadImmI64, arg1});
  }

  std::size_t offset = 0u;
  while (offset < length) {
    std::uint16_t raw_opcode = 0u;
    if (!read_u16_le(bytecode, length, offset, raw_opcode)) {
      break;
    }

    const pir::OpCode opcode = static_cast<pir::OpCode>(raw_opcode);
    switch (opcode) {
      case pir::OpCode::kNop:
        break;
      case pir::OpCode::kLoadImmI64: {
        std::int64_t imm = 0;
        if (!read_i64_le(bytecode, length, offset, imm)) {
          return false;
        }
        out_program.push_back({SecureIREngine::OpCode::kLoadImmI64, imm});
        break;
      }
      case pir::OpCode::kAddI:
        out_program.push_back({SecureIREngine::OpCode::kAdd, 0});
        break;
      case pir::OpCode::kSubI:
        out_program.push_back({SecureIREngine::OpCode::kSub, 0});
        break;
      case pir::OpCode::kMulI:
        out_program.push_back({SecureIREngine::OpCode::kMul, 0});
        break;

      // For MVP bridge we skip condition payload and treat compare as subtractive reduction.
      // Unsupported semantics route to mitigation via compile/execute failure path.
      case pir::OpCode::kCmpI:
        if (offset < length) {
          ++offset;
        }
        out_program.push_back({SecureIREngine::OpCode::kSub, 0});
        break;

      case pir::OpCode::kRet:
        out_program.push_back({SecureIREngine::OpCode::kRet, 0});
        return true;

      default:
        // Unsupported opcode in bridge MVP: fail closed to silent mitigation.
        return false;
    }

    if (out_program.size() > (kMaxBridgeBytecodeLength / 2u)) {
      return false;
    }
  }

  out_program.push_back({SecureIREngine::OpCode::kRet, 0});
  return true;
}

}  // namespace

extern "C" std::int32_t eippf_generated_run_template_checked(const std::uint8_t* bytecode,
                                                             std::size_t length,
                                                             const std::int64_t* args,
                                                             std::int32_t arg_count,
                                                             std::int64_t* out_result,
                                                             const void* const* vm_call_table,
                                                             std::int32_t vm_call_count) noexcept {
  if (out_result != nullptr) {
    *out_result = 0;
  }

  std::int64_t resolved_arg0 = 0;
  std::int64_t resolved_arg1 = 0;
  std::size_t resolved_arg_count = 0u;
  decode_call_arguments(args, arg_count, resolved_arg0, resolved_arg1, resolved_arg_count);

  if (is_vm2_program(bytecode, length)) {
    thread_local Vm2Program vm2_program{};
    if (!parse_vm2_program(bytecode, length, vm2_program)) {
      return 0;
    }
    std::int64_t vm2_result = 0;
    const std::size_t resolved_vm_call_count = vm_call_count > 0 ? static_cast<std::size_t>(vm_call_count) : 0u;
    if (!execute_vm2_program(
            vm2_program, args, resolved_arg_count, vm_call_table, resolved_vm_call_count, vm2_result)) {
      return 0;
    }
    if (out_result != nullptr) {
      *out_result = vm2_result;
    }
    return 1;
  }

  thread_local SecureIREngine engine{};
  thread_local SecureIREngine::Program program{};

  if (!lower_bytecode_to_secure_ir_program(
          bytecode, length, resolved_arg0, resolved_arg1, resolved_arg_count, program)) {
    return 0;
  }

  const SecureIREngine::CompileResult compiled = engine.compile(program);
  if (!compiled.ok()) {
    return 0;
  }

  const std::int64_t result = engine.execute(compiled);
  if (out_result != nullptr) {
    *out_result = result;
  }
  return 1;
}

extern "C" std::int64_t eippf_generated_run_template(const std::uint8_t* bytecode,
                                                      std::size_t length,
                                                      const std::int64_t* args,
                                                      std::int32_t arg_count) noexcept {
  std::int64_t result = 0;
  const std::int32_t ok =
      eippf_generated_run_template_checked(bytecode, length, args, arg_count, &result, nullptr, 0);
  if (ok == 0) {
    return 0;
  }
  return result;
}

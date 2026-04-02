#include <bit>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "runtime/proprietary_isa.hpp"

extern "C" std::int32_t eippf_generated_run_template_checked(const std::uint8_t* bytecode,
                                                               std::size_t length,
                                                               const std::int64_t* args,
                                                               std::int32_t arg_count,
                                                               std::int64_t* out_result,
                                                               const void* const* vm_call_table,
                                                               std::int32_t vm_call_count) noexcept;

namespace {

namespace pir = eippf::runtime::pir;

struct Vm2Instruction final {
  std::uint16_t opcode = 0u;
  std::uint16_t flags = 0u;
  std::uint32_t dst = 0u;
  std::uint32_t src0 = 0u;
  std::uint32_t src1 = 0u;
  std::int64_t imm = 0;
  std::uint64_t aux = 0u;
};

constexpr std::uint32_t kVm2InvalidSlot = 0xFFFFFFFFu;
constexpr std::uint16_t kVm2Version = 2u;
constexpr std::uint16_t kVm2LabelFlag = 0x1u;
constexpr std::uint16_t kVm2FCmpOEq = 0u;
constexpr std::uint16_t kVm2CastSIToFPFlag = 0x10u;
constexpr std::uint16_t kVm2CastFPToSIFlag = 0x12u;

void append_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
}

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>(value & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 8u) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 16u) & 0xFFu));
  out.push_back(static_cast<std::uint8_t>((value >> 24u) & 0xFFu));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (std::size_t i = 0; i < sizeof(std::uint64_t); ++i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8u * i)) & 0xFFu));
  }
}

void append_i64(std::vector<std::uint8_t>& out, std::int64_t value) {
  append_u64(out, static_cast<std::uint64_t>(value));
}

std::vector<std::uint8_t> build_vm2(std::uint32_t slot_count,
                                    std::uint32_t arg_count,
                                    std::uint32_t entry_block,
                                    const std::vector<Vm2Instruction>& instructions) {
  std::vector<std::uint8_t> out;
  out.reserve(24u + instructions.size() * 32u);
  out.push_back('E');
  out.push_back('V');
  out.push_back('M');
  out.push_back('2');
  append_u16(out, kVm2Version);
  append_u16(out, 0u);
  append_u32(out, slot_count);
  append_u32(out, arg_count);
  append_u32(out, entry_block);
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
  return out;
}

Vm2Instruction make_label(std::uint32_t label_id) {
  Vm2Instruction inst{};
  inst.opcode = static_cast<std::uint16_t>(pir::OpCode::kNop);
  inst.flags = kVm2LabelFlag;
  inst.dst = kVm2InvalidSlot;
  inst.src0 = kVm2InvalidSlot;
  inst.src1 = kVm2InvalidSlot;
  inst.imm = static_cast<std::int64_t>(label_id);
  return inst;
}

std::int64_t expected_complex(std::int64_t x) {
  std::int64_t acc = x * 3;
  if ((x & 1) != 0) {
    acc += 7;
  } else {
    acc -= 5;
  }

  switch (x & 3) {
    case 0:
      acc += 11;
      break;
    case 1:
      acc ^= 0x5A;
      break;
    default:
      acc += 2;
      break;
  }
  return acc;
}

bool run_program(const std::vector<std::uint8_t>& program,
                 const std::int64_t* args,
                 std::int32_t arg_count,
                 std::int64_t expected) {
  std::int64_t out = 0;
  const std::int32_t ok = eippf_generated_run_template_checked(
      program.data(), program.size(), args, arg_count, &out, nullptr, 0);
  return ok == 1 && out == expected;
}

bool test_simple_add_constant() {
  std::vector<Vm2Instruction> insts;
  insts.push_back(make_label(0u));

  Vm2Instruction load3{};
  load3.opcode = static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64);
  load3.flags = 64u;
  load3.dst = 1u;
  load3.src0 = kVm2InvalidSlot;
  load3.src1 = kVm2InvalidSlot;
  load3.imm = 3;
  insts.push_back(load3);

  Vm2Instruction add{};
  add.opcode = static_cast<std::uint16_t>(pir::OpCode::kAddI);
  add.flags = 64u;
  add.dst = 2u;
  add.src0 = 0u;
  add.src1 = 1u;
  insts.push_back(add);

  Vm2Instruction ret{};
  ret.opcode = static_cast<std::uint16_t>(pir::OpCode::kRet);
  ret.dst = kVm2InvalidSlot;
  ret.src0 = 2u;
  ret.src1 = kVm2InvalidSlot;
  insts.push_back(ret);

  const std::vector<std::uint8_t> program = build_vm2(3u, 1u, 0u, insts);
  const std::int64_t args[1] = {9};
  return run_program(program, args, 1, 12);
}

bool test_branch_and_switch_lowering_shape() {
  std::vector<Vm2Instruction> insts;
  insts.push_back(make_label(0u));

  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 1u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 3, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kMulI), 64u, 2u, 0u, 1u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 3u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 1, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kAnd), 64u, 4u, 0u, 3u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJcc), 0u, kVm2InvalidSlot, 4u,
                   kVm2InvalidSlot, 1, 2u});

  insts.push_back(make_label(1u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 5u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 7, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kAddI), 64u, 2u, 2u, 5u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJmp), 0u, kVm2InvalidSlot, kVm2InvalidSlot,
                   kVm2InvalidSlot, 3, 0u});

  insts.push_back(make_label(2u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 6u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 5, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kSubI), 64u, 2u, 2u, 6u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJmp), 0u, kVm2InvalidSlot, kVm2InvalidSlot,
                   kVm2InvalidSlot, 3, 0u});

  insts.push_back(make_label(3u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 7u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 3, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kAnd), 64u, 8u, 0u, 7u, 0, 0u});

  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 9u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kCmpI),
                   static_cast<std::uint16_t>(pir::ConditionCode::kEq), 10u, 8u, 9u, 0, 64u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJcc), 0u, kVm2InvalidSlot, 10u,
                   kVm2InvalidSlot, 4, 8u});

  insts.push_back(make_label(8u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 11u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 1, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kCmpI),
                   static_cast<std::uint16_t>(pir::ConditionCode::kEq), 10u, 8u, 11u, 0, 64u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJcc), 0u, kVm2InvalidSlot, 10u,
                   kVm2InvalidSlot, 5, 7u});

  insts.push_back(make_label(4u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 12u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 11, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kAddI), 64u, 2u, 2u, 12u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJmp), 0u, kVm2InvalidSlot, kVm2InvalidSlot,
                   kVm2InvalidSlot, 6, 0u});

  insts.push_back(make_label(5u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 13u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 0x5A, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kXor), 64u, 2u, 2u, 13u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJmp), 0u, kVm2InvalidSlot, kVm2InvalidSlot,
                   kVm2InvalidSlot, 6, 0u});

  insts.push_back(make_label(7u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 14u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 2, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kAddI), 64u, 2u, 2u, 14u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kJmp), 0u, kVm2InvalidSlot, kVm2InvalidSlot,
                   kVm2InvalidSlot, 6, 0u});

  insts.push_back(make_label(6u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kRet), 0u, kVm2InvalidSlot, 2u,
                   kVm2InvalidSlot, 0, 0u});

  const std::vector<std::uint8_t> program = build_vm2(15u, 1u, 0u, insts);

  for (std::int64_t x = 0; x < 16; ++x) {
    const std::int64_t args[1] = {x};
    if (!run_program(program, args, 1, expected_complex(x))) {
      return false;
    }
  }
  return true;
}

bool test_float_arithmetic_and_cmp() {
  std::vector<Vm2Instruction> insts;
  insts.push_back(make_label(0u));

  const std::uint64_t one_point_two_five = std::bit_cast<std::uint64_t>(1.25);
  const std::uint64_t two_point_five = std::bit_cast<std::uint64_t>(2.5);
  const std::uint64_t three_point_seven_five = std::bit_cast<std::uint64_t>(3.75);

  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 0u, kVm2InvalidSlot,
                   kVm2InvalidSlot, static_cast<std::int64_t>(one_point_two_five), 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 1u, kVm2InvalidSlot,
                   kVm2InvalidSlot, static_cast<std::int64_t>(two_point_five), 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kAddF), 64u, 2u, 0u, 1u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 3u, kVm2InvalidSlot,
                   kVm2InvalidSlot, static_cast<std::int64_t>(three_point_seven_five), 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kCmpF), kVm2FCmpOEq, 4u, 2u, 3u, 0, 64u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kSelect), 0u, 5u, 4u, 2u, 0, 3u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kRet), 0u, kVm2InvalidSlot, 5u,
                   kVm2InvalidSlot, 0, 0u});

  const std::vector<std::uint8_t> program = build_vm2(6u, 0u, 0u, insts);
  std::int64_t out = 0;
  const std::int32_t ok =
      eippf_generated_run_template_checked(program.data(), program.size(), nullptr, 0, &out, nullptr, 0);
  if (ok != 1) {
    return false;
  }
  const double value = std::bit_cast<double>(static_cast<std::uint64_t>(out));
  return value == 3.75;
}

bool test_invalid_program_rejected() {
  const std::uint8_t bad[4] = {'E', 'V', 'M', '2'};
  std::int64_t out = 123;
  const std::int32_t ok =
      eippf_generated_run_template_checked(bad, sizeof(bad), nullptr, 0, &out, nullptr, 0);
  return ok == 0 && out == 0;
}

extern "C" std::int64_t vm_test_host_add(std::int64_t a, std::int64_t b) {
  return a + b + 11;
}

bool test_vm_call_dispatch_table() {
  std::vector<Vm2Instruction> insts;
  insts.push_back(make_label(0u));
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 0u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 5, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 1u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 7, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kCall), 2u, 2u, 0u, 1u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kRet), 0u, kVm2InvalidSlot, 2u,
                   kVm2InvalidSlot, 0, 0u});

  const std::vector<std::uint8_t> program = build_vm2(3u, 0u, 0u, insts);
  const void* call_table[1] = {reinterpret_cast<const void*>(&vm_test_host_add)};
  std::int64_t out = 0;
  const std::int32_t ok = eippf_generated_run_template_checked(
      program.data(), program.size(), nullptr, 0, &out, call_table, 1);
  return ok == 1 && out == 23;
}

bool test_int_float_cast_pipeline() {
  std::vector<Vm2Instruction> insts;
  insts.push_back(make_label(0u));

  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 0u, kVm2InvalidSlot,
                   kVm2InvalidSlot, 9, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kMov), kVm2CastSIToFPFlag, 1u, 0u,
                   kVm2InvalidSlot, 0, (static_cast<std::uint64_t>(64u) << 32u) | 64u});

  const std::uint64_t one_point_five = std::bit_cast<std::uint64_t>(1.5);
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kLoadImmI64), 64u, 2u, kVm2InvalidSlot,
                   kVm2InvalidSlot, static_cast<std::int64_t>(one_point_five), 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kMulF), 64u, 3u, 1u, 2u, 0, 0u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kMov), kVm2CastFPToSIFlag, 4u, 3u,
                   kVm2InvalidSlot, 0, (static_cast<std::uint64_t>(64u) << 32u) | 64u});
  insts.push_back({static_cast<std::uint16_t>(pir::OpCode::kRet), 0u, kVm2InvalidSlot, 4u,
                   kVm2InvalidSlot, 0, 0u});

  const std::vector<std::uint8_t> program = build_vm2(5u, 0u, 0u, insts);
  std::int64_t out = 0;
  const std::int32_t ok =
      eippf_generated_run_template_checked(program.data(), program.size(), nullptr, 0, &out, nullptr, 0);
  return ok == 1 && out == 13;
}

}  // namespace

int main() {
  if (!test_simple_add_constant()) {
    std::cerr << "test_simple_add_constant failed\n";
    return 1;
  }
  if (!test_branch_and_switch_lowering_shape()) {
    std::cerr << "test_branch_and_switch_lowering_shape failed\n";
    return 1;
  }
  if (!test_float_arithmetic_and_cmp()) {
    std::cerr << "test_float_arithmetic_and_cmp failed\n";
    return 1;
  }
  if (!test_invalid_program_rejected()) {
    std::cerr << "test_invalid_program_rejected failed\n";
    return 1;
  }
  if (!test_int_float_cast_pipeline()) {
    std::cerr << "test_int_float_cast_pipeline failed\n";
    return 1;
  }
  if (!test_vm_call_dispatch_table()) {
    std::cerr << "test_vm_call_dispatch_table failed\n";
    return 1;
  }
  std::cout << "vm_runtime_bridge_vm2_test: PASS\n";
  return 0;
}

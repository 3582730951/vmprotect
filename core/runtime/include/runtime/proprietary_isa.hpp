#pragma once

#include <cstdint>

namespace eippf::runtime::pir {

enum class ValueType : std::uint8_t {
  kVoid = 0u,
  kI8 = 1u,
  kI16 = 2u,
  kI32 = 3u,
  kI64 = 4u,
  kF32 = 5u,
  kF64 = 6u,
  kPtr = 7u,
};

enum class ConditionCode : std::uint8_t {
  kEq = 0u,
  kNe = 1u,
  kLt = 2u,
  kLe = 3u,
  kGt = 4u,
  kGe = 5u,
  kUlt = 6u,
  kUle = 7u,
  kUgt = 8u,
  kUge = 9u,
};

// Turing-complete PIR opcodes covering ALU, memory, control-flow and FFI/syscall boundaries.
enum class OpCode : std::uint16_t {
  // Lifecycle / dispatch
  kNop = 0x0000u,
  kTrap = 0x0001u,
  kHalt = 0x0002u,
  kRet = 0x0003u,

  // Move / constants
  kMov = 0x0010u,
  kLoadImmI64 = 0x0011u,
  kLoadImmF64 = 0x0012u,
  kLoadAddr = 0x0013u,

  // Integer ALU
  kAddI = 0x0100u,
  kSubI = 0x0101u,
  kMulI = 0x0102u,
  kDivSI = 0x0103u,
  kDivUI = 0x0104u,
  kRemSI = 0x0105u,
  kRemUI = 0x0106u,
  kNegI = 0x0107u,
  kAbsI = 0x0108u,
  kMinI = 0x0109u,
  kMaxI = 0x010Au,

  // Bitwise / shift / rotate
  kAnd = 0x0120u,
  kOr = 0x0121u,
  kXor = 0x0122u,
  kNot = 0x0123u,
  kShl = 0x0124u,
  kLShr = 0x0125u,
  kAShr = 0x0126u,
  kRol = 0x0127u,
  kRor = 0x0128u,
  kClz = 0x0129u,
  kCtz = 0x012Au,
  kPopcnt = 0x012Bu,

  // Floating ALU
  kAddF = 0x0140u,
  kSubF = 0x0141u,
  kMulF = 0x0142u,
  kDivF = 0x0143u,
  kSqrtF = 0x0144u,
  kAbsF = 0x0145u,
  kMinF = 0x0146u,
  kMaxF = 0x0147u,
  kFmaF = 0x0148u,

  // Compare / select
  kCmpI = 0x0180u,
  kCmpF = 0x0181u,
  kSelect = 0x0182u,

  // Stack / frame
  kPush = 0x0200u,
  kPop = 0x0201u,
  kAlloca = 0x0202u,
  kStackSave = 0x0203u,
  kStackRestore = 0x0204u,

  // Memory operations (base + signed offset)
  kLoad8 = 0x0300u,
  kLoad16 = 0x0301u,
  kLoad32 = 0x0302u,
  kLoad64 = 0x0303u,
  kStore8 = 0x0304u,
  kStore16 = 0x0305u,
  kStore32 = 0x0306u,
  kStore64 = 0x0307u,
  kLoadF32 = 0x0310u,
  kLoadF64 = 0x0311u,
  kStoreF32 = 0x0312u,
  kStoreF64 = 0x0313u,
  kMemCopy = 0x0314u,
  kMemSet = 0x0315u,
  kMemCmp = 0x0316u,
  kFence = 0x0317u,

  // Control flow
  kJmp = 0x0400u,
  kJcc = 0x0401u,
  kSwitch = 0x0402u,
  kCall = 0x0403u,
  kCallIndirect = 0x0404u,
  kTailCall = 0x0405u,
  kPhiMove = 0x0406u,

  // Atomic / synchronization
  kAtomicLoad = 0x0500u,
  kAtomicStore = 0x0501u,
  kAtomicRmwAdd = 0x0502u,
  kAtomicRmwSub = 0x0503u,
  kAtomicCmpXchg = 0x0504u,

  // FFI / syscall boundaries
  kResolverCall = 0x0600u,  // resolve hash -> function pointer
  kFfiEnter = 0x0601u,
  kFfiCall = 0x0602u,
  kFfiExit = 0x0603u,
  kSyscallGate = 0x0604u,   // mediated syscall boundary
  kSysret = 0x0605u,
};

enum class BackendKind : std::uint8_t {
  kInterpreter = 0u,
  kJitX86_64 = 1u,
  kJitAArch64 = 2u,
};

enum class CallingConvention : std::uint8_t {
  kSystemV = 0u,      // Linux/macOS x86_64
  kWin64 = 1u,        // Windows x86_64
  kAArch64AAPCS = 2u, // Linux/macOS/Windows on ARM64
};

struct InstructionHeader final {
  OpCode opcode = OpCode::kNop;
  std::uint8_t dst = 0u;
  std::uint8_t src0 = 0u;
  std::uint8_t src1 = 0u;
  std::uint8_t flags = 0u;
};

struct BackendLoweringPlan final {
  BackendKind backend = BackendKind::kInterpreter;
  CallingConvention cc = CallingConvention::kSystemV;
  bool enable_constant_blinding = true;
  bool enable_block_shuffling = true;
};

}  // namespace eippf::runtime::pir

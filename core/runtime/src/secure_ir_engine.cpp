#include "runtime/secure_ir_engine.hpp"

#include <array>
#include <cstring>
#include <new>
#include <utility>

#include "runtime/constexpr_obfuscated_string.hpp"
#include "runtime/dynamic_api_resolver.hpp"
#include "runtime/environment_attestation.hpp"
#include "runtime/memory_hal.hpp"

namespace eippf::runtime::ir {

namespace {

constexpr std::uint64_t kFnv1aOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnv1aPrime = 1099511628211ull;

constexpr auto kOpLoadImmName =
    security::make_obfuscated_string<0x51u>("OP_LOAD_IMM_I64");
constexpr auto kOpAddName = security::make_obfuscated_string<0x52u>("OP_ADD");
constexpr auto kOpSubName = security::make_obfuscated_string<0x53u>("OP_SUB");
constexpr auto kOpMulName = security::make_obfuscated_string<0x54u>("OP_MUL");
constexpr auto kOpRetName = security::make_obfuscated_string<0x55u>("OP_RET");

constexpr auto kErrEmptyProgram =
    security::make_obfuscated_string<0x61u>("empty program");
constexpr auto kErrStackUnderflow =
    security::make_obfuscated_string<0x62u>("stack underflow");
constexpr auto kErrInvalidReturnDepth =
    security::make_obfuscated_string<0x63u>("invalid return depth");
constexpr auto kErrMissingReturn =
    security::make_obfuscated_string<0x64u>("missing return");
constexpr auto kErrBufferOverflow =
    security::make_obfuscated_string<0x65u>("code buffer overflow");
constexpr auto kErrAllocFailure =
    security::make_obfuscated_string<0x66u>("memory allocation failed");
constexpr auto kErrProtectFailure =
    security::make_obfuscated_string<0x67u>("memory protect failed");
constexpr auto kErrInvalidOpcode =
    security::make_obfuscated_string<0x68u>("invalid opcode");
constexpr auto kErrOk = security::make_obfuscated_string<0x69u>("ok");

constexpr auto kJitDebugSymbol =
    security::make_obfuscated_string<0x71u>("SecureIREngine::jit_entry");

enum class CompileState : int {
  kInit = 0,
  kFetch = 10,
  kDecode = 20,
  kEmitLoadImm = 30,
  kEmitAdd = 31,
  kEmitSub = 32,
  kEmitMul = 33,
  kEmitRet = 34,
  kFinalize = 90,
  kFail = 99,
};

enum class ExecuteState : int {
  kInit = 0,
  kAttest = 1,
  kRun = 2,
  kMitigate = 3,
  kDone = 4,
};

using Resolver = runtime::DynamicAPIResolver<128u, 8u>;

Resolver& resolver_instance() noexcept {
  static Resolver resolver{};
  return resolver;
}

runtime::EnvironmentAttestation& attestation_instance() noexcept {
  static runtime::EnvironmentAttestation attestation{};
  return attestation;
}

struct MetadataScope final {
  security::DecryptedBuffer<sizeof("OP_LOAD_IMM_I64")> op_load = kOpLoadImmName.decrypt();
  security::DecryptedBuffer<sizeof("OP_ADD")> op_add = kOpAddName.decrypt();
  security::DecryptedBuffer<sizeof("OP_SUB")> op_sub = kOpSubName.decrypt();
  security::DecryptedBuffer<sizeof("OP_MUL")> op_mul = kOpMulName.decrypt();
  security::DecryptedBuffer<sizeof("OP_RET")> op_ret = kOpRetName.decrypt();

  security::DecryptedBuffer<sizeof("empty program")> err_empty = kErrEmptyProgram.decrypt();
  security::DecryptedBuffer<sizeof("stack underflow")> err_underflow = kErrStackUnderflow.decrypt();
  security::DecryptedBuffer<sizeof("invalid return depth")> err_ret_depth =
      kErrInvalidReturnDepth.decrypt();
  security::DecryptedBuffer<sizeof("missing return")> err_missing_ret = kErrMissingReturn.decrypt();
  security::DecryptedBuffer<sizeof("code buffer overflow")> err_overflow =
      kErrBufferOverflow.decrypt();
  security::DecryptedBuffer<sizeof("memory allocation failed")> err_alloc =
      kErrAllocFailure.decrypt();
  security::DecryptedBuffer<sizeof("memory protect failed")> err_protect =
      kErrProtectFailure.decrypt();
  security::DecryptedBuffer<sizeof("invalid opcode")> err_invalid_opcode =
      kErrInvalidOpcode.decrypt();
  security::DecryptedBuffer<sizeof("ok")> err_ok = kErrOk.decrypt();

  security::DecryptedBuffer<sizeof("SecureIREngine::jit_entry")> dbg_symbol =
      kJitDebugSymbol.decrypt();

  [[nodiscard]] const char* opcode_name(SecureIREngine::OpCode op) const noexcept {
    switch (op) {
      case SecureIREngine::OpCode::kLoadImmI64:
        return op_load.c_str();
      case SecureIREngine::OpCode::kAdd:
        return op_add.c_str();
      case SecureIREngine::OpCode::kSub:
        return op_sub.c_str();
      case SecureIREngine::OpCode::kMul:
        return op_mul.c_str();
      case SecureIREngine::OpCode::kRet:
        return op_ret.c_str();
      default:
        return err_invalid_opcode.c_str();
    }
  }

  [[nodiscard]] const char* error_text(SecureIREngine::ErrorCode error) const noexcept {
    switch (error) {
      case SecureIREngine::ErrorCode::kEmptyProgram:
        return err_empty.c_str();
      case SecureIREngine::ErrorCode::kStackUnderflow:
        return err_underflow.c_str();
      case SecureIREngine::ErrorCode::kInvalidReturnDepth:
        return err_ret_depth.c_str();
      case SecureIREngine::ErrorCode::kMissingReturn:
        return err_missing_ret.c_str();
      case SecureIREngine::ErrorCode::kCodeBufferOverflow:
        return err_overflow.c_str();
      case SecureIREngine::ErrorCode::kMemoryAllocationFailed:
        return err_alloc.c_str();
      case SecureIREngine::ErrorCode::kMemoryProtectFailed:
        return err_protect.c_str();
      case SecureIREngine::ErrorCode::kInvalidOpcode:
        return err_invalid_opcode.c_str();
      case SecureIREngine::ErrorCode::kOk:
        return err_ok.c_str();
      default:
        return err_invalid_opcode.c_str();
    }
  }

  void wipe() noexcept {
    op_load.wipe();
    op_add.wipe();
    op_sub.wipe();
    op_mul.wipe();
    op_ret.wipe();

    err_empty.wipe();
    err_underflow.wipe();
    err_ret_depth.wipe();
    err_missing_ret.wipe();
    err_overflow.wipe();
    err_alloc.wipe();
    err_protect.wipe();
    err_invalid_opcode.wipe();
    err_ok.wipe();

    dbg_symbol.wipe();
  }
};

std::uint64_t append_hash(std::uint64_t seed, const char* text) noexcept {
  if (text == nullptr) {
    return seed;
  }
  std::uint64_t hash = seed;
  for (const char* cursor = text; *cursor != '\0'; ++cursor) {
    hash ^= static_cast<std::uint8_t>(static_cast<unsigned char>(*cursor));
    hash *= kFnv1aPrime;
  }
  return hash;
}

#if defined(__aarch64__) || defined(_M_ARM64)
[[nodiscard]] bool append_u32le(SecureIREngine::ExecutableMemory& code,
                                std::uint32_t value) noexcept {
  std::uint8_t bytes[4]{};
  bytes[0] = static_cast<std::uint8_t>(value & 0xFFu);
  bytes[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  bytes[2] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  bytes[3] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  return code.append_bytes(bytes, sizeof(bytes));
}

[[nodiscard]] constexpr std::uint32_t encode_movz_x(std::uint32_t rd,
                                                    std::uint16_t imm16,
                                                    std::uint32_t shift) noexcept {
  return 0xD2800000u | ((shift & 0x3u) << 21u) |
         (static_cast<std::uint32_t>(imm16) << 5u) | (rd & 0x1Fu);
}

[[nodiscard]] constexpr std::uint32_t encode_movk_x(std::uint32_t rd,
                                                    std::uint16_t imm16,
                                                    std::uint32_t shift) noexcept {
  return 0xF2800000u | ((shift & 0x3u) << 21u) |
         (static_cast<std::uint32_t>(imm16) << 5u) | (rd & 0x1Fu);
}

constexpr std::uint32_t kA64PushX9 = 0xA9BF7FE9u;    // stp x9, xzr, [sp, #-16]!
constexpr std::uint32_t kA64PopX9 = 0xA8C17FE9u;     // ldp x9, xzr, [sp], #16
constexpr std::uint32_t kA64PopX10 = 0xA8C17FEAu;    // ldp x10, xzr, [sp], #16
constexpr std::uint32_t kA64PopX0 = 0xA8C17FE0u;     // ldp x0, xzr, [sp], #16
constexpr std::uint32_t kA64AddX9X9X10 = 0x8B0A0129u;  // add x9, x9, x10
constexpr std::uint32_t kA64SubX9X9X10 = 0xCB0A0129u;  // sub x9, x9, x10
constexpr std::uint32_t kA64MulX9X9X10 = 0x9B0A7D29u;  // mul x9, x9, x10
constexpr std::uint32_t kA64Ret = 0xD65F03C0u;         // ret

[[nodiscard]] bool emit_a64_load_imm(SecureIREngine::ExecutableMemory& code,
                                     std::int64_t imm) noexcept {
  const std::uint64_t value = static_cast<std::uint64_t>(imm);
  const std::uint16_t part0 = static_cast<std::uint16_t>(value & 0xFFFFu);
  const std::uint16_t part1 = static_cast<std::uint16_t>((value >> 16u) & 0xFFFFu);
  const std::uint16_t part2 = static_cast<std::uint16_t>((value >> 32u) & 0xFFFFu);
  const std::uint16_t part3 = static_cast<std::uint16_t>((value >> 48u) & 0xFFFFu);

  return append_u32le(code, encode_movz_x(9u, part0, 0u)) &&
         append_u32le(code, encode_movk_x(9u, part1, 1u)) &&
         append_u32le(code, encode_movk_x(9u, part2, 2u)) &&
         append_u32le(code, encode_movk_x(9u, part3, 3u)) &&
         append_u32le(code, kA64PushX9);
}

[[nodiscard]] bool emit_a64_binary(SecureIREngine::ExecutableMemory& code,
                                   std::uint32_t op_word) noexcept {
  return append_u32le(code, kA64PopX10) && append_u32le(code, kA64PopX9) &&
         append_u32le(code, op_word) && append_u32le(code, kA64PushX9);
}

[[nodiscard]] bool emit_a64_ret(SecureIREngine::ExecutableMemory& code) noexcept {
  return append_u32le(code, kA64PopX0) && append_u32le(code, kA64Ret);
}
#endif

}  // namespace

SecureIREngine::ExecutableMemory::ExecutableMemory(std::size_t requested_size) noexcept {
  const runtime::MemoryHAL::Region region =
      runtime::MemoryHAL::allocate_rw(resolver_instance(), requested_size);
  memory_ = region.base;
  size_ = region.size;
}

SecureIREngine::ExecutableMemory::ExecutableMemory(ExecutableMemory&& other) noexcept {
  memory_ = std::exchange(other.memory_, nullptr);
  size_ = std::exchange(other.size_, 0u);
  offset_ = std::exchange(other.offset_, 0u);
  sealed_ = std::exchange(other.sealed_, false);
}

SecureIREngine::ExecutableMemory& SecureIREngine::ExecutableMemory::operator=(
    ExecutableMemory&& other) noexcept {
  if (this == &other) {
    return *this;
  }

  release();
  memory_ = std::exchange(other.memory_, nullptr);
  size_ = std::exchange(other.size_, 0u);
  offset_ = std::exchange(other.offset_, 0u);
  sealed_ = std::exchange(other.sealed_, false);
  return *this;
}

SecureIREngine::ExecutableMemory::~ExecutableMemory() {
  release();
}

void SecureIREngine::ExecutableMemory::release() noexcept {
  if (memory_ == nullptr) {
    return;
  }

  runtime::MemoryHAL::Region region{memory_, size_};
  (void)runtime::MemoryHAL::protect_rw(resolver_instance(), region);
  security::secure_zero(region.base, region.size);
  runtime::MemoryHAL::release(resolver_instance(), region);
  memory_ = nullptr;
  size_ = 0u;
  offset_ = 0u;
  sealed_ = false;
}

bool SecureIREngine::ExecutableMemory::valid() const noexcept {
  return memory_ != nullptr;
}

bool SecureIREngine::ExecutableMemory::append_u8(std::uint8_t byte) noexcept {
  if (!valid() || sealed_ || (offset_ + 1u) > size_) {
    return false;
  }
  static_cast<std::uint8_t*>(memory_)[offset_] = byte;
  ++offset_;
  return true;
}

bool SecureIREngine::ExecutableMemory::append_bytes(const std::uint8_t* bytes,
                                                    std::size_t count) noexcept {
  if (!valid() || sealed_ || bytes == nullptr || (offset_ + count) > size_) {
    return false;
  }
  std::memcpy(static_cast<std::uint8_t*>(memory_) + offset_, bytes, count);
  offset_ += count;
  return true;
}

bool SecureIREngine::ExecutableMemory::append_i64(std::int64_t value) noexcept {
  std::uint8_t raw[sizeof(std::int64_t)]{};
  std::memcpy(raw, &value, sizeof(value));
  return append_bytes(raw, sizeof(raw));
}

bool SecureIREngine::ExecutableMemory::seal_rx() noexcept {
  if (!valid() || sealed_) {
    return false;
  }

  const runtime::MemoryHAL::Region region{memory_, size_};
  if (!runtime::MemoryHAL::protect_rx(resolver_instance(), region)) {
    return false;
  }
  sealed_ = true;
  return true;
}

void* SecureIREngine::ExecutableMemory::entry_point() const noexcept {
  return memory_;
}

SecureIREngine::CompileResult SecureIREngine::compile(const Program& program) const noexcept {
  CompileResult result{};
  result.error = ErrorCode::kInvalidOpcode;

  MetadataScope metadata{};
  if (!runtime::MemoryHAL::runtime_dynamic_code_allowed()) {
    result.error = ErrorCode::kMemoryProtectFailed;
    result.gate_code = GateCode::kJitRouteForbiddenForTarget;
    result.error_message_hash = hash_bytes("jit_route_forbidden_for_target");
    metadata.wipe();
    return result;
  }

  std::unique_ptr<ExecutableMemory> code(
      new (std::nothrow) ExecutableMemory((program.size() * 24u) + 16u));

  if (code == nullptr || !code->valid()) {
    result.error = ErrorCode::kMemoryAllocationFailed;
    result.error_message_hash = hash_bytes(metadata.error_text(result.error));
    metadata.wipe();
    return result;
  }

  CompileState state = CompileState::kInit;
  std::size_t pc = 0u;
  std::size_t stack_depth = 0u;
  Instruction current{};

  while (true) {
    switch (state) {
      case CompileState::kInit:
        if (program.empty()) {
          result.error = ErrorCode::kEmptyProgram;
          state = CompileState::kFail;
          break;
        }
        pc = 0u;
        stack_depth = 0u;
        result.opcode_trace_hash = kFnv1aOffset;
        state = CompileState::kFetch;
        break;

      case CompileState::kFetch:
        if (pc >= program.size()) {
          result.error = ErrorCode::kMissingReturn;
          state = CompileState::kFail;
          break;
        }
        current = program[pc];
        state = CompileState::kDecode;
        break;

      case CompileState::kDecode:
        result.opcode_trace_hash = append_hash(result.opcode_trace_hash, metadata.opcode_name(current.op));
        switch (current.op) {
          case OpCode::kLoadImmI64:
            state = CompileState::kEmitLoadImm;
            break;
          case OpCode::kAdd:
            state = CompileState::kEmitAdd;
            break;
          case OpCode::kSub:
            state = CompileState::kEmitSub;
            break;
          case OpCode::kMul:
            state = CompileState::kEmitMul;
            break;
          case OpCode::kRet:
            state = CompileState::kEmitRet;
            break;
          default:
            result.error = ErrorCode::kInvalidOpcode;
            state = CompileState::kFail;
            break;
        }
        break;

      case CompileState::kEmitLoadImm:
      {
        bool emitted = false;
#if defined(__aarch64__) || defined(_M_ARM64)
        emitted = emit_a64_load_imm(*code, current.imm);
#elif defined(__x86_64__) || defined(_M_X64)
        emitted = code->append_u8(0x48u) && code->append_u8(0xB8u) && code->append_i64(current.imm) &&
                  code->append_u8(0x50u);
#else
          result.error = ErrorCode::kInvalidOpcode;
          state = CompileState::kFail;
          break;
#endif
        if (!emitted) {
          result.error = ErrorCode::kCodeBufferOverflow;
          state = CompileState::kFail;
          break;
        }
        ++stack_depth;
        ++pc;
        state = CompileState::kFetch;
        break;
      }

      case CompileState::kEmitAdd: {
        if (stack_depth < 2u) {
          result.error = ErrorCode::kStackUnderflow;
          state = CompileState::kFail;
          break;
        }
        bool emitted = false;
#if defined(__aarch64__) || defined(_M_ARM64)
        emitted = emit_a64_binary(*code, kA64AddX9X9X10);
#elif defined(__x86_64__) || defined(_M_X64)
        const std::uint8_t bytes[] = {0x58u, 0x59u, 0x48u, 0x01u, 0xC8u, 0x50u};
        emitted = code->append_bytes(bytes, sizeof(bytes));
#else
          result.error = ErrorCode::kInvalidOpcode;
          state = CompileState::kFail;
          break;
#endif
        if (!emitted) {
          result.error = ErrorCode::kCodeBufferOverflow;
          state = CompileState::kFail;
          break;
        }
        --stack_depth;
        ++pc;
        state = CompileState::kFetch;
        break;
      }

      case CompileState::kEmitSub: {
        if (stack_depth < 2u) {
          result.error = ErrorCode::kStackUnderflow;
          state = CompileState::kFail;
          break;
        }
        bool emitted = false;
#if defined(__aarch64__) || defined(_M_ARM64)
        emitted = emit_a64_binary(*code, kA64SubX9X9X10);
#elif defined(__x86_64__) || defined(_M_X64)
        const std::uint8_t bytes[] = {0x58u, 0x59u, 0x48u, 0x29u, 0xC1u, 0x51u};
        emitted = code->append_bytes(bytes, sizeof(bytes));
#else
          result.error = ErrorCode::kInvalidOpcode;
          state = CompileState::kFail;
          break;
#endif
        if (!emitted) {
          result.error = ErrorCode::kCodeBufferOverflow;
          state = CompileState::kFail;
          break;
        }
        --stack_depth;
        ++pc;
        state = CompileState::kFetch;
        break;
      }

      case CompileState::kEmitMul: {
        if (stack_depth < 2u) {
          result.error = ErrorCode::kStackUnderflow;
          state = CompileState::kFail;
          break;
        }
        bool emitted = false;
#if defined(__aarch64__) || defined(_M_ARM64)
        emitted = emit_a64_binary(*code, kA64MulX9X9X10);
#elif defined(__x86_64__) || defined(_M_X64)
        const std::uint8_t bytes[] = {0x58u, 0x59u, 0x48u, 0x0Fu, 0xAFu, 0xC1u, 0x50u};
        emitted = code->append_bytes(bytes, sizeof(bytes));
#else
          result.error = ErrorCode::kInvalidOpcode;
          state = CompileState::kFail;
          break;
#endif
        if (!emitted) {
          result.error = ErrorCode::kCodeBufferOverflow;
          state = CompileState::kFail;
          break;
        }
        --stack_depth;
        ++pc;
        state = CompileState::kFetch;
        break;
      }

      case CompileState::kEmitRet: {
        if (stack_depth != 1u) {
          result.error = ErrorCode::kInvalidReturnDepth;
          state = CompileState::kFail;
          break;
        }
        bool emitted = false;
#if defined(__aarch64__) || defined(_M_ARM64)
        emitted = emit_a64_ret(*code);
#elif defined(__x86_64__) || defined(_M_X64)
        const std::uint8_t bytes[] = {0x58u, 0xC3u};
        emitted = code->append_bytes(bytes, sizeof(bytes));
#else
          result.error = ErrorCode::kInvalidOpcode;
          state = CompileState::kFail;
          break;
#endif
        if (!emitted) {
          result.error = ErrorCode::kCodeBufferOverflow;
          state = CompileState::kFail;
          break;
        }
        if (!code->seal_rx()) {
          result.error = ErrorCode::kMemoryProtectFailed;
          state = CompileState::kFail;
          break;
        }
        state = CompileState::kFinalize;
        break;
      }

      case CompileState::kFinalize:
        result.error = ErrorCode::kOk;
        result.code = std::move(code);
        result.entry = reinterpret_cast<EntryFn>(result.code->entry_point());
        result.debug_symbol_hash = hash_bytes(metadata.dbg_symbol.c_str());
        metadata.wipe();
        return result;

      case CompileState::kFail:
        result.error_message_hash = hash_bytes(metadata.error_text(result.error));
        metadata.wipe();
        return result;
    }
  }
}

std::int64_t SecureIREngine::execute(const CompileResult& compiled) const noexcept {
  ExecuteState state = ExecuteState::kInit;
  std::int64_t result = 0;

  while (true) {
    switch (state) {
      case ExecuteState::kInit:
        if (!runtime::MemoryHAL::runtime_dynamic_code_allowed() || !compiled.ok()) {
          state = ExecuteState::kMitigate;
          break;
        }
        state = ExecuteState::kAttest;
        break;

      case ExecuteState::kAttest: {
        const runtime::EnvironmentAttestation::Verdict verdict =
            attestation_instance().evaluate(resolver_instance());
        state = verdict == runtime::EnvironmentAttestation::Verdict::kTrusted
                    ? ExecuteState::kRun
                    : ExecuteState::kMitigate;
        break;
      }

      case ExecuteState::kRun:
        result = compiled.entry();
        state = ExecuteState::kDone;
        break;

      case ExecuteState::kMitigate:
        result = 0;
        state = ExecuteState::kDone;
        break;

      case ExecuteState::kDone:
        return result;
    }
  }
}

std::uint64_t SecureIREngine::hash_bytes(const char* text) noexcept {
  return append_hash(kFnv1aOffset, text);
}

}  // namespace eippf::runtime::ir

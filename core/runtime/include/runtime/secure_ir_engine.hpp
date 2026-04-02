#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace eippf::runtime::ir {

class SecureIREngine final {
 public:
  enum class OpCode : std::uint8_t {
    kLoadImmI64 = 0x01u,
    kAdd = 0x02u,
    kSub = 0x03u,
    kMul = 0x04u,
    kRet = 0xFFu,
  };

  struct Instruction final {
    OpCode op = OpCode::kRet;
    std::int64_t imm = 0;
  };

  using Program = std::vector<Instruction>;

  enum class ErrorCode : std::uint8_t {
    kOk = 0u,
    kEmptyProgram = 1u,
    kStackUnderflow = 2u,
    kInvalidReturnDepth = 3u,
    kMissingReturn = 4u,
    kCodeBufferOverflow = 5u,
    kMemoryAllocationFailed = 6u,
    kMemoryProtectFailed = 7u,
    kInvalidOpcode = 8u,
  };

  class ExecutableMemory final {
   public:
    explicit ExecutableMemory(std::size_t requested_size) noexcept;
    ExecutableMemory(const ExecutableMemory&) = delete;
    ExecutableMemory& operator=(const ExecutableMemory&) = delete;
    ExecutableMemory(ExecutableMemory&& other) noexcept;
    ExecutableMemory& operator=(ExecutableMemory&& other) noexcept;
    ~ExecutableMemory();

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] bool append_u8(std::uint8_t byte) noexcept;
    [[nodiscard]] bool append_bytes(const std::uint8_t* bytes, std::size_t count) noexcept;
    [[nodiscard]] bool append_i64(std::int64_t value) noexcept;
    [[nodiscard]] bool seal_rx() noexcept;
    [[nodiscard]] void* entry_point() const noexcept;

   private:
    void release() noexcept;

    void* memory_ = nullptr;
    std::size_t size_ = 0u;
    std::size_t offset_ = 0u;
    bool sealed_ = false;
  };

  using EntryFn = std::int64_t (*)();

  struct CompileResult final {
    ErrorCode error = ErrorCode::kInvalidOpcode;
    std::uint64_t opcode_trace_hash = 0u;
    std::uint64_t debug_symbol_hash = 0u;
    std::uint64_t error_message_hash = 0u;
    std::unique_ptr<ExecutableMemory> code;
    EntryFn entry = nullptr;

    [[nodiscard]] bool ok() const noexcept {
      return error == ErrorCode::kOk && code != nullptr && entry != nullptr;
    }
  };

  [[nodiscard]] CompileResult compile(const Program& program) const noexcept;
  [[nodiscard]] std::int64_t execute(const CompileResult& compiled) const noexcept;

 private:
  [[nodiscard]] static std::uint64_t hash_bytes(const char* text) noexcept;
};

}  // namespace eippf::runtime::ir

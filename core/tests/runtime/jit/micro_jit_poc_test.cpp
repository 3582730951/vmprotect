#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <utility>
#include <vector>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace {

enum class OpCode : std::uint8_t {
  kLoadImmI64 = 0x01u,
  kAdd = 0x02u,
  kSub = 0x03u,
  kMul = 0x04u,
  kRet = 0xFFu,
};

struct Program final {
  std::vector<std::uint8_t> bytes;
};

void emit_u8(Program& program, std::uint8_t value) {
  program.bytes.push_back(value);
}

void emit_i64(Program& program, std::int64_t value) {
  std::uint8_t raw[sizeof(std::int64_t)]{};
  std::memcpy(raw, &value, sizeof(value));
  for (std::size_t i = 0; i < sizeof(raw); ++i) {
    program.bytes.push_back(raw[i]);
  }
}

void emit_load_imm(Program& program, std::int64_t value) {
  emit_u8(program, static_cast<std::uint8_t>(OpCode::kLoadImmI64));
  emit_i64(program, value);
}

void emit_op(Program& program, OpCode op) {
  emit_u8(program, static_cast<std::uint8_t>(op));
}

class BytecodeReader final {
 public:
  explicit BytecodeReader(const Program& program) : program_(program) {}

  [[nodiscard]] bool has_next() const noexcept { return offset_ < program_.bytes.size(); }

  [[nodiscard]] std::optional<OpCode> read_opcode() noexcept {
    if (offset_ >= program_.bytes.size()) {
      return std::nullopt;
    }
    const auto opcode = static_cast<OpCode>(program_.bytes[offset_]);
    ++offset_;
    return opcode;
  }

  [[nodiscard]] std::optional<std::int64_t> read_i64() noexcept {
    if ((offset_ + sizeof(std::int64_t)) > program_.bytes.size()) {
      return std::nullopt;
    }

    std::int64_t value = 0;
    std::memcpy(&value, program_.bytes.data() + offset_, sizeof(value));
    offset_ += sizeof(value);
    return value;
  }

  [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

 private:
  const Program& program_;
  std::size_t offset_ = 0u;
};

[[nodiscard]] std::optional<std::int64_t> interpret_program(const Program& program) {
  std::vector<std::int64_t> stack;
  stack.reserve(32);

  BytecodeReader reader(program);
  while (reader.has_next()) {
    const std::optional<OpCode> opcode = reader.read_opcode();
    if (!opcode.has_value()) {
      return std::nullopt;
    }

    switch (*opcode) {
      case OpCode::kLoadImmI64: {
        const std::optional<std::int64_t> value = reader.read_i64();
        if (!value.has_value()) {
          return std::nullopt;
        }
        stack.push_back(*value);
        break;
      }
      case OpCode::kAdd:
      case OpCode::kSub:
      case OpCode::kMul: {
        if (stack.size() < 2u) {
          return std::nullopt;
        }
        const std::int64_t rhs = stack.back();
        stack.pop_back();
        const std::int64_t lhs = stack.back();
        stack.pop_back();

        std::int64_t result = 0;
        if (*opcode == OpCode::kAdd) {
          result = lhs + rhs;
        } else if (*opcode == OpCode::kSub) {
          result = lhs - rhs;
        } else {
          result = lhs * rhs;
        }
        stack.push_back(result);
        break;
      }
      case OpCode::kRet: {
        if (stack.size() != 1u) {
          return std::nullopt;
        }
        return stack.back();
      }
      default:
        return std::nullopt;
    }
  }

  return std::nullopt;
}

#if defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))

class CodeBuffer final {
 public:
  explicit CodeBuffer(std::size_t requested_size) noexcept {
    const long page_size = ::sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
      return;
    }

    const std::size_t page = static_cast<std::size_t>(page_size);
    size_ = ((requested_size + page - 1u) / page) * page;
    if (size_ == 0u) {
      size_ = page;
    }

    memory_ = ::mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory_ == MAP_FAILED) {
      memory_ = nullptr;
      size_ = 0u;
    }
  }

  CodeBuffer(const CodeBuffer&) = delete;
  CodeBuffer& operator=(const CodeBuffer&) = delete;

  CodeBuffer(CodeBuffer&& other) noexcept {
    memory_ = std::exchange(other.memory_, nullptr);
    size_ = std::exchange(other.size_, 0u);
    offset_ = std::exchange(other.offset_, 0u);
    executable_ = std::exchange(other.executable_, false);
  }

  CodeBuffer& operator=(CodeBuffer&& other) noexcept {
    if (this == &other) {
      return *this;
    }
    this->~CodeBuffer();
    memory_ = std::exchange(other.memory_, nullptr);
    size_ = std::exchange(other.size_, 0u);
    offset_ = std::exchange(other.offset_, 0u);
    executable_ = std::exchange(other.executable_, false);
    return *this;
  }

  ~CodeBuffer() {
    if (memory_ != nullptr) {
      ::munmap(memory_, size_);
    }
  }

  [[nodiscard]] bool valid() const noexcept { return memory_ != nullptr; }

  [[nodiscard]] bool append_u8(std::uint8_t byte) noexcept {
    if ((offset_ + 1u) > size_) {
      return false;
    }
    static_cast<std::uint8_t*>(memory_)[offset_] = byte;
    ++offset_;
    return true;
  }

  [[nodiscard]] bool append_bytes(const std::uint8_t* bytes, std::size_t count) noexcept {
    if (bytes == nullptr || (offset_ + count) > size_) {
      return false;
    }
    std::memcpy(static_cast<std::uint8_t*>(memory_) + offset_, bytes, count);
    offset_ += count;
    return true;
  }

  [[nodiscard]] bool append_i64(std::int64_t value) noexcept {
    std::uint8_t raw[sizeof(std::int64_t)]{};
    std::memcpy(raw, &value, sizeof(value));
    return append_bytes(raw, sizeof(raw));
  }

  [[nodiscard]] bool make_executable() noexcept {
    if (memory_ == nullptr) {
      return false;
    }
    if (::mprotect(memory_, size_, PROT_READ | PROT_EXEC) != 0) {
      return false;
    }
    executable_ = true;
    return true;
  }

  [[nodiscard]] void* entry_point() const noexcept { return memory_; }

 private:
  void* memory_ = nullptr;
  std::size_t size_ = 0u;
  std::size_t offset_ = 0u;
  bool executable_ = false;
};

// PoC x86_64 emit:
// LOAD_IMM: movabs rax, imm64 ; push rax
// ADD:      pop rax ; pop rcx ; add rax, rcx ; push rax
// SUB:      pop rax ; pop rcx ; sub rcx, rax ; push rcx
// MUL:      pop rax ; pop rcx ; imul rax, rcx ; push rax
// RET:      pop rax ; ret
[[nodiscard]] std::optional<CodeBuffer> compile_to_native(const Program& program) {
  CodeBuffer buffer(program.bytes.size() * 16u);
  if (!buffer.valid()) {
    return std::nullopt;
  }

  BytecodeReader reader(program);
  std::size_t simulated_stack_depth = 0u;

  while (reader.has_next()) {
    const std::optional<OpCode> opcode = reader.read_opcode();
    if (!opcode.has_value()) {
      return std::nullopt;
    }

    switch (*opcode) {
      case OpCode::kLoadImmI64: {
        const std::optional<std::int64_t> imm = reader.read_i64();
        if (!imm.has_value()) {
          return std::nullopt;
        }
        if (!buffer.append_u8(0x48u) || !buffer.append_u8(0xB8u) || !buffer.append_i64(*imm) ||
            !buffer.append_u8(0x50u)) {
          return std::nullopt;
        }
        ++simulated_stack_depth;
        break;
      }
      case OpCode::kAdd: {
        if (simulated_stack_depth < 2u) {
          return std::nullopt;
        }
        const std::uint8_t bytes[] = {0x58u, 0x59u, 0x48u, 0x01u, 0xC8u, 0x50u};
        if (!buffer.append_bytes(bytes, sizeof(bytes))) {
          return std::nullopt;
        }
        --simulated_stack_depth;
        break;
      }
      case OpCode::kSub: {
        if (simulated_stack_depth < 2u) {
          return std::nullopt;
        }
        const std::uint8_t bytes[] = {0x58u, 0x59u, 0x48u, 0x29u, 0xC1u, 0x51u};
        if (!buffer.append_bytes(bytes, sizeof(bytes))) {
          return std::nullopt;
        }
        --simulated_stack_depth;
        break;
      }
      case OpCode::kMul: {
        if (simulated_stack_depth < 2u) {
          return std::nullopt;
        }
        const std::uint8_t bytes[] = {0x58u, 0x59u, 0x48u, 0x0Fu, 0xAFu, 0xC1u, 0x50u};
        if (!buffer.append_bytes(bytes, sizeof(bytes))) {
          return std::nullopt;
        }
        --simulated_stack_depth;
        break;
      }
      case OpCode::kRet: {
        if (simulated_stack_depth != 1u) {
          return std::nullopt;
        }
        const std::uint8_t bytes[] = {0x58u, 0xC3u};
        if (!buffer.append_bytes(bytes, sizeof(bytes))) {
          return std::nullopt;
        }
        if (reader.has_next()) {
          return std::nullopt;
        }
        if (!buffer.make_executable()) {
          return std::nullopt;
        }
        return buffer;
      }
      default:
        return std::nullopt;
    }
  }

  return std::nullopt;
}

using JitFunction = std::int64_t (*)();

[[nodiscard]] std::optional<std::int64_t> execute_jit(CodeBuffer& buffer) {
  if (!buffer.valid()) {
    return std::nullopt;
  }
  auto* fn = reinterpret_cast<JitFunction>(buffer.entry_point());
  return fn();
}

#endif

[[nodiscard]] Program build_sample_program() {
  Program program;
  // (10 + 20) * 3 - 5 = 85
  emit_load_imm(program, 10);
  emit_load_imm(program, 20);
  emit_op(program, OpCode::kAdd);
  emit_load_imm(program, 3);
  emit_op(program, OpCode::kMul);
  emit_load_imm(program, 5);
  emit_op(program, OpCode::kSub);
  emit_op(program, OpCode::kRet);
  return program;
}

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

}  // namespace

int main() {
  const Program program = build_sample_program();
  const std::optional<std::int64_t> interpreted = interpret_program(program);
  if (!expect(interpreted.has_value(), "interpreter should return a value")) {
    return 1;
  }
  if (!expect(*interpreted == 85, "interpreter result should be 85")) {
    return 1;
  }

#if defined(__x86_64__) && (defined(__linux__) || defined(__APPLE__))
  std::optional<CodeBuffer> code = compile_to_native(program);
  if (!expect(code.has_value(), "jit compilation should succeed")) {
    return 1;
  }
  const std::optional<std::int64_t> jitted = execute_jit(*code);
  if (!expect(jitted.has_value(), "jit execution should return a value")) {
    return 1;
  }
  if (!expect(*jitted == *interpreted, "jit result should match interpreter result")) {
    return 1;
  }
  std::cout << "[PASS] micro_jit_poc_test result=" << *jitted << '\n';
  return 0;
#else
  std::cout << "[PASS] micro_jit_poc_test skipped (requires x86_64 + mmap/mprotect)\n";
  return 0;
#endif
}

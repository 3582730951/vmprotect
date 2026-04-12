#include <algorithm>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <spawn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace {

struct ProbeResult final {
  bool attach_succeeded = false;
  bool anchor_found = false;
  std::string error;
};

struct Options final {
  bool self_test = false;
  std::optional<std::string> hold_anchor;
  int hold_seconds = 10;
  std::optional<std::uint64_t> pid;
  std::optional<std::string> scan_anchor;
  std::optional<std::filesystem::path> json_out;
};

std::string json_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size() + 8u);
  for (char ch : text) {
    switch (ch) {
      case '\\':
        out += "\\\\";
        break;
      case '"':
        out += "\\\"";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      default:
        out.push_back(ch);
        break;
    }
  }
  return out;
}

void write_probe_result(const ProbeResult& result,
                        const std::optional<std::filesystem::path>& json_out) {
  std::string payload;
  payload += "{\n";
  payload += std::string("  \"attach_succeeded\":") + (result.attach_succeeded ? "true" : "false") + ",\n";
  payload += std::string("  \"anchor_found\":") + (result.anchor_found ? "true" : "false") + ",\n";
  payload += "  \"error\":\"" + json_escape(result.error) + "\"\n";
  payload += "}\n";

  if (json_out.has_value()) {
    std::error_code ec;
    std::filesystem::create_directories(json_out->parent_path(), ec);
    std::ofstream out(*json_out, std::ios::binary | std::ios::trunc);
    out << payload;
  } else {
    std::cout << payload;
  }
}

bool parse_u64(std::string_view text, std::uint64_t& value_out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0u;
  for (char ch : text) {
    if (!std::isdigit(static_cast<unsigned char>(ch))) {
      return false;
    }
    value = (value * 10u) + static_cast<std::uint64_t>(ch - '0');
  }
  value_out = value;
  return true;
}

std::optional<Options> parse_args(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    auto require_value = [&](const char* name) -> const char* {
      if (i + 1 >= argc) {
        std::cerr << "[FAIL] missing value for " << name << '\n';
        return nullptr;
      }
      return argv[++i];
    };

    if (arg == "--self-test") {
      options.self_test = true;
    } else if (arg == "--hold-anchor") {
      const char* value = require_value("--hold-anchor");
      if (value == nullptr) {
        return std::nullopt;
      }
      options.hold_anchor = std::string(value);
    } else if (arg == "--hold-seconds") {
      const char* value = require_value("--hold-seconds");
      if (value == nullptr) {
        return std::nullopt;
      }
      std::uint64_t seconds = 0u;
      if (!parse_u64(value, seconds)) {
        std::cerr << "[FAIL] invalid hold seconds\n";
        return std::nullopt;
      }
      options.hold_seconds = static_cast<int>(seconds);
    } else if (arg == "--pid") {
      const char* value = require_value("--pid");
      if (value == nullptr) {
        return std::nullopt;
      }
      std::uint64_t pid = 0u;
      if (!parse_u64(value, pid)) {
        std::cerr << "[FAIL] invalid pid\n";
        return std::nullopt;
      }
      options.pid = pid;
    } else if (arg == "--scan-anchor") {
      const char* value = require_value("--scan-anchor");
      if (value == nullptr) {
        return std::nullopt;
      }
      options.scan_anchor = std::string(value);
    } else if (arg == "--json-out") {
      const char* value = require_value("--json-out");
      if (value == nullptr) {
        return std::nullopt;
      }
      options.json_out = std::filesystem::path(value);
    } else {
      std::cerr << "[FAIL] unknown arg: " << arg << '\n';
      return std::nullopt;
    }
  }
  return options;
}

bool contains_bytes(const std::vector<std::uint8_t>& haystack, std::string_view needle) {
  if (needle.empty() || haystack.size() < needle.size()) {
    return false;
  }
  const auto* needle_bytes = reinterpret_cast<const std::uint8_t*>(needle.data());
  return std::search(haystack.begin(), haystack.end(), needle_bytes, needle_bytes + needle.size()) !=
         haystack.end();
}

#if defined(_WIN32)

ProbeResult probe_pid_for_anchor(std::uint64_t pid, std::string_view anchor) {
  ProbeResult result;
  HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                                 static_cast<DWORD>(pid));
  if (process == nullptr) {
    result.error = "open_process_failed";
    return result;
  }

  if (::DebugActiveProcess(static_cast<DWORD>(pid)) == FALSE) {
    result.error = "debug_attach_failed";
    ::CloseHandle(process);
    return result;
  }
  result.attach_succeeded = true;

  MEMORY_BASIC_INFORMATION mbi{};
  std::uintptr_t address = 0u;
  std::vector<std::uint8_t> buffer(64u * 1024u);
  while (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) ==
         sizeof(mbi)) {
    const bool readable = (mbi.Protect & PAGE_READONLY) || (mbi.Protect & PAGE_READWRITE) ||
                          (mbi.Protect & PAGE_EXECUTE_READ) ||
                          (mbi.Protect & PAGE_EXECUTE_READWRITE);
    if (mbi.State == MEM_COMMIT && readable) {
      SIZE_T bytes_read = 0;
      const SIZE_T to_read = std::min<SIZE_T>(buffer.size(), mbi.RegionSize);
      if (::ReadProcessMemory(process, mbi.BaseAddress, buffer.data(), to_read, &bytes_read) != FALSE) {
        buffer.resize(bytes_read);
        if (contains_bytes(buffer, anchor)) {
          result.anchor_found = true;
          break;
        }
        buffer.resize(64u * 1024u);
      }
    }
    address = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (address == 0u) {
      break;
    }
  }

  ::DebugActiveProcessStop(static_cast<DWORD>(pid));
  ::CloseHandle(process);
  return result;
}

int hold_anchor_process(std::string_view anchor, int hold_seconds) {
  std::string anchor_buffer(anchor);
  volatile char marker = anchor_buffer.empty() ? '\0' : anchor_buffer.front();
  (void)marker;
  std::this_thread::sleep_for(std::chrono::seconds(hold_seconds));
  return 0;
}

std::optional<std::uint64_t> spawn_hold_process(const char* self_path,
                                                std::string_view anchor,
                                                int hold_seconds) {
  const std::string command = std::string("\"") + self_path + "\" --hold-anchor \"" +
                              std::string(anchor) + "\" --hold-seconds " +
                              std::to_string(hold_seconds);
  STARTUPINFOA si{};
  PROCESS_INFORMATION pi{};
  si.cb = sizeof(si);
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');
  if (::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                       &si, &pi) == FALSE) {
    return std::nullopt;
  }
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  return static_cast<std::uint64_t>(pi.dwProcessId);
}

void terminate_pid(std::uint64_t pid) {
  HANDLE process =
      ::OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid));
  if (process != nullptr) {
    ::TerminateProcess(process, 0);
    ::CloseHandle(process);
  }
}

#else

struct MemoryRegion final {
  std::uintptr_t begin = 0u;
  std::uintptr_t end = 0u;
  bool readable = false;
};

std::optional<MemoryRegion> parse_maps_line(const std::string& line) {
  const std::size_t dash = line.find('-');
  const std::size_t space = line.find(' ');
  if (dash == std::string::npos || space == std::string::npos || dash >= space) {
    return std::nullopt;
  }
  const std::string begin_text = line.substr(0u, dash);
  const std::string end_text = line.substr(dash + 1u, space - dash - 1u);
  char* end_ptr = nullptr;
  const auto begin = static_cast<std::uintptr_t>(std::strtoull(begin_text.c_str(), &end_ptr, 16));
  if (end_ptr == nullptr || *end_ptr != '\0') {
    return std::nullopt;
  }
  end_ptr = nullptr;
  const auto end = static_cast<std::uintptr_t>(std::strtoull(end_text.c_str(), &end_ptr, 16));
  if (end_ptr == nullptr || *end_ptr != '\0' || end <= begin) {
    return std::nullopt;
  }
  const bool readable = space + 1u < line.size() && line[space + 1u] == 'r';
  return MemoryRegion{begin, end, readable};
}

ProbeResult probe_pid_for_anchor(std::uint64_t raw_pid, std::string_view anchor) {
  ProbeResult result;
  const pid_t pid = static_cast<pid_t>(raw_pid);
  if (::ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) != 0) {
    result.error = "ptrace_attach_failed";
    return result;
  }
  result.attach_succeeded = true;

  int wait_status = 0;
  if (::waitpid(pid, &wait_status, 0) < 0) {
    result.error = "waitpid_failed";
    ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return result;
  }

  const std::filesystem::path maps_path = std::filesystem::path("/proc") / std::to_string(pid) / "maps";
  const std::filesystem::path mem_path = std::filesystem::path("/proc") / std::to_string(pid) / "mem";

  std::ifstream maps(maps_path);
  const int mem_fd = ::open(mem_path.c_str(), O_RDONLY);
  if (!maps.is_open() || mem_fd < 0) {
    result.error = "proc_maps_or_mem_unavailable";
    if (mem_fd >= 0) {
      ::close(mem_fd);
    }
    ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return result;
  }

  constexpr std::size_t kChunkSize = 4096u;
  constexpr std::size_t kMaxScanBytes = 16u * 1024u * 1024u;
  std::vector<std::uint8_t> buffer(kChunkSize);
  std::size_t total_scanned = 0u;

  std::string line;
  while (std::getline(maps, line)) {
    const auto region = parse_maps_line(line);
    if (!region.has_value() || !region->readable) {
      continue;
    }

    std::uintptr_t cursor = region->begin;
    while (cursor < region->end && total_scanned < kMaxScanBytes) {
      const std::size_t remaining =
          static_cast<std::size_t>(std::min<std::uintptr_t>(region->end - cursor, kChunkSize));
      const ssize_t read_size = ::pread(mem_fd, buffer.data(), remaining, static_cast<off_t>(cursor));
      if (read_size > 0) {
        buffer.resize(static_cast<std::size_t>(read_size));
        total_scanned += static_cast<std::size_t>(read_size);
        if (contains_bytes(buffer, anchor)) {
          result.anchor_found = true;
          break;
        }
        buffer.resize(kChunkSize);
      }
      cursor += remaining;
    }
    if (result.anchor_found || total_scanned >= kMaxScanBytes) {
      break;
    }
  }

  ::close(mem_fd);
  ::ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
  return result;
}

int hold_anchor_process(std::string_view anchor, int hold_seconds) {
  std::string anchor_buffer(anchor);
  volatile char marker = anchor_buffer.empty() ? '\0' : anchor_buffer.front();
  (void)marker;
  std::this_thread::sleep_for(std::chrono::seconds(hold_seconds));
  return 0;
}

std::optional<std::uint64_t> spawn_hold_process(const char* self_path,
                                                std::string_view anchor,
                                                int hold_seconds) {
  std::vector<std::string> args_storage = {
      self_path,
      "--hold-anchor",
      std::string(anchor),
      "--hold-seconds",
      std::to_string(hold_seconds),
  };
  std::vector<char*> argv;
  argv.reserve(args_storage.size() + 1u);
  for (std::string& item : args_storage) {
    argv.push_back(item.data());
  }
  argv.push_back(nullptr);

  pid_t child_pid = 0;
  const int rc = ::posix_spawn(&child_pid, self_path, nullptr, nullptr, argv.data(), environ);
  if (rc != 0) {
    return std::nullopt;
  }
  return static_cast<std::uint64_t>(child_pid);
}

void terminate_pid(std::uint64_t raw_pid) {
  const pid_t pid = static_cast<pid_t>(raw_pid);
  ::kill(pid, SIGKILL);
  int status = 0;
  (void)::waitpid(pid, &status, 0);
}

#endif

int run_self_test(const char* self_path, const std::optional<std::filesystem::path>& json_out) {
  constexpr std::string_view kAnchor = "EIPPF_REVERSE_ANCHOR_SELF_TEST";
  const auto child_pid = spawn_hold_process(self_path, kAnchor, 20);
  if (!child_pid.has_value()) {
    ProbeResult result{};
    result.error = "spawn_failed";
    write_probe_result(result, json_out);
    return 1;
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  ProbeResult result = probe_pid_for_anchor(*child_pid, kAnchor);
  terminate_pid(*child_pid);
  write_probe_result(result, json_out);
  return result.attach_succeeded && result.anchor_found ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  const auto options = parse_args(argc, argv);
  if (!options.has_value()) {
    return 1;
  }

  if (options->self_test) {
    return run_self_test(argv[0], options->json_out);
  }

  if (options->hold_anchor.has_value()) {
    return hold_anchor_process(*options->hold_anchor, options->hold_seconds);
  }

  if (options->pid.has_value() && options->scan_anchor.has_value()) {
    const ProbeResult result = probe_pid_for_anchor(*options->pid, *options->scan_anchor);
    write_probe_result(result, options->json_out);
    return result.attach_succeeded && result.anchor_found ? 0 : 1;
  }

  std::cerr << "[FAIL] expected --self-test or probe arguments\n";
  return 1;
}

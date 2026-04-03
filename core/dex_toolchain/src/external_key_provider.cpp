#include "dex_toolchain/external_key_provider.hpp"

#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace eippf::dex_toolchain {

namespace {

[[nodiscard]] std::string trim_ascii(std::string_view text) {
  std::size_t begin = 0u;
  while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
    ++begin;
  }
  std::size_t end = text.size();
  while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1u])) != 0) {
    --end;
  }
  return std::string(text.substr(begin, end - begin));
}

[[nodiscard]] bool parse_u8(std::string_view text, std::uint8_t& value_out) noexcept {
  if (text.empty()) {
    return false;
  }
  std::string owned(text);
  char* end = nullptr;
  errno = 0;
  const unsigned long parsed = std::strtoul(owned.c_str(), &end, 10);
  if (errno != 0 || end == nullptr || *end != '\0' || parsed > 0xFFul) {
    return false;
  }
  value_out = static_cast<std::uint8_t>(parsed);
  return true;
}

[[nodiscard]] bool path_is_within_root(const std::filesystem::path& path,
                                       const std::filesystem::path& root) {
  if (path.empty() || root.empty()) {
    return false;
  }
  std::error_code ec;
  const std::filesystem::path abs_path = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    return false;
  }
  ec.clear();
  const std::filesystem::path abs_root = std::filesystem::weakly_canonical(root, ec);
  if (ec) {
    return false;
  }

  auto path_it = abs_path.begin();
  auto root_it = abs_root.begin();
  while (root_it != abs_root.end()) {
    if (path_it == abs_path.end() || *path_it != *root_it) {
      return false;
    }
    ++path_it;
    ++root_it;
  }
  return true;
}

[[nodiscard]] bool is_executable_regular_file(const std::filesystem::path& path) noexcept {
  std::error_code ec;
  const std::filesystem::file_status status = std::filesystem::status(path, ec);
  if (ec || status.type() != std::filesystem::file_type::regular) {
    return false;
  }
  const auto perms = status.permissions();
  const bool owner_exec = (perms & std::filesystem::perms::owner_exec) != std::filesystem::perms::none;
  const bool group_exec = (perms & std::filesystem::perms::group_exec) != std::filesystem::perms::none;
  const bool others_exec = (perms & std::filesystem::perms::others_exec) != std::filesystem::perms::none;
  return owner_exec || group_exec || others_exec;
}

[[nodiscard]] bool points_to_regular_file(const std::filesystem::path& path) noexcept {
  std::error_code ec;
  const std::filesystem::file_status symlink_state = std::filesystem::symlink_status(path, ec);
  if (ec || symlink_state.type() != std::filesystem::file_type::symlink) {
    return false;
  }
  ec.clear();
  const std::filesystem::file_status target_state = std::filesystem::status(path, ec);
  return !ec && target_state.type() == std::filesystem::file_type::regular;
}

[[nodiscard]] KeyProviderError parse_provider_response(std::string_view provider_text,
                                                       std::string_view expected_key_id,
                                                       std::uint8_t& key_out) {
  std::string provider_protocol;
  std::string provider_status;
  std::string provider_key_id;
  std::string key_u8_text;
  bool seen_protocol = false;
  bool seen_status = false;
  bool seen_key_id = false;
  bool seen_key_u8 = false;

  std::size_t cursor = 0u;
  while (cursor <= provider_text.size()) {
    const std::size_t next = provider_text.find('\n', cursor);
    const std::size_t end = next == std::string::npos ? provider_text.size() : next;
    std::string line = trim_ascii(provider_text.substr(cursor, end - cursor));
    cursor = next == std::string::npos ? provider_text.size() + 1u : next + 1u;

    if (line.empty() || line[0] == '#') {
      continue;
    }

    const std::size_t eq = line.find('=');
    if (eq == std::string::npos) {
      return KeyProviderError::kMalformed;
    }

    const std::string key = trim_ascii(std::string_view(line).substr(0u, eq));
    const std::string value = trim_ascii(std::string_view(line).substr(eq + 1u));
    if (key.empty()) {
      return KeyProviderError::kMalformed;
    }

    if (key == "protocol") {
      if (seen_protocol) {
        return KeyProviderError::kMalformed;
      }
      provider_protocol = value;
      seen_protocol = true;
    } else if (key == "status") {
      if (seen_status) {
        return KeyProviderError::kMalformed;
      }
      provider_status = value;
      seen_status = true;
    } else if (key == "key_id") {
      if (seen_key_id) {
        return KeyProviderError::kMalformed;
      }
      provider_key_id = value;
      seen_key_id = true;
    } else if (key == "key_u8") {
      if (seen_key_u8) {
        return KeyProviderError::kMalformed;
      }
      key_u8_text = value;
      seen_key_u8 = true;
    } else {
      return KeyProviderError::kMalformed;
    }
  }

  if (!seen_protocol || provider_protocol != kKeyProviderProtocol) {
    return KeyProviderError::kMalformed;
  }
  if (!seen_status || !seen_key_id || !seen_key_u8) {
    return KeyProviderError::kMalformed;
  }
  if (provider_status != "ok" && provider_status != "deny") {
    return KeyProviderError::kMalformed;
  }
  if (provider_status == "deny") {
    return KeyProviderError::kProviderRejected;
  }
  if (provider_key_id != expected_key_id) {
    return KeyProviderError::kKeyIdMismatch;
  }

  std::uint8_t parsed_key = 0u;
  if (!parse_u8(key_u8_text, parsed_key)) {
    return KeyProviderError::kMalformed;
  }
  key_out = parsed_key;
  return KeyProviderError::kOk;
}

}  // namespace

std::string_view provider_endpoint_kind_name(ProviderEndpointKind kind) noexcept {
  switch (kind) {
    case ProviderEndpointKind::kExecutableAdapter:
      return "executable_adapter";
    case ProviderEndpointKind::kFifo:
      return "fifo";
    case ProviderEndpointKind::kUnixSocket:
      return "unix_socket";
    case ProviderEndpointKind::kInvalid:
      return "invalid";
  }
  return "invalid";
}

ProviderEndpointKind classify_provider_endpoint(const std::filesystem::path& provider_path) noexcept {
  std::error_code ec;
  const std::filesystem::file_status symlink_state = std::filesystem::symlink_status(provider_path, ec);
  if (ec) {
    return ProviderEndpointKind::kInvalid;
  }

  if (symlink_state.type() == std::filesystem::file_type::symlink && points_to_regular_file(provider_path)) {
    return ProviderEndpointKind::kInvalid;
  }

  if (is_executable_regular_file(provider_path)) {
    return ProviderEndpointKind::kExecutableAdapter;
  }

  if (symlink_state.type() == std::filesystem::file_type::fifo) {
    return ProviderEndpointKind::kFifo;
  }
  if (symlink_state.type() == std::filesystem::file_type::socket) {
    return ProviderEndpointKind::kUnixSocket;
  }

  ec.clear();
  const std::filesystem::file_status resolved_state = std::filesystem::status(provider_path, ec);
  if (ec) {
    return ProviderEndpointKind::kInvalid;
  }
  if (resolved_state.type() == std::filesystem::file_type::fifo) {
    return ProviderEndpointKind::kFifo;
  }
  if (resolved_state.type() == std::filesystem::file_type::socket) {
    return ProviderEndpointKind::kUnixSocket;
  }

  return ProviderEndpointKind::kInvalid;
}

KeyProviderError read_provider_response_from_executable(const std::filesystem::path& provider_path,
                                                        std::string_view expected_key_id,
                                                        std::string& response_out) {
#if defined(__unix__) || defined(__APPLE__)
  int stdout_pipe[2] = {-1, -1};
  int stderr_pipe[2] = {-1, -1};
  if (::pipe(stdout_pipe) != 0) {
    return KeyProviderError::kReadFailed;
  }
  if (::pipe(stderr_pipe) != 0) {
    ::close(stdout_pipe[0]);
    ::close(stdout_pipe[1]);
    return KeyProviderError::kReadFailed;
  }

  // Keep executable adapter invocation strict: only pass --key-id=<id>.
  const std::string key_id_arg = std::string("--key-id=") + std::string(expected_key_id);

  const pid_t pid = ::fork();
  if (pid < 0) {
    ::close(stdout_pipe[0]);
    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[0]);
    ::close(stderr_pipe[1]);
    return KeyProviderError::kExecutionFailed;
  }

  if (pid == 0) {
    (void)::dup2(stdout_pipe[1], STDOUT_FILENO);
    (void)::dup2(stderr_pipe[1], STDERR_FILENO);
    ::close(stdout_pipe[0]);
    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[0]);
    ::close(stderr_pipe[1]);
    char* const argv[] = {
        const_cast<char*>(provider_path.c_str()),
        const_cast<char*>(key_id_arg.c_str()),
        nullptr,
    };
    ::execv(provider_path.c_str(), argv);
    _exit(127);
  }

  ::close(stdout_pipe[1]);
  ::close(stderr_pipe[1]);

  auto close_fd = [](int& fd) noexcept {
    if (fd >= 0) {
      ::close(fd);
      fd = -1;
    }
  };

  std::array<char, 4096u> buffer{};
  response_out.clear();
  std::string stderr_capture;
  bool stdout_open = true;
  bool stderr_open = true;
  while (stdout_open || stderr_open) {
    struct pollfd fds[2];
    nfds_t nfds = 0;
    if (stdout_open) {
      fds[nfds].fd = stdout_pipe[0];
      fds[nfds].events = POLLIN | POLLERR | POLLHUP;
      fds[nfds].revents = 0;
      ++nfds;
    }
    if (stderr_open) {
      fds[nfds].fd = stderr_pipe[0];
      fds[nfds].events = POLLIN | POLLERR | POLLHUP;
      fds[nfds].revents = 0;
      ++nfds;
    }

    const int poll_result = ::poll(fds, nfds, -1);
    if (poll_result < 0) {
      close_fd(stdout_pipe[0]);
      close_fd(stderr_pipe[0]);
      (void)::waitpid(pid, nullptr, 0);
      response_out.clear();
      return KeyProviderError::kReadFailed;
    }

    for (nfds_t i = 0; i < nfds; ++i) {
      if ((fds[i].revents & (POLLIN | POLLERR | POLLHUP)) == 0) {
        continue;
      }
      const bool is_stdout = fds[i].fd == stdout_pipe[0];
      while (true) {
        const ssize_t read_size = ::read(fds[i].fd, buffer.data(), buffer.size());
        if (read_size < 0) {
          if (errno == EINTR) {
            continue;
          }
          close_fd(stdout_pipe[0]);
          close_fd(stderr_pipe[0]);
          (void)::waitpid(pid, nullptr, 0);
          response_out.clear();
          return KeyProviderError::kReadFailed;
        }
        if (read_size == 0) {
          if (is_stdout) {
            close_fd(stdout_pipe[0]);
            stdout_open = false;
          } else {
            close_fd(stderr_pipe[0]);
            stderr_open = false;
          }
          break;
        }
        if (is_stdout) {
          response_out.append(buffer.data(), static_cast<std::size_t>(read_size));
          if (response_out.size() > 64u * 1024u) {
            close_fd(stdout_pipe[0]);
            close_fd(stderr_pipe[0]);
            (void)::waitpid(pid, nullptr, 0);
            response_out.clear();
            return KeyProviderError::kReadFailed;
          }
        } else {
          stderr_capture.append(buffer.data(), static_cast<std::size_t>(read_size));
          if (stderr_capture.size() > 64u * 1024u) {
            close_fd(stdout_pipe[0]);
            close_fd(stderr_pipe[0]);
            (void)::waitpid(pid, nullptr, 0);
            response_out.clear();
            return KeyProviderError::kMalformed;
          }
        }
        if (static_cast<std::size_t>(read_size) < buffer.size()) {
          break;
        }
      }
    }
  }

  int wait_status = 0;
  if (::waitpid(pid, &wait_status, 0) < 0) {
    response_out.clear();
    return KeyProviderError::kExecutionFailed;
  }
  if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
    response_out.clear();
    return KeyProviderError::kExecutionFailed;
  }
  if (!stderr_capture.empty()) {
    response_out.clear();
    return KeyProviderError::kMalformed;
  }
  if (response_out.empty()) {
    return KeyProviderError::kReadFailed;
  }
  return KeyProviderError::kOk;
#else
  (void)provider_path;
  (void)expected_key_id;
  response_out.clear();
  return KeyProviderError::kUnsupportedEndpoint;
#endif
}

KeyProviderError read_provider_response_from_fifo(const std::filesystem::path& provider_path,
                                                  std::string& response_out) {
  std::ifstream input(provider_path, std::ios::binary);
  if (!input.is_open()) {
    response_out.clear();
    return KeyProviderError::kReadFailed;
  }
  response_out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  if (!input.good() && !input.eof()) {
    response_out.clear();
    return KeyProviderError::kReadFailed;
  }
  if (response_out.empty()) {
    return KeyProviderError::kReadFailed;
  }
  return KeyProviderError::kOk;
}

KeyProviderError read_provider_response_from_unix_socket(const std::filesystem::path& provider_path,
                                                         std::string& response_out) {
#if defined(__unix__) || defined(__APPLE__)
  response_out.clear();
  const int socket_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (socket_fd < 0) {
    return KeyProviderError::kReadFailed;
  }

  struct sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  const std::string provider_text = provider_path.string();
  if (provider_text.size() >= sizeof(addr.sun_path)) {
    ::close(socket_fd);
    return KeyProviderError::kReadFailed;
  }
  std::memcpy(addr.sun_path, provider_text.c_str(), provider_text.size() + 1u);

  if (::connect(socket_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
    ::close(socket_fd);
    return KeyProviderError::kReadFailed;
  }

  std::array<char, 4096u> buffer{};
  while (true) {
    const ssize_t read_size = ::recv(socket_fd, buffer.data(), buffer.size(), 0);
    if (read_size < 0) {
      ::close(socket_fd);
      response_out.clear();
      return KeyProviderError::kReadFailed;
    }
    if (read_size == 0) {
      break;
    }
    response_out.append(buffer.data(), static_cast<std::size_t>(read_size));
    if (response_out.size() > 64u * 1024u) {
      ::close(socket_fd);
      response_out.clear();
      return KeyProviderError::kReadFailed;
    }
  }

  ::close(socket_fd);
  if (response_out.empty()) {
    return KeyProviderError::kReadFailed;
  }
  return KeyProviderError::kOk;
#else
  (void)provider_path;
  response_out.clear();
  return KeyProviderError::kUnsupportedEndpoint;
#endif
}

KeyProviderError resolve_external_key_from_endpoint(const std::filesystem::path& provider_path,
                                                    std::string_view expected_key_id,
                                                    const std::filesystem::path& workspace_root,
                                                    const std::filesystem::path& temp_root,
                                                    std::uint8_t& key_out,
                                                    ProviderEndpointKind& endpoint_kind_out) {
  std::error_code ec;
  const std::filesystem::file_status symlink_state = std::filesystem::symlink_status(provider_path, ec);
  if (ec || symlink_state.type() == std::filesystem::file_type::not_found) {
    endpoint_kind_out = ProviderEndpointKind::kInvalid;
    return KeyProviderError::kReadFailed;
  }

  endpoint_kind_out = classify_provider_endpoint(provider_path);

  if (!ec) {
    const bool symlink_regular =
        symlink_state.type() == std::filesystem::file_type::symlink && points_to_regular_file(provider_path);
    if (symlink_regular) {
      return KeyProviderError::kStaticFileRejected;
    }

    ec.clear();
    const bool regular_file = std::filesystem::is_regular_file(provider_path, ec);
    if (!ec && regular_file && endpoint_kind_out != ProviderEndpointKind::kExecutableAdapter) {
      return KeyProviderError::kStaticFileRejected;
    }

    // Keep the explicit root checks for non-executable regular files only.
    // Executable adapters are allowed even when located under temp/workspace paths.
    const bool within_workspace = path_is_within_root(provider_path, workspace_root);
    const bool within_temp = path_is_within_root(provider_path, temp_root);
    if ((within_workspace || within_temp) && regular_file &&
        endpoint_kind_out != ProviderEndpointKind::kExecutableAdapter) {
      return KeyProviderError::kStaticFileRejected;
    }
  }

  std::string provider_text;
  KeyProviderError read_error = KeyProviderError::kUnsupportedEndpoint;
  switch (endpoint_kind_out) {
    case ProviderEndpointKind::kExecutableAdapter:
      read_error = read_provider_response_from_executable(provider_path, expected_key_id, provider_text);
      break;
    case ProviderEndpointKind::kFifo:
      read_error = read_provider_response_from_fifo(provider_path, provider_text);
      break;
    case ProviderEndpointKind::kUnixSocket:
      read_error = read_provider_response_from_unix_socket(provider_path, provider_text);
      break;
    case ProviderEndpointKind::kInvalid:
      return KeyProviderError::kUnsupportedEndpoint;
  }
  if (read_error != KeyProviderError::kOk) {
    return read_error;
  }
  return parse_provider_response(provider_text, expected_key_id, key_out);
}

}  // namespace eippf::dex_toolchain

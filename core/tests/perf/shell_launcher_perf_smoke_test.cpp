#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/stat.h>
#include <sys/wait.h>
#endif

#ifndef EIPPF_SCRIPT_GUARD_PATH
#error "EIPPF_SCRIPT_GUARD_PATH must be defined"
#endif

#ifndef EIPPF_SCRIPT_LAUNCHER_PATH
#error "EIPPF_SCRIPT_LAUNCHER_PATH must be defined"
#endif

namespace {

constexpr std::string_view kProviderProtocol = "eippf.external_key.v1";
constexpr int kRuns = 20;

[[nodiscard]] std::string quote_arg(const std::string& value) {
  std::string out = "\"";
  out.reserve(value.size() + 2u);
  for (const char ch : value) {
    if (ch == '"' || ch == '\\') {
      out.push_back('\\');
    }
    out.push_back(ch);
  }
  out.push_back('"');
  return out;
}

[[nodiscard]] int normalize_status(int status) {
#if defined(__unix__) || defined(__APPLE__)
  if (status == -1) {
    return -1;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  return status;
#else
  return status;
#endif
}

bool write_text(const std::filesystem::path& path, std::string_view text) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir = std::filesystem::temp_directory_path() /
                                         ("eippf_shell_perf_smoke_" +
                                          std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

[[nodiscard]] std::string provider_text(std::string_view status,
                                        std::string_view key_id,
                                        std::string_view key_u8) {
  std::string out;
  out.reserve(96u);
  out += "protocol=";
  out += kProviderProtocol;
  out += "\nstatus=";
  out += status;
  out += "\nkey_id=";
  out += key_id;
  out += "\nkey_u8=";
  out += key_u8;
  out += "\n";
  return out;
}

bool create_fifo_endpoint(const std::filesystem::path& path) {
#if defined(__unix__) || defined(__APPLE__)
  std::error_code ec;
  std::filesystem::remove(path, ec);
  if (::mkfifo(path.c_str(), 0600) != 0) {
    return false;
  }
  return true;
#else
  (void)path;
  return false;
#endif
}

[[nodiscard]] std::string wrap_command_with_fifo_provider(const std::string& command,
                                                          const std::filesystem::path& provider_path,
                                                          std::string_view provider_payload) {
  std::string wrapped = "( { cat > ";
  wrapped += quote_arg(provider_path.string());
  wrapped += " <<'__EIPPF_PROVIDER_EOF__'\n";
  wrapped += std::string(provider_payload);
  if (provider_payload.empty() || provider_payload.back() != '\n') {
    wrapped += '\n';
  }
  wrapped += "__EIPPF_PROVIDER_EOF__\n";
  wrapped += "} & writer_pid=$!; ";
  wrapped += command;
  wrapped += "; command_status=$?; ";
  wrapped += "wait \"$writer_pid\" 2>/dev/null || true; ";
  wrapped += "exit \"$command_status\"; )";
  return wrapped;
}

[[nodiscard]] std::string guard_command(const std::filesystem::path& script_path,
                                        const std::filesystem::path& bundle_path,
                                        const std::filesystem::path& manifest_path,
                                        const std::filesystem::path& provider_path,
                                        std::string_view key_id) {
  return std::string(EIPPF_SCRIPT_GUARD_PATH) + " --input-script=" + quote_arg(script_path.string()) +
         " --output-bundle=" + quote_arg(bundle_path.string()) + " --manifest=" +
         quote_arg(manifest_path.string()) + " --key-provider=" + quote_arg(provider_path.string()) +
         " --key-id=" + std::string(key_id);
}

[[nodiscard]] std::string baseline_command(const std::filesystem::path& script_path) {
  return std::string("/bin/sh ") + quote_arg(script_path.string()) + " alpha beta > /dev/null 2>&1";
}

[[nodiscard]] std::string candidate_command(const std::filesystem::path& bundle_path,
                                            const std::filesystem::path& manifest_path,
                                            const std::filesystem::path& provider_path,
                                            std::string_view key_id) {
  return std::string(EIPPF_SCRIPT_LAUNCHER_PATH) + " --input-bundle=" + quote_arg(bundle_path.string()) +
         " --manifest=" + quote_arg(manifest_path.string()) + " --key-provider=" +
         quote_arg(provider_path.string()) + " --key-id=" + std::string(key_id) +
         " -- alpha beta > /dev/null 2>&1";
}

bool run_timed(std::string_view label, const std::string& command, double& elapsed_ms_out) {
  const auto begin = std::chrono::steady_clock::now();
  const int status = normalize_status(std::system(command.c_str()));
  const auto end = std::chrono::steady_clock::now();
  elapsed_ms_out = std::chrono::duration<double, std::milli>(end - begin).count();
  if (status == 0) {
    return true;
  }
  std::cerr << "[FAIL] " << label << " returned " << status << '\n';
  return false;
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (temp_dir.empty()) {
    std::cerr << "[FAIL] cannot create temp dir\n";
    return 1;
  }

  const std::filesystem::path script_path = temp_dir / "perf.sh";
  const std::filesystem::path bundle_path = temp_dir / "perf.eippf";
  const std::filesystem::path manifest_path = temp_dir / "perf.manifest.json";
  const std::filesystem::path provider_path = temp_dir / "perf.provider";

  const std::string script =
      "#!/bin/sh\n"
      "arg1_len=${#1}\n"
      "arg2_len=${#2}\n"
      "acc=17\n"
      "i=0\n"
      "while [ \"$i\" -lt 120000 ]; do\n"
      "  acc=$(( (acc * 33 + i + arg1_len * 7 + arg2_len * 11) % 1000003 ))\n"
      "  i=$((i + 1))\n"
      "done\n"
      "printf 'PERF:%s:%s:%s\\n' \"$acc\" \"$arg1_len\" \"$arg2_len\"\n";
  const std::string provider_payload = provider_text("ok", "perf-key", "64");
  if (!write_text(script_path, script) ||
      !create_fifo_endpoint(provider_path)) {
    std::cerr << "[FAIL] cannot write perf fixtures\n";
    return 1;
  }

  const std::string guarded_bundle_command =
      wrap_command_with_fifo_provider(
          guard_command(script_path, bundle_path, manifest_path, provider_path, "perf-key"),
          provider_path,
          provider_payload);
  if (normalize_status(std::system(guarded_bundle_command.c_str())) != 0) {
    std::cerr << "[FAIL] cannot generate perf bundle fixtures\n";
    return 1;
  }

  const std::string baseline = baseline_command(script_path);
  const std::string candidate = wrap_command_with_fifo_provider(
      candidate_command(bundle_path, manifest_path, provider_path, "perf-key"),
      provider_path,
      provider_payload);

  double baseline_start_ms = 0.0;
  double candidate_start_ms = 0.0;
  if (!run_timed("baseline startup", baseline, baseline_start_ms) ||
      !run_timed("candidate startup", candidate, candidate_start_ms)) {
    return 1;
  }

  double baseline_total_ms = 0.0;
  double candidate_total_ms = 0.0;
  for (int i = 0; i < kRuns; ++i) {
    double one_baseline_ms = 0.0;
    double one_candidate_ms = 0.0;
    if (!run_timed("baseline loop", baseline, one_baseline_ms) ||
        !run_timed("candidate loop", candidate, one_candidate_ms)) {
      return 1;
    }
    baseline_total_ms += one_baseline_ms;
    candidate_total_ms += one_candidate_ms;
  }

  const double startup_overhead_ms = std::max(0.0, candidate_start_ms - baseline_start_ms);
  const double baseline_floor_ms = std::max(1.0, baseline_total_ms);
  const double overall_overhead_percent =
      ((candidate_total_ms - baseline_total_ms) / baseline_floor_ms) * 100.0;

  std::cout << std::fixed << std::setprecision(2)
            << "startup_overhead_ms=" << startup_overhead_ms << '\n'
            << "overall_overhead_percent=" << overall_overhead_percent << '\n';

  if (startup_overhead_ms > 250.0) {
    std::cerr << "[FAIL] startup_overhead_ms exceeds 250ms budget\n";
    return 1;
  }
  if (overall_overhead_percent > 10.0) {
    std::cerr << "[FAIL] overall_overhead_percent exceeds 10% budget\n";
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

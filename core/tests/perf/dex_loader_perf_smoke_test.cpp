#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

#ifndef EIPPF_DEX_TOOLCHAIN_PATH
#error "EIPPF_DEX_TOOLCHAIN_PATH must be defined"
#endif

#ifndef EIPPF_DEX_LOADER_PATH
#error "EIPPF_DEX_LOADER_PATH must be defined"
#endif

namespace {

constexpr std::string_view kProviderProtocol = "eippf.external_key.v1";
constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;
constexpr int kRuns = 12;
constexpr double kBudgetPercent = 10.0;

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

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

bool write_executable_script(const std::filesystem::path& path, std::string_view content) {
  if (!write_text(path, content)) {
    return false;
  }
  std::error_code ec;
  std::filesystem::permissions(
      path,
      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
          std::filesystem::perms::owner_exec | std::filesystem::perms::group_read |
          std::filesystem::perms::group_exec | std::filesystem::perms::others_read |
          std::filesystem::perms::others_exec,
      std::filesystem::perm_options::replace,
      ec);
  return !ec;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("eippf_dex_loader_perf_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

[[nodiscard]] std::string provider_payload(std::string_view status,
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

[[nodiscard]] std::string build_provider_script(std::string_view payload) {
  std::string script;
  script.reserve(payload.size() + 64u);
  script += "#!/bin/sh\n";
  script += "cat <<'__EIPPF_PROVIDER_EOF__'\n";
  script += std::string(payload);
  if (payload.empty() || payload.back() != '\n') {
    script.push_back('\n');
  }
  script += "__EIPPF_PROVIDER_EOF__\n";
  return script;
}

[[nodiscard]] std::string build_bundle_command(const std::filesystem::path& input_path,
                                               const std::filesystem::path& bundle_path,
                                               const std::filesystem::path& manifest_path,
                                               const std::filesystem::path& provider_path,
                                               std::string_view key_id) {
  return std::string(EIPPF_DEX_TOOLCHAIN_PATH) + " --input=" + quote_arg(input_path.string()) +
         " --output-bundle=" + quote_arg(bundle_path.string()) + " --manifest=" +
         quote_arg(manifest_path.string()) + " --key-provider=" + quote_arg(provider_path.string()) +
         " --key-id=" + std::string(key_id);
}

[[nodiscard]] std::string build_loader_command(const std::filesystem::path& bundle_path,
                                               const std::filesystem::path& manifest_path,
                                               const std::filesystem::path& provider_path,
                                               std::string_view key_id,
                                               std::string_view report_path,
                                               std::string_view bridge_token) {
  std::string command = std::string(EIPPF_DEX_LOADER_PATH) + " --input-bundle=" +
                        quote_arg(bundle_path.string()) + " --manifest=" +
                        quote_arg(manifest_path.string()) + " --key-provider=" +
                        quote_arg(provider_path.string()) + " --key-id=" + std::string(key_id) +
                        " --report=" + quote_arg(std::string(report_path));
  if (!bridge_token.empty()) {
    command += " --bridge-token=";
    command += std::string(bridge_token);
  }
  command += " > /dev/null 2>&1";
  return command;
}

[[nodiscard]] std::uint64_t fnv1a64(std::string_view text) noexcept {
  std::uint64_t hash = kFnvOffset;
  for (const char ch : text) {
    hash ^= static_cast<std::uint8_t>(ch);
    hash *= kFnvPrime;
  }
  return hash;
}

[[nodiscard]] std::string to_hex_u64(std::uint64_t value) {
  std::string out(16u, '0');
  for (std::size_t i = 0u; i < out.size(); ++i) {
    const std::size_t index = out.size() - 1u - i;
    const std::uint8_t nibble = static_cast<std::uint8_t>(value & 0x0Fu);
    out[index] = static_cast<char>(nibble < 10u ? ('0' + nibble) : ('a' + (nibble - 10u)));
    value >>= 4u;
  }
  return out;
}

[[nodiscard]] std::string make_bridge_token(std::string_view key_id) {
  std::string bridge_material(key_id);
  bridge_material += '\x1f';
  bridge_material += '0';
  bridge_material += '\x1f';
  bridge_material += '0';
  bridge_material += '\x1f';
  bridge_material += "eippf.dex.bridge.v1";
  return to_hex_u64(fnv1a64(bridge_material));
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
    std::cerr << "[FAIL] cannot create temp directory\n";
    return 1;
  }

  constexpr std::string_view kKeyId = "dex-perf";
  const std::filesystem::path input_path = temp_dir / "classes.input";
  const std::filesystem::path bundle_path = temp_dir / "classes.eippf";
  const std::filesystem::path manifest_path = temp_dir / "classes.manifest.json";
  const std::filesystem::path provider_path = temp_dir / "provider_ok.sh";
  const std::filesystem::path baseline_report_path = temp_dir / "baseline.report.json";
  const std::filesystem::path candidate_report_path = temp_dir / "candidate.report.json";

  std::vector<std::uint8_t> dex_bytes(128u * 1024u, static_cast<std::uint8_t>('A'));
  dex_bytes[0u] = static_cast<std::uint8_t>('d');
  dex_bytes[1u] = static_cast<std::uint8_t>('e');
  dex_bytes[2u] = static_cast<std::uint8_t>('x');
  dex_bytes[3u] = static_cast<std::uint8_t>('\n');
  dex_bytes[4u] = static_cast<std::uint8_t>('0');
  dex_bytes[5u] = static_cast<std::uint8_t>('3');
  dex_bytes[6u] = static_cast<std::uint8_t>('5');
  dex_bytes[7u] = 0u;

  if (!write_bytes(input_path, dex_bytes) ||
      !write_executable_script(
      provider_path,
          build_provider_script(provider_payload("ok", kKeyId, "127")))) {
    std::cerr << "[FAIL] cannot write perf fixtures\n";
    return 1;
  }

  const int bundle_status = normalize_status(
      std::system(build_bundle_command(input_path, bundle_path, manifest_path, provider_path, kKeyId).c_str()));
  if (bundle_status != 0) {
    std::cerr << "[FAIL] bundle generation returned " << bundle_status << '\n';
    return 1;
  }

  const std::string baseline_command = build_loader_command(
      bundle_path, manifest_path, provider_path, kKeyId, baseline_report_path.string(), "");
  const std::string candidate_command = build_loader_command(bundle_path,
                                                             manifest_path,
                                                             provider_path,
                                                             kKeyId,
                                                             candidate_report_path.string(),
                                                             make_bridge_token(kKeyId));

  double baseline_start_ms = 0.0;
  double candidate_start_ms = 0.0;
  if (!run_timed("baseline startup", baseline_command, baseline_start_ms) ||
      !run_timed("candidate startup", candidate_command, candidate_start_ms)) {
    return 1;
  }

  double baseline_total_ms = 0.0;
  double candidate_total_ms = 0.0;
  for (int i = 0; i < kRuns; ++i) {
    double baseline_ms = 0.0;
    double candidate_ms = 0.0;
    if (!run_timed("baseline loop", baseline_command, baseline_ms) ||
        !run_timed("candidate loop", candidate_command, candidate_ms)) {
      return 1;
    }
    baseline_total_ms += baseline_ms;
    candidate_total_ms += candidate_ms;
  }

  const double baseline_floor_ms = baseline_total_ms > 1.0 ? baseline_total_ms : 1.0;
  const double startup_overhead_ms = std::max(0.0, candidate_start_ms - baseline_start_ms);
  const double overall_overhead_percent =
      ((candidate_total_ms - baseline_total_ms) / baseline_floor_ms) * 100.0;

  std::cout << std::fixed << std::setprecision(2)
            << "startup_overhead_ms=" << startup_overhead_ms << '\n'
            << "overall_overhead_percent=" << overall_overhead_percent << '\n';

  if (overall_overhead_percent > kBudgetPercent) {
    std::cerr << "[FAIL] overall_overhead_percent exceeds 10% budget\n";
    return 1;
  }

  std::error_code ec;
  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

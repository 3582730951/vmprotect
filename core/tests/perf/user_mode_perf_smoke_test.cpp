#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/wait.h>
#endif

#ifndef EIPPF_POST_LINK_MUTATOR_BIN
#error "EIPPF_POST_LINK_MUTATOR_BIN must be defined"
#endif

#ifndef EIPPF_ARTIFACT_AUDIT_PATH
#error "EIPPF_ARTIFACT_AUDIT_PATH must be defined"
#endif

#ifndef EIPPF_LEXICAL_DENYLIST_PATH
#error "EIPPF_LEXICAL_DENYLIST_PATH must be defined"
#endif

namespace {

constexpr double kBudgetPercent = 10.0;
constexpr int kIterationsPerSample = 3;
constexpr int kMeasurementSamples = 5;
constexpr std::size_t kPayloadSizeBytes = 128u * 1024u;

struct PipelineSample final {
  std::string sample_name;
  std::string file_name;
  std::string target_label;
  std::string target_kind;
  std::vector<std::uint8_t> bytes;
};

struct TimedResult final {
  bool ok = false;
  double elapsed_ms = 0.0;
};

struct BudgetResult final {
  std::string lane_name;
  double baseline_ms = 0.0;
  double compared_ms = 0.0;
  double budget_percent = 0.0;
  double result_percent = 0.0;
  bool within_budget = false;
};

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

bool expect(bool condition, const char* message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    return false;
  }
  return true;
}

[[nodiscard]] std::filesystem::path make_temp_dir() {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  const auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const std::filesystem::path temp_dir =
      std::filesystem::temp_directory_path() /
      ("eippf_user_mode_perf_smoke_" + std::to_string(static_cast<long long>(stamp)));
  std::error_code ec;
  std::filesystem::create_directories(temp_dir, ec);
  if (ec) {
    return {};
  }
  return temp_dir;
}

bool write_bytes(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return static_cast<bool>(out);
}

[[nodiscard]] std::vector<std::uint8_t> make_repeated_payload(std::size_t bytes_count) {
  std::vector<std::uint8_t> payload;
  payload.resize(bytes_count);
  for (std::size_t i = 0; i < bytes_count; ++i) {
    payload[i] = static_cast<std::uint8_t>('A' + static_cast<char>(i % 23u));
  }
  return payload;
}

[[nodiscard]] std::vector<std::uint8_t> make_pe_fixture(std::size_t payload_size) {
  std::vector<std::uint8_t> pe(256u, 0u);
  pe[0] = static_cast<std::uint8_t>('M');
  pe[1] = static_cast<std::uint8_t>('Z');
  pe[0x3Cu] = 0x80u;
  pe[0x80u] = static_cast<std::uint8_t>('P');
  pe[0x81u] = static_cast<std::uint8_t>('E');
  pe[0x82u] = 0x00u;
  pe[0x83u] = 0x00u;
  const std::vector<std::uint8_t> payload = make_repeated_payload(payload_size);
  pe.insert(pe.end(), payload.begin(), payload.end());
  return pe;
}

[[nodiscard]] std::vector<std::uint8_t> make_elf_fixture(std::size_t payload_size) {
  std::vector<std::uint8_t> elf(0x40u + 0x38u, 0u);
  elf[0] = 0x7Fu;
  elf[1] = static_cast<std::uint8_t>('E');
  elf[2] = static_cast<std::uint8_t>('L');
  elf[3] = static_cast<std::uint8_t>('F');
  elf[4] = 2u;
  elf[5] = 1u;
  elf[6] = 1u;
  elf[0x20u] = 0x40u;
  elf[0x36u] = 0x38u;
  elf[0x38u] = 1u;
  const std::size_t ph = 0x40u;
  elf[ph + 0u] = 1u;
  elf[ph + 4u] = 0u;
  const std::vector<std::uint8_t> payload = make_repeated_payload(payload_size);
  elf.insert(elf.end(), payload.begin(), payload.end());
  return elf;
}

[[nodiscard]] int run_mutator(const std::filesystem::path& input_path,
                              const std::filesystem::path& output_path,
                              const std::filesystem::path& manifest_path,
                              std::string_view target_label,
                              std::string_view target_kind) {
  const std::string command = std::string(EIPPF_POST_LINK_MUTATOR_BIN) + " --input " +
                              quote_arg(input_path.string()) + " --output " +
                              quote_arg(output_path.string()) + " --manifest " +
                              quote_arg(manifest_path.string()) + " --target " +
                              quote_arg(std::string(target_label)) + " --target-kind " +
                              quote_arg(std::string(target_kind));
  return normalize_status(std::system(command.c_str()));
}

[[nodiscard]] int run_audit(const std::filesystem::path& input_path,
                            const std::filesystem::path& output_path,
                            std::string_view target_kind) {
  const std::string command = std::string("python3 ") + quote_arg(EIPPF_ARTIFACT_AUDIT_PATH) +
                              " --input " + quote_arg(input_path.string()) + " --denylist " +
                              quote_arg(EIPPF_LEXICAL_DENYLIST_PATH) + " --output " +
                              quote_arg(output_path.string()) + " --target-kind " +
                              quote_arg(std::string(target_kind));
  return normalize_status(std::system(command.c_str()));
}

TimedResult measure_sample_pipeline(const std::filesystem::path& temp_dir, const PipelineSample& sample) {
  const std::filesystem::path input_path = temp_dir / sample.file_name;
  if (!write_bytes(input_path, sample.bytes)) {
    return {};
  }

  const auto start = std::chrono::steady_clock::now();
  for (int iteration = 0; iteration < kIterationsPerSample; ++iteration) {
    const std::string suffix = "." + std::to_string(iteration);
    const std::filesystem::path output_path =
        temp_dir / (sample.sample_name + ".mutated" + suffix + ".bin");
    const std::filesystem::path manifest_path =
        temp_dir / (sample.sample_name + ".manifest" + suffix + ".json");
    const std::filesystem::path audit_path =
        temp_dir / (sample.sample_name + ".audit" + suffix + ".json");

    if (run_mutator(input_path, output_path, manifest_path, sample.target_label, sample.target_kind) != 0) {
      return {};
    }
    if (run_audit(output_path, audit_path, sample.target_kind) != 0) {
      return {};
    }
  }
  const auto end = std::chrono::steady_clock::now();
  const double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
  return {.ok = true, .elapsed_ms = elapsed_ms};
}

TimedResult measure_best_sample_pipeline(const std::filesystem::path& temp_dir,
                                         const PipelineSample& sample) {
  TimedResult best{};
  best.ok = false;
  best.elapsed_ms = std::numeric_limits<double>::infinity();

  for (int i = 0; i < kMeasurementSamples; ++i) {
    const TimedResult current = measure_sample_pipeline(temp_dir, sample);
    if (!current.ok) {
      return current;
    }
    if (!best.ok || current.elapsed_ms < best.elapsed_ms) {
      best = current;
    }
  }

  return best;
}

[[nodiscard]] double calculate_percent_delta(double baseline_ms, double compared_ms) {
  if (baseline_ms <= 0.0) {
    return std::numeric_limits<double>::infinity();
  }
  if (compared_ms <= baseline_ms) {
    return 0.0;
  }
  const double delta_ms = compared_ms - baseline_ms;
  return (delta_ms * 100.0) / baseline_ms;
}

[[nodiscard]] BudgetResult evaluate_budget(std::string lane_name, double baseline_ms, double compared_ms) {
  const double result_percent = calculate_percent_delta(baseline_ms, compared_ms);
  const bool within_budget = result_percent <= kBudgetPercent;
  return {.lane_name = std::move(lane_name),
          .baseline_ms = baseline_ms,
          .compared_ms = compared_ms,
          .budget_percent = kBudgetPercent,
          .result_percent = result_percent,
          .within_budget = within_budget};
}

void print_budget_result(const BudgetResult& result) {
  std::cout << std::fixed << std::setprecision(3)
            << "[PERF] lane=" << result.lane_name << " baseline_ms=" << result.baseline_ms
            << " compared_ms=" << result.compared_ms << " budget_pct=" << result.budget_percent
            << " result_pct=" << result.result_percent
            << " status=" << (result.within_budget ? "PASS" : "FAIL") << '\n';
}

}  // namespace

int main() {
  const std::filesystem::path temp_dir = make_temp_dir();
  if (!expect(!temp_dir.empty(), "failed to create temp directory")) {
    return 1;
  }

  const std::vector<std::uint8_t> pe_fixture = make_pe_fixture(kPayloadSizeBytes);
  const std::vector<std::uint8_t> elf_fixture = make_elf_fixture(kPayloadSizeBytes);

  const PipelineSample windows_exe{
      "windows_exe", "windows_sample.exe", "windows_sample.exe", "desktop_native", pe_fixture};
  const PipelineSample windows_dll{
      "windows_dll", "windows_sample.dll", "windows_sample.dll", "desktop_native", pe_fixture};
  const PipelineSample linux_elf{
      "linux_elf", "linux_sample.elf", "linux_sample.elf", "desktop_native", elf_fixture};
  const PipelineSample linux_so{
      "linux_so", "linux_sample.so", "linux_sample.so", "desktop_native", elf_fixture};
  const PipelineSample android_so{
      "android_so", "android_sample.so", "android_sample.so", "android_so", elf_fixture};

  const TimedResult windows_exe_time = measure_best_sample_pipeline(temp_dir, windows_exe);
  const TimedResult windows_dll_time = measure_best_sample_pipeline(temp_dir, windows_dll);
  const TimedResult linux_elf_time = measure_best_sample_pipeline(temp_dir, linux_elf);
  const TimedResult linux_so_time = measure_best_sample_pipeline(temp_dir, linux_so);
  const TimedResult android_so_time = measure_best_sample_pipeline(temp_dir, android_so);

  if (!expect(windows_exe_time.ok && windows_dll_time.ok && linux_elf_time.ok && linux_so_time.ok &&
                  android_so_time.ok,
              "all perf sample pipelines must execute successfully")) {
    std::filesystem::remove_all(temp_dir);
    return 1;
  }

  const BudgetResult windows_result =
      evaluate_budget("windows_exe_dll", windows_exe_time.elapsed_ms, windows_dll_time.elapsed_ms);
  const BudgetResult linux_result =
      evaluate_budget("linux_elf_so", linux_elf_time.elapsed_ms, linux_so_time.elapsed_ms);
  const BudgetResult android_result =
      evaluate_budget("android_so_vs_linux_so", linux_so_time.elapsed_ms, android_so_time.elapsed_ms);

  print_budget_result(windows_result);
  print_budget_result(linux_result);
  print_budget_result(android_result);

  const bool all_within_budget =
      windows_result.within_budget && linux_result.within_budget && android_result.within_budget;
  std::cout << "[PERF] budget_rule=<=10% overall_status=" << (all_within_budget ? "PASS" : "FAIL")
            << '\n';

  std::filesystem::remove_all(temp_dir);
  return all_within_budget ? 0 : 1;
}

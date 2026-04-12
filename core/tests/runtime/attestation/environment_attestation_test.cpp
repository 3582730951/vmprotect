#include "runtime/dynamic_api_resolver.hpp"
#include "runtime/environment_attestation.hpp"

#include <cstring>
#include <iostream>

namespace {

using Resolver = eippf::runtime::DynamicAPIResolver<64u, 4u>;
using Attestation = eippf::runtime::EnvironmentAttestation;

bool expect(bool condition, const char* message) {
  if (condition) {
    return true;
  }
  std::cerr << "[FAIL] " << message << '\n';
  return false;
}

bool test_success_path() {
  static constexpr char kStatus[] = "Name:\ttest\nTracerPid:\t0\n";
  return expect(Attestation::parse_tracer_pid_status(kStatus, std::strlen(kStatus)),
                "TracerPid=0 should be trusted");
}

bool test_failure_path() {
  static constexpr char kStatus[] = "Name:\ttest\nTracerPid:\t5231\n";
  return expect(!Attestation::parse_tracer_pid_status(kStatus, std::strlen(kStatus)),
                "non-zero TracerPid should fail attestation");
}

bool test_edge_security_path() {
  static constexpr char kMissingField[] = "Name:\ttest\nState:\tS\n";
  if (!expect(!Attestation::parse_tracer_pid_status(kMissingField, std::strlen(kMissingField)),
              "missing TracerPid must be treated as untrusted")) {
    return false;
  }

  Resolver resolver;
  Attestation attestation;
  const Attestation::Verdict first = attestation.evaluate(resolver);
  const Attestation::Verdict second = attestation.evaluate(resolver);
  return expect(first == second, "attestation verdict should be stable after caching");
}

bool test_suspicious_module_name_path() {
  if (!expect(Attestation::contains_suspicious_module_token("frida-agent-64.so"),
              "frida module name should be treated as suspicious")) {
    return false;
  }
  if (!expect(Attestation::contains_suspicious_module_token("Cheat Engine-x86_64.dll"),
              "cheat engine module name should be treated as suspicious")) {
    return false;
  }
  if (!expect(Attestation::contains_suspicious_module_token("IDA64.DLL"),
              "IDA module name should be treated as suspicious")) {
    return false;
  }
  if (!expect(Attestation::contains_suspicious_module_token("liblldb.so"),
              "lib-prefixed LLDB module should be treated as suspicious")) {
    return false;
  }
  if (!expect(!Attestation::contains_suspicious_module_token("validate_policy"),
              "short keyword matching must not false-positive on candidate strings")) {
    return false;
  }
  return expect(!Attestation::contains_suspicious_module_token("libssl.so.3"),
                "ordinary system libraries must stay allowed");
}

bool test_suspicious_proc_maps_path() {
  static constexpr char kSuspiciousMaps[] =
      "7f123000-7f124000 r-xp 00000000 08:01 1234 /tmp/frida-agent-64.so\n";
  if (!expect(Attestation::proc_maps_contains_suspicious_module(
                  kSuspiciousMaps, std::strlen(kSuspiciousMaps)),
              "proc maps with frida agent should be treated as suspicious")) {
    return false;
  }

  static constexpr char kBenignMaps[] =
      "7f123000-7f124000 r-xp 00000000 08:01 1234 /usr/lib/libssl.so.3\n";
  return expect(!Attestation::proc_maps_contains_suspicious_module(
                    kBenignMaps, std::strlen(kBenignMaps)),
                "proc maps without suspicious tooling should stay trusted");
}

}  // namespace

int main() {
  bool ok = true;
  ok = test_success_path() && ok;
  ok = test_failure_path() && ok;
  ok = test_edge_security_path() && ok;
  ok = test_suspicious_module_name_path() && ok;
  ok = test_suspicious_proc_maps_path() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] environment_attestation_test\n";
  return 0;
}

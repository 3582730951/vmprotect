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

}  // namespace

int main() {
  bool ok = true;
  ok = test_success_path() && ok;
  ok = test_failure_path() && ok;
  ok = test_edge_security_path() && ok;

  if (!ok) {
    return 1;
  }
  std::cout << "[PASS] environment_attestation_test\n";
  return 0;
}

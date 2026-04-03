#include "ios_safe_test_common.hpp"

#ifndef EIPPF_ARTIFACT_AUDIT_PATH
#error "EIPPF_ARTIFACT_AUDIT_PATH must be defined"
#endif

#ifndef EIPPF_LEXICAL_DENYLIST_PATH
#error "EIPPF_LEXICAL_DENYLIST_PATH must be defined"
#endif

#ifndef EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH
#error "EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH must be defined"
#endif

#ifndef EIPPF_SIGNATURE_VERIFIER_WORK_DIR
#error "EIPPF_SIGNATURE_VERIFIER_WORK_DIR must be defined"
#endif

int main() {
  using namespace eippf::tests::ios_safe;

  const std::filesystem::path temp_dir = make_temp_dir("eippf_ios_safe_security_edge");
  if (!expect(!temp_dir.empty(), "failed to create temp dir")) {
    return 1;
  }

  const std::filesystem::path trusted_dir = EIPPF_SIGNATURE_VERIFIER_WORK_DIR;
  std::error_code ec;
  std::filesystem::create_directories(trusted_dir, ec);
  if (!expect(!ec, "failed to create trusted verifier dir")) {
    return 1;
  }

  const std::filesystem::path verifier = make_verifier_wrapper(trusted_dir, "ios_safe_security_edge", "success");
  if (!expect(!verifier.empty(), "failed to create verifier wrapper")) {
    return 1;
  }

  const std::filesystem::path private_api_artifact = temp_dir / "private_api.bin";
  const std::filesystem::path rwx_artifact = temp_dir / "rwx.bin";
  const std::filesystem::path bad_policy_artifact = temp_dir / "bad_policy.bin";
  const std::filesystem::path manifest_path = temp_dir / "app.manifest.json";
  const std::filesystem::path bad_manifest_path = temp_dir / "app.bad.manifest.json";
  const std::filesystem::path report_path = temp_dir / "app.audit.json";

  if (!write_bytes(private_api_artifact,
                   build_macho_fixture(
                       true,
                       "/System/Library/PrivateFrameworks/FrontBoardServices.framework/FrontBoardServices",
                       false)) ||
      !write_bytes(rwx_artifact, build_macho_fixture(true, "", true)) ||
      !write_bytes(bad_policy_artifact, build_macho_fixture(true)) ||
      !write_text(manifest_path, make_ios_manifest_json(false)) ||
      !write_text(bad_manifest_path, make_ios_manifest_json(true))) {
    std::cerr << "[FAIL] cannot write fixtures\n";
    return 1;
  }

  if (!expect(run_audit(private_api_artifact, report_path, manifest_path, verifier) != 0,
              "private api artifact should fail")) {
    return 1;
  }
  const std::string private_api_report = read_text(report_path);
  if (!expect(private_api_report.find("private_api_detected") != std::string::npos,
              "private api report missing private_api_detected")) {
    return 1;
  }

  if (!expect(run_audit(rwx_artifact, report_path, manifest_path, verifier) != 0,
              "rwx artifact should fail")) {
    return 1;
  }
  const std::string rwx_report = read_text(report_path);
  if (!expect(rwx_report.find("rwx_segment_detected") != std::string::npos,
              "rwx report missing rwx_segment_detected")) {
    return 1;
  }

  if (!expect(run_audit(bad_policy_artifact, report_path, bad_manifest_path, verifier) != 0,
              "bad policy manifest should fail")) {
    return 1;
  }
  const std::string bad_policy_report = read_text(report_path);
  if (!expect(bad_policy_report.find("ios_gate_failed") != std::string::npos,
              "bad policy report missing ios_gate_failed")) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

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

  const std::filesystem::path temp_dir = make_temp_dir("eippf_ios_safe_failure");
  if (!expect(!temp_dir.empty(), "failed to create temp dir")) {
    return 1;
  }

  const std::filesystem::path trusted_dir = EIPPF_SIGNATURE_VERIFIER_WORK_DIR;
  std::error_code ec;
  std::filesystem::create_directories(trusted_dir, ec);
  if (!expect(!ec, "failed to create trusted verifier dir")) {
    return 1;
  }

  const std::filesystem::path verifier = make_verifier_wrapper(trusted_dir, "ios_safe_failure", "success");
  if (!expect(!verifier.empty(), "failed to create verifier wrapper")) {
    return 1;
  }

  const std::filesystem::path artifact_path = temp_dir / "app_unsigned.bin";
  const std::filesystem::path manifest_path = temp_dir / "app.manifest.json";
  const std::filesystem::path report_path = temp_dir / "app.audit.json";

  if (!write_bytes(artifact_path, build_macho_fixture(false)) ||
      !write_text(manifest_path, make_ios_manifest_json(false))) {
    std::cerr << "[FAIL] cannot write fixtures\n";
    return 1;
  }

  if (!expect(run_audit(artifact_path, report_path, manifest_path, verifier) != 0,
              "ios safe failure lane should fail without code signature")) {
    return 1;
  }

  const std::string report = read_text(report_path);
  if (!expect(report.find("macho_code_signature_missing") != std::string::npos,
              "report missing macho_code_signature_missing") ||
      !expect(report.find("\"validation_mode\": \"required_missing\"") != std::string::npos,
              "report missing required_missing validation mode") ||
      !expect(report.find("signature_missing") != std::string::npos,
              "report missing signature_missing")) {
    return 1;
  }

  std::filesystem::remove_all(temp_dir, ec);
  return 0;
}

#include "runtime/android_so_policy.hpp"

namespace eippf::runtime {

namespace {

[[nodiscard]] constexpr const char* to_json_bool(bool value) noexcept {
    return value ? "true" : "false";
}

}  // namespace

AndroidSoPolicyResult evaluate_android_so_policy(const AndroidSoPolicyInput& input) noexcept {
    AndroidSoPolicyResult result{};
    result.jni_export_surface_ok = input.jni_export_surface_ok;
    result.lexical_residual_strings_ok = input.lexical_residual_strings_ok;
    result.hook_check_ok = input.hook_check_ok;
    result.anti_debug_check_ok = input.anti_debug_check_ok;
    result.verdict_allow = result.jni_export_surface_ok &&
                           result.lexical_residual_strings_ok &&
                           result.hook_check_ok &&
                           result.anti_debug_check_ok;
    return result;
}

std::string build_android_so_policy_audit_record(const AndroidSoPolicyResult& result) {
    std::string record;
    record.reserve(256u);
    record += "{";
    record += "\"scope\": \"android_so_baseline\", ";
    record += "\"jni_export_surface_ok\": ";
    record += to_json_bool(result.jni_export_surface_ok);
    record += ", \"lexical_residual_strings_ok\": ";
    record += to_json_bool(result.lexical_residual_strings_ok);
    record += ", \"hook_check_ok\": ";
    record += to_json_bool(result.hook_check_ok);
    record += ", \"anti_debug_check_ok\": ";
    record += to_json_bool(result.anti_debug_check_ok);
    record += ", \"verdict_allow\": ";
    record += to_json_bool(result.verdict_allow);
    record += "}";
    return record;
}

}  // namespace eippf::runtime

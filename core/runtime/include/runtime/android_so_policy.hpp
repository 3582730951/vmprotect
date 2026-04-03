#pragma once

#include <string>

namespace eippf::runtime {

struct AndroidSoPolicyInput final {
    bool jni_export_surface_ok{false};
    bool lexical_residual_strings_ok{false};
    bool hook_check_ok{false};
    bool anti_debug_check_ok{false};
};

struct AndroidSoPolicyResult final {
    bool jni_export_surface_ok{false};
    bool lexical_residual_strings_ok{false};
    bool hook_check_ok{false};
    bool anti_debug_check_ok{false};
    bool verdict_allow{false};
};

[[nodiscard]] AndroidSoPolicyResult evaluate_android_so_policy(
    const AndroidSoPolicyInput& input) noexcept;

[[nodiscard]] std::string build_android_so_policy_audit_record(
    const AndroidSoPolicyResult& result);

}  // namespace eippf::runtime

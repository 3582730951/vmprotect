#pragma once

#include <array>
#include <string_view>

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

inline constexpr std::array<std::string_view, 5> kDefaultProtectionSuitePasses = {
    "ProtectionAnchor",
    "StringProtection",
    "IATMinimization",
    "MBAObfuscation",
    "CFFObfuscation",
};

inline constexpr std::string_view kDefaultProtectionSuiteSummary =
    "ProtectionAnchor,StringProtection,IATMinimization,MBAObfuscation,CFFObfuscation";

void append_default_protection_suite(llvm::ModulePassManager& module_pass_manager);
void register_protection_suite_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

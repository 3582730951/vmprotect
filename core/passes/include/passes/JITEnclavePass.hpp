#pragma once

#include <cstdint>

#include "llvm/IR/PassManager.h"

namespace llvm {
class PassBuilder;
}

namespace eippf::passes {

class JITEnclavePass : public llvm::PassInfoMixin<JITEnclavePass> {
 public:
  llvm::PreservedAnalyses run(llvm::Module& module, llvm::ModuleAnalysisManager& analysis_manager);

 private:
  enum class TargetKind : std::uint8_t {
    kDesktopNative = 0u,
    kAndroidSo = 1u,
    kIosAppStore = 2u,
    kWindowsDriver = 3u,
    kLinuxKernelModule = 4u,
    kAndroidKernelModule = 5u,
    kAndroidDex = 6u,
    kShellEphemeral = 7u,
    kUnknown = 8u,
  };

  [[nodiscard]] static TargetKind parse_target_kind_option() noexcept;
  [[nodiscard]] static bool is_desktop_target_kind(TargetKind kind) noexcept;
  [[nodiscard]] static const char* target_kind_name_for_diagnostic(TargetKind kind) noexcept;
};

void register_jit_enclave_pipeline(llvm::PassBuilder& pass_builder);

}  // namespace eippf::passes

find_package(LLVM REQUIRED CONFIG)

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
include(PassPluginCompat)

if(NOT COMMAND add_llvm_pass_plugin)
  message(FATAL_ERROR "LLVM CMake module does not provide add_llvm_pass_plugin.")
endif()

eippf_add_pass_plugin_target(eippf_string_protection_pass
  SOURCES
    src/StringProtectionPass.cpp
  COMPILE_DEFINITIONS
    EIPPF_STRING_PROTECTION_STANDALONE_PLUGIN=1
)

eippf_add_pass_plugin_target(eippf_selective_vm_pass
  SOURCES
    src/SelectiveVMPass.cpp
  COMPILE_DEFINITIONS
    EIPPF_SELECTIVE_VM_STANDALONE_PLUGIN=1
)

eippf_add_pass_plugin_target(eippf_mba_obfuscation_pass
  SOURCES
    src/MBAObfuscationPass.cpp
  COMPILE_DEFINITIONS
    EIPPF_MBA_OBFUSCATION_STANDALONE_PLUGIN=1
)

eippf_add_pass_plugin_target(eippf_iat_minimization_pass
  SOURCES
    src/IATMinimizationPass.cpp
  COMPILE_DEFINITIONS
    EIPPF_IAT_MINIMIZATION_STANDALONE_PLUGIN=1
)

eippf_add_pass_plugin_target(eippf_jit_enclave_pass
  SOURCES
    src/JITEnclavePass.cpp
  COMPILE_DEFINITIONS
    EIPPF_JIT_ENCLAVE_STANDALONE_PLUGIN=1
)

eippf_add_pass_plugin_target(eippf_protection_anchor_pass
  SOURCES
    src/ProtectionAnchorPass.cpp
  COMPILE_DEFINITIONS
    EIPPF_PROTECTION_ANCHOR_STANDALONE_PLUGIN=1
)

eippf_add_pass_plugin_target(eippf_cff_obfuscation_pass
  SOURCES
    src/CFFObfuscationPass.cpp
  COMPILE_DEFINITIONS
    EIPPF_CFF_OBFUSCATION_STANDALONE_PLUGIN=1
)

if(APPLE)
  set(eippf_protection_suite_prev_llvm_no_dead_strip "${LLVM_NO_DEAD_STRIP}")
  set(LLVM_NO_DEAD_STRIP ON)
endif()

eippf_add_pass_plugin_target(eippf_protection_suite_pass
  SOURCES
    src/ProtectionSuitePassPlugin.cpp
    src/StringProtectionPass.cpp
    src/ProtectionAnchorPass.cpp
    src/SelectiveVMPass.cpp
    src/JITEnclavePass.cpp
    src/CFFObfuscationPass.cpp
  OUTPUT_NAME
    eippf_protection_suite_pass
)
set_target_properties(eippf_protection_suite_pass PROPERTIES
  OUTPUT_NAME "eippf_protection_suite_pass"
  PREFIX ""
)

if(APPLE)
  set(LLVM_NO_DEAD_STRIP "${eippf_protection_suite_prev_llvm_no_dead_strip}")
  unset(eippf_protection_suite_prev_llvm_no_dead_strip)
endif()

if(NOT EIPPF_PASS_PLUGIN)
  eippf_register_pass_plugin("eippf_protection_suite_pass")
endif()

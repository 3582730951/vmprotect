find_package(LLVM REQUIRED CONFIG)

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

if(NOT COMMAND add_llvm_pass_plugin)
  message(FATAL_ERROR "LLVM CMake module does not provide add_llvm_pass_plugin.")
endif()

add_llvm_pass_plugin(eippf_string_protection_pass
  src/StringProtectionPass.cpp
)

target_include_directories(eippf_string_protection_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_string_protection_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_string_protection_pass PRIVATE
  EIPPF_STRING_PROTECTION_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_string_protection_pass)

add_llvm_pass_plugin(eippf_selective_vm_pass
  src/SelectiveVMPass.cpp
)

target_include_directories(eippf_selective_vm_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_selective_vm_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_selective_vm_pass PRIVATE
  EIPPF_SELECTIVE_VM_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_selective_vm_pass)

add_llvm_pass_plugin(eippf_mba_obfuscation_pass
  src/MBAObfuscationPass.cpp
)

target_include_directories(eippf_mba_obfuscation_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_mba_obfuscation_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_mba_obfuscation_pass PRIVATE
  EIPPF_MBA_OBFUSCATION_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_mba_obfuscation_pass)

add_llvm_pass_plugin(eippf_iat_minimization_pass
  src/IATMinimizationPass.cpp
)

target_include_directories(eippf_iat_minimization_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_iat_minimization_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_iat_minimization_pass PRIVATE
  EIPPF_IAT_MINIMIZATION_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_iat_minimization_pass)

add_llvm_pass_plugin(eippf_jit_enclave_pass
  src/JITEnclavePass.cpp
)

target_include_directories(eippf_jit_enclave_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_jit_enclave_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_jit_enclave_pass PRIVATE
  EIPPF_JIT_ENCLAVE_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_jit_enclave_pass)

add_llvm_pass_plugin(eippf_protection_anchor_pass
  src/ProtectionAnchorPass.cpp
)

target_include_directories(eippf_protection_anchor_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_protection_anchor_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_protection_anchor_pass PRIVATE
  EIPPF_PROTECTION_ANCHOR_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_protection_anchor_pass)

add_llvm_pass_plugin(eippf_cff_obfuscation_pass
  src/CFFObfuscationPass.cpp
)

target_include_directories(eippf_cff_obfuscation_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_cff_obfuscation_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(eippf_cff_obfuscation_pass PRIVATE
  EIPPF_CFF_OBFUSCATION_STANDALONE_PLUGIN=1
)
eippf_apply_common_compile_options(eippf_cff_obfuscation_pass)

add_llvm_pass_plugin(eippf_protection_suite_pass
  src/ProtectionSuitePassPlugin.cpp
  src/StringProtectionPass.cpp
  src/ProtectionAnchorPass.cpp
  src/SelectiveVMPass.cpp
  src/JITEnclavePass.cpp
  src/CFFObfuscationPass.cpp
)

target_include_directories(eippf_protection_suite_pass PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(eippf_protection_suite_pass SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)
eippf_apply_common_compile_options(eippf_protection_suite_pass)
set_target_properties(eippf_protection_suite_pass PROPERTIES
  OUTPUT_NAME "eippf_protection_suite_pass"
  PREFIX ""
)

if(NOT EIPPF_PASS_PLUGIN)
  eippf_register_pass_plugin("eippf_protection_suite_pass")
endif()

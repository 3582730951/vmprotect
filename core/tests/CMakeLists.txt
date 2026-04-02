function(eippf_maybe_add_test_subdir relative_path)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}/CMakeLists.txt")
    add_subdirectory("${relative_path}")
  endif()
endfunction()

add_executable(policy_engine_test
  runtime/policy/policy_engine_test.cpp
)

target_link_libraries(policy_engine_test
  PRIVATE
    eippf_runtime
)

target_include_directories(policy_engine_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(policy_engine_test)

add_test(NAME runtime_policy_engine_test COMMAND policy_engine_test)

add_executable(micro_jit_poc_test
  runtime/jit/micro_jit_poc_test.cpp
)

eippf_apply_common_compile_options(micro_jit_poc_test)

add_test(NAME runtime_micro_jit_poc_test COMMAND micro_jit_poc_test)

add_executable(constexpr_obfuscated_string_test
  runtime/security/constexpr_obfuscated_string_test.cpp
)

target_include_directories(constexpr_obfuscated_string_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(constexpr_obfuscated_string_test)

add_test(NAME runtime_constexpr_obfuscated_string_test COMMAND constexpr_obfuscated_string_test)

add_executable(state_machine_codegen_demo_test
  runtime/codegen/state_machine_codegen_demo_test.cpp
)

eippf_apply_common_compile_options(state_machine_codegen_demo_test)

add_test(NAME runtime_state_machine_codegen_demo_test COMMAND state_machine_codegen_demo_test)

add_executable(secure_ir_engine_test
  runtime/ir/secure_ir_engine_test.cpp
)

target_link_libraries(secure_ir_engine_test
  PRIVATE
    eippf_runtime
)

target_include_directories(secure_ir_engine_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(secure_ir_engine_test)

eippf_harden_target(secure_ir_engine_test
  NO_WRAPPER
  NO_MUTATION
  NO_PASS_PLUGIN
  TARGET_KIND desktop_native
)

add_test(NAME runtime_secure_ir_engine_test COMMAND secure_ir_engine_test)

foreach(_safe_backend IN ITEMS ios_appstore windows_driver)
  add_executable(secure_ir_engine_${_safe_backend}_safe_test
    runtime/ir/secure_ir_engine_safe_backend_test.cpp
  )

  target_link_libraries(secure_ir_engine_${_safe_backend}_safe_test
    PRIVATE
      eippf_runtime
  )

  target_include_directories(secure_ir_engine_${_safe_backend}_safe_test PRIVATE
    "${CMAKE_SOURCE_DIR}/runtime/include"
  )

  if(_safe_backend STREQUAL "ios_appstore")
    target_compile_definitions(secure_ir_engine_${_safe_backend}_safe_test PRIVATE
      EIPPF_EXPECT_IOS_APPSTORE=1
    )
    set(_runtime_target_kind ios_appstore)
  else()
    target_compile_definitions(secure_ir_engine_${_safe_backend}_safe_test PRIVATE
      EIPPF_EXPECT_WINDOWS_DRIVER=1
    )
    set(_runtime_target_kind windows_driver)
  endif()

  eippf_apply_common_compile_options(secure_ir_engine_${_safe_backend}_safe_test)

  eippf_harden_target(secure_ir_engine_${_safe_backend}_safe_test
    NO_WRAPPER
    NO_MUTATION
    NO_PASS_PLUGIN
    TARGET_KIND ${_runtime_target_kind}
  )

  add_test(
    NAME runtime_secure_ir_engine_${_safe_backend}_safe_test
    COMMAND secure_ir_engine_${_safe_backend}_safe_test
  )
endforeach()

add_executable(vm_runtime_bridge_vm2_test
  runtime/ir/vm_runtime_bridge_vm2_test.cpp
)

target_link_libraries(vm_runtime_bridge_vm2_test
  PRIVATE
    eippf_vm_rt
)

target_include_directories(vm_runtime_bridge_vm2_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(vm_runtime_bridge_vm2_test)

add_test(NAME runtime_vm_runtime_bridge_vm2_test COMMAND vm_runtime_bridge_vm2_test)

add_executable(dynamic_api_resolver_test
  runtime/resolver/dynamic_api_resolver_test.cpp
)

target_link_libraries(dynamic_api_resolver_test
  PRIVATE
    eippf_runtime
)

target_include_directories(dynamic_api_resolver_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(dynamic_api_resolver_test)

add_test(NAME runtime_dynamic_api_resolver_test COMMAND dynamic_api_resolver_test)

add_executable(memory_hal_test
  runtime/hal/memory_hal_test.cpp
)

target_link_libraries(memory_hal_test
  PRIVATE
    eippf_runtime
)

target_include_directories(memory_hal_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(memory_hal_test)

eippf_harden_target(memory_hal_test
  NO_WRAPPER
  NO_MUTATION
  NO_PASS_PLUGIN
  TARGET_KIND desktop_native
)

add_test(NAME runtime_memory_hal_test COMMAND memory_hal_test)

foreach(_safe_backend IN ITEMS ios_appstore windows_driver)
  add_executable(memory_hal_${_safe_backend}_safe_test
    runtime/hal/memory_hal_safe_backend_test.cpp
  )

  target_link_libraries(memory_hal_${_safe_backend}_safe_test
    PRIVATE
      eippf_runtime
  )

  target_include_directories(memory_hal_${_safe_backend}_safe_test PRIVATE
    "${CMAKE_SOURCE_DIR}/runtime/include"
  )

  if(_safe_backend STREQUAL "ios_appstore")
    target_compile_definitions(memory_hal_${_safe_backend}_safe_test PRIVATE
      EIPPF_EXPECT_IOS_APPSTORE=1
    )
    set(_runtime_target_kind ios_appstore)
  else()
    target_compile_definitions(memory_hal_${_safe_backend}_safe_test PRIVATE
      EIPPF_EXPECT_WINDOWS_DRIVER=1
    )
    set(_runtime_target_kind windows_driver)
  endif()

  eippf_apply_common_compile_options(memory_hal_${_safe_backend}_safe_test)

  eippf_harden_target(memory_hal_${_safe_backend}_safe_test
    NO_WRAPPER
    NO_MUTATION
    NO_PASS_PLUGIN
    TARGET_KIND ${_runtime_target_kind}
  )

  add_test(
    NAME runtime_memory_hal_${_safe_backend}_safe_test
    COMMAND memory_hal_${_safe_backend}_safe_test
  )
endforeach()

add_executable(environment_attestation_test
  runtime/attestation/environment_attestation_test.cpp
)

target_link_libraries(environment_attestation_test
  PRIVATE
    eippf_runtime
)

target_include_directories(environment_attestation_test PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
)

eippf_apply_common_compile_options(environment_attestation_test)

add_test(NAME runtime_environment_attestation_test COMMAND environment_attestation_test)

add_executable(gpu_graphics_coverage_test
  runtime/gpu/gpu_graphics_coverage_test.cpp
)

eippf_apply_common_compile_options(gpu_graphics_coverage_test)

add_test(NAME runtime_gpu_graphics_coverage_test COMMAND gpu_graphics_coverage_test)

add_executable(opencl_device_integration_test
  runtime/gpu/opencl_device_integration_test.cpp
)

eippf_apply_common_compile_options(opencl_device_integration_test)

add_test(NAME runtime_opencl_device_integration_test COMMAND opencl_device_integration_test)

add_executable(vulkan_device_integration_test
  runtime/gpu/vulkan_device_integration_test.cpp
)

eippf_apply_common_compile_options(vulkan_device_integration_test)

add_test(NAME runtime_vulkan_device_integration_test COMMAND vulkan_device_integration_test)

if(TARGET ip_weaver_ir AND TARGET LLVM)
  add_executable(ip_weaver_ir_opcode_mapper_test
    ip_weaver_ir/opcode_mapper_test.cpp
  )

  target_include_directories(ip_weaver_ir_opcode_mapper_test PRIVATE
    "${CMAKE_SOURCE_DIR}/runtime/include"
    "${CMAKE_SOURCE_DIR}/ip_weaver_ir/include"
  )
  target_include_directories(ip_weaver_ir_opcode_mapper_test SYSTEM PRIVATE
    ${EIPPF_LLVM_INCLUDE_DIRS}
  )

  target_link_libraries(ip_weaver_ir_opcode_mapper_test PRIVATE LLVM)

  eippf_apply_common_compile_options(ip_weaver_ir_opcode_mapper_test)

  add_test(NAME ip_weaver_ir_opcode_mapper_test COMMAND ip_weaver_ir_opcode_mapper_test)
endif()

set(EIPPF_EXTRA_PERF_COMMANDS "")
set(EIPPF_EXTRA_PERF_DEPENDS "")

if(TARGET ip_weaver_ir AND TARGET eippf_vm_rt)
  add_executable(rust_vm_full_coverage_test
    runtime/ir/rust_vm_full_coverage_test.cpp
  )

  target_compile_definitions(rust_vm_full_coverage_test PRIVATE
    EIPPF_PROXY_PATH="${CMAKE_SOURCE_DIR}/wrapper/weaver_proxy.py"
    EIPPF_WEAVER_PATH="$<TARGET_FILE:ip_weaver_ir>"
    EIPPF_VM_RT_PATH="$<TARGET_FILE:eippf_vm_rt>"
  )

  eippf_apply_common_compile_options(rust_vm_full_coverage_test)

  add_test(NAME runtime_rust_vm_full_coverage_test COMMAND rust_vm_full_coverage_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:rust_vm_full_coverage_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS rust_vm_full_coverage_test)

  add_executable(rust_transparent_link_test
    runtime/ir/rust_transparent_link_test.cpp
  )

  target_compile_definitions(rust_transparent_link_test PRIVATE
    EIPPF_PROXY_PATH="${CMAKE_SOURCE_DIR}/wrapper/weaver_proxy.py"
    EIPPF_WEAVER_PATH="$<TARGET_FILE:ip_weaver_ir>"
    EIPPF_VM_RT_PATH="$<TARGET_FILE:eippf_vm_rt>"
  )

  eippf_apply_common_compile_options(rust_transparent_link_test)

  add_test(NAME runtime_rust_transparent_link_test COMMAND rust_transparent_link_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:rust_transparent_link_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS rust_transparent_link_test)
endif()

set(EIPPF_ARTIFACT_AUDIT_TOOL "${CMAKE_SOURCE_DIR}/tools/artifact_audit.py")
if(EXISTS "${EIPPF_ARTIFACT_AUDIT_TOOL}")
  add_test(
    NAME tools_artifact_audit_selftest
    COMMAND python3 "${EIPPF_ARTIFACT_AUDIT_TOOL}" --self-test
  )
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS
    COMMAND python3 "${EIPPF_ARTIFACT_AUDIT_TOOL}" --self-test
  )
endif()

eippf_maybe_add_test_subdir(contracts)
eippf_maybe_add_test_subdir(runtime/backend)
eippf_maybe_add_test_subdir(post_link_mutator)
eippf_maybe_add_test_subdir(dex_toolchain)
eippf_maybe_add_test_subdir(script_guard)
eippf_maybe_add_test_subdir(tools)

if(TARGET protection_contracts_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:protection_contracts_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS protection_contracts_test)
endif()

if(TARGET backend_policy_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:backend_policy_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS backend_policy_test)
endif()

foreach(_safe_perf_target IN ITEMS
  secure_ir_engine_ios_appstore_safe_test
  secure_ir_engine_windows_driver_safe_test
  memory_hal_ios_appstore_safe_test
  memory_hal_windows_driver_safe_test
  hardened_target_ios_runtime_kind_test
  hardened_target_windows_driver_runtime_kind_test
  hardened_target_ios_secure_ir_engine_test
  hardened_target_windows_driver_secure_ir_engine_test
)
  if(TARGET ${_safe_perf_target})
    list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:${_safe_perf_target}>)
    list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS ${_safe_perf_target})
  endif()
endforeach()

if(TARGET post_link_mutator_smoke_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:post_link_mutator_smoke_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS post_link_mutator_smoke_test)
endif()

if(TARGET dex_toolchain_smoke_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:dex_toolchain_smoke_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS dex_toolchain_smoke_test)
endif()

if(TARGET script_guard_smoke_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:script_guard_smoke_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS script_guard_smoke_test)
endif()

if(TARGET artifact_audit_strict_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:artifact_audit_strict_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS artifact_audit_strict_test)
endif()

if(TARGET hardened_target_pipeline_test)
  list(APPEND EIPPF_EXTRA_PERF_COMMANDS COMMAND $<TARGET_FILE:hardened_target_pipeline_test>)
  list(APPEND EIPPF_EXTRA_PERF_DEPENDS DEPENDS hardened_target_pipeline_test)
endif()

add_custom_target(perf_smoke
  COMMAND $<TARGET_FILE:policy_engine_test>
  COMMAND $<TARGET_FILE:micro_jit_poc_test>
  COMMAND $<TARGET_FILE:constexpr_obfuscated_string_test>
  COMMAND $<TARGET_FILE:state_machine_codegen_demo_test>
  COMMAND $<TARGET_FILE:secure_ir_engine_test>
  COMMAND $<TARGET_FILE:vm_runtime_bridge_vm2_test>
  COMMAND $<TARGET_FILE:dynamic_api_resolver_test>
  COMMAND $<TARGET_FILE:memory_hal_test>
  COMMAND $<TARGET_FILE:environment_attestation_test>
  COMMAND $<TARGET_FILE:gpu_graphics_coverage_test>
  COMMAND $<TARGET_FILE:opencl_device_integration_test>
  COMMAND $<TARGET_FILE:vulkan_device_integration_test>
  DEPENDS policy_engine_test
  DEPENDS micro_jit_poc_test
  DEPENDS constexpr_obfuscated_string_test
  DEPENDS state_machine_codegen_demo_test
  DEPENDS secure_ir_engine_test
  DEPENDS vm_runtime_bridge_vm2_test
  DEPENDS dynamic_api_resolver_test
  DEPENDS memory_hal_test
  DEPENDS environment_attestation_test
  DEPENDS gpu_graphics_coverage_test
  DEPENDS opencl_device_integration_test
  DEPENDS vulkan_device_integration_test
  ${EIPPF_EXTRA_PERF_COMMANDS}
  ${EIPPF_EXTRA_PERF_DEPENDS}
  USES_TERMINAL
)

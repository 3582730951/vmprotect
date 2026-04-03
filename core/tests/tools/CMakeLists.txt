if(EXISTS "${CMAKE_SOURCE_DIR}/tools/artifact_audit.py")
  add_executable(hardened_target_pipeline_fixture
    hardened_target_pipeline_fixture.cpp
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(hardened_target_pipeline_fixture)
  else()
    target_compile_features(hardened_target_pipeline_fixture PRIVATE cxx_std_20)
  endif()

  eippf_harden_target(hardened_target_pipeline_fixture
    NO_WRAPPER
    NO_PASS_PLUGIN
    TARGET_KIND desktop_native
    MANIFEST_PATH "${CMAKE_CURRENT_BINARY_DIR}/hardened_target_pipeline_fixture.eippf.manifest.json"
    AUDIT_REPORT_PATH "${CMAKE_CURRENT_BINARY_DIR}/hardened_target_pipeline_fixture.eippf.audit.json"
  )

  add_executable(artifact_audit_strict_test
    artifact_audit_strict_test.cpp
  )

  target_compile_definitions(artifact_audit_strict_test PRIVATE
    EIPPF_ARTIFACT_AUDIT_PATH="${CMAKE_SOURCE_DIR}/tools/artifact_audit.py"
    EIPPF_LEXICAL_DENYLIST_PATH="${CMAKE_SOURCE_DIR}/tools/lexical_anchor_denylist.txt"
    EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/signature_verifier_fixture.py"
    EIPPF_SIGNATURE_VERIFIER_WORK_DIR="${CMAKE_CURRENT_BINARY_DIR}"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(artifact_audit_strict_test)
  else()
    target_compile_features(artifact_audit_strict_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME artifact_audit_strict_test COMMAND artifact_audit_strict_test)

  add_executable(hardened_target_pipeline_test
    hardened_target_pipeline_test.cpp
  )

  add_dependencies(hardened_target_pipeline_test hardened_target_pipeline_fixture)

  target_compile_definitions(hardened_target_pipeline_test PRIVATE
    EIPPF_HARDENED_FIXTURE_PATH="$<TARGET_FILE:hardened_target_pipeline_fixture>"
    EIPPF_HARDENED_FIXTURE_PRE_PATH="$<TARGET_FILE:hardened_target_pipeline_fixture>.pre_eippf"
    EIPPF_HARDENED_FIXTURE_MANIFEST_PATH="${CMAKE_CURRENT_BINARY_DIR}/hardened_target_pipeline_fixture.eippf.manifest.json"
    EIPPF_HARDENED_FIXTURE_AUDIT_PATH="${CMAKE_CURRENT_BINARY_DIR}/hardened_target_pipeline_fixture.eippf.audit.json"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(hardened_target_pipeline_test)
  else()
    target_compile_features(hardened_target_pipeline_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME hardened_target_pipeline_test COMMAND hardened_target_pipeline_test)

  add_executable(artifact_audit_user_mode_test
    artifact_audit_user_mode_test.cpp
  )

  target_compile_definitions(artifact_audit_user_mode_test PRIVATE
    EIPPF_ARTIFACT_AUDIT_PATH="${CMAKE_SOURCE_DIR}/tools/artifact_audit.py"
    EIPPF_LEXICAL_DENYLIST_PATH="${CMAKE_SOURCE_DIR}/tools/lexical_anchor_denylist.txt"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(artifact_audit_user_mode_test)
  else()
    target_compile_features(artifact_audit_user_mode_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME artifact_audit_user_mode_test COMMAND artifact_audit_user_mode_test)

  if(EXISTS "${CMAKE_SOURCE_DIR}/tests/sample_suite/sample_suite_report_contract_test.py")
    add_test(
      NAME sample_suite_report_contract_test
      COMMAND python3 "${CMAKE_SOURCE_DIR}/tests/sample_suite/sample_suite_report_contract_test.py"
    )
  endif()

  if(TARGET eippf_runtime)
    add_executable(android_so_pipeline_smoke_test
      android_so_pipeline_smoke_test.cpp
    )

    target_link_libraries(android_so_pipeline_smoke_test PRIVATE
      eippf_runtime
    )

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(android_so_pipeline_smoke_test)
    else()
      target_compile_features(android_so_pipeline_smoke_test PRIVATE cxx_std_20)
    endif()

    add_test(NAME android_so_pipeline_smoke_test COMMAND android_so_pipeline_smoke_test)
  endif()

  add_executable(user_mode_pipeline_fixture
    user_mode_pipeline_fixture.cpp
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(user_mode_pipeline_fixture)
  else()
    target_compile_features(user_mode_pipeline_fixture PRIVATE cxx_std_20)
  endif()

  if(TARGET eippf_post_link_mutator)
    add_executable(user_mode_pipeline_test
      user_mode_pipeline_test.cpp
    )

    target_compile_definitions(user_mode_pipeline_test PRIVATE
      EIPPF_POST_LINK_MUTATOR_BIN="$<TARGET_FILE:eippf_post_link_mutator>"
      EIPPF_ARTIFACT_AUDIT_PATH="${CMAKE_SOURCE_DIR}/tools/artifact_audit.py"
      EIPPF_LEXICAL_DENYLIST_PATH="${CMAKE_SOURCE_DIR}/tools/lexical_anchor_denylist.txt"
    )

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(user_mode_pipeline_test)
    else()
      target_compile_features(user_mode_pipeline_test PRIVATE cxx_std_20)
    endif()

    add_test(NAME user_mode_pipeline_test COMMAND user_mode_pipeline_test)
  endif()

  foreach(_runtime_target IN ITEMS desktop ios windows_driver linux_kernel_module android_kernel_module android_dex shell_ephemeral unknown)
    add_executable(hardened_target_${_runtime_target}_runtime_kind_test
      hardened_target_runtime_kind_test.cpp
    )

    target_link_libraries(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE eippf_runtime)

    set(_ht_target_kind "")
    set(_apply_harden_target TRUE)
    if(_runtime_target STREQUAL "desktop")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_DESKTOP_NATIVE=1
      )
      set(_ht_target_kind desktop_native)
    elseif(_runtime_target STREQUAL "ios")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_IOS_APPSTORE=1
      )
      set(_ht_target_kind ios_appstore)
    elseif(_runtime_target STREQUAL "windows_driver")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_WINDOWS_DRIVER=1
      )
      set(_ht_target_kind windows_driver)
    elseif(_runtime_target STREQUAL "linux_kernel_module")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_LINUX_KERNEL_MODULE=1
      )
      set(_ht_target_kind linux_kernel_module)
    elseif(_runtime_target STREQUAL "android_kernel_module")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_ANDROID_KERNEL_MODULE=1
      )
      set(_ht_target_kind android_kernel_module)
    elseif(_runtime_target STREQUAL "android_dex")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_ANDROID_DEX=1
      )
      set(_ht_target_kind android_dex)
    elseif(_runtime_target STREQUAL "shell_ephemeral")
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_SHELL_EPHEMERAL=1
      )
      set(_ht_target_kind shell_ephemeral)
    else()
      target_compile_definitions(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_UNKNOWN_TARGET=1
      )
      set(_apply_harden_target FALSE)
    endif()

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(hardened_target_${_runtime_target}_runtime_kind_test)
    else()
      target_compile_features(hardened_target_${_runtime_target}_runtime_kind_test PRIVATE cxx_std_20)
    endif()

    if(_apply_harden_target)
      eippf_harden_target(hardened_target_${_runtime_target}_runtime_kind_test
        NO_WRAPPER
        NO_MUTATION
        NO_PASS_PLUGIN
        TARGET_KIND ${_ht_target_kind}
      )
    endif()

    add_test(
      NAME hardened_target_${_runtime_target}_runtime_kind_test
      COMMAND hardened_target_${_runtime_target}_runtime_kind_test
    )
  endforeach()

  foreach(_safe_target IN ITEMS ios windows_driver linux_kernel_module android_kernel_module)
    add_executable(hardened_target_${_safe_target}_secure_ir_engine_test
      hardened_target_secure_ir_engine_test.cpp
    )

    target_link_libraries(hardened_target_${_safe_target}_secure_ir_engine_test PRIVATE eippf_runtime)

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(hardened_target_${_safe_target}_secure_ir_engine_test)
    else()
      target_compile_features(hardened_target_${_safe_target}_secure_ir_engine_test PRIVATE cxx_std_20)
    endif()

    if(_safe_target STREQUAL "ios")
      set(_secure_ir_target_kind ios_appstore)
    elseif(_safe_target STREQUAL "windows_driver")
      set(_secure_ir_target_kind windows_driver)
    elseif(_safe_target STREQUAL "linux_kernel_module")
      set(_secure_ir_target_kind linux_kernel_module)
    else()
      set(_secure_ir_target_kind android_kernel_module)
    endif()

    eippf_harden_target(hardened_target_${_safe_target}_secure_ir_engine_test
      NO_WRAPPER
      NO_MUTATION
      NO_PASS_PLUGIN
      TARGET_KIND ${_secure_ir_target_kind}
    )

    add_test(
      NAME hardened_target_${_safe_target}_secure_ir_engine_test
      COMMAND hardened_target_${_safe_target}_secure_ir_engine_test
    )
  endforeach()

  if(TARGET eippf_jit_enclave_pass)
    set(_jit_gate_clang_path "${CMAKE_CXX_COMPILER}")
    get_filename_component(_jit_gate_clang_name "${_jit_gate_clang_path}" NAME)
    if(NOT _jit_gate_clang_name MATCHES "^(clang\\+\\+|clang)$")
      find_program(_jit_gate_clang_candidate NAMES clang++ clang)
      if(_jit_gate_clang_candidate)
        set(_jit_gate_clang_path "${_jit_gate_clang_candidate}")
      endif()
    endif()

    add_executable(jit_enclave_pipeline_gate_test
      jit_enclave_pipeline_gate_test.cpp
    )

    add_dependencies(jit_enclave_pipeline_gate_test eippf_jit_enclave_pass)

    target_compile_definitions(jit_enclave_pipeline_gate_test PRIVATE
      EIPPF_CLANG_PATH="${_jit_gate_clang_path}"
      EIPPF_JIT_ENCLAVE_PLUGIN_PATH="$<TARGET_FILE:eippf_jit_enclave_pass>"
    )

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(jit_enclave_pipeline_gate_test)
    else()
      target_compile_features(jit_enclave_pipeline_gate_test PRIVATE cxx_std_20)
    endif()

    add_test(NAME jit_enclave_pipeline_gate_test COMMAND jit_enclave_pipeline_gate_test)
  endif()
endif()

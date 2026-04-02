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

  foreach(_safe_target IN ITEMS ios windows_driver)
    add_executable(hardened_target_${_safe_target}_runtime_kind_test
      hardened_target_runtime_kind_test.cpp
    )

    target_link_libraries(hardened_target_${_safe_target}_runtime_kind_test PRIVATE eippf_runtime)

    if(_safe_target STREQUAL "ios")
      target_compile_definitions(hardened_target_${_safe_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_IOS_APPSTORE=1
      )
      set(_ht_target_kind ios_appstore)
    else()
      target_compile_definitions(hardened_target_${_safe_target}_runtime_kind_test PRIVATE
        EIPPF_EXPECT_WINDOWS_DRIVER=1
      )
      set(_ht_target_kind windows_driver)
    endif()

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(hardened_target_${_safe_target}_runtime_kind_test)
    else()
      target_compile_features(hardened_target_${_safe_target}_runtime_kind_test PRIVATE cxx_std_20)
    endif()

    eippf_harden_target(hardened_target_${_safe_target}_runtime_kind_test
      NO_WRAPPER
      NO_MUTATION
      NO_PASS_PLUGIN
      TARGET_KIND ${_ht_target_kind}
    )

    add_test(
      NAME hardened_target_${_safe_target}_runtime_kind_test
      COMMAND hardened_target_${_safe_target}_runtime_kind_test
    )

    add_executable(hardened_target_${_safe_target}_secure_ir_engine_test
      hardened_target_secure_ir_engine_test.cpp
    )

    target_link_libraries(hardened_target_${_safe_target}_secure_ir_engine_test PRIVATE eippf_runtime)

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(hardened_target_${_safe_target}_secure_ir_engine_test)
    else()
      target_compile_features(hardened_target_${_safe_target}_secure_ir_engine_test PRIVATE cxx_std_20)
    endif()

    eippf_harden_target(hardened_target_${_safe_target}_secure_ir_engine_test
      NO_WRAPPER
      NO_MUTATION
      NO_PASS_PLUGIN
      TARGET_KIND ${_ht_target_kind}
    )

    add_test(
      NAME hardened_target_${_safe_target}_secure_ir_engine_test
      COMMAND hardened_target_${_safe_target}_secure_ir_engine_test
    )
  endforeach()
endif()

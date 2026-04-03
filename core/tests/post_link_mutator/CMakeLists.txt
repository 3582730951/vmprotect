if(TARGET eippf_post_link_mutator)
  set(_post_link_mutator_test_include_dirs
    "${CMAKE_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/post_link_mutator/include"
  )

  function(eippf_configure_post_link_mutator_test target_name)
    target_include_directories(${target_name} PRIVATE ${_post_link_mutator_test_include_dirs})
    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(${target_name})
    else()
      target_compile_features(${target_name} PRIVATE cxx_std_20)
    endif()
  endfunction()

  add_executable(post_link_mutator_smoke_test
    post_link_mutator_smoke_test.cpp
  )
  target_compile_definitions(post_link_mutator_smoke_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_BIN="$<TARGET_FILE:eippf_post_link_mutator>"
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_smoke_test)
  add_test(NAME post_link_mutator_smoke_test COMMAND post_link_mutator_smoke_test)

  add_executable(post_link_mutator_thin_entry_proof_test
    post_link_mutator_thin_entry_proof_test.cpp
  )
  target_compile_definitions(post_link_mutator_thin_entry_proof_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_MAIN_CPP="${CMAKE_SOURCE_DIR}/post_link_mutator/src/main.cpp"
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_thin_entry_proof_test)
  add_test(NAME post_link_mutator_thin_entry_proof_test COMMAND post_link_mutator_thin_entry_proof_test)

  add_executable(post_link_mutator_exit_code_trailer_contract_test
    post_link_mutator_exit_code_trailer_contract_test.cpp
  )
  target_link_libraries(post_link_mutator_exit_code_trailer_contract_test PRIVATE
    eippf_post_link_mutator_core
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_exit_code_trailer_contract_test)
  add_test(
    NAME post_link_mutator_exit_code_trailer_contract_test
    COMMAND post_link_mutator_exit_code_trailer_contract_test
  )

  add_executable(post_link_mutator_derived_target_kind_contract_test
    post_link_mutator_derived_target_kind_contract_test.cpp
  )
  target_compile_definitions(post_link_mutator_derived_target_kind_contract_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_BIN="$<TARGET_FILE:eippf_post_link_mutator>"
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_derived_target_kind_contract_test)
  add_test(
    NAME post_link_mutator_derived_target_kind_contract_test
    COMMAND post_link_mutator_derived_target_kind_contract_test
  )

  add_executable(post_link_mutator_hardened_pipeline_contract_test
    post_link_mutator_hardened_pipeline_contract_test.cpp
  )
  target_compile_definitions(post_link_mutator_hardened_pipeline_contract_test PRIVATE
    EIPPF_HARDENED_FIXTURE_PATH="${CMAKE_BINARY_DIR}/tests/tools/hardened_target_pipeline_fixture"
    EIPPF_HARDENED_FIXTURE_MANIFEST_PATH="${CMAKE_BINARY_DIR}/tests/tools/hardened_target_pipeline_fixture.eippf.manifest.json"
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_hardened_pipeline_contract_test)
  add_test(
    NAME post_link_mutator_hardened_pipeline_contract_test
    COMMAND post_link_mutator_hardened_pipeline_contract_test
  )

  add_executable(post_link_mutator_fault_isolation_contract_test
    post_link_mutator_fault_isolation_contract_test.cpp
  )
  target_compile_definitions(post_link_mutator_fault_isolation_contract_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_MAIN_CPP="${CMAKE_SOURCE_DIR}/post_link_mutator/src/main.cpp"
  )
  target_link_libraries(post_link_mutator_fault_isolation_contract_test PRIVATE
    eippf_post_link_mutator_core
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_fault_isolation_contract_test)
  add_test(
    NAME post_link_mutator_fault_isolation_contract_test
    COMMAND post_link_mutator_fault_isolation_contract_test
  )

  add_executable(post_link_mutator_target_classifier_test
    post_link_mutator_target_classifier_test.cpp
  )
  target_link_libraries(post_link_mutator_target_classifier_test PRIVATE
    eippf_post_link_mutator_core
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_target_classifier_test)
  add_test(
    NAME post_link_mutator_target_classifier_test
    COMMAND post_link_mutator_target_classifier_test
  )

  add_executable(post_link_mutator_user_mode_contract_test
    post_link_mutator_user_mode_contract_test.cpp
  )
  target_compile_definitions(post_link_mutator_user_mode_contract_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_BIN="$<TARGET_FILE:eippf_post_link_mutator>"
  )
  target_link_libraries(post_link_mutator_user_mode_contract_test PRIVATE
    eippf_post_link_mutator_core
  )
  eippf_configure_post_link_mutator_test(post_link_mutator_user_mode_contract_test)
  add_test(
    NAME post_link_mutator_user_mode_contract_test
    COMMAND post_link_mutator_user_mode_contract_test
  )
endif()

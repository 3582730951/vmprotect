set(_windows_driver_lane_tests
  windows_driver_success_test
  windows_driver_failure_test
  windows_driver_security_edge_test
)

foreach(_lane_test IN LISTS _windows_driver_lane_tests)
  add_executable(${_lane_test}
    ${_lane_test}.cpp
  )

  target_compile_definitions(${_lane_test} PRIVATE
    EIPPF_ARTIFACT_AUDIT_PATH="${CMAKE_SOURCE_DIR}/tools/artifact_audit.py"
    EIPPF_LEXICAL_DENYLIST_PATH="${CMAKE_SOURCE_DIR}/tools/lexical_anchor_denylist.txt"
    EIPPF_SIGNATURE_VERIFIER_FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/tools/signature_verifier_fixture.py"
    EIPPF_SIGNATURE_VERIFIER_WORK_DIR="${CMAKE_CURRENT_BINARY_DIR}"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(${_lane_test})
  else()
    target_compile_features(${_lane_test} PRIVATE cxx_std_20)
  endif()

  add_test(NAME ${_lane_test} COMMAND ${_lane_test})
endforeach()

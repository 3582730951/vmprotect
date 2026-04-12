set(EIPPF_DEX_TOOLCHAIN_TEST_BIN "eippf_dex_toolchain")
if(TARGET eippf_dex_toolchain)
  set(EIPPF_DEX_TOOLCHAIN_TEST_BIN "$<TARGET_FILE:eippf_dex_toolchain>")
endif()

set(EIPPF_DEX_LOADER_TEST_BIN "eippf_dex_loader")
if(TARGET eippf_dex_loader)
  set(EIPPF_DEX_LOADER_TEST_BIN "$<TARGET_FILE:eippf_dex_loader>")
endif()

if(TARGET eippf_dex_toolchain)
  set(EIPPF_DEX_TOOLCHAIN_TEST_CASES
    dex_toolchain_smoke_test
    android_dex_success_test
    android_dex_failure_test
    android_dex_security_edge_test
  )

  foreach(_dex_test IN LISTS EIPPF_DEX_TOOLCHAIN_TEST_CASES)
    add_executable(${_dex_test}
      ${_dex_test}.cpp
    )

    target_compile_features(${_dex_test} PRIVATE cxx_std_20)
    target_compile_definitions(${_dex_test} PRIVATE
      EIPPF_DEX_TOOLCHAIN_PATH="${EIPPF_DEX_TOOLCHAIN_TEST_BIN}"
      EIPPF_DEX_LOADER_PATH="${EIPPF_DEX_LOADER_TEST_BIN}"
      EIPPF_ARTIFACT_AUDIT_PATH="${CMAKE_SOURCE_DIR}/tools/artifact_audit.py"
    )
    add_dependencies(${_dex_test} eippf_dex_toolchain)
    if(TARGET eippf_dex_loader)
      add_dependencies(${_dex_test} eippf_dex_loader)
    endif()

    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(${_dex_test})
    endif()

    add_test(NAME ${_dex_test} COMMAND ${_dex_test})
  endforeach()
endif()

if(TARGET eippf_runtime)
  add_executable(backend_policy_test
    backend_policy_test.cpp
  )

  target_link_libraries(backend_policy_test PRIVATE eippf_runtime)

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(backend_policy_test)
  else()
    target_compile_features(backend_policy_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME backend_policy_test COMMAND backend_policy_test)

  add_executable(runtime_backend_extraction_contract_test
    runtime_backend_extraction_contract_test.cpp
  )

  target_link_libraries(runtime_backend_extraction_contract_test PRIVATE eippf_runtime)

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(runtime_backend_extraction_contract_test)
  else()
    target_compile_features(runtime_backend_extraction_contract_test PRIVATE cxx_std_20)
  endif()

  add_test(
    NAME runtime_backend_extraction_contract_test
    COMMAND runtime_backend_extraction_contract_test
  )
endif()

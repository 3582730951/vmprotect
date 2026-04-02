if(TARGET eippf_contracts)
  add_executable(protection_contracts_test
    protection_contracts_test.cpp
  )

  target_link_libraries(protection_contracts_test PRIVATE eippf_contracts)

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(protection_contracts_test)
  else()
    target_compile_features(protection_contracts_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME protection_contracts_test COMMAND protection_contracts_test)
endif()

if(TARGET eippf_runtime)
  add_executable(string_token_runtime_test
    string_token_runtime_test.cpp
  )

  target_link_libraries(string_token_runtime_test PRIVATE
    eippf_runtime
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(string_token_runtime_test)
  else()
    target_compile_features(string_token_runtime_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME string_token_runtime_test COMMAND string_token_runtime_test)

  add_executable(android_so_policy_test
    android_so_policy_test.cpp
  )

  target_link_libraries(android_so_policy_test PRIVATE
    eippf_runtime
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(android_so_policy_test)
  else()
    target_compile_features(android_so_policy_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME android_so_policy_test COMMAND android_so_policy_test)
endif()

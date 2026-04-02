if(TARGET eippf_script_guard)
  add_executable(script_guard_smoke_test
    script_guard_smoke_test.cpp
  )

  target_compile_features(script_guard_smoke_test PRIVATE cxx_std_20)
  target_compile_definitions(script_guard_smoke_test PRIVATE
    EIPPF_SCRIPT_GUARD_PATH="$<TARGET_FILE:eippf_script_guard>"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(script_guard_smoke_test)
  endif()

  add_test(NAME script_guard_smoke_test COMMAND script_guard_smoke_test)
endif()

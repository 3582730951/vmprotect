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

  if(TARGET eippf_script_launcher)
    add_executable(script_launcher_success_test
      script_launcher_success_test.cpp
    )
    target_compile_features(script_launcher_success_test PRIVATE cxx_std_20)
    target_compile_definitions(script_launcher_success_test PRIVATE
      EIPPF_SCRIPT_GUARD_PATH="$<TARGET_FILE:eippf_script_guard>"
      EIPPF_SCRIPT_LAUNCHER_PATH="$<TARGET_FILE:eippf_script_launcher>"
    )
    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(script_launcher_success_test)
    endif()
    add_test(NAME script_launcher_success_test COMMAND script_launcher_success_test)

    add_executable(script_launcher_failure_test
      script_launcher_failure_test.cpp
    )
    target_compile_features(script_launcher_failure_test PRIVATE cxx_std_20)
    target_compile_definitions(script_launcher_failure_test PRIVATE
      EIPPF_SCRIPT_GUARD_PATH="$<TARGET_FILE:eippf_script_guard>"
      EIPPF_SCRIPT_LAUNCHER_PATH="$<TARGET_FILE:eippf_script_launcher>"
    )
    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(script_launcher_failure_test)
    endif()
    add_test(NAME script_launcher_failure_test COMMAND script_launcher_failure_test)

    add_executable(script_launcher_security_edge_test
      script_launcher_security_edge_test.cpp
    )
    target_compile_features(script_launcher_security_edge_test PRIVATE cxx_std_20)
    target_compile_definitions(script_launcher_security_edge_test PRIVATE
      EIPPF_SCRIPT_GUARD_PATH="$<TARGET_FILE:eippf_script_guard>"
      EIPPF_SCRIPT_LAUNCHER_PATH="$<TARGET_FILE:eippf_script_launcher>"
    )
    if(COMMAND eippf_apply_common_compile_options)
      eippf_apply_common_compile_options(script_launcher_security_edge_test)
    endif()
    add_test(NAME script_launcher_security_edge_test COMMAND script_launcher_security_edge_test)
  endif()
endif()

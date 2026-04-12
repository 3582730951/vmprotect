if(TARGET eippf_post_link_mutator AND EXISTS "${CMAKE_SOURCE_DIR}/tools/artifact_audit.py")
  add_executable(user_mode_perf_smoke_test
    user_mode_perf_smoke_test.cpp
  )

  target_compile_definitions(user_mode_perf_smoke_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_BIN="$<TARGET_FILE:eippf_post_link_mutator>"
    EIPPF_ARTIFACT_AUDIT_PATH="${CMAKE_SOURCE_DIR}/tools/artifact_audit.py"
    EIPPF_LEXICAL_DENYLIST_PATH="${CMAKE_SOURCE_DIR}/tools/lexical_anchor_denylist.txt"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(user_mode_perf_smoke_test)
  else()
    target_compile_features(user_mode_perf_smoke_test PRIVATE cxx_std_20)
  endif()

  add_test(NAME user_mode_perf_smoke_test COMMAND user_mode_perf_smoke_test)
endif()

if(TARGET eippf_runtime)
  add_executable(ios_safe_perf_smoke_test
    ios_safe_perf_smoke_test.cpp
  )
  target_link_libraries(ios_safe_perf_smoke_test PRIVATE
    eippf_runtime
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(ios_safe_perf_smoke_test)
  else()
    target_compile_features(ios_safe_perf_smoke_test PRIVATE cxx_std_20)
  endif()
  add_test(NAME ios_safe_perf_smoke_test COMMAND ios_safe_perf_smoke_test)

  add_executable(windows_driver_perf_smoke_test
    windows_driver_perf_smoke_test.cpp
  )
  target_link_libraries(windows_driver_perf_smoke_test PRIVATE
    eippf_runtime
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(windows_driver_perf_smoke_test)
  else()
    target_compile_features(windows_driver_perf_smoke_test PRIVATE cxx_std_20)
  endif()
  add_test(NAME windows_driver_perf_smoke_test COMMAND windows_driver_perf_smoke_test)

  add_executable(linux_kernel_module_perf_smoke_test
    linux_kernel_module_perf_smoke_test.cpp
  )
  target_link_libraries(linux_kernel_module_perf_smoke_test PRIVATE
    eippf_runtime
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(linux_kernel_module_perf_smoke_test)
  else()
    target_compile_features(linux_kernel_module_perf_smoke_test PRIVATE cxx_std_20)
  endif()
  add_test(NAME linux_kernel_module_perf_smoke_test COMMAND linux_kernel_module_perf_smoke_test)

  add_executable(android_kernel_module_perf_smoke_test
    android_kernel_module_perf_smoke_test.cpp
  )
  target_link_libraries(android_kernel_module_perf_smoke_test PRIVATE
    eippf_runtime
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(android_kernel_module_perf_smoke_test)
  else()
    target_compile_features(android_kernel_module_perf_smoke_test PRIVATE cxx_std_20)
  endif()
  add_test(NAME android_kernel_module_perf_smoke_test COMMAND android_kernel_module_perf_smoke_test)
endif()

if(TARGET eippf_script_guard AND TARGET eippf_script_launcher)
  add_executable(shell_launcher_perf_smoke_test
    shell_launcher_perf_smoke_test.cpp
  )
  target_compile_features(shell_launcher_perf_smoke_test PRIVATE cxx_std_20)
  target_compile_definitions(shell_launcher_perf_smoke_test PRIVATE
    EIPPF_SCRIPT_GUARD_PATH="$<TARGET_FILE:eippf_script_guard>"
    EIPPF_SCRIPT_LAUNCHER_PATH="$<TARGET_FILE:eippf_script_launcher>"
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(shell_launcher_perf_smoke_test)
  endif()
  add_test(NAME shell_launcher_perf_smoke_test COMMAND shell_launcher_perf_smoke_test)
endif()

if(TARGET eippf_dex_toolchain AND TARGET eippf_dex_loader)
  add_executable(dex_loader_perf_smoke_test
    dex_loader_perf_smoke_test.cpp
  )
  target_compile_features(dex_loader_perf_smoke_test PRIVATE cxx_std_20)
  target_compile_definitions(dex_loader_perf_smoke_test PRIVATE
    EIPPF_DEX_TOOLCHAIN_PATH="$<TARGET_FILE:eippf_dex_toolchain>"
    EIPPF_DEX_LOADER_PATH="$<TARGET_FILE:eippf_dex_loader>"
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(dex_loader_perf_smoke_test)
  endif()
  add_dependencies(dex_loader_perf_smoke_test eippf_dex_toolchain eippf_dex_loader)
  add_test(NAME dex_loader_perf_smoke_test COMMAND dex_loader_perf_smoke_test)
endif()

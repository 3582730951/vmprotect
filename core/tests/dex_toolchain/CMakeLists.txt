if(TARGET eippf_dex_toolchain)
  add_executable(dex_toolchain_smoke_test
    dex_toolchain_smoke_test.cpp
  )

  target_compile_features(dex_toolchain_smoke_test PRIVATE cxx_std_20)
  target_compile_definitions(dex_toolchain_smoke_test PRIVATE
    EIPPF_DEX_TOOLCHAIN_PATH="$<TARGET_FILE:eippf_dex_toolchain>"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(dex_toolchain_smoke_test)
  endif()

  add_test(NAME dex_toolchain_smoke_test COMMAND dex_toolchain_smoke_test)
endif()

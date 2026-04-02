add_executable(eippf_dex_toolchain
  src/main.cpp
)

target_compile_features(eippf_dex_toolchain PRIVATE cxx_std_20)

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_dex_toolchain)
endif()

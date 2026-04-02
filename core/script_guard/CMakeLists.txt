add_executable(eippf_script_guard
  src/main.cpp
)

target_compile_features(eippf_script_guard PRIVATE cxx_std_20)

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_script_guard)
endif()

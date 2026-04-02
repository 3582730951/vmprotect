add_executable(eippf_wrapper
  src/main.cpp
  src/flag_mapper.cpp
)

target_include_directories(eippf_wrapper PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

eippf_apply_common_compile_options(eippf_wrapper)

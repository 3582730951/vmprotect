if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.27)
  project(EIPPFPostLinkMutator LANGUAGES CXX)
  enable_testing()
endif()

add_executable(eippf_post_link_mutator
  src/main.cpp
)

if(TARGET eippf_contracts)
  target_link_libraries(eippf_post_link_mutator PRIVATE eippf_contracts)
endif()

target_include_directories(eippf_post_link_mutator PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
)

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_post_link_mutator)
else()
  target_compile_features(eippf_post_link_mutator PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(eippf_post_link_mutator PRIVATE /W4 /EHs-c- /GR-)
    target_compile_definitions(eippf_post_link_mutator PRIVATE _HAS_EXCEPTIONS=0)
  else()
    target_compile_options(eippf_post_link_mutator PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wconversion
      -fno-exceptions
      -fno-rtti
    )
  endif()
endif()

option(EIPPF_BUILD_POST_LINK_MUTATOR_TESTS "Build post_link_mutator smoke tests." ON)
set(_post_link_test_dir "${CMAKE_CURRENT_SOURCE_DIR}/../tests/post_link_mutator")
if(
  CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR
  AND EIPPF_BUILD_POST_LINK_MUTATOR_TESTS
  AND EXISTS "${_post_link_test_dir}/CMakeLists.txt"
)
  add_subdirectory("${_post_link_test_dir}" "${CMAKE_CURRENT_BINARY_DIR}/post_link_mutator_tests")
endif()

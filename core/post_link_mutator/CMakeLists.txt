if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.27)
  project(EIPPFPostLinkMutator LANGUAGES CXX)
  enable_testing()
endif()

if(NOT TARGET eippf_contracts)
  add_library(eippf_contracts INTERFACE)
  target_include_directories(eippf_contracts INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
  )
endif()

add_library(eippf_post_link_mutator_core STATIC
  src/cli_options.cpp
  src/artifact_detector.cpp
  src/target_classifier.cpp
  src/binary_io.cpp
  src/mutation_trailer.cpp
  src/pe_user_mode_mutator.cpp
  src/pe_kernel_driver_mutator.cpp
  src/elf_user_mode_mutator.cpp
  src/elf_kernel_module_mutator.cpp
  src/macho_user_mode_mutator.cpp
  src/manifest_writer.cpp
  src/mutator_app.cpp
)

target_include_directories(eippf_post_link_mutator_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/../include"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(eippf_post_link_mutator_core PUBLIC
  eippf_contracts
)

add_executable(eippf_post_link_mutator
  src/main.cpp
)

target_link_libraries(eippf_post_link_mutator PRIVATE
  eippf_post_link_mutator_core
)

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_post_link_mutator_core)
  eippf_apply_common_compile_options(eippf_post_link_mutator)
else()
  target_compile_features(eippf_post_link_mutator_core PUBLIC cxx_std_20)
  target_compile_features(eippf_post_link_mutator PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(eippf_post_link_mutator_core PRIVATE /W4 /EHs-c- /GR-)
    target_compile_definitions(eippf_post_link_mutator_core PRIVATE _HAS_EXCEPTIONS=0)
    target_compile_options(eippf_post_link_mutator PRIVATE /W4 /EHs-c- /GR-)
    target_compile_definitions(eippf_post_link_mutator PRIVATE _HAS_EXCEPTIONS=0)
  else()
    target_compile_options(eippf_post_link_mutator_core PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wconversion
      -fno-exceptions
      -fno-rtti
    )
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

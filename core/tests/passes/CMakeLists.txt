add_executable(string_protection_pass_test
  string_protection_pass_test.cpp
  "${CMAKE_SOURCE_DIR}/passes/src/StringProtectionPass.cpp"
)

target_include_directories(string_protection_pass_test PRIVATE
  "${CMAKE_SOURCE_DIR}/passes/include"
)

if(DEFINED EIPPF_LLVM_INCLUDE_DIRS)
  target_include_directories(string_protection_pass_test SYSTEM PRIVATE
    ${EIPPF_LLVM_INCLUDE_DIRS}
  )
endif()

if(TARGET LLVM)
  target_link_libraries(string_protection_pass_test PRIVATE LLVM)
elseif(COMMAND llvm_map_components_to_libnames)
  find_program(EIPPF_LLVM_CONFIG_EXECUTABLE NAMES llvm-config REQUIRED)
  execute_process(COMMAND "${EIPPF_LLVM_CONFIG_EXECUTABLE}" --libdir
    OUTPUT_VARIABLE EIPPF_STRING_PROTECTION_TEST_LLVM_LIBDIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  find_library(EIPPF_STRING_PROTECTION_TEST_LLVM_MONOLITHIC
    NAMES LLVM-14 LLVM
    HINTS "${EIPPF_STRING_PROTECTION_TEST_LLVM_LIBDIR}"
    NO_DEFAULT_PATH
    REQUIRED
  )
  target_link_libraries(string_protection_pass_test PRIVATE "${EIPPF_STRING_PROTECTION_TEST_LLVM_MONOLITHIC}")
else()
  message(FATAL_ERROR "string_protection_pass_test requires a usable LLVM linking strategy.")
endif()

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(string_protection_pass_test)
else()
  target_compile_features(string_protection_pass_test PRIVATE cxx_std_20)
endif()

add_test(NAME string_protection_pass_test COMMAND string_protection_pass_test)

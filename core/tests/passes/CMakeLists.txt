function(eippf_add_llvm_pass_test target_name)
  add_executable(${target_name}
    ${ARGN}
  )

  target_include_directories(${target_name} PRIVATE
    "${CMAKE_SOURCE_DIR}/passes/include"
  )

  if(DEFINED EIPPF_LLVM_INCLUDE_DIRS)
    target_include_directories(${target_name} SYSTEM PRIVATE
      ${EIPPF_LLVM_INCLUDE_DIRS}
    )
  endif()

  if(TARGET LLVM)
    target_link_libraries(${target_name} PRIVATE LLVM)
  elseif(COMMAND llvm_map_components_to_libnames)
    if(NOT DEFINED EIPPF_LLVM_CONFIG_EXECUTABLE)
      find_program(EIPPF_LLVM_CONFIG_EXECUTABLE NAMES llvm-config REQUIRED)
    endif()
    if(NOT DEFINED EIPPF_PASS_TEST_LLVM_LIBDIR)
      execute_process(COMMAND "${EIPPF_LLVM_CONFIG_EXECUTABLE}" --libdir
        OUTPUT_VARIABLE EIPPF_PASS_TEST_LLVM_LIBDIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
    endif()
    if(NOT DEFINED EIPPF_PASS_TEST_LLVM_MONOLITHIC)
      find_library(EIPPF_PASS_TEST_LLVM_MONOLITHIC
        NAMES LLVM-14 LLVM
        HINTS "${EIPPF_PASS_TEST_LLVM_LIBDIR}"
        NO_DEFAULT_PATH
        REQUIRED
      )
    endif()
    target_link_libraries(${target_name} PRIVATE "${EIPPF_PASS_TEST_LLVM_MONOLITHIC}")
  else()
    message(FATAL_ERROR "${target_name} requires a usable LLVM linking strategy.")
  endif()

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(${target_name})
  else()
    target_compile_features(${target_name} PRIVATE cxx_std_20)
  endif()

  add_test(NAME ${target_name} COMMAND ${target_name})
endfunction()

eippf_add_llvm_pass_test(string_protection_pass_test
  string_protection_pass_test.cpp
  "${CMAKE_SOURCE_DIR}/passes/src/StringProtectionPass.cpp"
)

eippf_add_llvm_pass_test(cff_obfuscation_pass_test
  cff_obfuscation_pass_test.cpp
  "${CMAKE_SOURCE_DIR}/passes/src/CFFObfuscationPass.cpp"
)

eippf_add_llvm_pass_test(iat_minimization_pass_test
  iat_minimization_pass_test.cpp
  "${CMAKE_SOURCE_DIR}/passes/src/IATMinimizationPass.cpp"
)

eippf_add_llvm_pass_test(protection_suite_pass_test
  protection_suite_pass_test.cpp
  "${CMAKE_SOURCE_DIR}/passes/src/ProtectionSuitePassPlugin.cpp"
  "${CMAKE_SOURCE_DIR}/passes/src/ProtectionAnchorPass.cpp"
  "${CMAKE_SOURCE_DIR}/passes/src/StringProtectionPass.cpp"
  "${CMAKE_SOURCE_DIR}/passes/src/IATMinimizationPass.cpp"
  "${CMAKE_SOURCE_DIR}/passes/src/MBAObfuscationPass.cpp"
  "${CMAKE_SOURCE_DIR}/passes/src/CFFObfuscationPass.cpp"
)

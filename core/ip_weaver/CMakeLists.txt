find_package(LLVM REQUIRED CONFIG)

set(EIPPF_LLVM_INCLUDE_DIR "${LLVM_INCLUDE_DIRS}")
set(EIPPF_LLVM_LIB_DIR "${LLVM_LIBRARY_DIRS}")

if(NOT EIPPF_LLVM_LIB_DIR)
  set(_llvm_config_candidates
    "${LLVM_TOOLS_BINARY_DIR}/llvm-config"
    "/usr/lib/llvm-18/bin/llvm-config"
  )
  foreach(_candidate IN LISTS _llvm_config_candidates)
    if(EXISTS "${_candidate}")
      set(_llvm_config "${_candidate}")
      break()
    endif()
  endforeach()

  if(DEFINED _llvm_config)
    execute_process(
      COMMAND "${_llvm_config}" --includedir
      OUTPUT_VARIABLE EIPPF_LLVM_INCLUDE_DIR
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
      COMMAND "${_llvm_config}" --libdir
      OUTPUT_VARIABLE EIPPF_LLVM_LIB_DIR
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  endif()
endif()

find_library(EIPPF_CLANG_CPP_LIBRARY
  NAMES clang-cpp libclang-cpp.so.18.1
  PATHS ${EIPPF_LLVM_LIB_DIR} /usr/lib/llvm-18/lib /usr/lib /usr/lib64
)

if(NOT EIPPF_CLANG_CPP_LIBRARY)
  message(WARNING "ip_weaver disabled: libclang-cpp was not found.")
  return()
endif()

if(NOT EXISTS "${EIPPF_LLVM_INCLUDE_DIR}/clang/Tooling/Tooling.h")
  message(WARNING "ip_weaver disabled: clang tooling headers were not found in ${EIPPF_LLVM_INCLUDE_DIR}.")
  return()
endif()

add_executable(ip_weaver
  src/main.cpp
)

target_include_directories(ip_weaver PRIVATE
  ${EIPPF_LLVM_INCLUDE_DIR}
)

target_link_libraries(ip_weaver PRIVATE
  ${EIPPF_CLANG_CPP_LIBRARY}
)

if(TARGET LLVM)
  target_link_libraries(ip_weaver PRIVATE LLVM)
endif()

eippf_apply_common_compile_options(ip_weaver)

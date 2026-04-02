cmake_minimum_required(VERSION 3.27)
project(EIPPF LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(EIPPF_BUILD_TESTS "Build test targets when available." ON)
option(EIPPF_ENABLE_PERF_GATES "Enable performance budget gates." ON)
option(EIPPF_BUILD_IP_WEAVER "Build source-to-source ip_weaver tool." ON)
option(EIPPF_BUILD_IP_WEAVER_IR "Build LLVM bitcode transformer ip_weaver_ir tool." ON)
option(EIPPF_BUILD_POST_LINK_MUTATOR "Build post-link mutator module when available." ON)
option(EIPPF_BUILD_DEX_TOOLCHAIN "Build Android dex toolchain module when available." ON)
option(EIPPF_BUILD_SCRIPT_GUARD "Build shell script protection module when available." ON)
option(EIPPF_BUILD_TOOLING "Build tooling module when available." ON)

if(MSVC)
  foreach(_flag_var IN ITEMS
    CMAKE_CXX_FLAGS
    CMAKE_CXX_FLAGS_DEBUG
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_RELWITHDEBINFO
    CMAKE_CXX_FLAGS_MINSIZEREL
  )
    if(DEFINED ${_flag_var})
      string(REPLACE "/EHsc" "" ${_flag_var} "${${_flag_var}}")
    endif()
  endforeach()
endif()

set(EIPPF_PASS_PLUGIN "" CACHE STRING "LLVM pass plugin target name or absolute path.")
set(EIPPF_POST_LINK_MUTATOR "" CACHE STRING "Post-link mutator target name or absolute path.")
set(EIPPF_WRAPPER_EXECUTABLE "" CACHE STRING "Wrapper target name or absolute path override.")
set(EIPPF_ARTIFACT_AUDIT_TOOL "" CACHE STRING "Artifact audit tool absolute path override.")
set(EIPPF_SIGNATURE_VERIFIER_TOOL "" CACHE STRING "Signature verifier target name or absolute path override.")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerOptions)
include(HardenTarget)

if(NOT TARGET eippf_contracts)
  add_library(eippf_contracts INTERFACE)
  target_include_directories(eippf_contracts INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
  add_library(eippf::contracts ALIAS eippf_contracts)
endif()

if(EIPPF_PASS_PLUGIN)
  eippf_register_pass_plugin("${EIPPF_PASS_PLUGIN}")
endif()

if(EIPPF_POST_LINK_MUTATOR)
  eippf_register_post_link_mutator("${EIPPF_POST_LINK_MUTATOR}")
endif()

if(EIPPF_WRAPPER_EXECUTABLE)
  eippf_register_wrapper_executable("${EIPPF_WRAPPER_EXECUTABLE}")
endif()

if(EIPPF_ARTIFACT_AUDIT_TOOL)
  eippf_register_artifact_audit_tool("${EIPPF_ARTIFACT_AUDIT_TOOL}")
endif()

if(EIPPF_SIGNATURE_VERIFIER_TOOL)
  eippf_register_signature_verifier_tool("${EIPPF_SIGNATURE_VERIFIER_TOOL}")
endif()

add_subdirectory(wrapper)

if(NOT EIPPF_WRAPPER_EXECUTABLE AND TARGET eippf_wrapper)
  eippf_register_wrapper_executable("eippf_wrapper")
endif()

set(EIPPF_CORE_MODULES bootstrap passes runtime)
if(EIPPF_BUILD_POST_LINK_MUTATOR)
  list(APPEND EIPPF_CORE_MODULES post_link_mutator)
endif()
if(EIPPF_BUILD_IP_WEAVER)
  list(APPEND EIPPF_CORE_MODULES ip_weaver)
endif()
if(EIPPF_BUILD_IP_WEAVER_IR)
  list(APPEND EIPPF_CORE_MODULES ip_weaver_ir)
endif()
if(EIPPF_BUILD_DEX_TOOLCHAIN)
  list(APPEND EIPPF_CORE_MODULES dex_toolchain)
endif()
if(EIPPF_BUILD_SCRIPT_GUARD)
  list(APPEND EIPPF_CORE_MODULES script_guard)
endif()
if(EIPPF_BUILD_TOOLING)
  list(APPEND EIPPF_CORE_MODULES tools)
endif()

foreach(_module IN LISTS EIPPF_CORE_MODULES)
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${_module}/CMakeLists.txt")
    add_subdirectory("${_module}")
  endif()
endforeach()

if(NOT EIPPF_POST_LINK_MUTATOR AND TARGET eippf_post_link_mutator)
  eippf_register_post_link_mutator("eippf_post_link_mutator")
endif()

if(NOT EIPPF_ARTIFACT_AUDIT_TOOL AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/artifact_audit.py")
  eippf_register_artifact_audit_tool("${CMAKE_CURRENT_SOURCE_DIR}/tools/artifact_audit.py")
endif()

if(EIPPF_BUILD_TESTS)
  enable_testing()
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
  endif()
endif()

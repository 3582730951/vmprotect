include_guard(GLOBAL)

function(eippf_enable_weaver_launcher)
  set(options)
  set(one_value_args PROXY_SCRIPT IR_WEAVER_BIN COMPILE_COMMANDS VM_RUNTIME_LIB)
  cmake_parse_arguments(EIPPF_WEAVER "${options}" "${one_value_args}" "" ${ARGN})

  if(NOT EIPPF_WEAVER_PROXY_SCRIPT)
    set(EIPPF_WEAVER_PROXY_SCRIPT "${CMAKE_SOURCE_DIR}/core/wrapper/weaver_proxy.py")
  endif()

  if(NOT EIPPF_WEAVER_IR_WEAVER_BIN)
    message(FATAL_ERROR
      "eippf_enable_weaver_launcher requires IR_WEAVER_BIN (absolute path to IR weaver binary).")
  endif()
  if(NOT EIPPF_WEAVER_VM_RUNTIME_LIB)
    message(FATAL_ERROR
      "eippf_enable_weaver_launcher requires VM_RUNTIME_LIB (target name or absolute path).")
  endif()

  if(NOT EXISTS "${EIPPF_WEAVER_PROXY_SCRIPT}")
    message(FATAL_ERROR
      "eippf_enable_weaver_launcher: PROXY_SCRIPT not found: ${EIPPF_WEAVER_PROXY_SCRIPT}")
  endif()

  find_package(Python3 REQUIRED COMPONENTS Interpreter)

  set(_vm_runtime_lib "${EIPPF_WEAVER_VM_RUNTIME_LIB}")
  if(TARGET "${EIPPF_WEAVER_VM_RUNTIME_LIB}")
    set(_vm_runtime_lib "$<TARGET_FILE:${EIPPF_WEAVER_VM_RUNTIME_LIB}>")
  endif()

  set(_launcher_command
    "${Python3_EXECUTABLE}"
    "${EIPPF_WEAVER_PROXY_SCRIPT}"
    "--ir-weaver-bin" "${EIPPF_WEAVER_IR_WEAVER_BIN}"
    "--vm-runtime-lib" "${_vm_runtime_lib}"
  )
  if(EIPPF_WEAVER_COMPILE_COMMANDS)
    list(APPEND _launcher_command
      "--compile-commands" "${EIPPF_WEAVER_COMPILE_COMMANDS}"
    )
  endif()

  set(CMAKE_C_COMPILER_LAUNCHER
      "${_launcher_command}"
      CACHE STRING "Global C compiler launcher for transparent ip_weaver integration." FORCE)

  set(CMAKE_CXX_COMPILER_LAUNCHER
      "${_launcher_command}"
      CACHE STRING "Global C++ compiler launcher for transparent ip_weaver integration." FORCE)

  if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.27")
    set(CMAKE_C_LINKER_LAUNCHER
        "${_launcher_command}"
        CACHE STRING "Global C linker launcher for transparent eippf runtime auto-link." FORCE)
    set(CMAKE_CXX_LINKER_LAUNCHER
        "${_launcher_command}"
        CACHE STRING "Global C++ linker launcher for transparent eippf runtime auto-link." FORCE)
  endif()
endfunction()

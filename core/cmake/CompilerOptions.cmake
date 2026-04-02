include_guard(GLOBAL)

function(eippf_apply_common_compile_options target_name)
  if(NOT TARGET "${target_name}")
    message(FATAL_ERROR "eippf_apply_common_compile_options: unknown target '${target_name}'")
  endif()

  target_compile_features("${target_name}" PUBLIC cxx_std_20)

  if(MSVC)
    target_compile_options("${target_name}" PRIVATE
      /W4
      /WX-
      /permissive-
      /utf-8
      /Zc:__cplusplus
      /GR-
      /EHs-c-
    )
    target_compile_definitions("${target_name}" PRIVATE
      WIN32_LEAN_AND_MEAN
      NOMINMAX
      _HAS_EXCEPTIONS=0
      _CRT_SECURE_NO_WARNINGS
    )
  else()
    target_compile_options("${target_name}" PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wconversion
      -Wshadow
      -Wnull-dereference
      -fno-exceptions
      -fno-rtti
    )
  endif()
endfunction()

function(eippf_apply_freestanding_options target_name)
  if(NOT TARGET "${target_name}")
    message(FATAL_ERROR "eippf_apply_freestanding_options: unknown target '${target_name}'")
  endif()

  eippf_apply_common_compile_options("${target_name}")
  target_compile_definitions("${target_name}" PRIVATE EIPPF_FREESTANDING=1)

  if(MSVC)
    target_compile_options("${target_name}" PRIVATE
      /Zl
      /GS-
    )
    target_link_options("${target_name}" PRIVATE
      /NODEFAULTLIB
    )
  else()
    target_compile_options("${target_name}" PRIVATE
      -ffreestanding
      -fno-builtin
      -fno-stack-protector
      -fvisibility=hidden
    )
    target_link_options("${target_name}" PRIVATE
      -nostdlib
      -nodefaultlibs
    )
  endif()
endfunction()

function(eippf_apply_protected_runtime_profile target_name)
  eippf_apply_freestanding_options("${target_name}")
endfunction()

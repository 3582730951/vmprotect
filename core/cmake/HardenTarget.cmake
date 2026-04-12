include_guard(GLOBAL)
include(CMakeParseArguments)

function(eippf_register_pass_plugin pass_plugin)
  if(NOT pass_plugin)
    message(FATAL_ERROR "eippf_register_pass_plugin requires a non-empty value")
  endif()
  set_property(GLOBAL PROPERTY EIPPF_PASS_PLUGIN "${pass_plugin}")
endfunction()

function(eippf_register_post_link_mutator mutator)
  if(NOT mutator)
    message(FATAL_ERROR "eippf_register_post_link_mutator requires a non-empty value")
  endif()
  set_property(GLOBAL PROPERTY EIPPF_POST_LINK_MUTATOR "${mutator}")
endfunction()

function(eippf_register_wrapper_executable wrapper)
  if(NOT wrapper)
    message(FATAL_ERROR "eippf_register_wrapper_executable requires a non-empty value")
  endif()
  set_property(GLOBAL PROPERTY EIPPF_WRAPPER_EXECUTABLE "${wrapper}")
endfunction()

function(eippf_register_artifact_audit_tool audit_tool)
  if(NOT audit_tool)
    message(FATAL_ERROR "eippf_register_artifact_audit_tool requires a non-empty value")
  endif()
  set_property(GLOBAL PROPERTY EIPPF_ARTIFACT_AUDIT_TOOL "${audit_tool}")
endfunction()

function(eippf_register_signature_verifier_tool verifier_tool)
  if(NOT verifier_tool)
    message(FATAL_ERROR "eippf_register_signature_verifier_tool requires a non-empty value")
  endif()
  set_property(GLOBAL PROPERTY EIPPF_SIGNATURE_VERIFIER_TOOL "${verifier_tool}")
endfunction()

function(_eippf_resolve_tool_spec tool_spec out_var)
  if(TARGET "${tool_spec}")
    set("${out_var}" "$<TARGET_FILE:${tool_spec}>" PARENT_SCOPE)
  else()
    set("${out_var}" "${tool_spec}" PARENT_SCOPE)
  endif()
endfunction()

function(_eippf_parse_target_kind target_kind out_var out_name_var)
  if(NOT target_kind)
    message(FATAL_ERROR "eippf_harden_target requires TARGET_KIND to be set explicitly")
  endif()
  string(TOLOWER "${target_kind}" _kind_lower)
  if(_kind_lower STREQUAL "desktop_native")
    set(_parsed 1)
  elseif(_kind_lower STREQUAL "android_so")
    set(_parsed 2)
  elseif(_kind_lower STREQUAL "android_dex" OR _kind_lower STREQUAL "android_dex_research")
    set(_parsed 3)
  elseif(_kind_lower STREQUAL "ios_appstore")
    set(_parsed 4)
  elseif(_kind_lower STREQUAL "windows_driver")
    set(_parsed 5)
  elseif(_kind_lower STREQUAL "linux_kernel_module")
    set(_parsed 6)
  elseif(_kind_lower STREQUAL "android_kernel_module")
    set(_parsed 7)
  elseif(_kind_lower STREQUAL "shell_ephemeral")
    set(_parsed 8)
  else()
    message(FATAL_ERROR "eippf_harden_target: unsupported TARGET_KIND '${target_kind}'")
  endif()
  set("${out_var}" "${_parsed}" PARENT_SCOPE)
  set("${out_name_var}" "${_kind_lower}" PARENT_SCOPE)
endfunction()

function(eippf_harden_target target_name)
  if(NOT TARGET "${target_name}")
    message(FATAL_ERROR "eippf_harden_target: unknown target '${target_name}'")
  endif()

  set(_options NO_WRAPPER NO_MUTATION NO_PASS_PLUGIN)
  set(_one_value_args PASS_PLUGIN POST_LINK_MUTATOR WRAPPER MANIFEST_PATH ARTIFACT_AUDIT_TOOL AUDIT_REPORT_PATH TARGET_KIND SIGNATURE_VERIFIER_TOOL)
  set(_multi_value_args EXTRA_MUTATOR_ARGS EXTRA_AUDIT_ARGS)
  cmake_parse_arguments(EIPPF "${_options}" "${_one_value_args}" "${_multi_value_args}" ${ARGN})

  if(NOT EIPPF_NO_PASS_PLUGIN AND NOT EIPPF_PASS_PLUGIN)
    get_property(_global_pass_plugin GLOBAL PROPERTY EIPPF_PASS_PLUGIN)
    if(_global_pass_plugin)
      set(EIPPF_PASS_PLUGIN "${_global_pass_plugin}")
    endif()
  endif()

  if(NOT EIPPF_POST_LINK_MUTATOR)
    get_property(_global_mutator GLOBAL PROPERTY EIPPF_POST_LINK_MUTATOR)
    if(_global_mutator)
      set(EIPPF_POST_LINK_MUTATOR "${_global_mutator}")
    elseif(TARGET eippf_post_link_mutator)
      set(EIPPF_POST_LINK_MUTATOR "eippf_post_link_mutator")
    endif()
  endif()

  if(NOT EIPPF_WRAPPER)
    get_property(_global_wrapper GLOBAL PROPERTY EIPPF_WRAPPER_EXECUTABLE)
    if(_global_wrapper)
      set(EIPPF_WRAPPER "${_global_wrapper}")
    endif()
  endif()

  if(NOT EIPPF_NO_PASS_PLUGIN AND EIPPF_PASS_PLUGIN)
    _eippf_resolve_tool_spec("${EIPPF_PASS_PLUGIN}" _pass_plugin_cmd)
  endif()

  if(NOT EIPPF_ARTIFACT_AUDIT_TOOL)
    get_property(_global_audit_tool GLOBAL PROPERTY EIPPF_ARTIFACT_AUDIT_TOOL)
    if(_global_audit_tool)
      set(EIPPF_ARTIFACT_AUDIT_TOOL "${_global_audit_tool}")
    elseif(EXISTS "${CMAKE_SOURCE_DIR}/tools/artifact_audit.py")
      set(EIPPF_ARTIFACT_AUDIT_TOOL "${CMAKE_SOURCE_DIR}/tools/artifact_audit.py")
    endif()
  endif()

  if(NOT EIPPF_SIGNATURE_VERIFIER_TOOL)
    get_property(_global_signature_verifier_tool GLOBAL PROPERTY EIPPF_SIGNATURE_VERIFIER_TOOL)
    if(_global_signature_verifier_tool)
      set(EIPPF_SIGNATURE_VERIFIER_TOOL "${_global_signature_verifier_tool}")
    endif()
  endif()

  _eippf_parse_target_kind("${EIPPF_TARGET_KIND}" _runtime_target_kind _runtime_target_kind_name)
  target_compile_definitions("${target_name}" PRIVATE
    EIPPF_HARDENED_TARGET=1
    EIPPF_RUNTIME_TARGET_KIND=${_runtime_target_kind}
  )

  set(_runtime_anchor_source
    "${CMAKE_CURRENT_BINARY_DIR}/${target_name}.eippf_runtime_target_anchor.cpp"
  )
  set(_runtime_anchor_content
"extern \"C\" const unsigned int eippf_rtk0 = ${_runtime_target_kind}u;\n\
#if defined(_MSC_VER)\n\
#pragma section(\".eipptk\", read)\n\
extern \"C\" __declspec(allocate(\".eipptk\")) const unsigned char eippf_runtime_target_kind_marker[] = {\n\
  'E','I','P','P','F','T','K','1',\n\
  ${_runtime_target_kind}u, 0u, 0u, 0u\n\
};\n\
#else\n\
extern \"C\" const unsigned char eippf_runtime_target_kind_marker[] = {\n\
  'E','I','P','P','F','T','K','1',\n\
  ${_runtime_target_kind}u, 0u, 0u, 0u\n\
};\n\
#endif\n"
  )
  file(GENERATE
    OUTPUT "${_runtime_anchor_source}"
    CONTENT "${_runtime_anchor_content}"
  )
  target_sources("${target_name}" PRIVATE "${_runtime_anchor_source}")

  if(NOT EIPPF_NO_WRAPPER)
    if(EIPPF_WRAPPER)
      _eippf_resolve_tool_spec("${EIPPF_WRAPPER}" _wrapper_cmd)
      set(_launcher "${_wrapper_cmd}")
      if(_pass_plugin_cmd)
        list(APPEND _launcher "--pass-plugin=${_pass_plugin_cmd}")
      endif()
      list(APPEND _launcher "--")
      set_property(TARGET "${target_name}" PROPERTY C_COMPILER_LAUNCHER "${_launcher}")
      set_property(TARGET "${target_name}" PROPERTY CXX_COMPILER_LAUNCHER "${_launcher}")
    elseif(_pass_plugin_cmd)
      if(MSVC)
        target_compile_options("${target_name}" PRIVATE "/clang:-fpass-plugin=${_pass_plugin_cmd}")
      else()
        target_compile_options("${target_name}" PRIVATE "-fpass-plugin=${_pass_plugin_cmd}")
      endif()
    endif()
  elseif(_pass_plugin_cmd)
    if(MSVC)
      target_compile_options("${target_name}" PRIVATE "/clang:-fpass-plugin=${_pass_plugin_cmd}")
    else()
      target_compile_options("${target_name}" PRIVATE "-fpass-plugin=${_pass_plugin_cmd}")
    endif()
  endif()

  if(NOT EIPPF_NO_MUTATION AND EIPPF_POST_LINK_MUTATOR)
    _eippf_resolve_tool_spec("${EIPPF_POST_LINK_MUTATOR}" _mutator_cmd)
    if(TARGET "${EIPPF_POST_LINK_MUTATOR}")
      add_dependencies("${target_name}" "${EIPPF_POST_LINK_MUTATOR}")
    elseif(EXISTS "${EIPPF_POST_LINK_MUTATOR}")
      set_property(TARGET "${target_name}" APPEND PROPERTY LINK_DEPENDS
        "${EIPPF_POST_LINK_MUTATOR}"
      )
    endif()

    if(NOT EIPPF_MANIFEST_PATH)
      set(EIPPF_MANIFEST_PATH "${CMAKE_CURRENT_BINARY_DIR}/${target_name}.eippf.manifest")
    endif()
    if(NOT EIPPF_AUDIT_REPORT_PATH)
      set(EIPPF_AUDIT_REPORT_PATH "${EIPPF_MANIFEST_PATH}.audit.json")
    endif()

    set(_audit_input_path "$<TARGET_FILE:${target_name}>")
    set(_audit_input_copy_command)
    if(_runtime_target_kind_name STREQUAL "windows_driver")
      set(_audit_input_path
        "${CMAKE_CURRENT_BINARY_DIR}/${target_name}.eippf.audit_input.sys"
      )
      list(APPEND _audit_input_copy_command
        COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:${target_name}>" "${_audit_input_path}"
      )
    elseif(_runtime_target_kind_name STREQUAL "linux_kernel_module" OR
           _runtime_target_kind_name STREQUAL "android_kernel_module")
      set(_audit_input_path
        "${CMAKE_CURRENT_BINARY_DIR}/${target_name}.eippf.audit_input.ko"
      )
      list(APPEND _audit_input_copy_command
        COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:${target_name}>" "${_audit_input_path}"
      )
    endif()

    add_custom_command(
      TARGET "${target_name}" POST_BUILD
      COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_FILE:${target_name}>" "$<TARGET_FILE:${target_name}>.pre_eippf"
      COMMAND "${_mutator_cmd}"
              "--input=$<TARGET_FILE:${target_name}>"
              "--output=$<TARGET_FILE:${target_name}>"
              "--manifest=${EIPPF_MANIFEST_PATH}"
              "--target-kind=${_runtime_target_kind_name}"
              "--target=${target_name}"
              ${EIPPF_EXTRA_MUTATOR_ARGS}
      COMMAND_EXPAND_LISTS
      VERBATIM
      COMMENT "EIPPF post-link mutation for target '${target_name}'"
    )

    if(EIPPF_ARTIFACT_AUDIT_TOOL)
      if(EXISTS "${EIPPF_ARTIFACT_AUDIT_TOOL}")
        set_property(TARGET "${target_name}" APPEND PROPERTY LINK_DEPENDS
          "${EIPPF_ARTIFACT_AUDIT_TOOL}"
        )
      endif()
      set(_audit_signature_verifier_arg)
      if(EIPPF_SIGNATURE_VERIFIER_TOOL)
        _eippf_resolve_tool_spec("${EIPPF_SIGNATURE_VERIFIER_TOOL}" _signature_verifier_cmd)
        set(_audit_signature_verifier_arg "--signature-verifier=${_signature_verifier_cmd}")
        if(TARGET "${EIPPF_SIGNATURE_VERIFIER_TOOL}")
          add_dependencies("${target_name}" "${EIPPF_SIGNATURE_VERIFIER_TOOL}")
        elseif(EXISTS "${EIPPF_SIGNATURE_VERIFIER_TOOL}")
          set_property(TARGET "${target_name}" APPEND PROPERTY LINK_DEPENDS
            "${EIPPF_SIGNATURE_VERIFIER_TOOL}"
          )
        endif()
      endif()
      add_custom_command(
        TARGET "${target_name}" POST_BUILD
        ${_audit_input_copy_command}
        COMMAND python3
                "${EIPPF_ARTIFACT_AUDIT_TOOL}"
                "--input=${_audit_input_path}"
                "--manifest=${EIPPF_MANIFEST_PATH}"
                "--target-kind=${_runtime_target_kind_name}"
                "--output=${EIPPF_AUDIT_REPORT_PATH}"
                "--strict"
                ${_audit_signature_verifier_arg}
                ${EIPPF_EXTRA_AUDIT_ARGS}
        COMMAND_EXPAND_LISTS
        VERBATIM
        COMMENT "EIPPF artifact audit for target '${target_name}'"
      )
    endif()
  endif()
endfunction()

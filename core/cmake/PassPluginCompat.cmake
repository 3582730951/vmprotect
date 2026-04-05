function(_eippf_windows_normalize_string input output_var)
  string(REPLACE "\\" "/" _normalized "${input}")
  string(TOLOWER "${_normalized}" _normalized)
  set(${output_var} "${_normalized}" PARENT_SCOPE)
endfunction()

function(_eippf_windows_is_forbidden_dia_item input output_var)
  _eippf_windows_normalize_string("${input}" _normalized)

  set(_is_forbidden FALSE)
  if(_normalized MATCHES "diaguids\\.lib" OR
     _normalized MATCHES "dia sdk" OR
     _normalized MATCHES "dia/sdk" OR
     _normalized MATCHES "debuginfopdb" OR
     _normalized MATCHES "llvmdebuginfo")
    set(_is_forbidden TRUE)
  endif()

  set(${output_var} "${_is_forbidden}" PARENT_SCOPE)
endfunction()

function(_eippf_windows_collect_target_graph out_graph_targets out_forbidden_items)
  set(_queue ${ARGN})
  set(_visited)
  set(_graph_targets)
  set(_forbidden_items)
  set(_visited_count 0)
  set(_visited_limit 2048)

  set(_property_names
    INTERFACE_LINK_LIBRARIES
    IMPORTED_LINK_INTERFACE_LIBRARIES
    IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE
    IMPORTED_LINK_INTERFACE_LIBRARIES_RELWITHDEBINFO
    IMPORTED_LINK_INTERFACE_LIBRARIES_MINSIZEREL
    IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG
  )

  while(_queue)
    list(POP_FRONT _queue _current_item)
    if(NOT _current_item)
      continue()
    endif()

    _eippf_windows_is_forbidden_dia_item("${_current_item}" _current_item_forbidden)
    if(_current_item_forbidden)
      list(APPEND _forbidden_items "${_current_item}")
    endif()

    set(_candidate_target "${_current_item}")
    if(_candidate_target MATCHES "^\\$<LINK_ONLY:([^>$]+)>$")
      set(_candidate_target "${CMAKE_MATCH_1}")
    elseif(_candidate_target MATCHES "^\\$<BUILD_INTERFACE:([^>$]+)>$")
      set(_candidate_target "${CMAKE_MATCH_1}")
    elseif(_candidate_target MATCHES "^\\$<INSTALL_INTERFACE:([^>$]+)>$")
      set(_candidate_target "${CMAKE_MATCH_1}")
    endif()

    if(NOT TARGET "${_candidate_target}")
      continue()
    endif()

    get_target_property(_aliased_target "${_candidate_target}" ALIASED_TARGET)
    if(_aliased_target AND NOT _aliased_target MATCHES "-NOTFOUND$")
      set(_candidate_target "${_aliased_target}")
    endif()

    list(FIND _visited "${_candidate_target}" _seen_index)
    if(NOT _seen_index EQUAL -1)
      continue()
    endif()

    list(APPEND _visited "${_candidate_target}")
    list(APPEND _graph_targets "${_candidate_target}")

    math(EXPR _visited_count "${_visited_count} + 1")
    if(_visited_count GREATER _visited_limit)
      message(FATAL_ERROR
        "Windows LLVM target graph exceeded BFS node limit (${_visited_limit}) while processing ${_candidate_target}.")
    endif()

    foreach(_property_name IN LISTS _property_names)
      get_target_property(_property_values "${_candidate_target}" "${_property_name}")
      if(NOT _property_values OR _property_values MATCHES "-NOTFOUND$")
        continue()
      endif()

      foreach(_property_item IN ITEMS ${_property_values})
        if(NOT _property_item)
          continue()
        endif()

        _eippf_windows_is_forbidden_dia_item("${_property_item}" _property_item_forbidden)
        if(_property_item_forbidden)
          list(APPEND _forbidden_items "${_candidate_target}:${_property_name}:${_property_item}")
        endif()

        set(_next_target "${_property_item}")
        if(_next_target MATCHES "^\\$<LINK_ONLY:([^>$]+)>$")
          set(_next_target "${CMAKE_MATCH_1}")
        elseif(_next_target MATCHES "^\\$<BUILD_INTERFACE:([^>$]+)>$")
          set(_next_target "${CMAKE_MATCH_1}")
        elseif(_next_target MATCHES "^\\$<INSTALL_INTERFACE:([^>$]+)>$")
          set(_next_target "${CMAKE_MATCH_1}")
        elseif(_next_target MATCHES "^\\$<.*>$")
          set(_next_target "")
        endif()

        if(_next_target AND TARGET "${_next_target}")
          get_target_property(_next_aliased_target "${_next_target}" ALIASED_TARGET)
          if(_next_aliased_target AND NOT _next_aliased_target MATCHES "-NOTFOUND$")
            set(_next_target "${_next_aliased_target}")
          endif()
          list(APPEND _queue "${_next_target}")
        endif()
      endforeach()
    endforeach()
  endwhile()

  list(REMOVE_DUPLICATES _graph_targets)
  list(REMOVE_DUPLICATES _forbidden_items)

  set(${out_graph_targets} "${_graph_targets}" PARENT_SCOPE)
  set(${out_forbidden_items} "${_forbidden_items}" PARENT_SCOPE)
endfunction()

function(_eippf_windows_filter_forbidden_interface_list out_filtered out_removed)
  set(_filtered)
  set(_removed)

  foreach(_token IN ITEMS ${ARGN})
    if(NOT _token)
      continue()
    endif()

    _eippf_windows_is_forbidden_dia_item("${_token}" _token_forbidden)
    if(_token_forbidden)
      list(APPEND _removed "${_token}")
    else()
      list(APPEND _filtered "${_token}")
    endif()
  endforeach()

  set(${out_filtered} "${_filtered}" PARENT_SCOPE)
  set(${out_removed} "${_removed}" PARENT_SCOPE)
endfunction()

function(_eippf_windows_sanitize_target_graph out_removed_items)
  set(_direct_items ${ARGN})
  set(_removed_items)

  _eippf_windows_collect_target_graph(_graph_targets _initial_forbidden_items ${_direct_items})
  if(_initial_forbidden_items)
    list(APPEND _removed_items ${_initial_forbidden_items})
  endif()

  set(_property_names
    INTERFACE_LINK_LIBRARIES
    IMPORTED_LINK_INTERFACE_LIBRARIES
    IMPORTED_LINK_INTERFACE_LIBRARIES_RELEASE
    IMPORTED_LINK_INTERFACE_LIBRARIES_RELWITHDEBINFO
    IMPORTED_LINK_INTERFACE_LIBRARIES_MINSIZEREL
    IMPORTED_LINK_INTERFACE_LIBRARIES_DEBUG
  )

  foreach(_graph_target IN LISTS _graph_targets)
    if(NOT TARGET "${_graph_target}")
      continue()
    endif()

    get_target_property(_is_imported_target "${_graph_target}" IMPORTED)
    if(NOT _is_imported_target)
      continue()
    endif()

    foreach(_property_name IN LISTS _property_names)
      get_target_property(_property_values "${_graph_target}" "${_property_name}")
      if(NOT _property_values OR _property_values MATCHES "-NOTFOUND$")
        continue()
      endif()

      _eippf_windows_filter_forbidden_interface_list(
        _filtered_values
        _removed_values
        ${_property_values}
      )

      if(_removed_values)
        list(APPEND _removed_items "${_graph_target}:${_property_name}:${_removed_values}")
        set_property(TARGET "${_graph_target}" PROPERTY "${_property_name}" "${_filtered_values}")
      endif()
    endforeach()
  endforeach()

  list(REMOVE_DUPLICATES _removed_items)
  set(${out_removed_items} "${_removed_items}" PARENT_SCOPE)
endfunction()

function(eippf_add_pass_plugin_target name)
  cmake_parse_arguments(ARG "" "OUTPUT_NAME" "SOURCES;COMPILE_DEFINITIONS;WINDOWS_LLVM_COMPONENTS" ${ARGN})

  string(TOUPPER ${name} name_upper)
  set(LLVM_${name_upper}_LINK_INTO_TOOLS OFF CACHE BOOL "Force EIPPF pass plugins to remain loadable modules." FORCE)

  if(WIN32)
    if(NOT ARG_WINDOWS_LLVM_COMPONENTS)
      message(FATAL_ERROR "Missing WINDOWS_LLVM_COMPONENTS for ${name} on Windows.")
    endif()
    if(NOT COMMAND llvm_map_components_to_libnames)
      message(FATAL_ERROR "llvm_map_components_to_libnames is required for ${name} on Windows.")
    endif()
    llvm_map_components_to_libnames(eippf_pass_plugin_llvm_libs ${ARG_WINDOWS_LLVM_COMPONENTS})

    foreach(eippf_link_item IN LISTS eippf_pass_plugin_llvm_libs)
      _eippf_windows_is_forbidden_dia_item("${eippf_link_item}" eippf_link_item_forbidden)
      if(eippf_link_item_forbidden)
        message(FATAL_ERROR "Forbidden DIA SDK dependency detected for ${name}: ${eippf_link_item}")
      endif()
    endforeach()

    _eippf_windows_sanitize_target_graph(eippf_windows_removed_items ${eippf_pass_plugin_llvm_libs})

    _eippf_windows_collect_target_graph(
      eippf_windows_closure_targets
      eippf_windows_closure_forbidden_items
      ${eippf_pass_plugin_llvm_libs}
    )
    if(eippf_windows_closure_forbidden_items)
      list(JOIN eippf_windows_closure_forbidden_items "; " eippf_windows_closure_forbidden_text)
      message(FATAL_ERROR
        "Forbidden DIA SDK dependency remains after graph sanitization for ${name}: "
        "${eippf_windows_closure_forbidden_text}")
    endif()

    add_library(${name} SHARED ${ARG_SOURCES})
    set_target_properties(${name} PROPERTIES
      PREFIX ""
      WINDOWS_EXPORT_ALL_SYMBOLS ON
    )

    if(CMAKE_LIBRARY_OUTPUT_DIRECTORY)
      set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
      )
    endif()

    if(CMAKE_RUNTIME_OUTPUT_DIRECTORY)
      set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
      )
    endif()

    if(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE)
      set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE}"
        LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE}"
      )
    endif()

    if(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE)
      set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE}"
      )
    endif()

    target_link_libraries(${name} PRIVATE ${eippf_pass_plugin_llvm_libs})
  else()
    add_llvm_pass_plugin(${name} ${ARG_SOURCES})
  endif()

  get_target_property(eippf_target_type ${name} TYPE)
  if(NOT eippf_target_type STREQUAL "MODULE_LIBRARY" AND
     NOT eippf_target_type STREQUAL "SHARED_LIBRARY")
    message(FATAL_ERROR "${name} resolved to non-compilable target type: ${eippf_target_type}")
  endif()

  target_include_directories(${name} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
  target_include_directories(${name} SYSTEM PRIVATE
    ${LLVM_INCLUDE_DIRS}
  )
  if(ARG_COMPILE_DEFINITIONS)
    target_compile_definitions(${name} PRIVATE ${ARG_COMPILE_DEFINITIONS})
  endif()
  eippf_apply_common_compile_options(${name})
  if(ARG_OUTPUT_NAME)
    set_target_properties(${name} PROPERTIES OUTPUT_NAME "${ARG_OUTPUT_NAME}")
  endif()
endfunction()

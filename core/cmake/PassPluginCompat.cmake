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
      string(TOLOWER "${eippf_link_item}" eippf_link_item_lower)
      if(eippf_link_item_lower MATCHES "diaguids\\.lib" OR
         eippf_link_item_lower MATCHES "dia sdk")
        message(FATAL_ERROR "Forbidden DIA SDK dependency detected for ${name}: ${eippf_link_item}")
      endif()
    endforeach()

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

set(EIPPF_SCRIPT_GUARD_COMMON_SOURCES
  src/bundle_format.cpp
  src/external_key_provider.cpp
  src/unsafe_shell_scan.cpp
)

add_library(eippf_script_guard_common OBJECT
  ${EIPPF_SCRIPT_GUARD_COMMON_SOURCES}
)
target_compile_features(eippf_script_guard_common PRIVATE cxx_std_20)
target_include_directories(eippf_script_guard_common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_script_guard_common)
endif()

add_executable(eippf_script_guard
  src/main.cpp
  $<TARGET_OBJECTS:eippf_script_guard_common>
)
target_compile_features(eippf_script_guard PRIVATE cxx_std_20)
target_include_directories(eippf_script_guard
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_script_guard)
endif()

set(EIPPF_SCRIPT_GUARD_LAUNCHER_SOURCES
  src/launcher_main.cpp
  src/launcher.cpp
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/launcher_main.cpp" AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/launcher.cpp")
  add_executable(eippf_script_launcher
    ${EIPPF_SCRIPT_GUARD_LAUNCHER_SOURCES}
    $<TARGET_OBJECTS:eippf_script_guard_common>
  )
  target_compile_features(eippf_script_launcher PRIVATE cxx_std_20)
  target_include_directories(eippf_script_launcher
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(eippf_script_launcher)
  endif()
else()
  add_custom_target(eippf_script_launcher
    COMMENT "Phase 5 launcher sources are not available yet."
  )
endif()

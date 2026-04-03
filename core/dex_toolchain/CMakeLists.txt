set(EIPPF_DEX_TOOLCHAIN_COMMON_SOURCES
  src/bundle_format.cpp
  src/external_key_provider.cpp
  src/manifest_contract.cpp
)

add_library(eippf_dex_toolchain_common OBJECT
  ${EIPPF_DEX_TOOLCHAIN_COMMON_SOURCES}
)
target_compile_features(eippf_dex_toolchain_common PRIVATE cxx_std_20)
target_include_directories(eippf_dex_toolchain_common
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_dex_toolchain_common)
endif()

add_executable(eippf_dex_toolchain
  src/main.cpp
)
target_compile_features(eippf_dex_toolchain PRIVATE cxx_std_20)
target_link_libraries(eippf_dex_toolchain
  PRIVATE
    eippf_dex_toolchain_common
)
target_include_directories(eippf_dex_toolchain
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_dex_toolchain)
endif()

set(EIPPF_DEX_LOADER_SOURCES
  src/loader_main.cpp
  src/loader.cpp
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/loader_main.cpp" AND
   EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/loader.cpp")
  add_executable(eippf_dex_loader
    ${EIPPF_DEX_LOADER_SOURCES}
  )
  target_compile_features(eippf_dex_loader PRIVATE cxx_std_20)
  target_link_libraries(eippf_dex_loader
    PRIVATE
      eippf_dex_toolchain_common
  )
  target_include_directories(eippf_dex_loader
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/include
  )
  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(eippf_dex_loader)
  endif()
else()
  add_custom_target(eippf_dex_loader
    COMMENT "Phase 6 loader sources are not available yet."
  )
endif()

add_library(eippf_runtime STATIC
  src/EippfRuntime.cpp
  src/string_token_runtime.cpp
  src/android_so_policy.cpp
  src/backends/backend_registry.cpp
  src/backends/desktop_user_mode_backend.cpp
  src/backends/kernel_safe_backend.cpp
  src/backends/ios_safe_backend.cpp
  src/backends/dex_loader_backend.cpp
  src/backends/shell_launcher_backend.cpp
  src/backend_policy.cpp
  src/policy_engine.cpp
  src/secure_ir_engine.cpp
)

target_include_directories(eippf_runtime
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

if(TARGET eippf_contracts)
  target_link_libraries(eippf_runtime PUBLIC eippf_contracts)
endif()

if(WIN32)
  target_include_directories(eippf_runtime PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../bootstrap/include"
  )
endif()

if(UNIX AND NOT APPLE)
  target_link_libraries(eippf_runtime PUBLIC dl)
endif()

if(UNIX AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(eippf_runtime PRIVATE
    -fno-builtin-memset
    -fno-builtin-memcpy
    -fno-builtin-memmove
  )
endif()

eippf_apply_common_compile_options(eippf_runtime)

add_library(eippf_vm_rt STATIC
  src/backend_policy.cpp
  src/secure_ir_engine.cpp
  src/vm_runtime_bridge.cpp
)

target_include_directories(eippf_vm_rt
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

if(TARGET eippf_contracts)
  target_link_libraries(eippf_vm_rt PUBLIC eippf_contracts)
endif()

if(WIN32)
  target_include_directories(eippf_vm_rt PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../bootstrap/include"
  )
endif()

if(UNIX AND NOT APPLE)
  target_link_libraries(eippf_vm_rt PUBLIC dl)
endif()

if(UNIX AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(eippf_vm_rt PRIVATE
    -fno-builtin-memset
    -fno-builtin-memcpy
    -fno-builtin-memmove
  )
endif()

eippf_apply_common_compile_options(eippf_vm_rt)

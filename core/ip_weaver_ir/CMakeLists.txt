if(NOT DEFINED LLVM_INCLUDE_DIRS)
  find_package(LLVM REQUIRED CONFIG)
endif()

if(NOT DEFINED LLVM_PACKAGE_VERSION)
  message(WARNING "ip_weaver_ir disabled: LLVM was not discovered in parent scope.")
  return()
endif()

if(LLVM_PACKAGE_VERSION VERSION_LESS 14)
  message(WARNING "ip_weaver_ir disabled: LLVM >= 14 required, found ${LLVM_PACKAGE_VERSION}.")
  return()
endif()

set(EIPPF_LLVM_INCLUDE_DIRS "${LLVM_INCLUDE_DIRS}" CACHE INTERNAL
  "LLVM include directories exported for EIPPF test targets.")

add_executable(ip_weaver_ir
  src/ip_weaver_ir.cpp
)

target_include_directories(ip_weaver_ir PRIVATE
  "${CMAKE_SOURCE_DIR}/runtime/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(ip_weaver_ir SYSTEM PRIVATE
  ${LLVM_INCLUDE_DIRS}
)

if(TARGET LLVM)
  target_link_libraries(ip_weaver_ir PRIVATE LLVM)
elseif(COMMAND llvm_map_components_to_libnames)
  llvm_map_components_to_libnames(EIPPF_IP_WEAVER_IR_LLVM_LIBS
    Core
    Support
    BitReader
    BitWriter
    IRReader
    Passes
    Analysis
    TransformUtils
  )
  target_link_libraries(ip_weaver_ir PRIVATE ${EIPPF_IP_WEAVER_IR_LLVM_LIBS})
else()
  message(WARNING "ip_weaver_ir disabled: no usable LLVM linking strategy available.")
  set_property(TARGET ip_weaver_ir PROPERTY EXCLUDE_FROM_ALL TRUE)
endif()

eippf_apply_common_compile_options(ip_weaver_ir)

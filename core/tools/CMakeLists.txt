add_custom_target(eippf_tools
  SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/artifact_audit.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/redteam_harness.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/redteam_perf_compare.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/redteam_perf_smoke_collect.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/redteam_runtime_probe.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/lexical_anchor_denylist.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/setup_build_env.sh"
)

add_executable(eippf_redteam_host_probe
  redteam_host_probe.cpp
)

if(COMMAND eippf_apply_common_compile_options)
  eippf_apply_common_compile_options(eippf_redteam_host_probe)
else()
  target_compile_features(eippf_redteam_host_probe PRIVATE cxx_std_20)
endif()

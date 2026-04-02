add_custom_target(eippf_tools
  SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/artifact_audit.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/lexical_anchor_denylist.txt"
    "${CMAKE_CURRENT_SOURCE_DIR}/setup_build_env.sh"
)

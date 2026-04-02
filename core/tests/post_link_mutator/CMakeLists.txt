if(TARGET eippf_post_link_mutator)
  add_executable(post_link_mutator_smoke_test
    post_link_mutator_smoke_test.cpp
  )

  target_compile_definitions(post_link_mutator_smoke_test PRIVATE
    EIPPF_POST_LINK_MUTATOR_BIN="$<TARGET_FILE:eippf_post_link_mutator>"
  )

  if(COMMAND eippf_apply_common_compile_options)
    eippf_apply_common_compile_options(post_link_mutator_smoke_test)
  else()
    target_compile_features(post_link_mutator_smoke_test PRIVATE cxx_std_20)
  endif()

  if(COMMAND add_test)
    add_test(NAME post_link_mutator_smoke_test COMMAND post_link_mutator_smoke_test)
  endif()
endif()

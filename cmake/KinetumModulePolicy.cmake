# Exact module-image compile and link policy shared by repository and installed
# Kinetum::SDK targets. Keeping these options here prevents the in-tree module
# contract from drifting from the customer-facing CMake package.

include_guard(GLOBAL)

function(_kinetum_apply_module_sdk_policy TARGET_NAME)
  if(NOT TARGET ${TARGET_NAME})
    message(FATAL_ERROR
      "_kinetum_apply_module_sdk_policy: unknown target ${TARGET_NAME}")
  endif()

  target_compile_options(${TARGET_NAME} INTERFACE
    "$<$<COMPILE_LANG_AND_ID:C,GNU,Clang>:-fvisibility=hidden>"
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-fvisibility=hidden>"
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-fvisibility-inlines-hidden>"
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fno-gnu-unique>"
  )
  target_link_options(${TARGET_NAME} INTERFACE
    "LINKER:-z,defs"
    "LINKER:--exclude-libs,ALL"
  )
endfunction()

function(_kinetum_apply_module_dependency_policy TARGET_NAME)
  if(NOT TARGET ${TARGET_NAME})
    message(FATAL_ERROR
      "_kinetum_apply_module_dependency_policy: unknown target ${TARGET_NAME}")
  endif()

  # Shared module dependencies deliberately export their declared API. They
  # retain dependency closure and unload-safe C++ ownership without inheriting
  # the module image's hidden-by-default visibility.
  target_compile_options(${TARGET_NAME} INTERFACE
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fno-gnu-unique>"
  )
  target_link_options(${TARGET_NAME} INTERFACE
    "LINKER:-z,defs"
  )
endfunction()

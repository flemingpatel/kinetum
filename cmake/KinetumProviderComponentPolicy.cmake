# Exact provider-component and private-artifact ELF policy.
#
# Components are release-owned loadable implementations, not ordinary platform
# libraries. They expose one unversioned C query symbol, carry no SONAME or
# loader search path, resolve every import at link time, bind immediately, and
# retain no GNU-unique C++ ownership or loader lifetime/scope escape. Private
# artifacts may expose their deliberate dependency API and therefore keep a
# SONAME, but inherit the same closure, hardening, and no-search-path rules.

include_guard(GLOBAL)

set(KINETUM_PROVIDER_COMPONENT_EXPORT_MAP
    "${CMAKE_CURRENT_LIST_DIR}/provider_component.exports")

function(_kinetum_require_shared_provider_target TARGET_NAME POLICY_NAME)
  if(NOT TARGET ${TARGET_NAME})
    message(FATAL_ERROR "${POLICY_NAME}: unknown target ${TARGET_NAME}")
  endif()
  get_target_property(_kinetum_provider_target_type ${TARGET_NAME} TYPE)
  if(NOT _kinetum_provider_target_type STREQUAL "SHARED_LIBRARY")
    message(FATAL_ERROR
      "${POLICY_NAME}: ${TARGET_NAME} must be a SHARED library")
  endif()
endfunction()

function(_kinetum_apply_provider_elf_closure TARGET_NAME)
  target_compile_options(${TARGET_NAME} PRIVATE
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fno-gnu-unique>"
  )
  target_link_options(${TARGET_NAME} PRIVATE
    "LINKER:-z,defs"
    "LINKER:-z,now"
    "LINKER:-z,relro"
    "LINKER:-z,noexecstack"
    "LINKER:--exclude-libs,ALL"
  )
  set_target_properties(${TARGET_NAME} PROPERTIES
    BUILD_RPATH ""
    BUILD_WITH_INSTALL_RPATH OFF
    INSTALL_RPATH ""
    INSTALL_RPATH_USE_LINK_PATH OFF
    SKIP_BUILD_RPATH ON
  )
endfunction()

# Apply the compile-time half of the exact component policy to an OBJECT or
# STATIC input before its object files enter the final hardened shared image.
# Final-target visibility and link options cannot retroactively change GNU-
# unique binding or default visibility in an already compiled input object.
function(kinetum_configure_provider_component_input_target TARGET_NAME)
  if(NOT TARGET ${TARGET_NAME})
    message(FATAL_ERROR
      "kinetum_configure_provider_component_input_target: unknown target ${TARGET_NAME}")
  endif()
  get_target_property(_kinetum_provider_input_type ${TARGET_NAME} TYPE)
  if(NOT _kinetum_provider_input_type STREQUAL "OBJECT_LIBRARY" AND
     NOT _kinetum_provider_input_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR
      "Provider component input ${TARGET_NAME} must be an OBJECT or STATIC library")
  endif()
  set_target_properties(${TARGET_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
  target_compile_options(${TARGET_NAME} PRIVATE
    "$<$<COMPILE_LANG_AND_ID:CXX,GNU>:-fno-gnu-unique>"
  )
endfunction()

function(_kinetum_configure_provider_component_target_with_export_map
    TARGET_NAME EXPORT_MAP)
  _kinetum_require_shared_provider_target(
    ${TARGET_NAME} "kinetum_configure_provider_component_target")
  if(NOT IS_ABSOLUTE "${EXPORT_MAP}" OR NOT EXISTS "${EXPORT_MAP}")
    message(FATAL_ERROR
      "Provider component export map must be one exact existing absolute path")
  endif()

  set_target_properties(${TARGET_NAME} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    NO_SONAME ON
  )
  _kinetum_apply_provider_elf_closure(${TARGET_NAME})
  target_link_options(${TARGET_NAME} PRIVATE
    "LINKER:--version-script=${EXPORT_MAP}"
  )
  set_property(TARGET ${TARGET_NAME} APPEND PROPERTY
    LINK_DEPENDS "${EXPORT_MAP}")
  target_link_libraries(${TARGET_NAME} PRIVATE kinetum_provider_component_abi)
endfunction()

function(kinetum_configure_provider_component_target TARGET_NAME)
  _kinetum_configure_provider_component_target_with_export_map(
    ${TARGET_NAME} "${KINETUM_PROVIDER_COMPONENT_EXPORT_MAP}")
endfunction()

function(kinetum_configure_provider_private_artifact_target TARGET_NAME)
  _kinetum_require_shared_provider_target(
    ${TARGET_NAME} "kinetum_configure_provider_private_artifact_target")
  _kinetum_apply_provider_elf_closure(${TARGET_NAME})
endfunction()

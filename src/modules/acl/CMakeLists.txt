# ACL Module (libkinetum_acl.so)
#
# SDK-based Access Control List module exercising the public module contract.
# Built-in modules use the same SDK as customer modules.
#
# Ownership model:
# - Module OWNS its strict JSON config contract
# - acl.proto remains a host/offline authoring and test schema
# - Platform routes opaque config_blob without interpretation
# - Module uses only the public SDK plus explicit image-local mechanisms
# - Module has no dependency on src/dp/ policy/runtime objects or a host SDK library
#
# Runtime admission resolves this artifact through an exact canonical image
# declaration passed to module_manager::admit_generation().

kinetum_generate_proto(kinetum_acl_proto
  PROTO_DIR "${CMAKE_SOURCE_DIR}"
  OUT_DIR "${CMAKE_BINARY_DIR}"
  PROTOS src/modules/acl/acl.proto
  NO_GRPC
)
kinetum_configure_generated_proto_target(kinetum_acl_proto)

# Hidden implementation core is linked into both the exact module image and
# component tests. Tests never require module-internal DSO exports.
add_library(kinetum_acl_impl STATIC
  acl_impl.cpp
)
kinetum_configure_owned_target(kinetum_acl_impl)
kinetum_configure_module_implementation_target(kinetum_acl_impl)
target_include_directories(kinetum_acl_impl PUBLIC
  ${CMAKE_SOURCE_DIR}
)
target_include_directories(kinetum_acl_impl SYSTEM PUBLIC
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(kinetum_acl_impl PUBLIC
  kinetum_module_config_json
)

# ACL module image (public SDK contract plus image-local mechanisms)
add_library(kinetum_acl_module SHARED
  acl_module.cpp
)
kinetum_configure_owned_target(kinetum_acl_module)
kinetum_configure_module_target(kinetum_acl_module)

# Link against dependencies
target_link_libraries(kinetum_acl_module PRIVATE
  kinetum_acl_impl
)

# Set the deterministic artifact name used by bundle image declarations.
set_target_properties(kinetum_acl_module PROPERTIES
  OUTPUT_NAME "kinetum_acl"
  PREFIX "lib"
  # Position independent code for shared library
  POSITION_INDEPENDENT_CODE ON
  BUILD_RPATH_USE_ORIGIN TRUE
  INSTALL_RPATH "$ORIGIN"
)

# Compiler flags for hot-path optimization
foreach(target_name kinetum_acl_impl kinetum_acl_module)
  target_compile_options(${target_name} PRIVATE
    -funroll-loops                   # Unroll loops for better pipelining
  )
endforeach()

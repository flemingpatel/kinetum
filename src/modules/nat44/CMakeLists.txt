# NAT44 Module (libkinetum_nat44.so)
#
# SDK-based NAT44 module exercising the public module contract.
# Built-in modules use the same SDK as customer modules.
#
# Ownership model:
# - Module OWNS its strict JSON config contract
# - nat44.proto remains a host/offline authoring and test schema
# - Platform routes opaque config_blob without interpretation
# - Module uses only the public SDK plus explicit image-local mechanisms
# - Module has no dependency on src/dp/ policy/runtime objects or a host SDK library

kinetum_generate_proto(kinetum_nat44_proto
  PROTO_DIR "${CMAKE_SOURCE_DIR}"
  OUT_DIR "${CMAKE_BINARY_DIR}"
  PROTOS src/modules/nat44/nat44.proto
  NO_GRPC
)
kinetum_configure_generated_proto_target(kinetum_nat44_proto)

# Hidden implementation core is linked into both the exact module image and
# component tests. Tests never require module-internal DSO exports.
add_library(kinetum_nat44_impl STATIC
  nat44_impl.cpp
)
kinetum_configure_owned_target(kinetum_nat44_impl)
kinetum_configure_module_implementation_target(kinetum_nat44_impl)
target_include_directories(kinetum_nat44_impl PUBLIC
  ${CMAKE_SOURCE_DIR}
)
target_include_directories(kinetum_nat44_impl SYSTEM PUBLIC
  ${CMAKE_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(kinetum_nat44_impl PUBLIC
  kinetum_module_config_json
)

# NAT44 module image (public SDK contract plus image-local mechanisms)
add_library(kinetum_nat44_module SHARED
  nat44_module.cpp
)
kinetum_configure_owned_target(kinetum_nat44_module)
kinetum_configure_module_target(kinetum_nat44_module)

# Link against dependencies
target_link_libraries(kinetum_nat44_module PRIVATE
  kinetum_nat44_impl
)

set_target_properties(kinetum_nat44_module PROPERTIES
  OUTPUT_NAME "kinetum_nat44"
  PREFIX "lib"
  POSITION_INDEPENDENT_CODE ON
  BUILD_RPATH_USE_ORIGIN TRUE
  INSTALL_RPATH "$ORIGIN"
)

foreach(target_name kinetum_nat44_impl kinetum_nat44_module)
  target_compile_options(${target_name} PRIVATE
    -funroll-loops
  )
endforeach()

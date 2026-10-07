# Kinetum SDK-Based Policy Modules
#
# These modules demonstrate that built-in platform policies use the same
# SDK as customer modules. Each module is:
# - Self-contained shared library (.so)
# - Admitted as an exact canonical image by module_manager
# - Uses the same kinetum_sdk.h/hpp as customer modules
#
# Module List:
# - kinetum_acl_module   - Access Control List (5-tuple filtering)
# - kinetum_nat44_module - NAT44 with port translation (NAPT)
# - kinetum_qos_module   - Token bucket rate limiting
#
# Runtime admission is generation-atomic: verified image/context declarations
# enter module_manager::admit_generation(), and configuration ownership moves
# through the lifecycle executor plus module_lifecycle_adapter.

message(STATUS "Building SDK-conformant policy modules")

# Runtime configuration parsing is an image-local mechanism. It deliberately
# has no generated-schema or process-global registry dependency; module-owned
# proto targets below remain host/offline authoring and test tools only.
add_library(kinetum_module_config_json STATIC
  module_config_json.cpp
)
kinetum_configure_owned_target(kinetum_module_config_json)
kinetum_configure_module_implementation_target(kinetum_module_config_json)
target_include_directories(kinetum_module_config_json PUBLIC
  ${CMAKE_SOURCE_DIR}
)

# ACL Module - 5-tuple filtering with hash cache and SIMD batch evaluation
add_subdirectory(acl)

# NAT44 Module - Stateful NAT with one context-local session table
add_subdirectory(nat44)

# QoS Module - Token bucket rate limiting with fixed-point arithmetic
add_subdirectory(qos)

# Print build summary
message(STATUS "  - kinetum_acl_module   (ACL filtering)")
message(STATUS "  - kinetum_nat44_module (NAT44 translation)")
message(STATUS "  - kinetum_qos_module   (QoS policing)")

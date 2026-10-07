cmake_minimum_required(VERSION 3.28)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/VERSION")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" KINETUM_VERSION_STR_FILE)
if(NOT KINETUM_VERSION_STR_FILE MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)([-+][A-Za-z0-9._-]+)?\n$")
    message(FATAL_ERROR
      "VERSION must be one newline-terminated MAJOR.MINOR.PATCH "
      "with an optional prerelease/build suffix")
endif()
set(KINETUM_PROJECT_VERSION "${CMAKE_MATCH_1}")
# file(READ) normalizes CRLF. Every source byte must belong to the matched line.
string(LENGTH "${CMAKE_MATCH_0}" KINETUM_VERSION_MATCHED_BYTES)
file(SIZE "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" KINETUM_VERSION_SOURCE_BYTES)
if(NOT KINETUM_VERSION_MATCHED_BYTES EQUAL KINETUM_VERSION_SOURCE_BYTES)
    message(FATAL_ERROR "VERSION must use one LF terminator without additional bytes")
endif()
string(REGEX REPLACE "\n$" "" KINETUM_VERSION_STR_FILE "${KINETUM_VERSION_STR_FILE}")

project(kinetum_stack VERSION "${KINETUM_PROJECT_VERSION}" LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR
        "Kinetum supports Linux only (detected CMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME})")
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
   OR NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR
        "Kinetum requires GNU or Clang C and C++ compilers "
        "(detected C=${CMAKE_C_COMPILER_ID}, CXX=${CMAKE_CXX_COMPILER_ID})")
endif()

include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)
set(KINETUM_TARGET_TUPLE_PROBE [=[
#if !defined(__x86_64__) && !defined(__aarch64__)
#error "unsupported Kinetum target architecture"
#endif
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "unsupported Kinetum target byte order"
#endif
int main(void) { return 0; }
]=])
check_c_source_compiles(
  "${KINETUM_TARGET_TUPLE_PROBE}"
  KINETUM_C_SUPPORTED_TARGET
)
check_cxx_source_compiles(
  "${KINETUM_TARGET_TUPLE_PROBE}"
  KINETUM_CXX_SUPPORTED_TARGET
)
unset(KINETUM_TARGET_TUPLE_PROBE)
if(NOT KINETUM_C_SUPPORTED_TARGET
   OR NOT KINETUM_CXX_SUPPORTED_TARGET)
    message(FATAL_ERROR
        "Kinetum supports only little-endian x86-64 and AArch64 compiler targets")
endif()

# Owned Kinetum targets declare their language level with
# target_compile_features(). Do not set CMAKE_CXX_STANDARD globally; it
# propagates into FetchContent dependencies.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# One canonical public include tree serves both in-tree targets and installed
# SDK consumers. Public headers therefore use the same <kinetum/...> spelling
# in every build context and are never rewritten during packaging.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/KinetumModulePolicy.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/KinetumProviderComponentPolicy.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/KinetumDPDKDependency.cmake")

set(KINETUM_PUBLIC_HEADER_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/include/kinetum")
add_library(kinetum_public_headers INTERFACE)
target_include_directories(kinetum_public_headers INTERFACE
  "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)

# Mirror the installed Kinetum::SDK contract in-tree so built-in and test
# modules compile and link through the exact customer-facing policy.
add_library(kinetum_module_sdk INTERFACE)
target_link_libraries(kinetum_module_sdk INTERFACE kinetum_public_headers)
_kinetum_apply_module_sdk_policy(kinetum_module_sdk)
add_library(Kinetum::SDK ALIAS kinetum_module_sdk)

# ---- Compiler Warnings ----
# The warning set intentionally excludes -Wpedantic because the platform uses
# compiler-supported extensions such as __int128 for high-precision arithmetic.
set(KINETUM_STRICT_COMPILE_OPTIONS
    -Wall
    -Wextra
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wformat=2
    -Wnull-dereference
)

# ---- Sanitizer Options ----
option(KINETUM_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(KINETUM_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(KINETUM_ENABLE_TSAN "Enable ThreadSanitizer" OFF)

set(KINETUM_SANITIZER_COMPILE_OPTIONS)
set(KINETUM_SANITIZER_LINK_OPTIONS)
set(KINETUM_CPU_COMPILE_OPTIONS)
set(KINETUM_IPO_ENABLED OFF)

if(KINETUM_ENABLE_ASAN)
    list(APPEND KINETUM_SANITIZER_COMPILE_OPTIONS -fsanitize=address -fno-omit-frame-pointer)
    list(APPEND KINETUM_SANITIZER_LINK_OPTIONS -fsanitize=address)
endif()

if(KINETUM_ENABLE_UBSAN)
    list(APPEND KINETUM_SANITIZER_COMPILE_OPTIONS -fsanitize=undefined)
    list(APPEND KINETUM_SANITIZER_LINK_OPTIONS -fsanitize=undefined)
endif()

if(KINETUM_ENABLE_TSAN)
    list(APPEND KINETUM_SANITIZER_COMPILE_OPTIONS -fsanitize=thread)
    list(APPEND KINETUM_SANITIZER_LINK_OPTIONS -fsanitize=thread)
endif()

function(kinetum_configure_owned_target_common target_name)
  if(NOT TARGET ${target_name})
    message(FATAL_ERROR "kinetum_configure_owned_target_common: unknown target ${target_name}")
  endif()
  target_compile_definitions(${target_name} PRIVATE KINETUM_VERSION_STR="${KINETUM_VERSION_STR_FILE}")
  target_compile_options(${target_name} PRIVATE ${KINETUM_STRICT_COMPILE_OPTIONS})
  if(KINETUM_CPU_COMPILE_OPTIONS)
    target_compile_options(${target_name} PRIVATE ${KINETUM_CPU_COMPILE_OPTIONS})
  endif()
  if(KINETUM_SANITIZER_COMPILE_OPTIONS)
    target_compile_options(${target_name} PRIVATE ${KINETUM_SANITIZER_COMPILE_OPTIONS})
  endif()
  if(KINETUM_SANITIZER_LINK_OPTIONS)
    target_link_options(${target_name} PRIVATE ${KINETUM_SANITIZER_LINK_OPTIONS})
  endif()
  if(KINETUM_IPO_ENABLED)
    set_property(TARGET ${target_name} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    # CMake owns compiler-specific IPO flags and plugin-aware archives.
    # LTO diagnostics at the final owned link remain fatal.
    target_link_options(${target_name} PRIVATE
      "$<$<CONFIG:Release>:-Werror>"
    )
  endif()
  target_link_libraries(${target_name} PRIVATE kinetum_public_headers)
endfunction()

function(kinetum_configure_owned_target target_name)
  kinetum_configure_owned_target_common(${target_name})
  target_compile_features(${target_name} PUBLIC cxx_std_20)
endfunction()

function(kinetum_configure_owned_c_target target_name)
  kinetum_configure_owned_target_common(${target_name})
  target_compile_features(${target_name} PUBLIC c_std_11)
endfunction()

function(kinetum_configure_module_implementation_target target_name)
  if(NOT TARGET ${target_name})
    message(FATAL_ERROR "kinetum_configure_module_implementation_target: unknown target ${target_name}")
  endif()

  set_target_properties(${target_name} PROPERTIES
    C_VISIBILITY_PRESET hidden
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
  )
  # GNU-unique C++ definitions can make dlclose retain an otherwise unowned
  # image. Exact module ownership requires ordinary image-local definitions.
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${target_name} PRIVATE
      "$<$<COMPILE_LANGUAGE:CXX>:-fno-gnu-unique>"
    )
  endif()
endfunction()

function(kinetum_configure_module_target target_name)
  if(NOT TARGET ${target_name})
    message(FATAL_ERROR "kinetum_configure_module_target: unknown target ${target_name}")
  endif()

  # Built-in and test images consume the exact same include, visibility, and
  # link-closure authority exported to out-of-tree module builds. RTLD_NOW
  # remains the runtime backstop, not the first dependency-completeness check.
  target_link_libraries(${target_name} PRIVATE Kinetum::SDK)
endfunction()

# ---- Platform-Specific Optimizations ----
# CPU requirements belong to the selected build. Both modes can be packaged;
# public release qualification uses the declared baseline. These flags remain
# private to owned Release targets; SDK consumers select their own CPU target.
option(KINETUM_ENABLE_NATIVE_ARCH "Enable -march=native for local CPU optimization" ON)
if(KINETUM_ENABLE_NATIVE_ARCH)
    set(KINETUM_CPU_TARGET native)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(KINETUM_CPU_TARGET corei7)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(KINETUM_CPU_TARGET armv8-a+crc)
else()
    message(FATAL_ERROR "No Kinetum CPU baseline for target ${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(KINETUM_CPU_COMPILE_OPTIONS "$<$<CONFIG:Release>:-march=${KINETUM_CPU_TARGET}>")
message(STATUS "Kinetum Release CPU target: ${KINETUM_CPU_TARGET}")

# ---- Link-Time Optimization (LTO) ----
# LTO can improve optimized builds at the cost of longer link times.
option(KINETUM_ENABLE_LTO "Enable Link-Time Optimization for Release builds" ON)
if(KINETUM_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
    if(ipo_supported)
        set(KINETUM_IPO_ENABLED ON)
        message(STATUS "Link-Time Optimization (LTO) enabled for Kinetum Release targets")
    else()
        message(FATAL_ERROR
            "KINETUM_ENABLE_LTO=ON requires compiler/linker IPO support:\n${ipo_error}")
    endif()
endif()

# One hidden object stamps every packaged ELF with the exact source VERSION.
# Package production verifies this marker before archive publication so a
# caller-controlled filename can never relabel stale build output.
add_library(kinetum_release_version_marker OBJECT
  tooling/release/packaging/release_version_marker.c
)
kinetum_configure_owned_c_target(kinetum_release_version_marker)
set_target_properties(kinetum_release_version_marker PROPERTIES
  C_VISIBILITY_PRESET hidden
  POSITION_INDEPENDENT_CODE ON
)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(KinetumOptions)
include(KinetumProto)

set(KINETUM_THIRD_PARTY_SYSTEM_INCLUDE_DIRS)

# ---- Dependencies ----
# Installed and fetched builds use the same Ubuntu 24.04 dependency baseline.
set(KINETUM_GRPC_VERSION 1.51.1)
set(KINETUM_PROTOBUF_VERSION 3.21.12)
set(KINETUM_GTEST_VERSION 1.14.0)

# Cryptographic SHA-256 is an identity primitive, not a TLS capability.
# OpenSSL::Crypto is therefore required for every build. The TLS option controls
# only TLS helper/SSL linkage below. Resolve OpenSSL before fetched gRPC so both
# consume the same imported targets.
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(ZLIB REQUIRED)

if(KINETUM_FETCH_DEPS)
  message(STATUS
    "KINETUM_FETCH_DEPS=ON (requires internet). Fetching declared "
    "gRPC ${KINETUM_GRPC_VERSION}, Protobuf ${KINETUM_PROTOBUF_VERSION}, "
    "and GoogleTest ${KINETUM_GTEST_VERSION} for enabled tests.")
  include(FetchContent)
  set(FETCHCONTENT_QUIET OFF)

  # Keep gRPC's supporting libraries on the same system packages in both routes.
  # Protobuf is fetched independently because gRPC's submodule has a different pin.
  set(gRPC_INSTALL OFF CACHE BOOL "" FORCE)
  set(gRPC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(gRPC_BUILD_CODEGEN ON CACHE BOOL "" FORCE)
  set(gRPC_BUILD_GRPC_CPP_PLUGIN ON CACHE BOOL "" FORCE)
  set(gRPC_ABSL_PROVIDER "package" CACHE STRING "" FORCE)
  set(gRPC_CARES_PROVIDER "package" CACHE STRING "" FORCE)
  set(gRPC_PROTOBUF_PROVIDER "package" CACHE STRING "" FORCE)
  set(gRPC_PROTOBUF_PACKAGE_TYPE "CONFIG" CACHE STRING "" FORCE)
  set(gRPC_RE2_PROVIDER "package" CACHE STRING "" FORCE)
  set(gRPC_SSL_PROVIDER "package" CACHE STRING "" FORCE)
  set(gRPC_ZLIB_PROVIDER "package" CACHE STRING "" FORCE)
  set(protobuf_INSTALL OFF CACHE BOOL "" FORCE)
  set(protobuf_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(protobuf_BUILD_PROTOC_BINARIES ON CACHE BOOL "" FORCE)
  set(protobuf_WITH_ZLIB ON CACHE BOOL "" FORCE)

  FetchContent_Declare(
    protobuf
    GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
    GIT_TAG        v${KINETUM_PROTOBUF_VERSION}
    GIT_SHALLOW    TRUE
    GIT_SUBMODULES ""
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(protobuf)
  # gRPC reads this target's include interface to locate the well-known schemas.
  target_include_directories(libprotoc SYSTEM INTERFACE "${protobuf_SOURCE_DIR}/src")

  FetchContent_Declare(
    grpc
    GIT_REPOSITORY https://github.com/grpc/grpc.git
    GIT_TAG        v${KINETUM_GRPC_VERSION}
    GIT_SHALLOW    TRUE
    GIT_SUBMODULES
      third_party/envoy-api
      third_party/googleapis
      third_party/opencensus-proto
      third_party/xds
    GIT_SUBMODULES_RECURSE TRUE
  )
  FetchContent_MakeAvailable(grpc)
  set(KINETUM_PROTOBUF_IMPORT_DIRS "${protobuf_SOURCE_DIR}/src")
  list(APPEND KINETUM_THIRD_PARTY_SYSTEM_INCLUDE_DIRS
    "${grpc_SOURCE_DIR}/include"
    ${KINETUM_PROTOBUF_IMPORT_DIRS}
  )

  # When gRPC is built from source via FetchContent, targets are named without
  # the gRPC:: namespace prefix. Create aliases to match the installed package
  # target names that our code expects.
  add_library(gRPC::grpc++ ALIAS grpc++)
  add_executable(gRPC::grpc_cpp_plugin ALIAS grpc_cpp_plugin)

  if(KINETUM_ENABLE_TESTS)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG        v${KINETUM_GTEST_VERSION}
      GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(googletest)
  endif()
else()
  find_package(Protobuf ${KINETUM_PROTOBUF_VERSION} EXACT MODULE REQUIRED)
  set(KINETUM_PROTOBUF_IMPORT_DIRS ${Protobuf_INCLUDE_DIRS})
  list(APPEND KINETUM_THIRD_PARTY_SYSTEM_INCLUDE_DIRS ${KINETUM_PROTOBUF_IMPORT_DIRS})
  find_package(gRPC ${KINETUM_GRPC_VERSION} EXACT CONFIG REQUIRED)
endif()

list(REMOVE_DUPLICATES KINETUM_THIRD_PARTY_SYSTEM_INCLUDE_DIRS)

foreach(dependency_target IN ITEMS
    protobuf::libprotobuf protobuf::protoc gRPC::grpc++ gRPC::grpc_cpp_plugin)
  if(NOT TARGET ${dependency_target})
    message(FATAL_ERROR "Required dependency target is missing: ${dependency_target}")
  endif()
endforeach()

if(NOT KINETUM_FETCH_DEPS)
  # FindProtobuf only warns when its compiler and library versions differ.
  get_target_property(KINETUM_PROTOC_EXECUTABLE protobuf::protoc IMPORTED_LOCATION)
  execute_process(
    COMMAND "${KINETUM_PROTOC_EXECUTABLE}" --version
    RESULT_VARIABLE KINETUM_PROTOC_RESULT
    OUTPUT_VARIABLE KINETUM_PROTOC_VERSION
    ERROR_VARIABLE KINETUM_PROTOC_ERROR
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_STRIP_TRAILING_WHITESPACE
    TIMEOUT 5
  )
  if(NOT KINETUM_PROTOC_RESULT STREQUAL "0" OR
     NOT KINETUM_PROTOC_VERSION STREQUAL "libprotoc ${KINETUM_PROTOBUF_VERSION}")
    message(FATAL_ERROR
      "Protobuf ${KINETUM_PROTOBUF_VERSION} requires matching protoc. "
      "${KINETUM_PROTOC_EXECUTABLE} returned '${KINETUM_PROTOC_VERSION}' "
      "(status: ${KINETUM_PROTOC_RESULT}). ${KINETUM_PROTOC_ERROR}")
  endif()
endif()

function(kinetum_configure_generated_proto_target target_name)
  if(NOT TARGET ${target_name})
    message(FATAL_ERROR "kinetum_configure_generated_proto_target: unknown target ${target_name}")
  endif()
  target_compile_features(${target_name} PUBLIC cxx_std_20)
  target_link_libraries(${target_name} PUBLIC protobuf::libprotobuf)
  if(KINETUM_THIRD_PARTY_SYSTEM_INCLUDE_DIRS)
    target_include_directories(${target_name} SYSTEM BEFORE PUBLIC ${KINETUM_THIRD_PARTY_SYSTEM_INCLUDE_DIRS})
  endif()
  target_compile_options(${target_name} PRIVATE -Wno-conversion -Wno-sign-conversion -Wno-error)
endfunction()

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED IMPORTED_TARGET libelf)

if(KINETUM_ENABLE_MLIR)
  find_package(LLVM REQUIRED CONFIG)
  find_package(MLIR REQUIRED CONFIG)
  message(STATUS "LLVM_DIR=${LLVM_DIR}")
  message(STATUS "MLIR_DIR=${MLIR_DIR}")
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}" "${MLIR_CMAKE_DIR}")
  include(AddLLVM)
  include(AddMLIR)
  include(TableGen)
  include(HandleLLVMOptions)
  # Store LLVM/MLIR settings for target-specific application.
  set(KINETUM_LLVM_DEFINITIONS ${LLVM_DEFINITIONS})
  set(KINETUM_LLVM_INCLUDE_DIRS ${LLVM_INCLUDE_DIRS})
  set(KINETUM_MLIR_INCLUDE_DIRS ${MLIR_INCLUDE_DIRS})
endif()

# The complete source configuration requires one verified, tuple-exact DPDK
# package. Its owning module verifies the package before its executable CMake
# config is evaluated and imports one closure target; no native link policy is
# reconstructed here.
kinetum_require_dpdk_dependency("${CMAKE_CURRENT_SOURCE_DIR}")
# ---- Protos ----
set(KINETUM_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(KINETUM_GEN_DIR   "${CMAKE_CURRENT_BINARY_DIR}/gen")

set(KINETUM_PROTOS
  kinetum/common/v1/common.proto
  kinetum/axiom/v1/axiom.proto
  kinetum/hw/v1/hardware.proto
  kinetum/gluon/v1/plan.proto
  kinetum/gluon/v1/bindings.proto
  kinetum/telemetry/v1/telemetry.proto
  kinetum/control/v1/control.proto
  kinetum/dataplane/v1/dataplane.proto
  kinetum/control/internal/v1/transition_authority.proto
)

kinetum_generate_proto(kinetum_proto
  PROTO_DIR "${KINETUM_PROTO_DIR}"
  OUT_DIR "${KINETUM_GEN_DIR}"
  PROTOS ${KINETUM_PROTOS}
)
kinetum_configure_generated_proto_target(kinetum_proto)
target_link_libraries(kinetum_proto PUBLIC gRPC::grpc++)

set(KINETUM_PROVIDER_CONTRACT_PROTOS
  kinetum/facility/dpdk/v1/dpdk_facility.proto
  kinetum/io/dpdk/v1/dpdk_driver.proto
  kinetum/storage/dpdk/v1/dpdk_storage.proto
  kinetum/io/udp/v1/udp_driver.proto
  kinetum/storage/host/v1/host_storage.proto
  kinetum/execution/cpu/v1/cpu_execution.proto
  kinetum/transition/core/v1/core_transition.proto
  kinetum/transition/cpu/v1/cpu_transition.proto
)

# The provider ABI identity is generated from its complete physical authority:
# the one C11 ABI header plus every pure provider contract schema. A changed
# byte forces reconfiguration and a new exact identity; no hand-maintained
# version or compatibility table can drift from the declarations.
set(KINETUM_PROVIDER_ABI_INPUTS
  src/provider/provider_component_abi.h
  ${KINETUM_PROVIDER_CONTRACT_PROTOS}
)
set(KINETUM_PROVIDER_ABI_IDENTITY_MATERIAL "")
foreach(provider_abi_input IN LISTS KINETUM_PROVIDER_ABI_INPUTS)
  if(provider_abi_input STREQUAL "src/provider/provider_component_abi.h")
    set(provider_abi_path "${CMAKE_CURRENT_SOURCE_DIR}/${provider_abi_input}")
  else()
    set(provider_abi_path "${KINETUM_PROTO_DIR}/${provider_abi_input}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${provider_abi_path}")
  file(SHA256 "${provider_abi_path}" provider_abi_input_sha256)
  string(APPEND KINETUM_PROVIDER_ABI_IDENTITY_MATERIAL
    "${provider_abi_input}:${provider_abi_input_sha256}\n"
  )
endforeach()
string(SHA256 KINETUM_PROVIDER_ABI_IDENTITY_HEX "${KINETUM_PROVIDER_ABI_IDENTITY_MATERIAL}")
string(REGEX MATCHALL ".." KINETUM_PROVIDER_ABI_IDENTITY_BYTE_HEX
  "${KINETUM_PROVIDER_ABI_IDENTITY_HEX}"
)
set(KINETUM_PROVIDER_ABI_IDENTITY_BYTE_VALUES)
foreach(provider_abi_byte IN LISTS KINETUM_PROVIDER_ABI_IDENTITY_BYTE_HEX)
  list(APPEND KINETUM_PROVIDER_ABI_IDENTITY_BYTE_VALUES "0x${provider_abi_byte}")
endforeach()
string(JOIN ", " KINETUM_PROVIDER_ABI_IDENTITY_INITIALIZER
  ${KINETUM_PROVIDER_ABI_IDENTITY_BYTE_VALUES}
)
list(GET KINETUM_PROVIDER_ABI_IDENTITY_BYTE_HEX 0
  KINETUM_PROVIDER_ABI_IDENTITY_FIRST_BYTE_HEX
)
set(KINETUM_PROVIDER_ABI_IDENTITY_TAIL_BYTE_VALUES
  ${KINETUM_PROVIDER_ABI_IDENTITY_BYTE_VALUES}
)
list(REMOVE_AT KINETUM_PROVIDER_ABI_IDENTITY_TAIL_BYTE_VALUES 0)
string(JOIN ", " KINETUM_PROVIDER_ABI_IDENTITY_TAIL_INITIALIZER
  ${KINETUM_PROVIDER_ABI_IDENTITY_TAIL_BYTE_VALUES}
)
file(MAKE_DIRECTORY "${KINETUM_GEN_DIR}/kinetum/provider")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/src/provider/provider_build_identity.h.in"
  "${KINETUM_GEN_DIR}/kinetum/provider/provider_build_identity.h"
  @ONLY
)

kinetum_generate_proto(kinetum_provider_contract_proto
  NO_GRPC
  PROTO_DIR "${KINETUM_PROTO_DIR}"
  OUT_DIR "${KINETUM_GEN_DIR}"
  PROTOS ${KINETUM_PROVIDER_CONTRACT_PROTOS}
)
kinetum_configure_generated_proto_target(kinetum_provider_contract_proto)

kinetum_generate_proto(kinetum_provider_inventory_proto
  NO_GRPC
  PROTO_DIR "${KINETUM_PROTO_DIR}"
  OUT_DIR "${KINETUM_GEN_DIR}"
  PROTOS kinetum/provider/v1/installed_provider_inventory.proto
)
kinetum_configure_generated_proto_target(kinetum_provider_inventory_proto)

kinetum_generate_proto(kinetum_provider_release_proto
  NO_GRPC
  PROTO_DIR "${KINETUM_PROTO_DIR}"
  OUT_DIR "${KINETUM_GEN_DIR}"
  PROTOS kinetum/release/v1/provider_release.proto
)
kinetum_configure_generated_proto_target(kinetum_provider_release_proto)
target_link_libraries(kinetum_provider_release_proto PUBLIC kinetum_provider_inventory_proto)
add_dependencies(kinetum_provider_release_proto kinetum_provider_inventory_proto)

# ---- Common ----
# Host-owned packet-thread exclusion is also used by the isolated native tests.
# Keep its implementation independent of RPC, file logging, and provider code.
find_package(Threads REQUIRED)
add_library(kinetum_packet_thread_log_guard STATIC
  src/common/packet_thread_log_guard.cpp
)
kinetum_configure_owned_target(kinetum_packet_thread_log_guard)
target_include_directories(kinetum_packet_thread_log_guard PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_packet_thread_log_guard PRIVATE Threads::Threads)

add_library(kinetum_common STATIC
  src/common/bootstrap_config_snapshot.cpp
  src/common/control_response_contract.cpp
  src/common/dataplane_health_contract.cpp
  src/common/linux_cpu_set.cpp
  src/common/pbtxt.cpp
  src/common/file_io.cpp
  src/common/path_admission.cpp
  src/common/process_image.cpp
  src/common/sha256.cpp
  src/common/ed25519.cpp
  src/common/held_file.cpp
  src/common/durable_directory.cpp
  src/common/epoch_transition_contract.cpp
  src/common/generated_snapshot_identity.cpp
  src/common/transition_idempotency_key.cpp
  src/common/protobuf_contract.cpp
  src/common/runtime_telemetry_contract.cpp
  src/common/canonical_content_identity.cpp
  src/common/packet_route_condition.cpp
  src/common/plan_buffer_budget.cpp
  src/common/transition_topology.cpp
  src/common/tls.cpp
  src/common/time.cpp
  src/common/log.cpp
  src/common/log_record.cpp
  src/common/log_options.cpp
  src/common/log_file.cpp
  src/common/grpc_logging.cpp
  src/common/grpc_logging_gpr.cpp
  src/common/logging_status.cpp
)
kinetum_configure_owned_target(kinetum_common)
target_include_directories(kinetum_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_common
  PUBLIC kinetum_proto OpenSSL::Crypto
  PRIVATE kinetum_packet_thread_log_guard
)

# Exact shared-object mechanics are separate from generic common utilities so
# only loaders inherit libdl. Policy remains with module/provider admission.
add_library(kinetum_shared_object STATIC
  src/common/shared_object.cpp
)
kinetum_configure_owned_target(kinetum_shared_object)
target_include_directories(kinetum_shared_object PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_shared_object PUBLIC kinetum_common dl)

if(KINETUM_ENABLE_TLS)
  target_link_libraries(kinetum_common PUBLIC OpenSSL::SSL)
  target_compile_definitions(kinetum_common PRIVATE KINETUM_TLS_HELPERS_ENABLED=1)
else()
  target_compile_definitions(kinetum_common PRIVATE KINETUM_TLS_HELPERS_ENABLED=0)
endif()

# Axiom's protobuf semantic contract is independent from file parsing and the
# optional MLIR frontend. Cold consumers such as the provider-topology compiler
# compose this exact validator without acquiring an MLIR build dependency.
add_library(kinetum_axiom_contract STATIC
  src/axiom/axiom_contract.cpp
)
kinetum_configure_owned_target(kinetum_axiom_contract)
target_include_directories(kinetum_axiom_contract PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_axiom_contract PUBLIC kinetum_common)

# ---- Pure Provider Contracts ----
add_library(kinetum_provider_contracts STATIC
  src/provider/provider_contract_catalog.cpp
)
kinetum_configure_owned_target(kinetum_provider_contracts)
target_include_directories(kinetum_provider_contracts PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_provider_contracts
  PUBLIC
  kinetum_provider_contract_proto
  PRIVATE
  kinetum_common
)

# ---- Shared Compiled Provider Topology ----
# This cold semantic authority composes the canonical plan with the pure
# provider-contract catalog. It owns no provider-native dependency and is the
# sole structural artifact consumed by Gluon, Quark, bundle validation, and DP.
add_library(kinetum_provider_topology_compiler STATIC
  src/provider/compiled_provider_topology.cpp
)
kinetum_configure_owned_target(kinetum_provider_topology_compiler)
target_include_directories(kinetum_provider_topology_compiler PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_provider_topology_compiler
  PUBLIC
  kinetum_common
  kinetum_provider_contracts
  PRIVATE
  kinetum_axiom_contract
)

# ---- Provider-aware Deployment Plan Identity ----
# Generic snapshot identity remains in common. DeploymentPlan identity composes
# that cryptographic mechanism with the pure provider-contract catalog so no
# generic target needs to understand provider Any payloads.
add_library(kinetum_deployment_plan_identity STATIC
  src/provider/deployment_plan_identity.cpp
)
kinetum_configure_owned_target(kinetum_deployment_plan_identity)
target_include_directories(kinetum_deployment_plan_identity PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_deployment_plan_identity
  PUBLIC
  kinetum_provider_contracts
  PRIVATE
  kinetum_common
)

# ---- Exact Provider Component ABI and Provenance ----
add_library(kinetum_provider_component_abi INTERFACE)
target_include_directories(kinetum_provider_component_abi INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_include_directories(kinetum_provider_component_abi SYSTEM INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}"
)

add_library(kinetum_provider_inventory STATIC
  src/provider/provider_inventory.cpp
  src/provider/provider_inventory_signing.cpp
)
kinetum_configure_owned_target(kinetum_provider_inventory)
target_include_directories(kinetum_provider_inventory PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kinetum_provider_inventory SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kinetum_provider_inventory
  PUBLIC
  kinetum_provider_inventory_proto
  PRIVATE
  kinetum_provider_contracts
  kinetum_common
)

add_library(kinetum_provider_release_trust STATIC
  src/provider/provider_release_trust.cpp
)
kinetum_configure_owned_target(kinetum_provider_release_trust)
target_include_directories(kinetum_provider_release_trust PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_provider_release_trust PUBLIC kinetum_common)

add_library(kinetum_provider_installation STATIC
  src/provider/provider_installation.cpp
)
kinetum_configure_owned_target(kinetum_provider_installation)
target_include_directories(kinetum_provider_installation PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_provider_installation PUBLIC kinetum_common)

# Static artifact preflight is deliberately independent from dlopen. Release
# finalization can inspect either supported target tuple without acquiring a
# dynamic-loader edge or executing foreign code.
add_library(kinetum_provider_component_preflight STATIC
  src/provider/provider_target_tuple.cpp
  src/provider/provider_elf.cpp
  src/provider/provider_component_preflight.cpp
)
kinetum_configure_owned_target(kinetum_provider_component_preflight)
target_include_directories(kinetum_provider_component_preflight PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kinetum_provider_component_preflight SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kinetum_provider_component_preflight
  PUBLIC
  kinetum_provider_component_abi
  kinetum_provider_inventory
  PRIVATE
  PkgConfig::LIBELF
)

# Static release reconstruction owns exact target-tuple artifact facts and has
# no dynamic-loader edge. This is the architecture-neutral signer boundary.
add_library(kinetum_provider_inventory_reconstruction STATIC
  src/provider/provider_inventory_reconstruction.cpp
)
kinetum_configure_owned_target(kinetum_provider_inventory_reconstruction)
target_include_directories(kinetum_provider_inventory_reconstruction PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kinetum_provider_inventory_reconstruction SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kinetum_provider_inventory_reconstruction
  PUBLIC
  kinetum_provider_component_preflight
  kinetum_provider_inventory
)

add_library(kinetum_provider_release STATIC
  src/provider/provider_release.cpp
)
kinetum_configure_owned_target(kinetum_provider_release)
target_include_directories(kinetum_provider_release PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kinetum_provider_release SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kinetum_provider_release
  PUBLIC
  kinetum_provider_installation
  kinetum_provider_inventory_reconstruction
  kinetum_provider_release_proto
  PRIVATE
  kinetum_common
)

add_library(kinetum_provider_component_admission STATIC
  src/provider/provider_component_admission.cpp
)
kinetum_configure_owned_target(kinetum_provider_component_admission)
target_include_directories(kinetum_provider_component_admission PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kinetum_provider_component_admission SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kinetum_provider_component_admission
  PUBLIC
  kinetum_provider_component_abi
  kinetum_provider_component_preflight
  kinetum_shared_object
  PRIVATE
  kinetum_provider_contracts
)

add_library(kinetum_provider_loader STATIC
  src/provider/provider_component_loader.cpp
)
kinetum_configure_owned_target(kinetum_provider_loader)
target_include_directories(kinetum_provider_loader PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(kinetum_provider_loader SYSTEM PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(kinetum_provider_loader
  PUBLIC
  kinetum_provider_component_admission
  kinetum_provider_installation
  kinetum_provider_inventory
)

# One provider-neutral startup authority owns the compiled C-ABI fact
# projection, exact required-set loading, and COMPONENT-phase host proofs. It
# performs no provider factory call or materialization.
add_library(kinetum_provider_runtime_admission STATIC
  src/provider/provider_runtime_admission.cpp
)
kinetum_configure_owned_target(kinetum_provider_runtime_admission)
target_include_directories(kinetum_provider_runtime_admission PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_provider_runtime_admission
  PUBLIC
  kinetum_provider_loader
  kinetum_provider_topology_compiler
)

# The native prepare worker and static signing operation share reconstruction
# machinery. Only preparation calls the component-admission owner.
add_library(kinetum_provider_release_signing_key STATIC
  tooling/release/packaging/provider_release_signing_key.cpp
)
kinetum_configure_owned_target(kinetum_provider_release_signing_key)
target_include_directories(kinetum_provider_release_signing_key PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_provider_release_signing_key PUBLIC kinetum_common)

add_library(kinetum_package_release STATIC
  tooling/release/packaging/package_release.cpp
)
kinetum_configure_owned_target(kinetum_package_release)
target_include_directories(kinetum_package_release PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_package_release
  PUBLIC
  kinetum_provider_release_signing_key
  kinetum_provider_component_admission
  kinetum_provider_release
)

# ---- Axiom ----
# ---- Axiom MLIR dialect ----
if(KINETUM_ENABLE_MLIR AND KINETUM_ENABLE_MLIR_DIALECT)
  set(LLVM_TARGET_DEFINITIONS "${CMAKE_CURRENT_SOURCE_DIR}/mlir/axiom/AxiomOps.td")
  mlir_tablegen(AxiomOps.h.inc -gen-op-decls)
  mlir_tablegen(AxiomOps.cpp.inc -gen-op-defs)
  mlir_tablegen(AxiomDialect.h.inc -gen-dialect-decls)
  mlir_tablegen(AxiomDialect.cpp.inc -gen-dialect-defs)
  add_public_tablegen_target(KinetumAxiomMLIRIncGen)

  add_library(kinetum_axiom_mlir_dialect STATIC
    src/axiom/mlir/axiom_dialect.cpp
    src/axiom/mlir/axiom_ops.cpp
    src/axiom/mlir/axiom_passes.cpp
  )
  kinetum_configure_owned_target(kinetum_axiom_mlir_dialect)
  add_dependencies(kinetum_axiom_mlir_dialect KinetumAxiomMLIRIncGen)
  target_include_directories(kinetum_axiom_mlir_dialect PUBLIC src)
  target_include_directories(kinetum_axiom_mlir_dialect SYSTEM PUBLIC
    "${CMAKE_CURRENT_BINARY_DIR}"
    ${KINETUM_LLVM_INCLUDE_DIRS} ${KINETUM_MLIR_INCLUDE_DIRS})
  target_compile_definitions(kinetum_axiom_mlir_dialect PUBLIC ${KINETUM_LLVM_DEFINITIONS})
  target_link_libraries(kinetum_axiom_mlir_dialect PUBLIC MLIRIR MLIRParser MLIRPass MLIRSupport LLVMCore)
  target_compile_definitions(kinetum_axiom_mlir_dialect PUBLIC KINETUM_ENABLE_MLIR_DIALECT=1)
endif()

add_library(kinetum_axiom_lib STATIC
  src/axiom/axiom_pbtxt_io.cpp
  src/axiom/axiom_mlir_frontend.cpp
)
kinetum_configure_owned_target(kinetum_axiom_lib)
target_include_directories(kinetum_axiom_lib PUBLIC src)
target_link_libraries(kinetum_axiom_lib PUBLIC kinetum_axiom_contract kinetum_common)

if(KINETUM_ENABLE_MLIR)
  target_compile_definitions(kinetum_axiom_lib PUBLIC KINETUM_ENABLE_MLIR=1)
  target_include_directories(kinetum_axiom_lib SYSTEM PUBLIC
    ${KINETUM_LLVM_INCLUDE_DIRS} ${KINETUM_MLIR_INCLUDE_DIRS})
  target_compile_definitions(kinetum_axiom_lib PUBLIC ${KINETUM_LLVM_DEFINITIONS})
  target_link_libraries(kinetum_axiom_lib PUBLIC MLIRParser MLIRIR MLIRPass MLIRSupport LLVMCore)
  if(KINETUM_ENABLE_MLIR_DIALECT)
    target_compile_definitions(kinetum_axiom_lib PUBLIC KINETUM_ENABLE_MLIR_DIALECT=1)
    target_link_libraries(kinetum_axiom_lib PUBLIC kinetum_axiom_mlir_dialect)
  else()
    target_compile_definitions(kinetum_axiom_lib PUBLIC KINETUM_ENABLE_MLIR_DIALECT=0)
  endif()
else()
  target_compile_definitions(kinetum_axiom_lib PUBLIC KINETUM_ENABLE_MLIR=0)
  target_compile_definitions(kinetum_axiom_lib PUBLIC KINETUM_ENABLE_MLIR_DIALECT=0)
endif()

add_executable(kinetum_axiom src/axiom/axiom_main.cpp)
kinetum_configure_owned_target(kinetum_axiom)
target_link_libraries(kinetum_axiom PRIVATE kinetum_axiom_lib)

# ---- Quark runtime host proof ----
find_path(NUMA_INCLUDE_DIR numa.h)
find_library(NUMA_LIBRARY numa)
if(NOT NUMA_INCLUDE_DIR OR NOT NUMA_LIBRARY)
  message(FATAL_ERROR
    "The complete Kinetum build requires libnuma headers and library for exact process-local host proof")
endif()
add_library(NUMA::NUMA UNKNOWN IMPORTED)
set_target_properties(NUMA::NUMA PROPERTIES
  IMPORTED_LOCATION "${NUMA_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${NUMA_INCLUDE_DIR}"
)

add_library(kinetum_quark STATIC
  src/quark/host_probe.cpp
  src/quark/runtime_compat.cpp
)
kinetum_configure_owned_target(kinetum_quark)
target_include_directories(kinetum_quark PUBLIC src)
target_link_libraries(kinetum_quark
  PUBLIC
  kinetum_common
  kinetum_provider_topology_compiler
  PRIVATE
  NUMA::NUMA
)

# ---- Gluon ----
add_library(kinetum_gluon_lib STATIC
  src/gluon/boundary_topology_lowering.cpp
  src/gluon/deployment_bindings_lowering.cpp
  src/gluon/gluon_planner.cpp
  src/gluon/runtime_core_placement.cpp
  src/gluon/topology_lowering.cpp
  src/gluon/transition_plan_lowering.cpp
)
kinetum_configure_owned_target(kinetum_gluon_lib)
target_include_directories(kinetum_gluon_lib PUBLIC src)
target_link_libraries(kinetum_gluon_lib
  PUBLIC
  kinetum_axiom_lib
  kinetum_deployment_plan_identity
  PRIVATE
  kinetum_provider_topology_compiler
)

add_executable(kinetum_gluon src/gluon/gluon_main.cpp)
kinetum_configure_owned_target(kinetum_gluon)
target_link_libraries(kinetum_gluon PRIVATE kinetum_gluon_lib)

# ---- Dataplane core and exact provider components ----
# The runtime core owns no provider-native source, include path, compile flag,
# or link dependency. Provider implementation objects belong only to their
# final component and native-test compile domains; the runtime reaches them
# only through authenticated component admission.

# One provider-neutral memory owner supplies exact aligned anonymous mappings,
# optional strict NUMA placement, prefault, and resident-page proof. Packet
# pools and runtime boundary storage compose this target rather than duplicating
# mmap/mempolicy arithmetic.
add_library(kinetum_numa_memory STATIC
  src/dp/numa_memory.cpp
)
kinetum_configure_owned_target(kinetum_numa_memory)
set_target_properties(kinetum_numa_memory PROPERTIES POSITION_INDEPENDENT_CODE ON)
kinetum_configure_provider_component_input_target(kinetum_numa_memory)
target_include_directories(kinetum_numa_memory PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Provider-neutral fixed packet storage is a reusable mechanism rather than a
# core-runtime implementation detail. The host-storage component and mechanism
# tests consume this one source identity directly; neither acquires a
# provider-native dependency or a second packet representation.
add_library(kinetum_fixed_packet_pool STATIC
  src/dp/fixed_packet_pool.cpp
)
kinetum_configure_owned_target(kinetum_fixed_packet_pool)
set_target_properties(kinetum_fixed_packet_pool PROPERTIES POSITION_INDEPENDENT_CODE ON)
kinetum_configure_provider_component_input_target(kinetum_fixed_packet_pool)
target_include_directories(kinetum_fixed_packet_pool PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(kinetum_fixed_packet_pool PUBLIC kinetum_numa_memory)

# One exact host component supplies current host storage, CPU execution, and
# core transition contracts without collapsing those role-specific factories.
add_library(kinetum_provider_host_component SHARED
  src/provider/components/host/host_component.cpp
)
kinetum_configure_owned_target(kinetum_provider_host_component)
kinetum_configure_provider_component_target(kinetum_provider_host_component)
target_link_libraries(kinetum_provider_host_component PRIVATE
  kinetum_fixed_packet_pool
)

add_library(kinetum_dp_core STATIC
  src/dp/config_snapshot_epoch_store.cpp
  src/dp/dp_engine.cpp
  src/dp/packet_mechanism.cpp
  src/dp/net/ipv4.cpp
  src/dp/module/module_manager.cpp
  src/dp/module/module_epoch_store.cpp
  src/dp/module/module_lifecycle_adapter.cpp
  src/dp/lifecycle/lifecycle_context.cpp
  src/dp/lifecycle/prepared_config_ownership.cpp
  src/dp/lifecycle/config_lifecycle_executor.cpp
  src/dp/lifecycle/runtime_service_launcher.cpp
  src/dp/region_worker_launcher.cpp
  src/dp/worker_telemetry_channel.cpp
  src/dp/module/module_descriptor_admission.cpp
)
kinetum_configure_owned_target(kinetum_dp_core)
target_include_directories(kinetum_dp_core PUBLIC src)
target_link_libraries(kinetum_dp_core
  PUBLIC
  kinetum_common
  kinetum_numa_memory
  kinetum_shared_object
)

# The complete packet-runtime generation owns only provider-neutral operation
# tables and the generic admitted provider catalog. Native implementation,
# include, definition, and link requirements remain confined to components.
add_library(kinetum_packet_runtime STATIC
  src/provider/provider_runtime_materialization.cpp
  src/dp/active/worker_async_work.cpp
  src/dp/active/worker_active_stage_scheduler.cpp
  src/dp/dataplane_control_service.cpp
  src/dp/dp_control_event_loop.cpp
  src/dp/epoch/boundary_epoch_channel.cpp
  src/dp/epoch/boundary_epoch_storage.cpp
  src/dp/epoch/epoch_transition_command_mailbox.cpp
  src/dp/epoch/epoch_transition_certificate.cpp
  src/dp/epoch/epoch_transition_completion.cpp
  src/dp/epoch/epoch_transition_coordinator.cpp
  src/dp/epoch/epoch_protocol_fault.cpp
  src/dp/epoch/epoch_transition_preparation.cpp
  src/dp/epoch/epoch_transition_staging.cpp
  src/dp/epoch/frozen_transition_participants.cpp
  src/dp/epoch/worker_boundary_receiver.cpp
  src/dp/epoch/worker_boundary_sender.cpp
  src/dp/epoch/worker_epoch_activation.cpp
  src/dp/epoch/worker_epoch_ledger.cpp
  src/dp/lifecycle/materialized_runtime_service_backend.cpp
  src/dp/lifecycle/numa_lifecycle_memory_provider.cpp
  src/dp/module/module_runtime_generation.cpp
  src/dp/module/worker_module_health.cpp
  src/dp/packet_runtime_generation.cpp
  src/dp/packet_worker_kernel.cpp
  src/dp/partitioned_runtime.cpp
  src/dp/runtime_status.cpp
  src/dp/runtime_telemetry_aggregator.cpp
  src/dp/runtime_telemetry_snapshot_source.cpp
  src/dp/runtime_telemetry_source_owner.cpp
  src/dp/runtime_telemetry_wire.cpp
  src/dp/thread_affinity.cpp
  src/dp/worker_input_scheduler.cpp
  src/dp/worker_runtime_command.cpp
  src/dp/worker_runtime_telemetry.cpp
)
kinetum_configure_owned_target(kinetum_packet_runtime)
target_include_directories(kinetum_packet_runtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_packet_runtime
  PUBLIC
  kinetum_dp_core
  kinetum_provider_runtime_admission
  PRIVATE
  kinetum_deployment_plan_identity
  kinetum_numa_memory
)

# Provider implementation objects are deliberately position-independent, so
# exact component targets can wrap the same source identity without relocating
# implementation files.
add_library(kinetum_provider_udp_impl_objects OBJECT
  src/dp/backends/udp/udp_io.cpp
)
kinetum_configure_owned_target(kinetum_provider_udp_impl_objects)
kinetum_configure_provider_component_input_target(kinetum_provider_udp_impl_objects)
target_link_libraries(kinetum_provider_udp_impl_objects PRIVATE
  kinetum_provider_component_abi
)

# The development UDP implementation is one exact component, not a linked
# runtime fallback. Its native socket mechanics and public query live in this
# target; production kinetum_dp has no edge to either object set.
add_library(kinetum_provider_udp_component SHARED
  src/provider/components/udp/udp_component.cpp
  $<TARGET_OBJECTS:kinetum_provider_udp_impl_objects>
)
kinetum_configure_owned_target(kinetum_provider_udp_component)
kinetum_configure_provider_component_target(kinetum_provider_udp_component)

add_library(kinetum_provider_dpdk_impl_objects OBJECT
  src/dp/backends/dpdk/dpdk_host_probe.cpp
  src/dp/backends/dpdk/dpdk_io.cpp
  src/dp/backends/dpdk/dpdk_process_facility.cpp
)
kinetum_configure_owned_target(kinetum_provider_dpdk_impl_objects)
kinetum_configure_provider_component_input_target(kinetum_provider_dpdk_impl_objects)
target_link_libraries(kinetum_provider_dpdk_impl_objects PRIVATE
  kinetum_provider_component_abi
  KinetumDPDK::StaticComponentClosure
)
target_compile_options(kinetum_provider_dpdk_impl_objects PRIVATE
  "$<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang>:-fno-semantic-interposition>"
)

# The production DPDK implementation is one exact link-closed component. Its
# native dependency closure is PRIVATE and cannot reach kinetum_dp, core, the
# SDK, or generic test translation units.
add_library(kinetum_provider_dpdk_component SHARED
  src/provider/components/dpdk/dpdk_component.cpp
  $<TARGET_OBJECTS:kinetum_provider_dpdk_impl_objects>
)
kinetum_configure_owned_target(kinetum_provider_dpdk_component)
kinetum_configure_provider_component_target(kinetum_provider_dpdk_component)
target_link_libraries(kinetum_provider_dpdk_component PRIVATE
  KinetumDPDK::StaticComponentClosure
)

add_executable(kinetum_dp src/dp/dp_main.cpp)
kinetum_configure_owned_target(kinetum_dp)
target_link_libraries(kinetum_dp PRIVATE
  kinetum_packet_runtime
  kinetum_provider_runtime_admission
  kinetum_provider_release_trust
  kinetum_pack_lib
  kinetum_quark
)

# ---- SDK-based policy modules ----
# Built-in policy modules use the same SDK ABI as customer modules.
# Each module is a self-contained .so loaded by module_manager.
option(KINETUM_BUILD_MODULES "Build SDK-based policy modules" ON)
if(KINETUM_ENABLE_TESTS AND NOT KINETUM_BUILD_MODULES)
  message(FATAL_ERROR "KINETUM_ENABLE_TESTS=ON requires KINETUM_BUILD_MODULES=ON")
endif()
if(KINETUM_BUILD_MODULES)
  add_subdirectory(src/modules)
endif()

# ---- Control plane ----
add_library(kinetum_guardrails_contract STATIC
  src/cp/guardrails_policy.cpp
)
kinetum_configure_owned_target(kinetum_guardrails_contract)
target_include_directories(kinetum_guardrails_contract PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_guardrails_contract PUBLIC kinetum_common)

add_library(kinetum_cp_lib STATIC
  src/cp/bootstrap_startup.cpp
  src/cp/config_store.cpp
  src/cp/control_loop.cpp
  src/cp/cp_grpc.cpp
  src/cp/cp_termination_signal.cpp
  src/cp/dataplane_bootstrap.cpp
  src/cp/dataplane_transition_client.cpp
  src/cp/guardrails.cpp
  src/cp/guardrails_evaluator.cpp
  src/cp/health_correlator.cpp
  src/cp/runtime_authority_fence.cpp
  src/cp/transition_reconciliation.cpp
)
kinetum_configure_owned_target(kinetum_cp_lib)
target_include_directories(kinetum_cp_lib PUBLIC src)
target_link_libraries(kinetum_cp_lib PUBLIC kinetum_common PRIVATE kinetum_guardrails_contract)

add_executable(kinetum_cp src/cp/cp_main.cpp)
kinetum_configure_owned_target(kinetum_cp)
target_link_libraries(kinetum_cp PRIVATE kinetum_cp_lib)

# ---- CLI ----
add_executable(kinetumctl src/ctl/kinetumctl_main.cpp)
kinetum_configure_owned_target(kinetumctl)
target_link_libraries(kinetumctl PRIVATE kinetum_common kinetum_guardrails_contract)

# ---- Bundle pack/verify ----
add_library(kinetum_pack_lib STATIC
  src/pack/bundle_manifest.cpp
  src/pack/pack_source_admission.cpp
  src/pack/runtime_bundle.cpp
)
kinetum_configure_owned_target(kinetum_pack_lib)
target_include_directories(kinetum_pack_lib PUBLIC src)
target_link_libraries(kinetum_pack_lib
  PUBLIC
  kinetum_common
  kinetum_deployment_plan_identity
  PRIVATE
  kinetum_provider_topology_compiler
)

add_executable(kinetum_pack src/pack/kinetum_pack_main.cpp)
kinetum_configure_owned_target(kinetum_pack)
target_link_libraries(kinetum_pack PRIVATE kinetum_pack_lib kinetum_axiom_lib kinetum_gluon_lib)

add_executable(kinetum_bundle_verify src/pack/kinetum_bundle_verify_main.cpp)
kinetum_configure_owned_target(kinetum_bundle_verify)
target_link_libraries(kinetum_bundle_verify PRIVATE kinetum_pack_lib)

# ---- Photon ----
add_library(kinetum_photon_lib STATIC
  src/photon/process.cpp
  src/photon/readiness.cpp
  src/photon/startup.cpp
)
kinetum_configure_owned_target(kinetum_photon_lib)
target_include_directories(kinetum_photon_lib PUBLIC src)
target_link_libraries(kinetum_photon_lib PUBLIC kinetum_common)

add_executable(kinetum_photon src/photon/photon_main.cpp)
kinetum_configure_owned_target(kinetum_photon)
target_link_libraries(kinetum_photon PRIVATE kinetum_photon_lib kinetum_pack_lib)

# ---- Release verification ----
add_library(kinetum_payload_manifest_verifier STATIC
  tooling/release/verification/payload_manifest.cpp
)
kinetum_configure_owned_target(kinetum_payload_manifest_verifier)
target_include_directories(kinetum_payload_manifest_verifier PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(kinetum_payload_manifest_verifier PUBLIC kinetum_common)

add_library(kinetum_runtime_verification STATIC
  tooling/release/verification/runtime_verification.cpp
)
kinetum_configure_owned_target(kinetum_runtime_verification)
target_include_directories(kinetum_runtime_verification PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kinetum_runtime_verification
  PUBLIC kinetum_payload_manifest_verifier kinetum_provider_component_preflight
  PRIVATE kinetum_provider_release kinetum_provider_release_trust
)

add_executable(kinetum_info tooling/release/verification/kinetum_info.cpp)
kinetum_configure_owned_target(kinetum_info)
target_include_directories(kinetum_info PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(kinetum_info PRIVATE
  KINETUM_ENABLE_TLS=$<BOOL:${KINETUM_ENABLE_TLS}>
  KINETUM_ENABLE_MLIR=$<BOOL:${KINETUM_ENABLE_MLIR}>
  KINETUM_ENABLE_MLIR_DIALECT=$<BOOL:${KINETUM_ENABLE_MLIR_DIALECT}>
  KINETUM_DPDK_VERSION="${KinetumDPDK_VERSION}"
)
set_target_properties(kinetum_info PROPERTIES OUTPUT_NAME "kinetum-info")
target_link_libraries(kinetum_info PRIVATE
  kinetum_common
  kinetum_runtime_verification
  kinetum_provider_installation
)

# Archive codecs belong only to the packaging process. These direct links
# are neither SDK usage requirements nor runtime/provider/module edges.
find_package(LibArchive REQUIRED)
add_executable(kinetum_package
  tooling/release/packaging/kinetum_package.cpp
  tooling/release/packaging/package_files.cpp
)
kinetum_configure_owned_target(kinetum_package)
target_include_directories(kinetum_package PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/release-packaging)
target_link_libraries(kinetum_package PRIVATE
  kinetum_common kinetum_package_release kinetum_runtime_verification
  kinetum_provider_release_trust PkgConfig::LIBELF LibArchive::LibArchive ZLIB::ZLIB
)

# ---- Validation helpers ----
add_executable(kinetum_tap_sender validation/native/kinetum_tap_sender.cpp)
kinetum_configure_owned_target(kinetum_tap_sender)
target_include_directories(kinetum_tap_sender PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(kinetum_tap_analyzer validation/native/kinetum_tap_analyzer.cpp)
kinetum_configure_owned_target(kinetum_tap_analyzer)
target_include_directories(kinetum_tap_analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ---- Tests ----
if(KINETUM_ENABLE_TESTS)
  enable_testing()

  if(NOT KINETUM_FETCH_DEPS)
    find_package(GTest ${KINETUM_GTEST_VERSION} EXACT CONFIG REQUIRED)
  endif()

  # ---- Plain-C exact provider-component conformance closure ----
  add_library(kinetum_test_provider_private SHARED
    tests/provider_components/test_provider_private.c
  )
  kinetum_configure_owned_c_target(kinetum_test_provider_private)
  kinetum_configure_provider_private_artifact_target(kinetum_test_provider_private)
  target_include_directories(kinetum_test_provider_private PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  set_target_properties(kinetum_test_provider_private PROPERTIES
    OUTPUT_NAME "kinetum_test_provider_private"
  )

  function(kinetum_add_test_provider_component target_name output_name)
    add_library(${target_name} SHARED
      tests/provider_components/test_provider_component.c
    )
    kinetum_configure_owned_c_target(${target_name})
    kinetum_configure_provider_component_target(${target_name})
    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${target_name} PRIVATE kinetum_test_provider_private)
    set_target_properties(${target_name} PROPERTIES
      C_EXTENSIONS OFF
      OUTPUT_NAME "${output_name}"
    )
  endfunction()

  kinetum_add_test_provider_component(
    kinetum_test_provider_component
    "kinetum_test_provider_component"
  )

  # A valid DPDK-facility row whose COMPONENT proof deterministically fails
  # after the real installed loader has loaded its complete private closure.
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_host_proof_failure
    "kinetum_test_provider_component_host_proof_failure"
  )
  target_compile_definitions(
    kinetum_test_provider_component_host_proof_failure PRIVATE
    KINETUM_TEST_PROVIDER_COMPONENT_ID="kinetum.test.provider.host_proof_failure"
    KINETUM_TEST_PROVIDER_CONTRACT_TYPE_URL="type.googleapis.com/kinetum.facility.dpdk.v1.DpdkFacilityConfig"
    KINETUM_TEST_PROVIDER_ROLE=KINETUM_PROVIDER_ROLE_PROCESS_FACILITY
    KINETUM_TEST_PROVIDER_FACTORY_ROLE=KINETUM_PROVIDER_ROLE_PROCESS_FACILITY
    KINETUM_TEST_PROVIDER_FAILING_HOST_PROOF=1
  )

  # A real C++ implementation behind the same C ABI proves C linkage,
  # noexcept callback compatibility, and the GNU-unique suppression policy.
  add_library(kinetum_test_provider_component_cpp SHARED
    tests/provider_components/test_provider_component_cpp.cpp
  )
  kinetum_configure_owned_target(kinetum_test_provider_component_cpp)
  kinetum_configure_provider_component_target(
    kinetum_test_provider_component_cpp
  )
  target_include_directories(
    kinetum_test_provider_component_cpp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
  )
  target_link_libraries(
    kinetum_test_provider_component_cpp PRIVATE kinetum_test_provider_private
  )
  set_target_properties(kinetum_test_provider_component_cpp PROPERTIES
    CXX_EXTENSIONS OFF
    OUTPUT_NAME "kinetum_test_provider_component_cpp"
  )

  # One image owns two canonically ordered rows so descriptor admission and
  # requested-only publication execute their real multi-contract paths.
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_multi
    "kinetum_test_provider_component_multi"
  )
  target_compile_definitions(kinetum_test_provider_component_multi PRIVATE
    KINETUM_TEST_PROVIDER_COMPONENT_ID="kinetum.test.provider.multi"
    KINETUM_TEST_PROVIDER_CONTRACT_TYPE_URL="type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig"
    KINETUM_TEST_PROVIDER_ROLE=KINETUM_PROVIDER_ROLE_EXECUTION
    KINETUM_TEST_PROVIDER_FACTORY_ROLE=KINETUM_PROVIDER_ROLE_EXECUTION
    KINETUM_TEST_PROVIDER_SECOND_CONTRACT_TYPE_URL="type.googleapis.com/kinetum.transition.core.v1.ZeroCopyShareConfig"
    KINETUM_TEST_PROVIDER_SECOND_ROLE=KINETUM_PROVIDER_ROLE_STORAGE_TRANSITION
  )

  kinetum_add_test_provider_component(
    kinetum_test_provider_component_nodelete
    "kinetum_test_provider_component_nodelete"
  )
  # Deliberately violates exact handle-owned lifetime so ELF admission proves
  # that a component cannot escape catalog retirement through DF_1_NODELETE.
  target_link_options(
    kinetum_test_provider_component_nodelete PRIVATE "LINKER:-z,nodelete"
  )
  add_library(kinetum_test_provider_component_versioned SHARED
    tests/provider_components/test_provider_component.c
  )
  kinetum_configure_owned_c_target(
    kinetum_test_provider_component_versioned
  )
  _kinetum_configure_provider_component_target_with_export_map(
    kinetum_test_provider_component_versioned
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/provider_components/test_provider_component_versioned.exports"
  )
  target_include_directories(
    kinetum_test_provider_component_versioned PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
  )
  target_link_libraries(
    kinetum_test_provider_component_versioned PRIVATE kinetum_test_provider_private
  )
  set_target_properties(kinetum_test_provider_component_versioned PROPERTIES
    C_EXTENSIONS OFF
    OUTPUT_NAME "kinetum_test_provider_component_versioned"
  )
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_older
    "kinetum_test_provider_component_older"
  )
  target_compile_definitions(kinetum_test_provider_component_older PRIVATE
    KINETUM_TEST_PROVIDER_PRODUCT_VERSION_MINOR=0
  )
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_newer
    "kinetum_test_provider_component_newer"
  )
  target_compile_definitions(kinetum_test_provider_component_newer PRIVATE
    KINETUM_TEST_PROVIDER_PRODUCT_VERSION_MINOR=2
  )
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_wrong_abi
    "kinetum_test_provider_component_wrong_abi"
  )
  target_compile_definitions(kinetum_test_provider_component_wrong_abi PRIVATE
    KINETUM_TEST_PROVIDER_CORRUPT_ABI=1
  )
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_wrong_role
    "kinetum_test_provider_component_wrong_role"
  )
  target_compile_definitions(kinetum_test_provider_component_wrong_role PRIVATE
    KINETUM_TEST_PROVIDER_ROLE=KINETUM_PROVIDER_ROLE_EXECUTION
  )
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_nonzero_padding
    "kinetum_test_provider_component_nonzero_padding"
  )
  target_compile_definitions(
    kinetum_test_provider_component_nonzero_padding PRIVATE
    KINETUM_TEST_PROVIDER_DESCRIPTOR_TAIL_PADDING=1
  )
  kinetum_add_test_provider_component(
    kinetum_test_provider_component_second
    "kinetum_test_provider_component_second"
  )
  target_compile_definitions(kinetum_test_provider_component_second PRIVATE
    KINETUM_TEST_PROVIDER_COMPONENT_ID="kinetum.test.provider.second"
    KINETUM_TEST_PROVIDER_CONTRACT_TYPE_URL="type.googleapis.com/kinetum.execution.cpu.v1.CpuExecutionConfig"
    KINETUM_TEST_PROVIDER_ROLE=KINETUM_PROVIDER_ROLE_EXECUTION
    KINETUM_TEST_PROVIDER_FACTORY_ROLE=KINETUM_PROVIDER_ROLE_EXECUTION
  )

  # One hardened image implements seven contracts across five roles to prove
  # complete publication, recoverable reverse rollback, and post-facility fail-stop.
  add_library(kinetum_test_provider_materialization_component SHARED
    tests/provider_components/test_provider_materialization_component.c
  )
  kinetum_configure_owned_c_target(
    kinetum_test_provider_materialization_component
  )
  kinetum_configure_provider_component_target(
    kinetum_test_provider_materialization_component
  )
  target_include_directories(
    kinetum_test_provider_materialization_component
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
  )
  set_target_properties(
    kinetum_test_provider_materialization_component PROPERTIES
    C_EXTENSIONS OFF
    OUTPUT_NAME "kinetum_test_provider_materialization_component"
  )

  # ---- Test module (Module SDK) ----
  add_library(kinetum_test_module SHARED
    tests/test_modules/test_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_module)
  kinetum_configure_module_target(kinetum_test_module)
  set_target_properties(kinetum_test_module PROPERTIES
    OUTPUT_NAME "kinetum_test_module"
  )

  # Define the test module path as a compile-time constant.
  # This allows tests to find the .so regardless of the working directory.
  # The path is set to the location where CMake places the built library.
  set(KINETUM_TEST_MODULE_PATH "$<TARGET_FILE:kinetum_test_module>")

  # ---- Test active module (Active Stage ABI) ----
  add_library(kinetum_test_active_module SHARED
    tests/test_modules/test_active_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_active_module)
  kinetum_configure_module_target(kinetum_test_active_module)
  set_target_properties(kinetum_test_active_module PROPERTIES
    OUTPUT_NAME "kinetum_test_active_module"
  )
  set(KINETUM_TEST_ACTIVE_MODULE_PATH "$<TARGET_FILE:kinetum_test_active_module>")

  # ---- Test tracked-async active module ----
  add_library(kinetum_test_active_async_module SHARED
    tests/test_modules/test_active_async_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_active_async_module)
  kinetum_configure_module_target(kinetum_test_active_async_module)
  set_target_properties(kinetum_test_active_async_module PROPERTIES
    OUTPUT_NAME "kinetum_test_active_async_module"
  )
  set(KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH "$<TARGET_FILE:kinetum_test_active_async_module>")

  # ---- Test lifecycle-serialization module ----
  add_library(kinetum_test_serialized_module SHARED
    tests/test_modules/test_serialized_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_serialized_module)
  kinetum_configure_module_target(kinetum_test_serialized_module)
  set_target_properties(kinetum_test_serialized_module PROPERTIES
    OUTPUT_NAME "kinetum_test_serialized_module"
  )
  set(KINETUM_TEST_SERIALIZED_MODULE_PATH "$<TARGET_FILE:kinetum_test_serialized_module>")

  # ---- Test exact-ABI rejection modules ----
  add_library(kinetum_test_older_abi_module SHARED
    tests/test_modules/test_incompatible_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_older_abi_module)
  kinetum_configure_module_target(kinetum_test_older_abi_module)
  target_compile_definitions(kinetum_test_older_abi_module PRIVATE
    KINETUM_TEST_INCOMPATIBLE_MODULE_ID="kinetum.test.abi_older"
    KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION=-1
  )
  set_target_properties(kinetum_test_older_abi_module PROPERTIES
    OUTPUT_NAME "kinetum_test_older_abi_module"
  )
  set(KINETUM_TEST_OLDER_ABI_MODULE_PATH "$<TARGET_FILE:kinetum_test_older_abi_module>")

  add_library(kinetum_test_newer_abi_module SHARED
    tests/test_modules/test_incompatible_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_newer_abi_module)
  kinetum_configure_module_target(kinetum_test_newer_abi_module)
  target_compile_definitions(kinetum_test_newer_abi_module PRIVATE
    KINETUM_TEST_INCOMPATIBLE_MODULE_ID="kinetum.test.abi_newer"
    KINETUM_TEST_INCOMPATIBLE_ABI_DIRECTION=1
  )
  set_target_properties(kinetum_test_newer_abi_module PROPERTIES
    OUTPUT_NAME "kinetum_test_newer_abi_module"
  )
  set(KINETUM_TEST_NEWER_ABI_MODULE_PATH "$<TARGET_FILE:kinetum_test_newer_abi_module>")

  # ---- Test SATCOM module (SDK domain-extension example) ----
  add_library(kinetum_test_satcom_module SHARED
    tests/test_modules/satcom_acm_module.cpp
  )
  kinetum_configure_owned_target(kinetum_test_satcom_module)
  kinetum_configure_module_target(kinetum_test_satcom_module)
  set_target_properties(kinetum_test_satcom_module PROPERTIES
    OUTPUT_NAME "kinetum_test_satcom_module"
  )

  # ---- Plain-C exact SDK module ----
  # This target is the link-time canary for the installed header-only contract:
  # any module-facing SDK helper that regresses to a host-owned definition makes
  # -z defs fail this shared-object link before a loader can observe it.
  add_library(kinetum_test_c_module SHARED
    tests/test_modules/test_c_module.c
  )
  kinetum_configure_owned_c_target(kinetum_test_c_module)
  kinetum_configure_module_target(kinetum_test_c_module)
  set_target_properties(kinetum_test_c_module PROPERTIES
    OUTPUT_NAME "kinetum_test_c_module"
  )
  set(KINETUM_TEST_C_MODULE_PATH "$<TARGET_FILE:kinetum_test_c_module>")

  add_executable(kinetum_tests
    tests/test_axiom_contract.cpp
    tests/test_axiom_mlir_frontend.cpp
    tests/test_axiom_pbtxt_io.cpp
    tests/test_gluon_boundary_topology.cpp
    tests/test_gluon_determinism.cpp
    tests/test_gluon_examples.cpp
    tests/test_gluon_plan_schema.cpp
    tests/test_hardware_schema.cpp
    tests/test_gluon_port_bindings.cpp
    tests/test_gluon_runtime_core_placement.cpp
    tests/test_config_snapshot_epoch_store.cpp
    tests/test_epoch_transition_command_mailbox.cpp
    tests/test_epoch_transition_certificate.cpp
    tests/test_epoch_transition_completion.cpp
    tests/test_epoch_transition_coordinator.cpp
    tests/test_epoch_transition_preparation.cpp
    tests/test_epoch_transition_primitives.cpp
    tests/test_epoch_protocol_fault.cpp
    tests/test_worker_runtime_command.cpp
    tests/test_worker_input_scheduler.cpp
    tests/test_dataplane_transition_client.cpp
    tests/test_module_epoch_store.cpp
    tests/test_worker_module_health.cpp
    tests/test_transition_topology.cpp
    tests/test_lifecycle_context.cpp
    tests/test_config_lifecycle_executor.cpp
    tests/test_runtime_service_launcher.cpp
    tests/test_content_identity.cpp
    tests/test_provider_contract_catalog.cpp
    tests/test_compiled_provider_topology.cpp
    tests/test_provider_component_abi.cpp
    tests/test_ed25519.cpp
    tests/test_provider_inventory.cpp
    tests/test_provider_component_admission.cpp
    tests/test_provider_component_loader.cpp
    tests/test_provider_components.cpp
    tests/test_provider_runtime_materialization.cpp
    tests/test_provider_release.cpp
    tests/test_payload_manifest.cpp
    tests/test_bundle_manifest.cpp
    tests/test_pack_source_admission.cpp
    tests/test_runtime_bundle.cpp
    tests/test_config_store.cpp
    tests/test_cp_transition_persistence.cpp
    tests/test_common_schema.cpp
    tests/test_status.cpp
    tests/test_file_io.cpp
    tests/test_common_log.cpp
    tests/test_log_delivery.cpp
    tests/test_packet_thread_log_guard.cpp
    tests/test_log_file.cpp
    tests/test_logging_status.cpp
    tests/test_grpc_logging_gpr.cpp
    tests/test_path_admission.cpp
    tests/test_process_image.cpp
    tests/test_dp_parse_ipv4.cpp
    tests/test_packet_record.cpp
    tests/test_dp_acl.cpp
    tests/test_simd_classify.cpp
    tests/test_dp_nat44.cpp
    tests/test_dp_qos_policer.cpp
    tests/test_module_config_parsing.cpp
    tests/test_dp_module_sdk.cpp
    tests/test_sdk_c_mechanisms.cpp
    tests/test_c_module_sdk.cpp
    tests/test_module_abi_layout.cpp
    tests/test_module_generation.cpp
    tests/test_module_execution_views.cpp
    tests/test_numa_lifecycle_memory_provider.cpp
    tests/test_sha256.cpp
    tests/test_tls.cpp
    tests/test_photon_process.cpp
    tests/test_signal_control.cpp
    tests/test_photon_startup.cpp
    tests/test_cp_bootstrap_startup.cpp
    tests/test_cp_termination_signal.cpp
    tests/test_control_api_schema.cpp
    tests/test_guardrails.cpp
    tests/test_guardrails_evaluator.cpp
    tests/test_boundary_epoch_channel.cpp
    tests/test_partitioned_runtime_construction.cpp
    tests/test_runtime_io_backend.cpp
    tests/test_dp_integration.cpp
    tests/test_edge_conditions.cpp
    tests/test_module_concurrency.cpp
    tests/test_dp_lifecycle.cpp
    tests/test_dataplane_control_service.cpp
    tests/test_runtime_status.cpp
    tests/test_runtime_telemetry_aggregator.cpp
    tests/test_runtime_authority_fence.cpp
    tests/test_runtime_telemetry_contract.cpp
    tests/test_telemetry_schema.cpp
    tests/test_dataplane_schema.cpp
    tests/test_worker_boundary_receiver.cpp
    tests/test_worker_boundary_sender.cpp
    tests/test_worker_active_stage_scheduler.cpp
    tests/test_worker_async_work.cpp
    tests/test_worker_epoch_ledger.cpp
    tests/test_worker_runtime_telemetry.cpp
    tests/test_epoch_transition_staging.cpp
    tests/test_region_worker_launcher.cpp
    tests/test_thread_affinity.cpp
    tests/test_nat44_table.cpp
    tests/test_internet_checksum.cpp
    tests/test_cp_stats_forwarding.cpp
    tests/test_kinetum_info.cpp
    tests/test_kinetumctl_stats.cpp
    tests/test_quark_runtime_compat.cpp
    tests/test_quiescence_domain.cpp
    tests/test_rcu_buffer.cpp
    tests/test_timer_wheel.cpp
    tests/test_algo_primitives.cpp
    tests/test_bounded_service_order.cpp
    tests/test_perf_regression.cpp
    tests/test_validation_tap_analyzer.cpp
    tests/test_validation_tap_sender.cpp
  )
  kinetum_configure_owned_target(kinetum_tests)
  target_include_directories(kinetum_tests SYSTEM PRIVATE ${CMAKE_BINARY_DIR})
  target_link_libraries(kinetum_tests PRIVATE
    kinetum_common
    kinetum_provider_contracts
    kinetum_provider_loader
    kinetum_provider_release
    kinetum_provider_release_trust
    kinetum_package_release
    kinetum_payload_manifest_verifier
    kinetum_runtime_verification
    kinetum_provider_runtime_admission
    kinetum_axiom_lib
    kinetum_gluon_lib
    kinetum_quark
    kinetum_dp_core
    kinetum_packet_runtime
    kinetum_fixed_packet_pool
    kinetum_pack_lib
    kinetum_cp_lib       # For config_store and guardrails tests
    kinetum_photon_lib   # For Photon startup and process-owner tests
    kinetum_acl_impl
    kinetum_nat44_impl
    kinetum_qos_impl
    kinetum_acl_proto
    kinetum_nat44_proto
    kinetum_qos_proto
    PkgConfig::LIBELF
    GTest::gtest_main
  )
  target_sources(kinetum_tests PRIVATE
    $<TARGET_OBJECTS:kinetum_provider_udp_impl_objects>
  )

  # UDP white-box tests consume provider-private socket mechanics, so their
  # translation unit has its own provider compile domain. UDP has no
  # process-global runtime precondition; its objects may therefore join the
  # generic final test process without giving generic sources a provider edge.
  add_library(kinetum_provider_udp_test_objects OBJECT
    tests/test_udp_io.cpp
  )
  kinetum_configure_owned_target(kinetum_provider_udp_test_objects)
  target_link_libraries(kinetum_provider_udp_test_objects PRIVATE
    kinetum_provider_component_abi
    kinetum_fixed_packet_pool
    GTest::gtest_main
  )
  target_sources(kinetum_tests PRIVATE
    $<TARGET_OBJECTS:kinetum_provider_udp_test_objects>
  )

  # Pass module paths as compile definitions using generator expressions.
  # This ensures tests can find the .so files regardless of the working directory.
  target_compile_definitions(kinetum_tests PRIVATE
    KINETUM_TEST_MODULE_PATH="${KINETUM_TEST_MODULE_PATH}"
    KINETUM_TEST_ACTIVE_MODULE_PATH="${KINETUM_TEST_ACTIVE_MODULE_PATH}"
    KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH="${KINETUM_TEST_ACTIVE_ASYNC_MODULE_PATH}"
    KINETUM_TEST_SERIALIZED_MODULE_PATH="${KINETUM_TEST_SERIALIZED_MODULE_PATH}"
    KINETUM_TEST_OLDER_ABI_MODULE_PATH="${KINETUM_TEST_OLDER_ABI_MODULE_PATH}"
    KINETUM_TEST_NEWER_ABI_MODULE_PATH="${KINETUM_TEST_NEWER_ABI_MODULE_PATH}"
    KINETUM_TEST_C_MODULE_PATH="${KINETUM_TEST_C_MODULE_PATH}"
    KINETUM_ACL_MODULE_PATH="$<TARGET_FILE:kinetum_acl_module>"
    KINETUM_NAT44_MODULE_PATH="$<TARGET_FILE:kinetum_nat44_module>"
    KINETUM_QOS_MODULE_PATH="$<TARGET_FILE:kinetum_qos_module>"
    KINETUM_TEST_PROVIDER_PRIVATE_PATH="$<TARGET_FILE:kinetum_test_provider_private>"
    KINETUM_TEST_PROVIDER_PRIVATE_SONAME="$<TARGET_FILE_NAME:kinetum_test_provider_private>"
    KINETUM_TEST_PROVIDER_COMPONENT_PATH="$<TARGET_FILE:kinetum_test_provider_component>"
    KINETUM_TEST_PROVIDER_HOST_PROOF_FAILURE_PATH="$<TARGET_FILE:kinetum_test_provider_component_host_proof_failure>"
    KINETUM_TEST_PROVIDER_COMPONENT_CPP_PATH="$<TARGET_FILE:kinetum_test_provider_component_cpp>"
    KINETUM_TEST_PROVIDER_COMPONENT_MULTI_PATH="$<TARGET_FILE:kinetum_test_provider_component_multi>"
    KINETUM_TEST_PROVIDER_NODELETE_PATH="$<TARGET_FILE:kinetum_test_provider_component_nodelete>"
    KINETUM_TEST_PROVIDER_VERSIONED_PATH="$<TARGET_FILE:kinetum_test_provider_component_versioned>"
    KINETUM_TEST_PROVIDER_COMPONENT_OLDER_PATH="$<TARGET_FILE:kinetum_test_provider_component_older>"
    KINETUM_TEST_PROVIDER_COMPONENT_NEWER_PATH="$<TARGET_FILE:kinetum_test_provider_component_newer>"
    KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ABI_PATH="$<TARGET_FILE:kinetum_test_provider_component_wrong_abi>"
    KINETUM_TEST_PROVIDER_COMPONENT_WRONG_ROLE_PATH="$<TARGET_FILE:kinetum_test_provider_component_wrong_role>"
    KINETUM_TEST_PROVIDER_PADDING_PATH="$<TARGET_FILE:kinetum_test_provider_component_nonzero_padding>"
    KINETUM_TEST_PROVIDER_COMPONENT_SECOND_PATH="$<TARGET_FILE:kinetum_test_provider_component_second>"
    KINETUM_TEST_PROVIDER_MATERIALIZATION_COMPONENT_PATH="$<TARGET_FILE:kinetum_test_provider_materialization_component>"
    KINETUM_PROVIDER_HOST_COMPONENT_PATH="$<TARGET_FILE:kinetum_provider_host_component>"
    KINETUM_PROVIDER_UDP_COMPONENT_PATH="$<TARGET_FILE:kinetum_provider_udp_component>"
    KINETUM_PROVIDER_DPDK_COMPONENT_PATH="$<TARGET_FILE:kinetum_provider_dpdk_component>"
    KINETUM_PRODUCTION_PACKAGE_PATH="$<TARGET_FILE:kinetum_package>"
    KINETUM_PRODUCTION_AXIOM_PATH="$<TARGET_FILE:kinetum_axiom>"
    KINETUM_PRODUCTION_GLUON_PATH="$<TARGET_FILE:kinetum_gluon>"
    KINETUM_PRODUCTION_DP_PATH="$<TARGET_FILE:kinetum_dp>"
    KINETUM_PRODUCTION_CP_PATH="$<TARGET_FILE:kinetum_cp>"
    KINETUM_PRODUCTION_CTL_PATH="$<TARGET_FILE:kinetumctl>"
    KINETUM_PRODUCTION_PACK_PATH="$<TARGET_FILE:kinetum_pack>"
    KINETUM_TEST_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
    KINETUM_PRODUCTION_BUNDLE_VERIFY_PATH="$<TARGET_FILE:kinetum_bundle_verify>"
    KINETUM_PRODUCTION_PHOTON_PATH="$<TARGET_FILE:kinetum_photon>"
    KINETUM_PRODUCTION_INFO_PATH="$<TARGET_FILE:kinetum_info>"
    KINETUM_TEST_INFO_DPDK_VERSION="${KinetumDPDK_VERSION}"
    KINETUM_TEST_INFO_ENABLE_TLS=$<BOOL:${KINETUM_ENABLE_TLS}>
    KINETUM_TEST_INFO_ENABLE_MLIR=$<BOOL:${KINETUM_ENABLE_MLIR}>
    KINETUM_TEST_INFO_ENABLE_MLIR_DIALECT=$<BOOL:${KINETUM_ENABLE_MLIR_DIALECT}>
    KINETUM_VALIDATION_TAP_SENDER_PATH="$<TARGET_FILE:kinetum_tap_sender>"
    KINETUM_VALIDATION_TAP_ANALYZER_PATH="$<TARGET_FILE:kinetum_tap_analyzer>"
  )

  # Tests use generated headers as typed host-side authoring models. Exact
  # runtime module images do not link these generated registries.
  add_dependencies(kinetum_tests
    kinetum_test_module
    kinetum_test_active_module
    kinetum_test_active_async_module
    kinetum_test_serialized_module
    kinetum_test_older_abi_module
    kinetum_test_newer_abi_module
    kinetum_test_satcom_module
    kinetum_test_c_module
    kinetum_test_provider_private
    kinetum_test_provider_component
    kinetum_test_provider_component_host_proof_failure
    kinetum_test_provider_component_cpp
    kinetum_test_provider_component_multi
    kinetum_test_provider_component_nodelete
    kinetum_test_provider_component_versioned
    kinetum_test_provider_component_older
    kinetum_test_provider_component_newer
    kinetum_test_provider_component_wrong_abi
    kinetum_test_provider_component_wrong_role
    kinetum_test_provider_component_nonzero_padding
    kinetum_test_provider_component_second
    kinetum_test_provider_materialization_component
    kinetum_provider_host_component
    kinetum_provider_udp_component
    kinetum_provider_dpdk_component
    kinetum_package
    kinetum_acl_module
    kinetum_nat44_module
    kinetum_qos_module
    kinetum_acl_proto
    kinetum_nat44_proto
    kinetum_qos_proto
    kinetum_axiom
    kinetum_gluon
    kinetum_dp
    kinetum_cp
    kinetumctl
    kinetum_pack
    kinetum_bundle_verify
    kinetum_photon
    kinetum_info
    kinetum_tap_sender
    kinetum_tap_analyzer
  )

  # DPDK owns process-global EAL, ethdev, mempool, and PMD registration state.
  # Its native white-box tests therefore run in one dedicated process that
  # links the same exact static closure as the component and never loads that
  # component. Generic tests retain a separate provider-neutral compile/link
  # domain and may admit the component only through the production loader seam.
  add_library(kinetum_provider_dpdk_test_objects OBJECT
    tests/test_dpdk_host_probe.cpp
    tests/test_dpdk_io.cpp
    tests/test_dpdk_process_facility.cpp
  )
  kinetum_configure_owned_target(kinetum_provider_dpdk_test_objects)
  target_link_libraries(kinetum_provider_dpdk_test_objects PRIVATE
    kinetum_provider_component_abi
    KinetumDPDK::StaticComponentClosure
    GTest::gtest_main
  )
  add_executable(kinetum_provider_dpdk_tests
    $<TARGET_OBJECTS:kinetum_provider_dpdk_impl_objects>
    $<TARGET_OBJECTS:kinetum_provider_dpdk_test_objects>
  )
  kinetum_configure_owned_target(kinetum_provider_dpdk_tests)
  target_link_libraries(kinetum_provider_dpdk_tests PRIVATE
    kinetum_provider_component_abi
    kinetum_packet_thread_log_guard
    KinetumDPDK::StaticComponentClosure
    GTest::gtest_main
  )

  # Generic ELF tests inspect, but never link or execute inside, the native
  # test image. The dependency is build ordering only and carries no usage
  # requirement into kinetum_tests.
  add_dependencies(kinetum_tests kinetum_provider_dpdk_tests)
  target_compile_definitions(kinetum_tests PRIVATE
    KINETUM_PROVIDER_DPDK_TESTS_PATH="$<TARGET_FILE:kinetum_provider_dpdk_tests>"
  )

  include(GoogleTest)
  gtest_discover_tests(kinetum_tests)
  gtest_discover_tests(kinetum_provider_dpdk_tests)

  # Fast SDK consumers build and test Release against a fresh SDK stage. The same project
  # also serves the distinct distributed-SDK gate on a source-free native host.
  add_test(NAME sdk_stage
    COMMAND "${CMAKE_COMMAND}" -Dbuild_root=${CMAKE_CURRENT_BINARY_DIR}
      -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/installed_sdk/stage_sdk.cmake")
  set_tests_properties(sdk_stage PROPERTIES FIXTURES_SETUP sdk_payload TIMEOUT 120)
  find_program(KINETUM_SDK_GNU_CC NAMES gcc REQUIRED)
  find_program(KINETUM_SDK_GNU_CXX NAMES g++ REQUIRED)
  find_program(KINETUM_SDK_CLANG_CC NAMES clang REQUIRED)
  find_program(KINETUM_SDK_CLANG_CXX NAMES clang++ REQUIRED)
  foreach(compiler IN ITEMS GNU Clang)
    string(TOUPPER "${compiler}" compiler_key)
    add_test(NAME sdk_consumer_${compiler_key}
      COMMAND /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C
        "${CMAKE_CTEST_COMMAND}" --build-and-test
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/installed_sdk"
        "${CMAKE_CURRENT_BINARY_DIR}/sdk-consumer-builds/${compiler_key}"
        --build-generator "${CMAKE_GENERATOR}"
        --build-config Release
        --build-options
          -DKINETUM_SDK_ROOT=${CMAKE_CURRENT_BINARY_DIR}/sdk-consumer-prefix/sdk
          -DKINETUM_SDK_EXPECTED_COMPILER_ID=${compiler}
          -DCMAKE_C_COMPILER=${KINETUM_SDK_${compiler_key}_CC}
          -DCMAKE_CXX_COMPILER=${KINETUM_SDK_${compiler_key}_CXX}
        --test-command "${CMAKE_CTEST_COMMAND}" -C Release --output-on-failure)
    set_tests_properties(sdk_consumer_${compiler_key} PROPERTIES FIXTURES_REQUIRED sdk_payload TIMEOUT 600)
  endforeach()
endif()

# ---- Release membership and componentized staging ----
# CMake alone chooses installed membership. Native packaging reads the staged
# trees; the generated projections below check copying without choosing files.
# Package preparation consumes an existing build. Common package requirements
# are admitted at envelope staging; CPU targeting stays with that build.
# Public release qualification additionally proves the declared CPU baseline.
# Any new package-staging requirement belongs in this admission list, never
# in a packager-side configure. Test execution remains a separate gate.
set(KINETUM_RELEASE_CONFIGURATION_ERRORS)
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE STREQUAL "Release")
  list(APPEND KINETUM_RELEASE_CONFIGURATION_ERRORS "CMAKE_BUILD_TYPE=Release")
endif()
foreach(release_setting IN ITEMS KINETUM_ENABLE_TLS KINETUM_ENABLE_LTO KINETUM_BUILD_MODULES)
  if(NOT ${release_setting})
    list(APPEND KINETUM_RELEASE_CONFIGURATION_ERRORS "${release_setting}=ON")
  endif()
endforeach()
foreach(release_setting IN ITEMS KINETUM_ENABLE_ASAN KINETUM_ENABLE_UBSAN KINETUM_ENABLE_TSAN
    KINETUM_ENABLE_MLIR KINETUM_ENABLE_MLIR_DIALECT KINETUM_FETCH_DEPS)
  if(${release_setting})
    list(APPEND KINETUM_RELEASE_CONFIGURATION_ERRORS "${release_setting}=OFF")
  endif()
endforeach()
string(JOIN ", " KINETUM_RELEASE_CONFIGURATION_ERRORS ${KINETUM_RELEASE_CONFIGURATION_ERRORS})
install(CODE "
  if(NOT CMAKE_INSTALL_CONFIG_NAME STREQUAL \"Release\")
    message(FATAL_ERROR \"Release packaging requires the Release configuration\")
  endif()
  if(NOT \"${KINETUM_RELEASE_CONFIGURATION_ERRORS}\" STREQUAL \"\")
    message(FATAL_ERROR \"Release packaging requires ${KINETUM_RELEASE_CONFIGURATION_ERRORS}. Reconfigure and build the selected directory before preparation.\")
  endif()
" COMPONENT KinetumPackageEnvelope EXCLUDE_FROM_ALL)

set(KINETUM_RUNTIME_EXECUTABLE_TARGETS
  kinetum_axiom kinetum_bundle_verify kinetum_cp kinetum_dp kinetum_gluon
  kinetum_info kinetum_pack kinetum_photon kinetumctl
)
set(KINETUM_BUILTIN_MODULE_TARGETS
  kinetum_acl_module kinetum_nat44_module kinetum_qos_module
)
set(KINETUM_PRODUCTION_PROVIDER_TARGETS
  kinetum_provider_dpdk_component kinetum_provider_host_component
)
set(KINETUM_RELEASE_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/release-packaging")
file(MAKE_DIRECTORY "${KINETUM_RELEASE_GENERATED_DIR}")
set(KINETUM_VERSION "${KINETUM_VERSION_STR_FILE}")
set(KINETUM_FIXED_PROJECTIONS "")
set(KINETUM_TREE_PROJECTIONS "")
set(KINETUM_FIXED_PROJECTION_COUNT 0)
set(KINETUM_TREE_PROJECTION_COUNT 0)

# Fixed-file staging and its byte projection are declared together. This
# projection contains only source-relative names and content digests.
function(kinetum_stage_file product input destination source_authority)
  get_filename_component(destination_parent "${destination}" DIRECTORY)
  get_filename_component(destination_name "${destination}" NAME)
  if(product STREQUAL "RUNTIME")
    set(component KinetumRuntimePayload)
  else()
    set(component KinetumSDK)
  endif()
  install(FILES "${input}" DESTINATION "${destination_parent}"
    RENAME "${destination_name}" COMPONENT ${component} EXCLUDE_FROM_ALL)
  file(SHA256 "${input}" staged_hash)
  set(source_path "")
  set(source_hash "")
  if(NOT source_authority STREQUAL "")
    file(RELATIVE_PATH source_path "${CMAKE_CURRENT_SOURCE_DIR}" "${source_authority}")
    if(source_path MATCHES "^\\.\\.")
      message(FATAL_ERROR "Package source projection escapes its source authority")
    endif()
    file(SHA256 "${source_authority}" source_hash)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source_authority}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${input}")
  string(APPEND KINETUM_FIXED_PROJECTIONS
    "  {product_kind::${product}, \"${source_path}\", \"${destination}\", \"${source_hash}\", \"${staged_hash}\"},\n")
  math(EXPR KINETUM_FIXED_PROJECTION_COUNT "${KINETUM_FIXED_PROJECTION_COUNT} + 1")
  set(KINETUM_FIXED_PROJECTIONS "${KINETUM_FIXED_PROJECTIONS}" PARENT_SCOPE)
  set(KINETUM_FIXED_PROJECTION_COUNT "${KINETUM_FIXED_PROJECTION_COUNT}" PARENT_SCOPE)
endfunction()

# A root association proves the complete installed tree equals its source.
# It carries no enumerated file list into the ELF.
function(kinetum_stage_sdk_tree input destination relative_source)
  install(DIRECTORY "${input}/" DESTINATION "${destination}"
    COMPONENT KinetumSDK EXCLUDE_FROM_ALL)
  string(APPEND KINETUM_TREE_PROJECTIONS
    "  {\"${relative_source}\", \"${destination}\"},\n")
  math(EXPR KINETUM_TREE_PROJECTION_COUNT "${KINETUM_TREE_PROJECTION_COUNT} + 1")
  set(KINETUM_TREE_PROJECTIONS "${KINETUM_TREE_PROJECTIONS}" PARENT_SCOPE)
  set(KINETUM_TREE_PROJECTION_COUNT "${KINETUM_TREE_PROJECTION_COUNT}" PARENT_SCOPE)
endfunction()

foreach(package_document IN ITEMS runtime_README.md sdk_README.md)
  configure_file("tooling/release/packaging/${package_document}.in"
    "${KINETUM_RELEASE_GENERATED_DIR}/${package_document}" @ONLY)
endforeach()
configure_file("sdk/kinetum.pc.in" "${KINETUM_RELEASE_GENERATED_DIR}/kinetum.pc" @ONLY)
configure_file("cmake/KinetumConfig.cmake.in" "${KINETUM_RELEASE_GENERATED_DIR}/KinetumConfig.cmake" @ONLY)

# Package production and SDK consumers use the same complete development tree.
kinetum_stage_sdk_tree("${KINETUM_PUBLIC_HEADER_ROOT}" sdk/include/kinetum
  include/kinetum)
kinetum_stage_sdk_tree("${CMAKE_CURRENT_SOURCE_DIR}/examples" sdk/examples
  examples)
kinetum_stage_file(SDK "${KINETUM_RELEASE_GENERATED_DIR}/kinetum.pc"
  sdk/lib/pkgconfig/kinetum.pc "${CMAKE_CURRENT_SOURCE_DIR}/sdk/kinetum.pc.in")
kinetum_stage_file(SDK "${KINETUM_RELEASE_GENERATED_DIR}/KinetumConfig.cmake"
  sdk/lib/cmake/Kinetum/KinetumConfig.cmake "${CMAKE_CURRENT_SOURCE_DIR}/cmake/KinetumConfig.cmake.in")
kinetum_stage_file(SDK "${CMAKE_CURRENT_SOURCE_DIR}/cmake/KinetumModulePolicy.cmake"
  sdk/lib/cmake/Kinetum/KinetumModulePolicy.cmake "${CMAKE_CURRENT_SOURCE_DIR}/cmake/KinetumModulePolicy.cmake")

foreach(product IN ITEMS RUNTIME SDK)
  string(TOLOWER "${product}" product_directory)
  foreach(legal IN ITEMS VERSION LICENSE NOTICE)
    kinetum_stage_file(${product} "${CMAKE_CURRENT_SOURCE_DIR}/${legal}"
      "${product_directory}/${legal}" "${CMAKE_CURRENT_SOURCE_DIR}/${legal}")
  endforeach()
  kinetum_stage_file(${product} "${KINETUM_RELEASE_GENERATED_DIR}/${product_directory}_README.md"
    "${product_directory}/README.md"
    "${CMAKE_CURRENT_SOURCE_DIR}/tooling/release/packaging/${product_directory}_README.md.in")
endforeach()
kinetum_stage_file(RUNTIME
  "${CMAKE_CURRENT_SOURCE_DIR}/tooling/release/packaging/runtime_THIRD_PARTY_NOTICES.md"
  "runtime/THIRD_PARTY_NOTICES.md"
  "${CMAKE_CURRENT_SOURCE_DIR}/tooling/release/packaging/runtime_THIRD_PARTY_NOTICES.md")
install(DIRECTORY DESTINATION sdk/share/kinetum/release
  COMPONENT KinetumSDK EXCLUDE_FROM_ALL)
install(TARGETS kinetum_package EXCLUDE_FROM_ALL
  RUNTIME DESTINATION . COMPONENT KinetumPackageEnvelope)

foreach(release_image IN LISTS KINETUM_RUNTIME_EXECUTABLE_TARGETS)
  target_sources(${release_image} PRIVATE $<TARGET_OBJECTS:kinetum_release_version_marker>)
  target_link_options(${release_image} PRIVATE "LINKER:--undefined=kinetum_release_version_marker")
endforeach()
target_sources(kinetum_package PRIVATE $<TARGET_OBJECTS:kinetum_release_version_marker>)
target_link_options(kinetum_package PRIVATE "LINKER:--undefined=kinetum_release_version_marker")

if(KINETUM_BUILD_MODULES)
  foreach(release_image IN LISTS KINETUM_BUILTIN_MODULE_TARGETS KINETUM_PRODUCTION_PROVIDER_TARGETS)
    target_sources(${release_image} PRIVATE $<TARGET_OBJECTS:kinetum_release_version_marker>)
    target_link_options(${release_image} PRIVATE "LINKER:--undefined=kinetum_release_version_marker")
  endforeach()
  add_custom_target(kinetum_release DEPENDS
    ${KINETUM_RUNTIME_EXECUTABLE_TARGETS} ${KINETUM_BUILTIN_MODULE_TARGETS}
    ${KINETUM_PRODUCTION_PROVIDER_TARGETS} kinetum_package)
  install(TARGETS ${KINETUM_RUNTIME_EXECUTABLE_TARGETS} EXCLUDE_FROM_ALL
    RUNTIME DESTINATION runtime/bin COMPONENT KinetumRuntimePayload)
  install(TARGETS ${KINETUM_BUILTIN_MODULE_TARGETS} EXCLUDE_FROM_ALL
    LIBRARY DESTINATION runtime/lib/modules COMPONENT KinetumRuntimePayload)
  install(TARGETS ${KINETUM_PRODUCTION_PROVIDER_TARGETS} EXCLUDE_FROM_ALL
    LIBRARY DESTINATION runtime/lib/kinetum/providers COMPONENT KinetumRuntimePayload)
endif()
install(DIRECTORY DESTINATION runtime/share/kinetum/providers
  COMPONENT KinetumRuntimePayload EXCLUDE_FROM_ALL)
install(DIRECTORY DESTINATION runtime/share/kinetum/release
  COMPONENT KinetumRuntimePayload EXCLUDE_FROM_ALL)

set(KINETUM_DPDK_RUNTIME_LICENSE_ROOT "${KINETUM_DPDK_DEPENDENCY_ROOT}/share/licenses/KinetumDPDK")
foreach(dpdk_license IN ITEMS README bsd-2-clause.txt bsd-3-clause.txt
    exceptions.txt gpl-2.0.txt isc.txt lgpl-2.1.txt mit.txt)
  kinetum_stage_file(RUNTIME "${KINETUM_DPDK_RUNTIME_LICENSE_ROOT}/dpdk/${dpdk_license}"
    "runtime/share/licenses/KinetumDPDK/dpdk/${dpdk_license}" "")
endforeach()
kinetum_stage_file(RUNTIME "${KINETUM_DPDK_RUNTIME_LICENSE_ROOT}/DPDK_STATIC_CLOSURE_NOTICE.txt"
  runtime/share/licenses/KinetumDPDK/DPDK_STATIC_CLOSURE_NOTICE.txt "")

file(GENERATE OUTPUT "${KINETUM_RELEASE_GENERATED_DIR}/package_projections.inc"
  CONTENT "constexpr std::array<fixed_projection, ${KINETUM_FIXED_PROJECTION_COUNT}> FIXED_PROJECTIONS{{\n${KINETUM_FIXED_PROJECTIONS}}};\nconstexpr std::array<tree_projection, ${KINETUM_TREE_PROJECTION_COUNT}> TREE_PROJECTIONS{{\n${KINETUM_TREE_PROJECTIONS}}};\n")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tooling/release/packaging/install.sh.in")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/tooling/release/packaging/install.sh.in" KINETUM_INSTALL_BOOTSTRAP)
file(GENERATE OUTPUT "${KINETUM_RELEASE_GENERATED_DIR}/install_bootstrap.inc"
  CONTENT "constexpr std::string_view INSTALL_BOOTSTRAP = R\"KINETUM_INSTALL(${KINETUM_INSTALL_BOOTSTRAP})KINETUM_INSTALL\";\n")

add_subdirectory(validation)

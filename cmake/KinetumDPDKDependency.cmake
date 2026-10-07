# Source-authoritative import of the exact Kinetum DPDK build dependency.
#
# The generated package config is executable CMake. Verify every package byte
# through the source producer before evaluating that config, then import its
# sole target without reconstructing native linkage in the platform build.

include_guard(GLOBAL)

function(kinetum_require_dpdk_dependency SOURCE_ROOT)
  if(NOT IS_ABSOLUTE "${SOURCE_ROOT}")
    message(FATAL_ERROR
      "kinetum_require_dpdk_dependency requires an absolute source root")
  endif()

  set(_kinetum_dpdk_policy_files
    third_party/dpdk/dependency_manifest.json
    third_party/dpdk/i40e_close.patch
    third_party/dpdk/KinetumDPDKConfig.cmake.in
    third_party/dpdk/KinetumDPDKConfigVersion.cmake.in
    tooling/environment/build_kinetum_dpdk.py
  )
  foreach(_kinetum_dpdk_policy_file IN LISTS _kinetum_dpdk_policy_files)
    set(_kinetum_dpdk_policy_path
      "${SOURCE_ROOT}/${_kinetum_dpdk_policy_file}")
    if(NOT EXISTS "${_kinetum_dpdk_policy_path}" OR
       IS_DIRECTORY "${_kinetum_dpdk_policy_path}")
      message(FATAL_ERROR
        "KinetumDPDK policy input is missing: ${_kinetum_dpdk_policy_file}")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
      "${_kinetum_dpdk_policy_path}")
  endforeach()

  find_package(Python3 3.12...<3.13 REQUIRED COMPONENTS Interpreter)
  set(_kinetum_dpdk_previous_default "")
  if(DEFINED _KINETUM_DPDK_DEPENDENCY_DEFAULT_ROOT)
    set(_kinetum_dpdk_previous_default
      "${_KINETUM_DPDK_DEPENDENCY_DEFAULT_ROOT}")
  endif()
  if(NOT DEFINED KINETUM_DPDK_DEPENDENCY_ROOT OR
     "${KINETUM_DPDK_DEPENDENCY_ROOT}" STREQUAL
       "${_kinetum_dpdk_previous_default}")
    execute_process(
      COMMAND
        "${Python3_EXECUTABLE}" -I -B
        "${SOURCE_ROOT}/tooling/environment/build_kinetum_dpdk.py"
        --print-default-prefix
      RESULT_VARIABLE _kinetum_dpdk_prefix_result
      OUTPUT_VARIABLE _kinetum_dpdk_default_root
      ERROR_VARIABLE _kinetum_dpdk_prefix_error
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_STRIP_TRAILING_WHITESPACE
    )
    if(NOT "${_kinetum_dpdk_prefix_result}" STREQUAL "0")
      message(FATAL_ERROR
        "KinetumDPDK default-root derivation failed.\n"
        "${_kinetum_dpdk_prefix_error}")
    endif()
    set(KINETUM_DPDK_DEPENDENCY_ROOT "${_kinetum_dpdk_default_root}"
      CACHE PATH "Root of the exact KinetumDPDK dependency package" FORCE)
    set(_KINETUM_DPDK_DEPENDENCY_DEFAULT_ROOT
      "${_kinetum_dpdk_default_root}" CACHE INTERNAL
      "Last source-derived KinetumDPDK package root" FORCE)
  endif()
  if(NOT IS_ABSOLUTE "${KINETUM_DPDK_DEPENDENCY_ROOT}")
    message(FATAL_ERROR
      "KINETUM_DPDK_DEPENDENCY_ROOT must be one exact absolute path")
  endif()

  execute_process(
    COMMAND
      "${Python3_EXECUTABLE}" -I -B
      "${SOURCE_ROOT}/tooling/environment/build_kinetum_dpdk.py"
      --prefix "${KINETUM_DPDK_DEPENDENCY_ROOT}"
      --verify-only
    RESULT_VARIABLE _kinetum_dpdk_verify_result
    OUTPUT_QUIET
    ERROR_VARIABLE _kinetum_dpdk_verify_error
    ERROR_STRIP_TRAILING_WHITESPACE
  )
  if(NOT "${_kinetum_dpdk_verify_result}" STREQUAL "0")
    message(FATAL_ERROR
      "KinetumDPDK verification failed before package-config evaluation. "
      "Produce the exact dependency with tooling/environment/build_kinetum_dpdk.py.\n"
      "${_kinetum_dpdk_verify_error}")
  endif()

  # This exact config was verified above. Package discovery could instead use
  # a cached directory or redirect and evaluate different, unchecked bytes.
  include(
    "${KINETUM_DPDK_DEPENDENCY_ROOT}/lib/cmake/KinetumDPDK/KinetumDPDKConfig.cmake"
  )
  if(NOT KinetumDPDK_FOUND)
    message(FATAL_ERROR
      "Verified KinetumDPDK package rejected this build: ${KinetumDPDK_NOT_FOUND_MESSAGE}")
  endif()
  if(NOT TARGET KinetumDPDK::StaticComponentClosure)
    message(FATAL_ERROR
      "Verified KinetumDPDK package did not publish its exact imported target")
  endif()
  if(NOT DEFINED KinetumDPDK_VERSION OR
     "${KinetumDPDK_VERSION}" STREQUAL "")
    message(FATAL_ERROR
      "Verified KinetumDPDK package did not publish its exact version identity")
  endif()
  set(KinetumDPDK_VERSION "${KinetumDPDK_VERSION}" PARENT_SCOPE)
endfunction()

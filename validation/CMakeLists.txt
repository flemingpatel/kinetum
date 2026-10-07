# Private validation wheel contents and native helper identity.
find_package(Python3 3.12...<3.13 REQUIRED COMPONENTS Interpreter)
set(KINETUM_VALIDATION_EXECUTABLE_TARGETS kinetum_tap_analyzer kinetum_tap_sender)
set(KINETUM_VALIDATION_WHEEL_PLATFORM "linux_${CMAKE_SYSTEM_PROCESSOR}")
set(KINETUM_VALIDATION_DATA_DIR "validation/kinetum_validation/data")
set(KINETUM_VALIDATION_BINARY_MANIFEST "")
foreach(validation_target IN LISTS KINETUM_VALIDATION_EXECUTABLE_TARGETS)
  target_sources(${validation_target} PRIVATE $<TARGET_OBJECTS:kinetum_release_version_marker>)
  target_link_options(${validation_target} PRIVATE "LINKER:--undefined=kinetum_release_version_marker")
  get_target_property(output_name ${validation_target} OUTPUT_NAME)
  if(NOT output_name)
    set(output_name "${validation_target}")
  endif()
  string(APPEND KINETUM_VALIDATION_BINARY_MANIFEST
    "  bin/${output_name}${CMAKE_EXECUTABLE_SUFFIX}\n")
endforeach()
foreach(template IN ITEMS pyproject.toml hatch_build.py README.md MANIFEST.txt)
  configure_file("${template}.in" "${CMAKE_CURRENT_BINARY_DIR}/${template}" @ONLY)
endforeach()
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pyproject.toml" "${CMAKE_CURRENT_BINARY_DIR}/hatch_build.py"
  DESTINATION validation COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL)
install(TARGETS ${KINETUM_VALIDATION_EXECUTABLE_TARGETS} EXCLUDE_FROM_ALL
  RUNTIME DESTINATION "${KINETUM_VALIDATION_DATA_DIR}/bin" COMPONENT KinetumValidationKit)
install(PROGRAMS "${PROJECT_SOURCE_DIR}/scripts/dpdk_hugepages.sh"
  "${PROJECT_SOURCE_DIR}/scripts/install_trex_ubuntu.sh"
  DESTINATION "${KINETUM_VALIDATION_DATA_DIR}/scripts" COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/validation/kinetum_validation"
  "${PROJECT_SOURCE_DIR}/validation/kinetum_benchmark"
  DESTINATION validation COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL
  PATTERN "__pycache__" EXCLUDE PATTERN "*.pyc" EXCLUDE PATTERN "*.pyo" EXCLUDE)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/validation/cloudlab"
  DESTINATION "${KINETUM_VALIDATION_DATA_DIR}" COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL
  PATTERN "__pycache__" EXCLUDE PATTERN "*.pyc" EXCLUDE PATTERN "*.pyo" EXCLUDE)
install(DIRECTORY "${PROJECT_SOURCE_DIR}/examples/" DESTINATION "${KINETUM_VALIDATION_DATA_DIR}/examples"
  COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL)
install(FILES "${PROJECT_SOURCE_DIR}/docs/VALIDATION_GUIDE.md"
  DESTINATION "${KINETUM_VALIDATION_DATA_DIR}/docs" COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL)
install(FILES "${PROJECT_SOURCE_DIR}/VERSION" "${PROJECT_SOURCE_DIR}/LICENSE" "${PROJECT_SOURCE_DIR}/NOTICE"
  THIRD_PARTY_NOTICES.md "${CMAKE_CURRENT_BINARY_DIR}/README.md"
  DESTINATION "${KINETUM_VALIDATION_DATA_DIR}" COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/MANIFEST.txt" DESTINATION "${KINETUM_VALIDATION_DATA_DIR}"
  RENAME VALIDATION_MANIFEST.txt COMPONENT KinetumValidationKit EXCLUDE_FROM_ALL)
add_custom_target(kinetum_validation_kit
  COMMAND "${CMAKE_COMMAND}" -Dbuild_root=${PROJECT_BINARY_DIR}
    -Dpython=${Python3_EXECUTABLE}
    -P "${CMAKE_CURRENT_SOURCE_DIR}/build_wheel.cmake"
  DEPENDS ${KINETUM_VALIDATION_EXECUTABLE_TARGETS}
  VERBATIM)

# One CTest fixture prepares the complete SDK files for native consumers.
cmake_minimum_required(VERSION 3.28)
if(NOT DEFINED build_root OR NOT IS_ABSOLUTE "${build_root}")
  message(FATAL_ERROR "SDK fixture requires its owning build root")
endif()
set(prefix "${build_root}/sdk-consumer-prefix")
file(REMOVE_RECURSE "${prefix}" "${build_root}/sdk-consumer-builds")
execute_process(COMMAND "${CMAKE_COMMAND}" --install "${build_root}" --config Release
  --prefix "${prefix}" --component KinetumSDK RESULT_VARIABLE result)
if(NOT result STREQUAL "0")
  message(FATAL_ERROR "SDK staging failed: ${result}")
endif()

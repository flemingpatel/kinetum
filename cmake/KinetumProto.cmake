# Protobuf + gRPC generation through the dependency targets admitted by the
# top-level build. System packages and explicit FetchContent builds publish
# the same target names; generation performs no independent tool discovery.

function(kinetum_generate_proto TARGET_NAME)
  set(options NO_GRPC)
  set(oneValueArgs PROTO_DIR OUT_DIR)
  set(multiValueArgs PROTOS)
  cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

  if(NOT ARG_PROTO_DIR)
    message(FATAL_ERROR "kinetum_generate_proto: PROTO_DIR is required")
  endif()
  if(NOT ARG_OUT_DIR)
    message(FATAL_ERROR "kinetum_generate_proto: OUT_DIR is required")
  endif()

  file(MAKE_DIRECTORY "${ARG_OUT_DIR}")

  set(GEN_SRCS "")
  set(GEN_HDRS "")

  # protoc needs the selected dependency's schema roots independently of C++ includes.
  set(PROTOC_IMPORT_ARGS "--proto_path=${ARG_PROTO_DIR}")
  foreach(PROTOBUF_IMPORT_DIR IN LISTS KINETUM_PROTOBUF_IMPORT_DIRS)
    list(APPEND PROTOC_IMPORT_ARGS "--proto_path=${PROTOBUF_IMPORT_DIR}")
  endforeach()

  foreach(PROTO ${ARG_PROTOS})
    get_filename_component(PROTO_ABS "${PROTO}" ABSOLUTE BASE_DIR "${ARG_PROTO_DIR}")
    get_filename_component(PROTO_DIRNAME "${PROTO}" DIRECTORY)
    get_filename_component(PROTO_NAME "${PROTO}" NAME_WE)

    # Preserve directory structure under OUT_DIR
    set(OUT_SUBDIR "${ARG_OUT_DIR}/${PROTO_DIRNAME}")
    file(MAKE_DIRECTORY "${OUT_SUBDIR}")

    set(PB_CC "${OUT_SUBDIR}/${PROTO_NAME}.pb.cc")
    set(PB_H  "${OUT_SUBDIR}/${PROTO_NAME}.pb.h")
    set(DEPFILE "${OUT_SUBDIR}/${PROTO_NAME}.d")
    set(COMMAND_OUTPUTS "${PB_CC}" "${PB_H}")
    set(PROTOC_ARGS
      ${PROTOC_IMPORT_ARGS}
      "--cpp_out=${ARG_OUT_DIR}"
      "--dependency_out=${DEPFILE}"
    )

    if(NOT ARG_NO_GRPC)
      set(GRPC_CC "${OUT_SUBDIR}/${PROTO_NAME}.grpc.pb.cc")
      set(GRPC_H  "${OUT_SUBDIR}/${PROTO_NAME}.grpc.pb.h")
      list(APPEND COMMAND_OUTPUTS "${GRPC_CC}" "${GRPC_H}")
      list(APPEND PROTOC_ARGS
        "--grpc_out=${ARG_OUT_DIR}"
        "--plugin=protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
      )
    endif()
    list(APPEND PROTOC_ARGS "${PROTO_ABS}")

    set(COMMAND_DEPENDS "${PROTO_ABS}" protobuf::protoc)
    if(NOT ARG_NO_GRPC)
      list(APPEND COMMAND_DEPENDS gRPC::grpc_cpp_plugin)
    endif()

    if(ARG_NO_GRPC)
      set(GENERATION_COMMENT "Generating protobuf sources for ${PROTO}")
    else()
      set(GENERATION_COMMENT "Generating protobuf/grpc sources for ${PROTO}")
    endif()

    # protoc owns the transitive import graph; imported schema edits must also
    # regenerate every consumer, not only the edited schema's own output.
    add_custom_command(
      OUTPUT ${COMMAND_OUTPUTS}
      COMMAND "$<TARGET_FILE:protobuf::protoc>" ${PROTOC_ARGS}
      DEPENDS ${COMMAND_DEPENDS}
      DEPFILE "${DEPFILE}"
      COMMENT "${GENERATION_COMMENT}"
      VERBATIM
    )

    list(APPEND GEN_SRCS "${PB_CC}")
    list(APPEND GEN_HDRS "${PB_H}")
    if(NOT ARG_NO_GRPC)
      list(APPEND GEN_SRCS "${GRPC_CC}")
      list(APPEND GEN_HDRS "${GRPC_H}")
    endif()
  endforeach()

  add_library(${TARGET_NAME} STATIC ${GEN_SRCS} ${GEN_HDRS})
  # Export both the nested gen/ directory (for "kinetum/..." includes) and its
  # parent (for "gen/kinetum/..." includes used in some source files). Module
  # protos may use OUT_DIR=${CMAKE_BINARY_DIR}; in that case no parent include
  # is needed and the source tree must not be marked SYSTEM.
  get_filename_component(ARG_OUT_DIR_REAL "${ARG_OUT_DIR}" REALPATH)
  get_filename_component(ARG_OUT_DIR_PARENT "${ARG_OUT_DIR_REAL}" DIRECTORY)
  get_filename_component(CMAKE_BINARY_DIR_REAL "${CMAKE_BINARY_DIR}" REALPATH)
  get_filename_component(PROJECT_BINARY_DIR_REAL "${PROJECT_BINARY_DIR}" REALPATH)
  get_filename_component(CMAKE_SOURCE_DIR_REAL "${CMAKE_SOURCE_DIR}" REALPATH)
  get_filename_component(PROJECT_SOURCE_DIR_REAL "${PROJECT_SOURCE_DIR}" REALPATH)

  set(KINETUM_PROTO_INCLUDE_DIRS "${ARG_OUT_DIR_REAL}")
  if(NOT ARG_OUT_DIR_REAL STREQUAL CMAKE_BINARY_DIR_REAL
     AND NOT ARG_OUT_DIR_REAL STREQUAL PROJECT_BINARY_DIR_REAL
     AND NOT ARG_OUT_DIR_PARENT STREQUAL CMAKE_SOURCE_DIR_REAL
     AND NOT ARG_OUT_DIR_PARENT STREQUAL PROJECT_SOURCE_DIR_REAL)
    list(APPEND KINETUM_PROTO_INCLUDE_DIRS "${ARG_OUT_DIR_PARENT}")
  endif()
  target_include_directories(${TARGET_NAME} SYSTEM PUBLIC ${KINETUM_PROTO_INCLUDE_DIRS})
endfunction()

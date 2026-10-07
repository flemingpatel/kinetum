# Kinetum build options

option(KINETUM_ENABLE_TESTS "Enable unit tests" OFF)
option(KINETUM_ENABLE_MLIR "Enable MLIR-based Axiom frontend (requires LLVM/MLIR dev packages)" OFF)
option(KINETUM_FETCH_DEPS "Fetch the pinned gRPC, Protobuf, and test dependencies (requires internet)" OFF)
option(KINETUM_ENABLE_TLS "Enable TLS transport/certificate helpers (OpenSSL::Crypto remains required)" ON)

option(KINETUM_ENABLE_MLIR_DIALECT "Build/register Axiom MLIR dialect (requires MLIR frontend)"
       "${KINETUM_ENABLE_MLIR}")

if(KINETUM_ENABLE_MLIR_DIALECT AND NOT KINETUM_ENABLE_MLIR)
  message(FATAL_ERROR
    "KINETUM_ENABLE_MLIR_DIALECT=ON requires KINETUM_ENABLE_MLIR=ON")
endif()

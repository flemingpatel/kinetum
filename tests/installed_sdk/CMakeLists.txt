cmake_minimum_required(VERSION 3.28)

# This consumer project has no import or include edge into platform source.
# The owner supplies either an in-tree SDK stage or a distributed SDK root.
# The requested compiler family is checked against CMake's actual probes;
# an executable named gcc or clang is not evidence of its compiler identity.
if(NOT DEFINED KINETUM_SDK_EXPECTED_COMPILER_ID
   OR NOT KINETUM_SDK_EXPECTED_COMPILER_ID MATCHES "^(GNU|Clang)$")
  message(FATAL_ERROR "SDK qualification requires KINETUM_SDK_EXPECTED_COMPILER_ID=GNU or Clang")
endif()
foreach(environment_name IN ITEMS CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
    OBJC_INCLUDE_PATH CFLAGS CXXFLAGS CPPFLAGS LDFLAGS LIBRARY_PATH
    CMAKE_PREFIX_PATH CMAKE_MODULE_PATH CMAKE_TOOLCHAIN_FILE
    COMPILER_PATH GCC_EXEC_PREFIX CCC_OVERRIDE_OPTIONS PKG_CONFIG_PATH PKG_CONFIG_LIBDIR)
  unset(ENV{${environment_name}})
endforeach()
project(kinetum_installed_sdk_consumers LANGUAGES C CXX)
if(NOT CMAKE_C_COMPILER_ID STREQUAL KINETUM_SDK_EXPECTED_COMPILER_ID
   OR NOT CMAKE_CXX_COMPILER_ID STREQUAL KINETUM_SDK_EXPECTED_COMPILER_ID)
  message(FATAL_ERROR
    "SDK qualification requested ${KINETUM_SDK_EXPECTED_COMPILER_ID}, detected C=${CMAKE_C_COMPILER_ID}, CXX=${CMAKE_CXX_COMPILER_ID}")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT DEFINED KINETUM_SDK_ROOT OR NOT IS_ABSOLUTE "${KINETUM_SDK_ROOT}")
  message(FATAL_ERROR "Provide one exact installed SDK root")
endif()
file(REAL_PATH "${KINETUM_SDK_ROOT}" sdk_root)
if(NOT sdk_root STREQUAL KINETUM_SDK_ROOT)
  message(FATAL_ERROR "Installed SDK root contains indirection")
endif()
set(CMAKE_FIND_USE_PACKAGE_REGISTRY FALSE)
set(CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY FALSE)
set(Kinetum_DIR "${sdk_root}/lib/cmake/Kinetum")
find_package(Kinetum CONFIG REQUIRED
  PATHS "${sdk_root}/lib/cmake/Kinetum" NO_DEFAULT_PATH)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ELF REQUIRED IMPORTED_TARGET libelf)
set(ENV{PKG_CONFIG_PATH} "${sdk_root}/lib/pkgconfig")
set(ENV{PKG_CONFIG_LIBDIR} "${sdk_root}/lib/pkgconfig")
pkg_check_modules(SDK_C REQUIRED IMPORTED_TARGET kinetum)
foreach(interface IN ITEMS Kinetum::SDK PkgConfig::SDK_C)
  get_target_property(includes ${interface} INTERFACE_INCLUDE_DIRECTORIES)
  if(NOT includes)
    message(FATAL_ERROR "SDK consumer interface omitted its include root")
  endif()
  foreach(include IN LISTS includes)
    file(REAL_PATH "${include}" exact_include)
    if(NOT exact_include STREQUAL "${sdk_root}/include")
      message(FATAL_ERROR "SDK consumer interface refers outside the selected SDK: ${include}")
    endif()
  endforeach()
endforeach()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_SKIP_RPATH TRUE)
add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror)
add_library(sdk_static_support STATIC support.c)
add_library(sdk_dependency SHARED dependency.cpp)
target_link_libraries(sdk_dependency PRIVATE Kinetum::ModuleDependency)
add_library(sdk_c_module SHARED module.c)
target_link_libraries(sdk_c_module PRIVATE PkgConfig::SDK_C sdk_static_support)
add_library(sdk_cpp_module SHARED module.cpp)
target_link_libraries(sdk_cpp_module PRIVATE Kinetum::SDK sdk_static_support sdk_dependency)

add_executable(sdk_inspect inspect.cpp)
target_include_directories(sdk_inspect PRIVATE "${sdk_root}/include")
target_link_libraries(sdk_inspect PRIVATE PkgConfig::ELF ${CMAKE_DL_LIBS})

# A successful plain object compile precedes each expected link rejection.
# The object carries a default-visible strong import; only link policy rejects it.
add_library(sdk_missing_import OBJECT EXCLUDE_FROM_ALL support.c)
target_compile_definitions(sdk_missing_import PRIVATE KINETUM_SDK_FIXTURE_UNRESOLVED=1)
foreach(interface IN ITEMS SDK ModuleDependency)
  add_library(rejected_${interface} SHARED EXCLUDE_FROM_ALL $<TARGET_OBJECTS:sdk_missing_import>)
  set_target_properties(rejected_${interface} PROPERTIES LINKER_LANGUAGE C)
  target_link_libraries(rejected_${interface} PRIVATE Kinetum::${interface})
endforeach()
add_library(rejected_pkgconfig SHARED EXCLUDE_FROM_ALL $<TARGET_OBJECTS:sdk_missing_import>)
set_target_properties(rejected_pkgconfig PROPERTIES LINKER_LANGUAGE C)
target_link_libraries(rejected_pkgconfig PRIVATE PkgConfig::SDK_C)

enable_testing()
add_test(NAME c11_module COMMAND sdk_inspect "$<TARGET_FILE:sdk_c_module>")
add_test(NAME cpp20_module COMMAND sdk_inspect "$<TARGET_FILE:sdk_cpp_module>" "$<TARGET_FILE:sdk_dependency>")
foreach(interface IN ITEMS SDK ModuleDependency)
  set(rejection_targets rejected_${interface})
  if(interface STREQUAL "SDK")
    list(APPEND rejection_targets rejected_pkgconfig)
  endif()
  add_test(NAME ${interface}_rejects_unresolved_import
    COMMAND "${CMAKE_COMMAND}" -Dbuild_root=${CMAKE_CURRENT_BINARY_DIR}
      "-Dtargets=${rejection_targets}" -Dconfiguration=$<CONFIG>
      -P "${CMAKE_CURRENT_SOURCE_DIR}/expect_link_rejection.cmake")
  set_tests_properties(${interface}_rejects_unresolved_import PROPERTIES RUN_SERIAL TRUE TIMEOUT 120)
endforeach()
set_tests_properties(c11_module cpp20_module PROPERTIES TIMEOUT 30)

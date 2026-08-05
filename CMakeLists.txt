cmake_minimum_required(VERSION 3.22)

# ---------------------------------------------------------------------------
# Project version is kept in the VERSION file so that CMake, CITATION.cff,
# packaging and the compiled binaries cannot drift apart.
# ---------------------------------------------------------------------------
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" PQTLS_VERSION_RAW)
string(STRIP "${PQTLS_VERSION_RAW}" PQTLS_VERSION_RAW)
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" PQTLS_VERSION_CORE "${PQTLS_VERSION_RAW}")

project(pqtls-lab
    VERSION ${PQTLS_VERSION_CORE}
    DESCRIPTION "Crypto-agile TLS 1.3 research prototype for hybrid post-quantum key establishment"
    HOMEPAGE_URL "https://github.com/nbermparis/pqtls-lab"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(PQTLS_BUILD_TESTS      "Build unit tests"                          ON)
option(PQTLS_ENABLE_WERROR    "Treat compiler warnings as errors"         OFF)
option(PQTLS_ENABLE_HARDENING "Enable link/compile hardening flags"       ON)
option(PQTLS_ENABLE_ASAN      "Enable AddressSanitizer"                   OFF)
option(PQTLS_ENABLE_UBSAN     "Enable UndefinedBehaviorSanitizer"         OFF)
option(PQTLS_ENABLE_TSAN      "Enable ThreadSanitizer (mutually exclusive with ASan)" OFF)
option(PQTLS_ENABLE_CLANG_TIDY "Run clang-tidy as part of the build"      OFF)

# Post-quantum profiles are gated on the *detected* OpenSSL, never assumed.
set(PQTLS_MIN_OPENSSL_FOR_PQ "3.5.0" CACHE STRING
    "Minimum OpenSSL version required before PQ profiles may be enabled")

include(CompilerWarnings)
include(Sanitizers)

# ---------------------------------------------------------------------------
# Dependencies
#
# Every dependency is pinned to an exact tag. FetchContent is only used when
# the dependency is not already installed on the system, and never updates
# silently: FETCHCONTENT_UPDATES_DISCONNECTED keeps builds reproducible.
# ---------------------------------------------------------------------------
include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)
set(FETCHCONTENT_QUIET OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS SSL Crypto)
include(OpenSSLFeatures)   # must come after find_package(OpenSSL)

find_package(Threads REQUIRED)

# --- nlohmann/json (MIT) ---------------------------------------------------
find_package(nlohmann_json 3.11 QUIET)
if(NOT nlohmann_json_FOUND)
    message(STATUS "nlohmann_json not found on system; fetching pinned v3.11.3")
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        9cca280a4d0ccf0c08f47a99aa71d1b0e52f8d03  # v3.11.3
        GIT_SHALLOW    FALSE)
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# --- yaml-cpp (MIT) --------------------------------------------------------
find_package(yaml-cpp 0.8 QUIET)
if(NOT yaml-cpp_FOUND)
    message(STATUS "yaml-cpp not found on system; fetching pinned 0.8.0")
    FetchContent_Declare(yaml-cpp
        GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
        GIT_TAG        f7320141120f720aecc4c32be25586e7da9eb978  # 0.8.0
        GIT_SHALLOW    FALSE)
    set(YAML_CPP_BUILD_TESTS OFF CACHE INTERNAL "")
    set(YAML_CPP_BUILD_TOOLS OFF CACHE INTERNAL "")
    set(YAML_BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
    FetchContent_MakeAvailable(yaml-cpp)
endif()

# --- spdlog (MIT) ----------------------------------------------------------
find_package(spdlog 1.13 QUIET)
if(NOT spdlog_FOUND)
    message(STATUS "spdlog not found on system; fetching pinned v1.14.1")
    FetchContent_Declare(spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG        27cb4c76708608465c413f6d0e6b8d99a4d84302  # v1.14.1
        GIT_SHALLOW    FALSE)
    set(SPDLOG_BUILD_EXAMPLE OFF CACHE INTERNAL "")
    set(SPDLOG_BUILD_TESTS OFF CACHE INTERNAL "")
    FetchContent_MakeAvailable(spdlog)
endif()

# ---------------------------------------------------------------------------
# Generated build information header
# ---------------------------------------------------------------------------
find_package(Git QUIET)
set(PQTLS_GIT_COMMIT "unknown")
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short=12 HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE PQTLS_GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(PQTLS_GIT_COMMIT STREQUAL "")
        set(PQTLS_GIT_COMMIT "unknown")
    endif()
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_info.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/pqtls/build_info.hpp"
    @ONLY)

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
add_library(pqtls_core STATIC
    src/common/application_protocol.cpp
    src/common/capabilities.cpp
    src/common/config.cpp
    src/common/error.cpp
    src/common/metrics.cpp
    src/common/security_profile.cpp
    src/common/tls_context.cpp
    src/common/transport.cpp)

target_include_directories(pqtls_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_BINARY_DIR}/generated")

target_link_libraries(pqtls_core
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        Threads::Threads
    PRIVATE
        yaml-cpp::yaml-cpp)

pqtls_set_warnings(pqtls_core)
pqtls_enable_sanitizers(pqtls_core)

if(PQTLS_OPENSSL_HAS_PQ_GROUPS)
    target_compile_definitions(pqtls_core PUBLIC PQTLS_OPENSSL_HAS_PQ_GROUPS=1)
else()
    target_compile_definitions(pqtls_core PUBLIC PQTLS_OPENSSL_HAS_PQ_GROUPS=0)
endif()

if(PQTLS_ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy clang-tidy-18 clang-tidy-17)
    if(CLANG_TIDY_EXE)
        set_target_properties(pqtls_core PROPERTIES
            CXX_CLANG_TIDY "${CLANG_TIDY_EXE};--quiet")
    else()
        message(WARNING "PQTLS_ENABLE_CLANG_TIDY=ON but clang-tidy was not found")
    endif()
endif()

# ---------------------------------------------------------------------------
# Executables
# ---------------------------------------------------------------------------
add_executable(pqtls-server src/server/main.cpp src/server/server.cpp)
target_link_libraries(pqtls-server PRIVATE pqtls_core)
pqtls_set_warnings(pqtls-server)
pqtls_enable_sanitizers(pqtls-server)

add_executable(pqtls-client src/client/main.cpp src/client/client.cpp)
target_link_libraries(pqtls-client PRIVATE pqtls_core)
pqtls_set_warnings(pqtls-client)
pqtls_enable_sanitizers(pqtls-client)

# ---------------------------------------------------------------------------
# Hardening
#
# Applied only where the toolchain actually accepts the flag. See
# docs/build-guide.md for the platform dependency notes.
# ---------------------------------------------------------------------------
if(PQTLS_ENABLE_HARDENING)
    include(CheckCXXCompilerFlag)
    foreach(target pqtls_core pqtls-server pqtls-client)
        if(NOT MSVC)
            target_compile_options(${target} PRIVATE
                -fstack-protector-strong
                $<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=2>)
        endif()
    endforeach()

    if(UNIX AND NOT APPLE)
        foreach(target pqtls-server pqtls-client)
            target_link_options(${target} PRIVATE
                -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
            set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)
        endforeach()
    endif()
endif()

install(TARGETS pqtls-server pqtls-client RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(PQTLS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Configuration summary
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "==================== pqtls-lab configuration ====================")
message(STATUS "  Version               : ${PQTLS_VERSION_RAW}")
message(STATUS "  Git commit            : ${PQTLS_GIT_COMMIT}")
message(STATUS "  Build type            : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler              : ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  OpenSSL (headers)     : ${OPENSSL_VERSION}")
message(STATUS "  PQ groups usable      : ${PQTLS_OPENSSL_HAS_PQ_GROUPS}")
message(STATUS "  Detected PQ groups    : ${PQTLS_DETECTED_PQ_GROUPS}")
message(STATUS "  Warnings as errors    : ${PQTLS_ENABLE_WERROR}")
message(STATUS "  Hardening             : ${PQTLS_ENABLE_HARDENING}")
message(STATUS "  ASan / UBSan / TSan   : ${PQTLS_ENABLE_ASAN} / ${PQTLS_ENABLE_UBSAN} / ${PQTLS_ENABLE_TSAN}")
message(STATUS "  Tests                 : ${PQTLS_BUILD_TESTS}")
message(STATUS "=================================================================")
message(STATUS "")

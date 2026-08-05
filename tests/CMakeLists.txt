# Unit tests.
#
# Catch2 is pinned by commit. Integration and interoperability tests are Python
# and are driven by pytest rather than ctest, because they need to start real
# processes and to distinguish SKIP from FAIL on capability grounds.

include(FetchContent)

find_package(Catch2 3.4 QUIET)
if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found on system; fetching pinned v3.5.2")
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG        05e10dfccc28c7f973727c54f850237d07d5e10f  # v3.5.2
        GIT_SHALLOW    FALSE)
    FetchContent_MakeAvailable(Catch2)
    list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
endif()

add_executable(pqtls_unit_tests
    unit/test_application_protocol.cpp
    unit/test_config.cpp
    unit/test_metrics.cpp
    unit/test_security_profiles.cpp
    unit/test_capabilities.cpp
    unit/test_errors.cpp)

target_link_libraries(pqtls_unit_tests
    PRIVATE
        pqtls_core
        Catch2::Catch2WithMain)

pqtls_set_warnings(pqtls_unit_tests)
pqtls_enable_sanitizers(pqtls_unit_tests)

include(Catch)
catch_discover_tests(pqtls_unit_tests)

# Convenience target: the Python suites are not run by ctest because they need
# built binaries and a live network stack, and because pytest's own reporting
# distinguishes SKIP from FAIL in a way ctest does not.
add_custom_target(integration-tests
    COMMAND ${CMAKE_COMMAND} -E echo "Run the integration suite with:"
    COMMAND ${CMAKE_COMMAND} -E echo "  PQTLS_BUILD_DIR=$<TARGET_FILE_DIR:pqtls-client> python3 -m pytest tests/integration -v"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# Scour — offline document inspector and scrubber.
# Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
cmake_minimum_required(VERSION 3.20)

project(scour
    VERSION 1.0.0
    DESCRIPTION "Offline PDF inspector, scrubber and redactor"
    HOMEPAGE_URL "https://github.com/scour-pdf/scour"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SCOUR_BUILD_TESTS "Build the test suite" ON)
option(SCOUR_BUILD_BENCH "Build the micro-benchmarks" OFF)
option(SCOUR_BUILD_TOOLS "Build developer fixture tools" ON)
option(SCOUR_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(SCOUR_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(SCOUR_BUILD_FUZZ "Build the mutation fuzzer (pair it with SCOUR_SANITIZE)" OFF)
option(SCOUR_NATIVE "Tune the build for the host CPU (never for redistributable binaries)" OFF)

# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------
add_library(scour_warnings INTERFACE)
if(MSVC)
    # /utf-8 is not cosmetic. The source is UTF-8 throughout — box drawing in the
    # dashboard, the ellipsis truncate_cells appends, the arrows in the help bar.
    # Without it MSVC encodes narrow literals in the local code page, so those
    # glyphs become '?' and any test asserting UTF-8 bytes fails; on a CP1252
    # machine that is 20 warnings and one broken assertion.
    target_compile_options(scour_warnings INTERFACE /W4 /permissive- /Zc:__cplusplus /utf-8)
else()
    target_compile_options(scour_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor -Wold-style-cast
        -Wcast-align -Wunused -Woverloaded-virtual -Wnull-dereference
        -Wdouble-promotion -Wformat=2 -Wimplicit-fallthrough
        # Conversion noise is reported but does not fail the build; every other
        # warning does, so a warning is never ignorable background noise.
        -Wconversion -Wsign-conversion -Wno-error=conversion)
    if(SCOUR_WARNINGS_AS_ERRORS)
        target_compile_options(scour_warnings INTERFACE -Werror)
    endif()
endif()

add_library(scour_sanitizers INTERFACE)
if(SCOUR_SANITIZE)
    target_compile_options(scour_sanitizers INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(scour_sanitizers INTERFACE -fsanitize=address,undefined)
endif()

add_library(scour_optimize INTERFACE)
if(SCOUR_NATIVE)
    target_compile_options(scour_optimize INTERFACE -march=native)
endif()

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
set(SCOUR_CORE_SOURCES
    src/core/bytes.cpp
    src/core/error.cpp
    src/core/hash.cpp
    src/core/inflate.cpp
    src/core/deflate.cpp
    src/core/object.cpp
    src/core/crypt.cpp
    src/core/lexer.cpp
    src/core/parser.cpp
    src/core/filters.cpp
    src/core/document.cpp
    src/core/writer.cpp
    src/core/pages.cpp
    src/core/text.cpp
    src/core/patterns.cpp
    src/core/redact.cpp
    src/core/inspector.cpp
    src/core/sanitize.cpp
)

add_library(scour_core STATIC ${SCOUR_CORE_SOURCES})
target_include_directories(scour_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_link_libraries(scour_core
    PUBLIC scour_optimize
    PRIVATE scour_warnings scour_sanitizers)

# ---------------------------------------------------------------------------
# Executable (added once the CLI lands)
# ---------------------------------------------------------------------------
# The CLI and the dashboard drive a POSIX terminal: isatty() for the plain
# report, termios/ioctl/SIGWINCH for the dashboard. Neither has a Windows
# equivalent that could be reached without a separate console backend, so a
# Windows build produces the engine, the fixtures and the tests instead of
# failing three translation units deep. Say so rather than leaving someone to
# discover it from a missing binary.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/main.cpp")
    if(WIN32)
        message(STATUS "scour: the CLI and dashboard need a POSIX terminal; building the engine and tests only")
    else()
        add_executable(scour
            src/cli/main.cpp
            src/tui/app.cpp
            src/tui/screen.cpp)
        target_include_directories(scour PRIVATE src)
        target_link_libraries(scour PRIVATE scour_core scour_warnings scour_sanitizers)
    endif()
endif()

# ---------------------------------------------------------------------------
# Developer fixture generator (declared before tests so the end-to-end test
# can depend on the real target, not on a shell path)
# ---------------------------------------------------------------------------
if(SCOUR_BUILD_TOOLS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/fixtures.cpp")
    add_executable(scour_fixtures tools/fixtures.cpp tests/support/fixtures.cpp)
    target_include_directories(scour_fixtures PRIVATE tests/support)
    target_link_libraries(scour_fixtures PRIVATE scour_core scour_warnings)
endif()

# ---------------------------------------------------------------------------
# Fuzzer
# ---------------------------------------------------------------------------
if(SCOUR_BUILD_FUZZ AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/pdf_fuzz.cpp")
    add_executable(scour_fuzz fuzz/pdf_fuzz.cpp)
    target_link_libraries(scour_fuzz PRIVATE scour_core scour_warnings scour_sanitizers)
endif()

if(SCOUR_BUILD_BENCH AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bench/bench.cpp")
    add_executable(scour_bench bench/bench.cpp)
    target_link_libraries(scour_bench PRIVATE scour_core scour_warnings)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SCOUR_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS scour_core ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/scour DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(TARGET scour)
    install(TARGETS scour RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/man/scour.1")
    install(FILES man/scour.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif()

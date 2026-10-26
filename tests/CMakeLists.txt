# Scour — test suite.
set(SCOUR_TEST_SOURCES
    framework.cpp
    support/fixtures.cpp
    test_bytes.cpp
    test_hash.cpp
    test_inflate.cpp
    test_crypt.cpp
    test_object.cpp
    test_lexer.cpp
    test_parser.cpp
    test_document.cpp
    test_writer.cpp
    test_patterns.cpp
    test_redact.cpp
    test_pages.cpp
    test_text.cpp
    test_inspector.cpp
    test_sanitize.cpp
)

add_executable(scour_tests ${SCOUR_TEST_SOURCES})
target_include_directories(scour_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(scour_tests PRIVATE scour_core scour_warnings scour_sanitizers)

add_test(NAME scour_unit COMMAND scour_tests)
set_tests_properties(scour_unit PROPERTIES TIMEOUT 300)

# Individual suites can be run with: ctest --test-dir build -R inflate
foreach(suite bytes hash inflate deflate crypt object lexer parser document writer pages text patterns redact inspector sanitize)
    add_test(NAME unit_${suite} COMMAND scour_tests --filter=${suite})
endforeach()

# End-to-end tests drive the real binary: exit codes, files on disk, terminal
# frames. They are shell rather than C++ because that is the interface a user
# actually touches.
if(TARGET scour AND TARGET scour_fixtures)
    add_test(NAME cli_e2e
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/cli_e2e.sh
            $<TARGET_FILE:scour> $<TARGET_FILE:scour_fixtures>
            ${CMAKE_CURRENT_BINARY_DIR}/e2e)
    set_tests_properties(cli_e2e PROPERTIES TIMEOUT 120 DEPENDS scour_unit)
endif()

// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// A dependency-free test harness. It is deliberately tiny: a registry, a few
// assertion macros that report the expression and the location, and a runner
// that supports filtering by substring so a single suite can be exercised while
// iterating.
#ifndef SCOUR_TEST_FRAMEWORK_HPP
#define SCOUR_TEST_FRAMEWORK_HPP

#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "scour/error.hpp"

namespace scour_test {

struct Case {
    std::string suite;
    std::string name;
    void (*fn)();
};

std::vector<Case>& registry();
int& failure_count();

void record_failure(const char* file, int line, const std::string& detail);

struct Registrar {
    Registrar(const char* suite, const char* name, void (*fn)());
};

template <typename T>
std::string describe(const T& value) {
    using V = std::decay_t<T>;
    if constexpr (std::is_same_v<V, std::string> || std::is_same_v<V, std::string_view> ||
                  std::is_same_v<V, const char*>) {
        std::string text(value);
        std::string out = "\"";
        for (char c : text) {
            if (c == '\n') {
                out += "\\n";
            } else if (c == '\r') {
                out += "\\r";
            } else if (c == '\t') {
                out += "\\t";
            } else if (static_cast<unsigned char>(c) < 32) {
                static constexpr char kHex[] = "0123456789abcdef";
                out += "\\x";
                out += kHex[(static_cast<unsigned char>(c) >> 4) & 0xF];
                out += kHex[static_cast<unsigned char>(c) & 0xF];
            } else {
                out += c;
            }
        }
        out += '"';
        return out;
    } else if constexpr (std::is_same_v<V, std::vector<std::uint8_t>>) {
        std::ostringstream os;
        os << "<" << value.size() << " bytes>";
        return os.str();
    } else if constexpr (std::is_enum_v<V>) {
        std::ostringstream os;
        os << static_cast<long long>(value);
        return os.str();
    } else if constexpr (std::is_integral_v<V>) {
        std::ostringstream os;
        if constexpr (std::is_signed_v<V>) {
            os << static_cast<long long>(value);
        } else {
            os << static_cast<unsigned long long>(value);
        }
        return os.str();
    } else if constexpr (std::is_floating_point_v<V>) {
        std::ostringstream os;
        os << value;
        return os.str();
    } else {
        return "<value>";
    }
}

}  // namespace scour_test

#define SCOUR_TEST_CONCAT_INNER(a, b) a##b
#define SCOUR_TEST_CONCAT(a, b) SCOUR_TEST_CONCAT_INNER(a, b)

#define SCOUR_TEST(suite_name, case_name)                                          \
    static void SCOUR_TEST_CONCAT(scour_test_fn_, __LINE__)();                     \
    static ::scour_test::Registrar SCOUR_TEST_CONCAT(scour_test_reg_, __LINE__)(   \
        #suite_name, #case_name, &SCOUR_TEST_CONCAT(scour_test_fn_, __LINE__));    \
    static void SCOUR_TEST_CONCAT(scour_test_fn_, __LINE__)()

#define CHECK(condition)                                                           \
    do {                                                                           \
        if (!(condition)) {                                                        \
            ::scour_test::record_failure(__FILE__, __LINE__, "CHECK(" #condition ")"); \
        }                                                                          \
    } while (false)

#define CHECK_EQ(actual, expected)                                                 \
    do {                                                                           \
        const auto& scour_test_a = (actual);                                       \
        const auto& scour_test_b = (expected);                                     \
        if (!(scour_test_a == scour_test_b)) {                                     \
            ::scour_test::record_failure(                                          \
                __FILE__, __LINE__,                                                \
                std::string("CHECK_EQ(" #actual ", " #expected "): ") +            \
                    ::scour_test::describe(scour_test_a) + " != " +                \
                    ::scour_test::describe(scour_test_b));                         \
        }                                                                          \
    } while (false)

#define CHECK_NE(actual, unexpected)                                               \
    do {                                                                           \
        if ((actual) == (unexpected)) {                                            \
            ::scour_test::record_failure(__FILE__, __LINE__,                       \
                                         "CHECK_NE(" #actual ", " #unexpected ")"); \
        }                                                                          \
    } while (false)

#define CHECK_LT(a, b)                                                             \
    do {                                                                           \
        const auto& scour_test_a = (a);                                            \
        const auto& scour_test_b = (b);                                            \
        if (!(scour_test_a < scour_test_b)) {                                      \
            ::scour_test::record_failure(                                          \
                __FILE__, __LINE__,                                                \
                std::string("CHECK_LT(" #a ", " #b "): ") +                        \
                    ::scour_test::describe(scour_test_a) + " !< " +                \
                    ::scour_test::describe(scour_test_b));                         \
        }                                                                          \
    } while (false)

#define CHECK_GT(a, b)                                                             \
    do {                                                                           \
        const auto& scour_test_a = (a);                                            \
        const auto& scour_test_b = (b);                                            \
        if (!(scour_test_a > scour_test_b)) {                                      \
            ::scour_test::record_failure(                                          \
                __FILE__, __LINE__,                                                \
                std::string("CHECK_GT(" #a ", " #b "): ") +                        \
                    ::scour_test::describe(scour_test_a) + " !> " +                \
                    ::scour_test::describe(scour_test_b));                         \
        }                                                                          \
    } while (false)

#define CHECK_THROWS(expression, code_substring)                                   \
    do {                                                                           \
        bool scour_test_threw = false;                                             \
        try {                                                                      \
            (void)(expression);                                                    \
        } catch (const ::scour::ScourError& scour_test_error) {                    \
            scour_test_threw = true;                                               \
            const std::string scour_test_code = scour_test_error.code();           \
            const std::string scour_test_expected = (code_substring);              \
            if (scour_test_code.find(scour_test_expected) == std::string::npos) {  \
                ::scour_test::record_failure(                                      \
                    __FILE__, __LINE__,                                            \
                    "expected error code containing " + scour_test_expected +      \
                        ", got " + scour_test_code);                               \
            }                                                                      \
        }                                                                          \
        if (!scour_test_threw) {                                                   \
            ::scour_test::record_failure(__FILE__, __LINE__,                       \
                                         "expected " #expression " to throw");      \
        }                                                                          \
    } while (false)

#endif  // SCOUR_TEST_FRAMEWORK_HPP

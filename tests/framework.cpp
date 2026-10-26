// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <cstring>
#include <iostream>

namespace scour_test {
namespace {
int g_failures = 0;
std::string g_current;
}  // namespace

std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

int& failure_count() { return g_failures; }

void record_failure(const char* file, int line, const std::string& detail) {
    ++g_failures;
    std::cerr << "  FAIL " << g_current << "\n       " << file << ":" << line << ": " << detail
              << "\n";
}

Registrar::Registrar(const char* suite, const char* name, void (*fn)()) {
    registry().push_back(Case{suite, name, fn});
}

}  // namespace scour_test

int main(int argc, char** argv) {
    std::string filter;
    bool list_only = false;
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--list") {
            list_only = true;
        } else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else if (arg.rfind("--filter=", 0) == 0) {
            filter = arg.substr(9);
        } else if (arg == "--filter" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "usage: scour_tests [--filter=SUBSTRING] [--list] [--verbose]\n";
            return 0;
        } else {
            filter = arg;
        }
    }

    auto& cases = scour_test::registry();
    int run = 0;
    int passed = 0;
    for (const auto& test : cases) {
        const std::string full = test.suite + "." + test.name;
        if (!filter.empty() && full.find(filter) == std::string::npos) continue;
        if (list_only) {
            std::cout << full << "\n";
            continue;
        }
        ++run;
        const int before = scour_test::failure_count();
        scour_test::g_current = full;
        if (verbose) std::cout << "RUN  " << full << "\n";
        try {
            test.fn();
        } catch (const std::exception& e) {
            scour_test::record_failure("<test body>", 0,
                                       std::string("uncaught exception: ") + e.what());
        } catch (...) {
            scour_test::record_failure("<test body>", 0, "uncaught non-standard exception");
        }
        if (scour_test::failure_count() == before) {
            ++passed;
            if (verbose) std::cout << "  ok  " << full << "\n";
        }
    }
    if (list_only) return 0;

    std::cout << "\n" << passed << "/" << run << " tests passed";
    if (scour_test::failure_count() != 0)
        std::cout << ", " << scour_test::failure_count() << " assertion failures";
    std::cout << "\n";
    return scour_test::failure_count() == 0 ? 0 : 1;
}

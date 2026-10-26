// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Writes the sample documents used in docs/ and for manual testing. They are
// byte-for-byte the same fixtures the test suite runs against, so a screenshot
// can never show behaviour the tests do not cover.
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "fixtures.hpp"

namespace fs = std::filesystem;
using scour::Bytes;

namespace {

bool write(const fs::path& path, const Bytes& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    if (!stream) return false;
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(stream);
}

}  // namespace

int main(int argc, char** argv) {
    const fs::path directory = argc > 1 ? fs::path(argv[1]) : fs::path("fixtures");
    std::error_code error;
    fs::create_directories(directory, error);
    if (error) {
        std::fprintf(stderr, "cannot create %s\n", directory.string().c_str());
        return 1;
    }

    const std::vector<std::pair<std::string, Bytes>> documents = {
        {"contract-leak.pdf", scour_test::make_fixture(scour_test::FixtureSpec{})},
        {"revisions.pdf", scour_test::make_incremental_fixture()},
        {"hidden-text.pdf", scour_test::make_hidden_text_fixture()},
        {"scanned-report.pdf", scour_test::make_scanned_fixture()},
        {"clean-memo.pdf",
         scour_test::make_minimal_pdf("Logistics memo. Nothing confidential on this page.")},
    };

    for (const auto& [name, bytes] : documents) {
        const fs::path path = directory / name;
        if (!write(path, bytes)) {
            std::fprintf(stderr, "cannot write %s\n", path.string().c_str());
            return 1;
        }
        std::cout << path.string() << "  " << bytes.size() << " bytes\n";
    }
    return 0;
}

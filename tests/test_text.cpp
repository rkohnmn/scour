// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "scour/pages.hpp"
#include "scour/text.hpp"
#include "support/fixtures.hpp"

using namespace scour;

namespace {

struct Loaded {
    Document document;
    DocumentText text;
};

Loaded load_and_extract(const Bytes& bytes) {
    Diagnostics diagnostics;
    Document document = Document::load(bytes, LoadOptions{}, diagnostics);
    Loaded result{std::move(document), {}};
    result.text = analyze_document(result.document, TextOptions{}, diagnostics);
    return result;
}

const TextStream* find_stream(const PageAnalysis& page, std::uint32_t number) {
    for (const TextStream& stream : page.streams) {
        if (stream.object_number == number) return &stream;
    }
    return nullptr;
}

}  // namespace

SCOUR_TEST(text, extracts_latin_text_with_shapes) {
    Loaded loaded = load_and_extract(scour_test::make_fixture({}));
    CHECK_EQ(loaded.text.pages.size(), std::size_t{3});
    const PageAnalysis& page = loaded.text.pages[0];
    CHECK(page.has_text);
    CHECK(page.reliable);
    CHECK(page.text.find("PROJECT BLUEBIRD") != std::string::npos);
    CHECK(page.text.find("Prepared for") != std::string::npos);
    CHECK(page.text.find(scour_test::kPhone) != std::string::npos);
    CHECK(page.text.find("alice@example.com") != std::string::npos);
    CHECK_EQ(page.run_of_byte.size(), page.text.size());
    CHECK(not page.runs.empty());
    CHECK(page.box.approximately_equals(Rect{0, 0, 612, 792}));
}

SCOUR_TEST(text, glyphs_map_back_to_encoded_bytes) {
    Loaded loaded = load_and_extract(scour_test::make_fixture({}));
    const PageAnalysis& page = loaded.text.pages[0];
    bool checked = false;
    for (const TextRun& run : page.runs) {
        if (run.stream_object == 0) continue;
        const TextStream* source = find_stream(page, run.stream_object);
        CHECK(source != nullptr);
        if (source == nullptr) continue;
        CHECK_LT(run.begin, run.end);
        CHECK_LT(run.end, source->decoded.size());
        const std::string_view raw = view_of(source->decoded).substr(run.begin, run.end - run.begin);
        CHECK_EQ(raw.front(), '(');
        CHECK_EQ(raw.back(), ')');
        for (const Glyph& glyph : run.glyphs) {
            CHECK_LT(glyph.byte_start, glyph.byte_end);
            CHECK_LT(glyph.byte_end, run.end - run.begin);
            CHECK(not glyph.utf8.empty());
            CHECK_GT(glyph.advance, 0.0);
        }
        checked = true;
    }
    CHECK(checked);
}

SCOUR_TEST(text, pii_pages_are_extracted) {
    Loaded loaded = load_and_extract(scour_test::make_fixture({}));
    const std::string& second = loaded.text.pages[1].text;
    CHECK(second.find(scour_test::kSsn) != std::string::npos);
    CHECK(second.find(scour_test::kCard) != std::string::npos);
    CHECK(second.find(scour_test::kIban) != std::string::npos);
}

SCOUR_TEST(text, all_text_joins_pages_with_form_feed) {
    Loaded loaded = load_and_extract(scour_test::make_fixture({}));
    const std::string all = loaded.text.all_text();
    CHECK_GT(all.size(), std::size_t{10});
    CHECK_EQ(std::count(all.begin(), all.end(), '\f'), std::ptrdiff_t{2});
}

SCOUR_TEST(text, split_runs_are_joined_without_a_space) {
    Loaded loaded = load_and_extract(scour_test::make_fixture({}));
    const PageAnalysis& page = loaded.text.pages[0];
    CHECK(page.text.find("alice@example.com") != std::string::npos);
    std::size_t runs = 0;
    for (const TextRun& run : page.runs) {
        if (run.text.find("alice@exam") != std::string::npos) ++runs;
    }
    CHECK_EQ(runs, std::size_t{1});
}

SCOUR_TEST(text, page_without_content_has_no_text) {
    Loaded loaded = load_and_extract(scour_test::make_minimal_pdf(""));
    CHECK_EQ(loaded.text.pages.size(), std::size_t{1});
    CHECK(not loaded.text.pages[0].has_text);
    CHECK(loaded.text.pages[0].text.empty());
}

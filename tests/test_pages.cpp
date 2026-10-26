// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "scour/pages.hpp"
#include "scour/text.hpp"
#include "scour/writer.hpp"
#include "support/fixtures.hpp"

using namespace scour;

namespace {

Document load(const Bytes& bytes) {
    Diagnostics diagnostics;
    return Document::load(bytes, LoadOptions{}, diagnostics);
}

std::string page_text(Document& document, int index) {
    Diagnostics diagnostics;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    if (index < 0 || static_cast<std::size_t>(index) >= pages.size()) return {};
    const PageAnalysis analysis = analyze_page(document, pages[static_cast<std::size_t>(index)], index,
                                               TextOptions{}, diagnostics);
    return analysis.text;
}

Document roundtrip(Document& document) {
    Diagnostics diagnostics;
    const WriteResult written = write_document(document, WriteOptions{}, diagnostics);
    return Document::load(written.bytes, LoadOptions{}, diagnostics);
}

}  // namespace

SCOUR_TEST(pages, collects_page_numbers_in_order) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    CHECK_EQ(pages.size(), std::size_t{3});
    CHECK_EQ(pages[0], std::uint32_t{3});
    CHECK_EQ(pages[1], std::uint32_t{4});
    CHECK_EQ(pages[2], std::uint32_t{5});
}

SCOUR_TEST(pages, extract_reorders_and_keeps_content) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    Document extracted = extract_pages(document, {2, 0}, diagnostics);
    CHECK_EQ(collect_page_numbers(extracted, diagnostics).size(), std::size_t{2});
    CHECK(page_text(extracted, 0).find("Draft - internal use only") != std::string::npos);
    CHECK(page_text(extracted, 1).find("PROJECT BLUEBIRD") != std::string::npos);

    Document reopened = roundtrip(extracted);
    CHECK_EQ(collect_page_numbers(reopened, diagnostics).size(), std::size_t{2});
    CHECK(page_text(reopened, 1).find(scour_test::kEmail) != std::string::npos);
    CHECK(reopened.diagnostics().count(Severity::Warning) == 0);
}

SCOUR_TEST(pages, merge_concatenates_documents) {
    Document first = load(scour_test::make_minimal_pdf("First document."));
    Document second = load(scour_test::make_minimal_pdf("Second document."));
    Diagnostics diagnostics;
    Document merged = merge_documents({&first, &second}, diagnostics);
    CHECK_EQ(collect_page_numbers(merged, diagnostics).size(), std::size_t{2});
    CHECK(page_text(merged, 0).find("First document.") != std::string::npos);
    CHECK(page_text(merged, 1).find("Second document.") != std::string::npos);

    Document reopened = roundtrip(merged);
    CHECK(page_text(reopened, 0).find("First document.") != std::string::npos);
    CHECK(page_text(reopened, 1).find("Second document.") != std::string::npos);
}

SCOUR_TEST(pages, copied_page_has_a_new_parent) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    Document extracted = extract_pages(document, {0}, diagnostics);
    const std::vector<std::uint32_t> pages = collect_page_numbers(extracted, diagnostics);
    CHECK_EQ(pages.size(), std::size_t{1});
    const Object* page = extracted.resolve_ref(pages[0]);
    CHECK(page != nullptr);
    const std::uint32_t parent = page->dict().get_ref("Parent");
    const Object* parent_object = extracted.resolve_ref(parent);
    CHECK(parent_object != nullptr);
    CHECK_EQ(parent_object->dict().get_name("Type"), std::string("Pages"));
    CHECK_EQ(parent_object->dict().get_int("Count"), std::int64_t{1});
    CHECK_EQ(parent_object->find("Kids")->items().size(), std::size_t{1});
}

SCOUR_TEST(pages, annotations_are_copied_without_a_page_backreference) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    Document extracted = extract_pages(document, {0}, diagnostics);
    const std::vector<std::uint32_t> pages = collect_page_numbers(extracted, diagnostics);
    const Object* page = extracted.resolve_ref(pages[0]);
    const Object* annots = page->find("Annots");
    CHECK(annots != nullptr && annots->is_array());
    CHECK_EQ(annots->items().size(), std::size_t{1});
    const Object* annotation = extracted.resolve(annots->items()[0]);
    CHECK(annotation != nullptr);
    CHECK(annotation->find("P") == nullptr);
    CHECK(annotation->dict().get_string("Contents").find(scour_test::kPhone) != std::string::npos);
}

SCOUR_TEST(pages, rotation_roundtrips) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    CHECK_EQ(page_rotation(document, pages[0]), 0);
    set_page_rotation(document, pages[0], 90);
    CHECK_EQ(page_rotation(document, pages[0]), 90);
    set_page_rotation(document, pages[0], -90);
    CHECK_EQ(page_rotation(document, pages[0]), 270);

    Document reopened = roundtrip(document);
    const std::vector<std::uint32_t> reopened_pages = collect_page_numbers(reopened, diagnostics);
    CHECK_EQ(page_rotation(reopened, reopened_pages[0]), 270);
}

SCOUR_TEST(pages, geometry_defaults_and_inheritance) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    CHECK(page_box(document, pages[0]).approximately_equals(Rect{0, 0, 612, 792}));
    CHECK_EQ(pages.size(), std::size_t{3});
}

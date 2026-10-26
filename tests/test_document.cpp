// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "support/fixtures.hpp"

using namespace scour;

namespace {

Document load(const Bytes& bytes, Diagnostics& diagnostics, LoadOptions options = {}) {
    return Document::load(bytes, options, diagnostics);
}

int page_count(const Document& document) {
    const Object* catalog = document.catalog();
    if (catalog == nullptr) return -1;
    const Object* pages = document.resolve_ref(catalog->dict().get_ref("Pages"));
    if (pages == nullptr) return -1;
    return static_cast<int>(pages->dict().get_int("Count", -1));
}

std::string page_text(const Document& document, int page_index) {
    const Object* catalog = document.catalog();
    if (catalog == nullptr) return {};
    const Object* pages = document.resolve_ref(catalog->dict().get_ref("Pages"));
    if (pages == nullptr) return {};
    const Object* kids = pages->find("Kids");
    if (kids == nullptr || kids->items().empty()) return {};
    const Object* page =
        document.resolve_ref(kids->items()[static_cast<std::size_t>(page_index)].ref_number());
    if (page == nullptr) return {};
    const Object* contents = document.resolve_ref(page->dict().get_ref("Contents"));
    if (contents == nullptr) return {};
    const Bytes data = document.decode_stream(*contents);
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

}  // namespace

SCOUR_TEST(document, loads_fixture_structure) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_fixture({}), diagnostics);
    CHECK_EQ(document.version_string(), std::string("1.7"));
    CHECK_EQ(page_count(document), 3);
    CHECK(not document.repaired());
    CHECK(not document.encrypted());
    CHECK_EQ(document.revision_count(), 1);

    const Object* catalog = document.catalog();
    CHECK(catalog != nullptr);
    CHECK_EQ(catalog->dict().get_name("Type"), std::string("Catalog"));

    // Metadata, JavaScript, attachments and form fields must all be reachable.
    CHECK(catalog->dict().contains("Metadata"));
    CHECK(catalog->dict().contains("OpenAction"));
    CHECK(catalog->dict().contains("AcroForm"));
    const Object* info = document.resolve_ref(document.trailer().get_ref("Info"));
    CHECK(info != nullptr);
    CHECK_EQ(info->dict().get_string("Author"), std::string(scour_test::kAuthor));
    CHECK_EQ(info->dict().get_string("Producer"), std::string(scour_test::kProducer));
}

SCOUR_TEST(document, decodes_flate_content_and_joins_runs) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_fixture({}), diagnostics);
    const std::string text = page_text(document, 0);
    CHECK(text.find("PROJECT BLUEBIRD") != std::string::npos);
    CHECK(text.find("alice@exam") != std::string::npos);
    CHECK(text.find("ple.com") != std::string::npos);
}

SCOUR_TEST(document, unreferenced_objects_are_still_reachable_by_number) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_fixture({}), diagnostics);
    const Object* orphan = document.resolve_ref(30);
    CHECK(orphan != nullptr);
    CHECK(orphan->is_stream());
    const Bytes data = document.decode_stream(*orphan);
    CHECK_EQ(view_of(data), std::string_view(scour_test::kOrphanSecret));
}

SCOUR_TEST(document, incremental_update_keeps_the_old_content) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_incremental_fixture(), diagnostics);
    CHECK_EQ(document.revision_count(), 2);
    CHECK_EQ(page_count(document), 3);

    // The visible page 3 is the rewritten one...
    CHECK(page_text(document, 2).find("Redacted") != std::string::npos);
    // ...but the original content stream is still in the file, byte for byte.
    const Object* old_content = document.resolve_ref(9);
    CHECK(old_content != nullptr);
    const Bytes leaked_bytes = document.decode_stream(*old_content);
    const std::string leaked(reinterpret_cast<const char*>(leaked_bytes.data()),
                             leaked_bytes.size());
    CHECK(leaked.find(scour_test::kEmail) != std::string::npos);
}

SCOUR_TEST(document, rebuilds_a_broken_xref_table) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_broken_xref_pdf(), diagnostics);
    CHECK(document.repaired());
    CHECK_EQ(page_count(document), 1);
    CHECK(page_text(document, 0).find("Broken cross reference") != std::string::npos);
    CHECK(diagnostics.count(Severity::Warning) > 0);
}

SCOUR_TEST(document, accepts_cr_only_line_endings) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_quirky_pdf(), diagnostics);
    CHECK_EQ(page_count(document), 1);
    CHECK(not page_text(document, 0).empty());
}

SCOUR_TEST(document, rejects_non_pdf_input) {
    Diagnostics diagnostics;
    CHECK_THROWS(load(bytes_of("this is not a pdf at all"), diagnostics), "pdf.load");
}

SCOUR_TEST(document, minimal_pdf_roundtrip_through_loader) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_minimal_pdf("Only one line."), diagnostics);
    CHECK_EQ(page_count(document), 1);
    CHECK(page_text(document, 0).find("Only one line.") != std::string::npos);
    CHECK_EQ(document.file_id0().size(), std::size_t{16});
}

SCOUR_TEST(document, garbage_collection_removes_unreachable_objects) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_fixture({}), diagnostics);
    CHECK(document.resolve_ref(30) != nullptr);
    const std::size_t removed = document.collect_garbage();
    CHECK_GT(removed, std::size_t{0});
    CHECK(document.resolve_ref(30) == nullptr);
}

SCOUR_TEST(document, decode_stream_reports_images) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_minimal_pdf("x"), diagnostics);
    Dict dict;
    dict.set("Filter", Object::name("DCTDecode"));
    dict.set("Subtype", Object::name("Image"));
    Object image = Object::stream(dict, bytes_of(std::string("\xFF\xD8\xFF", 3)));
    const DecodeResult result = document.decode_stream_info(image);
    CHECK(result.image);
    CHECK_EQ(result.data.size(), std::size_t{3});
}

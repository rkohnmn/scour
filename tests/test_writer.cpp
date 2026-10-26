// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "scour/writer.hpp"
#include "support/fixtures.hpp"

using namespace scour;

namespace {

WriteResult write(Document& document, WriteOptions options = {}) {
    Diagnostics diagnostics;
    return write_document(document, options, diagnostics);
}

std::string as_text(const Bytes& bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string first_page_text(const Document& document) {
    const Object* catalog = document.catalog();
    if (catalog == nullptr) return {};
    const Object* pages = document.resolve_ref(catalog->dict().get_ref("Pages"));
    if (pages == nullptr) return {};
    const Object* kids = pages->find("Kids");
    if (kids == nullptr || kids->items().empty()) return {};
    const Object* page = document.resolve_ref(kids->items()[0].ref_number());
    if (page == nullptr) return {};
    const Object* contents = document.resolve_ref(page->dict().get_ref("Contents"));
    if (contents == nullptr) return {};
    const Bytes data = document.decode_stream(*contents);
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

}  // namespace

SCOUR_TEST(writer, escapes_values) {
    CHECK_EQ(escape_literal_string("a(b)c\\d"), std::string("a\\(b\\)c\\\\d"));
    CHECK_EQ(escape_literal_string(std::string("\x01", 1)), std::string("\\001"));
    CHECK_EQ(escape_name("Simple"), std::string("Simple"));
    CHECK_EQ(escape_name("A B#C/D"), std::string("A#20B#23C#2FD"));
    CHECK_EQ(format_pdf_real(1.0), std::string("1"));
    CHECK_EQ(format_pdf_real(0.5), std::string("0.5"));
    CHECK_EQ(format_pdf_real(-0.25), std::string("-0.25"));
    CHECK_EQ(format_pdf_real(1e-7), std::string("0.0000001"));
}

SCOUR_TEST(writer, roundtrip_preserves_structure) {
    Diagnostics load_diagnostics;
    Document original = Document::load(scour_test::make_minimal_pdf("Round trip text."),
                                       LoadOptions{}, load_diagnostics);
    const WriteResult written = write(original);
    CHECK_GT(written.bytes.size(), std::size_t{100});
    CHECK_EQ(as_text(written.bytes).find("%PDF-1."), std::size_t{0});

    Diagnostics reload_diagnostics;
    Document reloaded = Document::load(written.bytes, LoadOptions{}, reload_diagnostics);
    CHECK_EQ(reloaded.file_size(), written.bytes.size());
    CHECK(reloaded.catalog() != nullptr);
    CHECK(not reloaded.repaired());
    CHECK_EQ(reloaded.diagnostics().count(Severity::Warning), std::size_t{0});
}

SCOUR_TEST(writer, output_is_deterministic) {
    Diagnostics diagnostics;
    Document document = Document::load(scour_test::make_fixture({}), LoadOptions{}, diagnostics);
    const WriteResult first = write(document);
    const WriteResult second = write(document);
    CHECK_EQ(first.bytes, second.bytes);
    CHECK_EQ(first.objects_written, second.objects_written);
}

SCOUR_TEST(writer, drops_unreachable_objects_and_info) {
    Diagnostics diagnostics;
    Document document = Document::load(scour_test::make_fixture({}), LoadOptions{}, diagnostics);
    WriteOptions options;
    options.trailer_keys = {"Root"};
    const WriteResult written = write(document, options);
    const std::string text = as_text(written.bytes);
    CHECK(text.find(scour_test::kOrphanSecret) == std::string::npos);
    CHECK(text.find("CreationDate") == std::string::npos);
    CHECK(text.find("CreatorTool") != std::string::npos);  // XMP is reachable

    Diagnostics reload_diagnostics;
    Document reloaded = Document::load(written.bytes, LoadOptions{}, reload_diagnostics);
    CHECK(not reloaded.trailer().contains("Info"));
    CHECK(reloaded.trailer().contains("ID"));
}

SCOUR_TEST(writer, keeps_info_when_requested) {
    Diagnostics diagnostics;
    Document document = Document::load(scour_test::make_fixture({}), LoadOptions{}, diagnostics);
    WriteOptions options;
    options.trailer_keys = {"Root", "Info"};
    const WriteResult written = write(document, options);
    CHECK(as_text(written.bytes).find("Acme ScanSuite") != std::string::npos);
}

SCOUR_TEST(writer, compresses_streams_on_request) {
    Diagnostics diagnostics;
    Document document = Document::load(scour_test::make_minimal_pdf(std::string(400, 'a')),
                                       LoadOptions{}, diagnostics);
    WriteOptions plain;
    const WriteResult uncompressed = write(document, plain);
    WriteOptions compressed;
    compressed.compress_streams = true;
    const WriteResult smaller = write(document, compressed);
    CHECK_LT(smaller.bytes.size(), uncompressed.bytes.size());
    CHECK_GT(smaller.stream_bytes_saved, std::size_t{0});

    Diagnostics reload_diagnostics;
    Document reloaded = Document::load(smaller.bytes, LoadOptions{}, reload_diagnostics);
    CHECK(first_page_text(reloaded).find("aaaa") != std::string::npos);
}

SCOUR_TEST(writer, throws_when_root_is_missing) {
    Document document;
    document.trailer().set("Size", Object::integer(1));
    Diagnostics diagnostics;
    CHECK_THROWS(write_document(document, WriteOptions{}, diagnostics), "pdf.write");
}

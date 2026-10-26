// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "scour/pages.hpp"
#include "scour/redact.hpp"
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
    return analyze_page(document, pages[static_cast<std::size_t>(index)], index, TextOptions{},
                        diagnostics)
        .text;
}

RedactionTargets terms_and_pii() {
    RedactionTargets targets;
    targets.terms = {"PROJECT BLUEBIRD"};
    targets.pii = true;
    return targets;
}

}  // namespace

SCOUR_TEST(redact, removes_terms_and_pii_and_verifies) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    const RedactionReport report = redact_document(document, terms_and_pii(), diagnostics);
    CHECK(report.clean());
    CHECK_GT(report.glyphs_removed, 0);
    CHECK(not report.found.empty());
    CHECK_GT(report.boxes_painted, 0);

    CHECK(page_text(document, 0).find("PROJECT BLUEBIRD") == std::string::npos);
    CHECK(page_text(document, 0).find("alice@example.com") == std::string::npos);
    CHECK(page_text(document, 1).find(scour_test::kSsn) == std::string::npos);
    CHECK(page_text(document, 1).find(scour_test::kCard) == std::string::npos);
    CHECK(page_text(document, 1).find(scour_test::kIban) == std::string::npos);
    // Unrelated content is untouched.
    CHECK(page_text(document, 0).find("Scour fixture - page 1") != std::string::npos);
    CHECK(page_text(document, 1).find("intentionally noisy") != std::string::npos);
}

SCOUR_TEST(redact, survives_a_write_and_reload) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    CHECK(redact_document(document, terms_and_pii(), diagnostics).clean());
    const WriteResult written = write_document(document, WriteOptions{}, diagnostics);
    Document reopened = Document::load(written.bytes, LoadOptions{}, diagnostics);
    const RedactionReport verification = verify_document(reopened, terms_and_pii(), diagnostics);
    CHECK(verification.clean());
    CHECK(reopened.diagnostics().count(Severity::Warning) == 0);
}

SCOUR_TEST(redact, keeps_layout_by_replacing_glyphs_not_whole_runs) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    RedactionTargets targets;
    targets.terms = {"alice@example.com"};
    const RedactionReport report = redact_document(document, targets, diagnostics);
    CHECK(report.clean());
    const std::string text = page_text(document, 0);
    CHECK(text.find("Contact:") != std::string::npos);
    CHECK(text.find("Phone:") != std::string::npos);
}

SCOUR_TEST(redact, paints_boxes_on_top_of_the_content) {
    Document document = load(scour_test::make_minimal_pdf("Secret line stays visible."));
    Diagnostics diagnostics;
    RedactionTargets targets;
    targets.terms = {"Secret"};
    const RedactionReport report = redact_document(document, targets, diagnostics);
    CHECK(report.clean());
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    const Object* page = document.resolve_ref(pages[0]);
    const Object* contents = page->find("Contents");
    CHECK(contents != nullptr);
    CHECK(contents->is_array());
    CHECK_EQ(contents->items().size(), std::size_t{2});
    const Object* overlay = document.resolve(contents->items()[1]);
    CHECK(overlay != nullptr && overlay->is_stream());
    const Bytes overlay_bytes = document.decode_stream(*overlay);
    const std::string data(reinterpret_cast<const char*>(overlay_bytes.data()),
                           overlay_bytes.size());
    CHECK(data.find(" re f") != std::string::npos);
    CHECK(data.find("0 g") != std::string::npos);
}

SCOUR_TEST(redact, can_disable_boxes) {
    Document document = load(scour_test::make_minimal_pdf("Secret"));
    Diagnostics diagnostics;
    RedactionTargets targets;
    targets.terms = {"Secret"};
    targets.paint = false;
    CHECK(redact_document(document, targets, diagnostics).clean());
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    const Object* raw = document.resolve_ref(pages[0])->find("Contents");
    const Object* contents = raw == nullptr ? nullptr : document.resolve(*raw);
    CHECK(contents == nullptr || contents->is_stream());
}

SCOUR_TEST(redact, painted_boxes_merge_across_neighbouring_glyphs) {
    Document document = load(scour_test::make_minimal_pdf("Secret line stays visible."));
    Diagnostics diagnostics;
    RedactionTargets targets;
    targets.terms = {"line stays"};
    const RedactionReport report = redact_document(document, targets, diagnostics);
    CHECK(report.clean());
    CHECK_GT(report.glyphs_removed, 1);
    // One block covers the run; a rectangle per glyph would be thousands of
    // operators on a real page and was the reason painting was slow.
    CHECK_EQ(report.boxes_painted, 1);
}

SCOUR_TEST(redact, rect_targets_remove_intersecting_text) {
    Document document = load(scour_test::make_minimal_pdf("Top line to keep. Remove this line."));
    Diagnostics diagnostics;
    RedactionTargets targets;
    // The fixture draws a single line with its baseline at y=720, so this box
    // covers the glyphs on that line and nothing else.
    targets.rects[1] = {Rect{60.0, 700.0, 560.0, 740.0}};
    const RedactionReport report = redact_document(document, targets, diagnostics);
    CHECK(report.clean());
    const std::string text = page_text(document, 0);
    CHECK(text.find("Remove this line.") == std::string::npos);
    CHECK(text.find("Top line to keep.") == std::string::npos);
}

SCOUR_TEST(redact, verification_reports_leftovers_from_untouchable_text) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    RedactionTargets targets;
    targets.terms = {"escalate to"};  // present only on page 3, which we exclude below
    targets.pages = {1};
    const RedactionReport report = redact_document(document, targets, diagnostics);
    CHECK(not report.clean());
    CHECK(not report.remaining.empty());
    CHECK_EQ(report.remaining[0].page, 3);
}

SCOUR_TEST(redact, finds_nothing_when_no_targets_given) {
    Document document = load(scour_test::make_fixture({}));
    Diagnostics diagnostics;
    RedactionTargets targets;
    const RedactionReport report = redact_document(document, targets, diagnostics);
    CHECK(report.clean());
    CHECK_EQ(report.glyphs_removed, 0);
    CHECK(report.found.empty());
}

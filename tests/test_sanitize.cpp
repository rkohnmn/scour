// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "scour/inspector.hpp"
#include "scour/sanitize.hpp"
#include "scour/text.hpp"
#include "scour/writer.hpp"
#include "support/fixtures.hpp"

using namespace scour;

namespace {

Document load(const Bytes& bytes) {
    Diagnostics diagnostics;
    return Document::load(bytes, LoadOptions{}, diagnostics);
}

struct RoundTrip {
    Document document;
    WriteResult written;
};

RoundTrip scrub_and_write(Document document, const ScrubOptions& options,
                          Diagnostics& diagnostics) {
    scrub_document(document, options, diagnostics);
    WriteResult written = write_document(document, WriteOptions{}, diagnostics);
    return RoundTrip{std::move(document), std::move(written)};
}

std::string all_text(Document& document) {
    Diagnostics diagnostics;
    return analyze_document(document, TextOptions{}, diagnostics).all_text();
}

const Finding* find_by_id(const InspectionReport& report, std::string_view id) {
    for (const Finding& finding : report.findings) {
        if (finding.id == id) return &finding;
    }
    return nullptr;
}

}  // namespace

SCOUR_TEST(sanitize, strips_metadata_annotations_attachments_and_scripts) {
    Diagnostics diagnostics;
    RoundTrip round = scrub_and_write(load(scour_test::make_fixture({})), ScrubOptions{},
                                      diagnostics);
    Document reopened = load(round.written.bytes);
    const InspectionReport report =
        inspect_document(reopened, "scrubbed.pdf", InspectOptions{}, diagnostics);
    CHECK(report.facts.author.empty());
    CHECK(report.facts.producer.empty());
    CHECK_EQ(report.facts.embedded_files, std::size_t{0});
    CHECK_EQ(report.facts.annotations, std::size_t{0});
    CHECK(!report.has("actions"));
    CHECK(!report.has("annotations"));
    CHECK(find_by_id(report, "metadata.author") == nullptr);
    CHECK(find_by_id(report, "metadata.xmp") == nullptr);
}

SCOUR_TEST(sanitize, a_rewrite_drops_unreachable_objects) {
    Diagnostics diagnostics;
    RoundTrip round = scrub_and_write(load(scour_test::make_incremental_fixture()),
                                      ScrubOptions{}, diagnostics);
    Document reopened = load(round.written.bytes);
    const InspectionReport report =
        inspect_document(reopened, "scrubbed.pdf", InspectOptions{}, diagnostics);
    CHECK(report.facts.revisions <= 1);
    CHECK(find_by_id(report, "structure.dead-objects") == nullptr);
    // The old page text really is gone from the file, not merely unreferenced.
    const std::string bytes(reinterpret_cast<const char*>(round.written.bytes.data()),
                            round.written.bytes.size());
    CHECK(bytes.find("Escalate to") == std::string::npos);
}

SCOUR_TEST(sanitize, redacts_terms_and_detected_pii_then_verifies) {
    Diagnostics diagnostics;
    ScrubOptions options;
    options.targets.terms = {scour_test::kNeedle};
    options.targets.pii = true;
    RoundTrip round = scrub_and_write(load(scour_test::make_fixture({})), options, diagnostics);

    Document reopened = load(round.written.bytes);
    const std::string text = all_text(reopened);
    CHECK(text.find(scour_test::kNeedle) == std::string::npos);
    CHECK(text.find(scour_test::kEmail) == std::string::npos);
    CHECK(text.find(scour_test::kSsn) == std::string::npos);
    CHECK(text.find(scour_test::kCard) == std::string::npos);
    CHECK(text.find(scour_test::kIban) == std::string::npos);
    // Unrelated words survive.
    CHECK(text.find("Scour fixture - page 1") != std::string::npos);
    const RedactionReport verification = verify_document(reopened, options.targets, diagnostics);
    CHECK(verification.clean());
}

SCOUR_TEST(sanitize, verify_reports_leftovers_in_the_source) {
    Diagnostics diagnostics;
    Document document = load(scour_test::make_fixture({}));
    RedactionTargets targets;
    targets.terms = {scour_test::kNeedle};
    targets.pii = true;
    const RedactionReport report = verify_document(document, targets, diagnostics);
    CHECK(!report.clean());
    CHECK(!report.remaining.empty());
    CHECK_EQ(report.remaining.front().page, 1);
}

SCOUR_TEST(sanitize, scrub_keeps_the_document_readable) {
    Diagnostics diagnostics;
    RoundTrip round = scrub_and_write(load(scour_test::make_fixture({})), ScrubOptions{},
                                      diagnostics);
    Document reopened = load(round.written.bytes);
    CHECK_EQ(reopened.version_major(), 1);
    CHECK(round.written.objects_written >= std::size_t{8});
    CHECK_LT(round.written.objects_written, std::size_t{30});
    CHECK(!round.written.bytes.empty());
}

SCOUR_TEST(sanitize, options_can_keep_each_class_of_data) {
    Diagnostics diagnostics;
    ScrubOptions options;
    options.strip_metadata = false;
    options.strip_annotations = false;
    options.strip_attachments = false;
    options.strip_scripts = false;
    RoundTrip round = scrub_and_write(load(scour_test::make_fixture({})), options, diagnostics);
    Document reopened = load(round.written.bytes);
    const InspectionReport report =
        inspect_document(reopened, "kept.pdf", InspectOptions{}, diagnostics);
    CHECK_EQ(report.facts.author, std::string(scour_test::kAuthor));
    CHECK(report.facts.annotations >= std::size_t{1});
    CHECK(report.facts.embedded_files >= std::size_t{1});
    CHECK(report.has("actions"));
}

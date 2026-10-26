// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/document.hpp"
#include "scour/inspector.hpp"
#include "support/fixtures.hpp"

using namespace scour;

namespace {

Document load(const Bytes& bytes) {
    Diagnostics diagnostics;
    return Document::load(bytes, LoadOptions{}, diagnostics);
}

InspectionReport inspect(Document& document, const std::string& name = "fixture.pdf") {
    Diagnostics diagnostics;
    return inspect_document(document, name, InspectOptions{}, diagnostics);
}

const Finding* find_by_id(const InspectionReport& report, std::string_view id) {
    for (const Finding& finding : report.findings) {
        if (finding.id == id) return &finding;
    }
    return nullptr;
}

}  // namespace

SCOUR_TEST(inspector, reports_metadata_attachments_and_actions) {
    Document document = load(scour_test::make_fixture({}));
    const InspectionReport report = inspect(document);
    CHECK_EQ(report.facts.author, std::string(scour_test::kAuthor));
    CHECK_EQ(report.facts.producer, std::string(scour_test::kProducer));
    CHECK(report.facts.embedded_files >= 1);
    CHECK(report.has("metadata"));
    CHECK(report.has("embedded"));
    CHECK(report.has("actions"));
    CHECK(report.has("annotations"));
    CHECK(find_by_id(report, "actions.javascript") != nullptr);
    CHECK(find_by_id(report, "embedded.files") != nullptr);
    CHECK(report.risk >= 55);
}

SCOUR_TEST(inspector, finds_every_way_text_can_hide) {
    Document document = load(scour_test::make_hidden_text_fixture());
    const InspectionReport report = inspect(document);
    CHECK(find_by_id(report, "hidden-text.invisible") != nullptr);
    CHECK(find_by_id(report, "hidden-text.covered") != nullptr);
    CHECK(find_by_id(report, "hidden-text.white") != nullptr);
    CHECK(find_by_id(report, "hidden-text.off-page") != nullptr);
    CHECK(report.risk >= 55);

    const Finding* invisible = find_by_id(report, "hidden-text.invisible");
    CHECK(invisible != nullptr);
    if (invisible != nullptr) CHECK(invisible->evidence.find("BLUEBIRD") != std::string::npos);
    const Finding* covered = find_by_id(report, "hidden-text.covered");
    CHECK(covered != nullptr);
    if (covered != nullptr) {
        CHECK(covered->evidence.find("Secret settlement") != std::string::npos);
        CHECK(covered->has_location);
        CHECK_EQ(covered->page, 1);
    }
}

SCOUR_TEST(inspector, clean_document_scores_zero) {
    Document document = load(scour_test::make_minimal_pdf("A memo with no secrets."));
    const InspectionReport report = inspect(document);
    CHECK_EQ(report.risk, 0);
    CHECK_EQ(report.grade, std::string("clean"));
    CHECK(report.findings.empty());
}

SCOUR_TEST(inspector, image_only_page_is_a_limitation_not_a_pass) {
    Document document = load(scour_test::make_scanned_fixture());
    const InspectionReport report = inspect(document);
    CHECK(find_by_id(report, "integrity.image-only") != nullptr);
    CHECK_EQ(report.facts.text_pages, 0);
    CHECK_EQ(report.facts.image_pages, 1);
    CHECK(report.risk > 0);
}

SCOUR_TEST(inspector, incremental_update_leaves_recoverable_text) {
    Document document = load(scour_test::make_incremental_fixture());
    const InspectionReport report = inspect(document);
    CHECK(report.facts.revisions >= 2);
    const Finding* dead = find_by_id(report, "structure.dead-objects");
    CHECK(dead != nullptr);
    if (dead != nullptr) {
        CHECK(!dead->evidence.empty());
        CHECK(dead->severity == Severity::Error);
    }
}

SCOUR_TEST(inspector, json_is_well_formed_and_escaped) {
    Document document = load(scour_test::make_fixture({}));
    const InspectionReport report = inspect(document, "a \"quoted\" file.pdf");
    const std::string json = report.to_json();
    CHECK(json.find("\"tool\": \"scour\"") != std::string::npos);
    CHECK(json.find("\"findings\": [") != std::string::npos);
    CHECK(json.find("a \\\"quoted\\\" file.pdf") != std::string::npos);
    int braces = 0;
    for (const char c : json) {
        if (c == '{') ++braces;
        if (c == '}') --braces;
    }
    CHECK_EQ(braces, 0);
    // No raw control characters may leak into a JSON string.
    for (const char c : json) {
        CHECK(static_cast<unsigned char>(c) >= 0x20 || c == '\n');
    }
}

SCOUR_TEST(inspector, text_report_names_the_categories_it_found) {
    Document document = load(scour_test::make_fixture({}));
    const InspectionReport report = inspect(document);
    const std::string text = report.to_text();
    CHECK(text.find("SCOUR REPORT") != std::string::npos);
    CHECK(text.find("HIDDEN-TEXT") == std::string::npos);  // fixture has no hidden text
    CHECK(text.find("METADATA") != std::string::npos);
    CHECK(text.find("RISK") != std::string::npos);
}

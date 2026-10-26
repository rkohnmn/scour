// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_INSPECTOR_HPP
#define SCOUR_INSPECTOR_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "scour/document.hpp"
#include "scour/error.hpp"
#include "scour/geometry.hpp"

namespace scour {

/// One reason the document is not safe to share. Findings are aggregated: a
/// page with two thousand invisible glyphs produces one finding, not two
/// thousand, because a report a human cannot read is not a report.
struct Finding {
    std::string id;        ///< stable identifier, e.g. "hidden-text.covered"
    std::string category;  ///< metadata | hidden-text | annotations | embedded | actions | structure | pii | integrity
    Severity severity = Severity::Info;
    std::string title;     ///< one line, sentence case
    std::string detail;    ///< what was found and why it matters
    std::string evidence;  ///< the leak itself, truncated and sanitised
    int page = 0;          ///< 1-based page number, 0 for document level
    bool has_location = false;
    Rect location;
};

struct CategoryScore {
    std::string category;
    int points = 0;
    int maximum = 0;
    int findings = 0;
};

/// Facts a reader wants before the findings: what the file is, what produced it
/// and how it is protected. Nothing here is guessed; absent values stay empty.
struct DocumentFacts {
    std::string path;
    std::size_t size = 0;
    std::string version;
    int pages = 0;
    int objects = 0;
    int revisions = 0;
    bool repaired = false;
    bool encrypted = false;
    std::string encryption;  ///< human summary, e.g. "AES-256 (R6), owner password"
    bool authenticated = false;
    std::string author;
    std::string title;
    std::string subject;
    std::string keywords;
    std::string creator;
    std::string producer;
    std::string created;
    std::string modified;
    bool has_xmp = false;
    int text_pages = 0;
    int image_pages = 0;
    int scanned_pages = 0;
    std::size_t text_characters = 0;
    std::size_t embedded_files = 0;
    std::size_t annotations = 0;
};

struct InspectionReport {
    DocumentFacts facts;
    std::vector<Finding> findings;
    std::vector<CategoryScore> scores;
    int risk = 0;  ///< 0 (nothing found) .. 100 (do not share this file)
    std::string grade;
    std::string headline;

    [[nodiscard]] int count(Severity severity) const noexcept;
    [[nodiscard]] bool has(std::string_view category) const noexcept;
    [[nodiscard]] std::string to_text() const;
    [[nodiscard]] std::string to_json() const;
};

struct InspectOptions {
    bool include_pii = true;
    bool read_metadata = true;
};

/// Reads the document end to end and reports what a recipient could recover
/// that the sender probably does not intend to share. Never mutates the input.
InspectionReport inspect_document(Document& document, std::string path,
                                  const InspectOptions& options, Diagnostics& diagnostics);

/// Escapes a UTF-8 string and wraps it in double quotes, so every JSON writer in
/// the tool emits the same well-formed output. Control characters become \u00XX.
[[nodiscard]] std::string json_quote(std::string_view text);

}  // namespace scour

#endif  // SCOUR_INSPECTOR_HPP

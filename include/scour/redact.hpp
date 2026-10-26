// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_REDACT_HPP
#define SCOUR_REDACT_HPP

#include <map>
#include <string>
#include <vector>

#include "scour/document.hpp"
#include "scour/geometry.hpp"

namespace scour {

struct RedactionTargets {
    std::vector<std::string> terms;  ///< literal, case-insensitive
    bool pii = false;                ///< every detector from patterns.hpp
    std::vector<int> pages;          ///< 1-based; empty means every page
    std::map<int, std::vector<Rect>> rects;  ///< 1-based page -> user-space boxes
    bool paint = true;               ///< draw solid boxes over removed glyphs
};

struct RedactionFinding {
    int page = 0;  ///< 1-based
    std::string kind;
    std::string text;
    Rect box;
};

struct RedactionReport {
    std::vector<RedactionFinding> found;
    std::vector<RedactionFinding> remaining;
    int pages_scanned = 0;
    int glyphs_removed = 0;
    int boxes_painted = 0;
    bool verified = false;
    std::vector<std::string> warnings;

    [[nodiscard]] bool clean() const noexcept { return verified && remaining.empty(); }
};

/// Removes matching glyphs from the content streams of the selected pages and
/// (optionally) paints opaque boxes over them. The text is removed from the
/// content stream, not merely covered, and the function re-extracts the result
/// to prove it. Returns the report; inspect `remaining` for anything it could
/// not remove (text inside images, undecodable fonts).
RedactionReport redact_document(Document& document, const RedactionTargets& targets,
                                Diagnostics& diagnostics);

/// Re-runs detection against the current state of the document. Used by
/// `scour verify` and after a scrub.
RedactionReport verify_document(Document& document, const RedactionTargets& targets,
                               Diagnostics& diagnostics);

}  // namespace scour

#endif  // SCOUR_REDACT_HPP

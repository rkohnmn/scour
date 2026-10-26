// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_SANITIZE_HPP
#define SCOUR_SANITIZE_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "scour/document.hpp"
#include "scour/error.hpp"
#include "scour/redact.hpp"

namespace scour {

struct ScrubOptions {
    RedactionTargets targets;

    /// Remove /Info, the XMP packet and /PieceInfo.
    bool strip_metadata = true;
    /// Remove every annotation, and the form field dictionary with it.
    bool strip_annotations = true;
    /// Remove /Names/EmbeddedFiles and /AF attachments.
    bool strip_attachments = true;
    /// Remove /OpenAction, /AA, /JS and the JavaScript name tree.
    bool strip_scripts = true;

    /// Run the redaction pass when targets are present. Set false for a
    /// metadata/annotation-only scrub.
    bool redact = true;
};

struct ScrubReport {
    RedactionReport redaction;
    int metadata_removed = 0;
    int annotations_removed = 0;
    int attachments_removed = 0;
    int actions_removed = 0;
    int form_fields_removed = 0;
    bool redacted = false;
    std::vector<std::string> notes;
};

/// Removes the selected classes of embedded data in place. The caller is
/// expected to rewrite the document afterwards: a full rewrite is what drops
/// the now-unreachable objects and, with them, every earlier revision.
ScrubReport scrub_document(Document& document, const ScrubOptions& options,
                           Diagnostics& diagnostics);

}  // namespace scour

#endif  // SCOUR_SANITIZE_HPP

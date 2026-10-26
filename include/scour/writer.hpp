// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_WRITER_HPP
#define SCOUR_WRITER_HPP

#include <cstddef>
#include <string>
#include <vector>

#include "scour/bytes.hpp"
#include "scour/document.hpp"
#include "scour/error.hpp"

namespace scour {

struct WriteOptions {
    /// Only write objects reachable from these trailer keys. Defaults to the
    /// catalog plus /Info: everything else is garbage, and a scrubber must not
    /// resurrect it. `scour scrub` removes /Info from the trailer itself, so a
    /// metadata scrub is a deletion, not a writer flag.
    std::vector<std::string> trailer_keys{"Root", "Info"};
    /// Re-deflate uncompressed streams when that makes them smaller.
    bool compress_streams = false;
    /// Derive /ID from a hash of the body instead of random bytes. Deterministic
    /// output is what lets CI diff two scrubs of the same document.
    bool deterministic_id = true;
    /// Header version. Zero keeps the source document's version (clamped to
    /// 1.4-2.0).
    int version_major = 0;
    int version_minor = 0;
};

struct WriteResult {
    Bytes bytes;
    std::size_t objects_written = 0;
    std::size_t objects_dropped = 0;
    std::size_t stream_bytes_saved = 0;
};

/// Serialises the object graph into a fresh, fully rewritten PDF: classic
/// cross-reference table, no incremental update, no dead objects.
WriteResult write_document(Document& document, const WriteOptions& options,
                           Diagnostics& diagnostics);

/// Escapes a byte string as a PDF literal string. Exposed for tests.
std::string escape_literal_string(std::string_view bytes);
std::string escape_name(std::string_view name);
std::string format_pdf_real(double value);

}  // namespace scour

#endif  // SCOUR_WRITER_HPP

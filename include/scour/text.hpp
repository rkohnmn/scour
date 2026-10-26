// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_TEXT_HPP
#define SCOUR_TEXT_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "scour/bytes.hpp"
#include "scour/document.hpp"
#include "scour/geometry.hpp"

namespace scour {

/// One decoded glyph. `byte_start`/`byte_end` address the *encoded* string in
/// the content stream, which is what a redaction rewrites.
struct Glyph {
    std::string utf8;
    std::uint32_t byte_start = 0;
    std::uint32_t byte_end = 0;
    double advance = 0.0;  ///< horizontal advance in unscaled text space units
    double width = 0.0;    ///< glyph width in em
    Rect box;
    int render_mode = 0;    ///< PDF text rendering mode (3 and 7 are invisible)
    double fill_gray = 0.0; ///< approximate luminance of the fill colour, 0 = black
};

struct TextRun {
    std::uint32_t stream_object = 0;  ///< content stream or form XObject number
    std::size_t begin = 0;            ///< span of the whole string operand
    std::size_t end = 0;
    std::string text;
    Rect box;
    std::vector<Glyph> glyphs;
    bool from_form = false;
    /// Encoded bytes of a space glyph in this font, used by redaction to keep
    /// the advance width while removing the original characters.
    std::string space_bytes = " ";
    /// Painting order within the page (0 = first). Content painted later covers
    /// content painted earlier; the inspector uses this to find text buried
    /// under a rectangle that was drawn on top of it.
    std::size_t order = 0;
};

/// An opaque axis-aligned rectangle filled on the page. Only rectangles drawn
/// with `re` + a fill operator are recorded: that is what a "redaction" made by
/// drawing a black box produces, and it is what can hide live text.
struct PaintBox {
    Rect box;
    double gray = 0.0;  ///< approximate luminance of the fill, 0 = black
    std::size_t order = 0;
};

/// A decoded content stream that may need to be edited.
struct TextStream {
    std::uint32_t object_number = 0;
    Bytes decoded;
};

struct PageAnalysis {
    int page_index = 0;
    std::uint32_t page_object = 0;
    Rect box;
    std::vector<TextStream> streams;
    std::vector<TextRun> runs;
    std::vector<PaintBox> paint_boxes;
    std::string text;                       ///< reading-order text with separators
    std::vector<std::uint32_t> run_of_byte; ///< parallel to `text`
    /// Byte offset in `text` where each run's own characters begin. Separators
    /// inserted between runs are mapped to the following run in `run_of_byte`,
    /// so subtracting from a match offset needs this table, not a search.
    std::vector<std::size_t> run_text_start;
    bool has_text = false;
    bool has_images = false;
    bool reliable = true;       ///< false when a font's encoding cannot be trusted
    bool has_form_text = false; ///< text inside form XObjects

    [[nodiscard]] std::string_view text_view() const noexcept { return text; }
};

struct TextOptions {
    bool include_forms = true;
    int max_form_depth = 6;
};

PageAnalysis analyze_page(Document& document, std::uint32_t page_object, int page_index,
                          const TextOptions& options, Diagnostics& diagnostics);

struct DocumentText {
    std::vector<PageAnalysis> pages;
    [[nodiscard]] std::string all_text() const;
};

DocumentText analyze_document(Document& document, const TextOptions& options,
                              Diagnostics& diagnostics);

}  // namespace scour

#endif  // SCOUR_TEXT_HPP

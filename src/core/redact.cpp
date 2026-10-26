// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Redaction works at the level of the encoded string, not the rendered page.
// Each matched glyph's bytes are replaced by a space glyph of the same width, so
// the text layer no longer contains the secret while the layout does not move.
// The whole run is not deleted: an entire paragraph should not disappear because
// a phone number was found in it.
#include "scour/redact.hpp"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <tuple>
#include <unordered_set>

#include "scour/deflate.hpp"
#include "scour/lexer.hpp"
#include "scour/pages.hpp"
#include "scour/patterns.hpp"
#include "scour/text.hpp"
#include "scour/writer.hpp"

namespace scour {

namespace {

struct Edit {
    std::size_t begin = 0;
    std::size_t end = 0;
    std::string replacement;
};

struct PageWork {
    PageAnalysis analysis;
    std::vector<std::vector<bool>> marked;  // per run, per glyph
    std::vector<Rect> boxes;
    std::vector<RedactionFinding> findings;
};    std::string operand_bytes(std::string_view stream, std::size_t begin, std::size_t end) {
    Lexer lexer(stream, begin);
    const Token token = lexer.next();
    if (token.end > end) return {};
    return token.text;
}

std::string space_filler(const std::string& space_bytes, std::size_t length) {
    std::string filler = space_bytes.empty() ? std::string(" ") : space_bytes;
    while (filler.size() < length) filler.push_back(' ');
    filler.resize(length);
    return filler;
}

/// One entry per byte of the run's text, holding the glyph that produced it.
/// A document with many matches would otherwise scan a run's glyph list for
/// every byte of every match, which is quadratic in the length of a line.
std::vector<std::uint32_t> glyph_offsets(const TextRun& run) {
    std::size_t length = 0;
    for (const Glyph& glyph : run.glyphs) length += glyph.utf8.size();
    std::vector<std::uint32_t> offsets(length, 0);
    std::size_t offset = 0;
    for (std::size_t g = 0; g < run.glyphs.size(); ++g) {
        const std::size_t size = run.glyphs[g].utf8.size();
        for (std::size_t i = 0; i < size; ++i) offsets[offset + i] = static_cast<std::uint32_t>(g);
        offset += size;
    }
    return offsets;
}

/// Merges boxes that touch or overlap so a painted block covers a run instead
/// of one rectangle per glyph. Ordering by baseline first keeps the glyphs of
/// one line together -- sorting by x alone interleaves every column of the
/// page, which both prevents the merge and makes it quadratic. A union can
/// change the block's x reach, so the sweep repeats until nothing merges.
void merge_boxes(std::vector<Rect>& boxes) {
    if (boxes.size() < 2) return;
    bool merged = true;
    std::vector<Rect> out;
    while (merged) {
        merged = false;
        std::sort(boxes.begin(), boxes.end(), [](const Rect& a, const Rect& b) {
            if (a.y0 != b.y0) return a.y0 < b.y0;
            return a.x0 < b.x0;
        });
        out.clear();
        out.reserve(boxes.size());
        for (const Rect& box : boxes) {
            if (!out.empty() && out.back().expanded(1.0).intersects(box)) {
                out.back() = out.back().united(box);
                merged = true;
                continue;
            }
            out.push_back(box);
        }
        boxes.swap(out);
    }
}

std::vector<int> selected_pages(const RedactionTargets& targets, int page_count) {
    std::vector<int> pages;
    if (targets.pages.empty()) {
        pages.resize(static_cast<std::size_t>(page_count));
        for (int i = 0; i < page_count; ++i) pages[static_cast<std::size_t>(i)] = i;
        return pages;
    }
    for (int page : targets.pages) {
        if (page >= 1 && page <= page_count) pages.push_back(page - 1);
    }
    return pages;
}

std::vector<PatternMatch> matches_for(std::string_view text, const RedactionTargets& targets) {
    std::vector<PatternMatch> matches;
    if (!targets.terms.empty()) {
        const std::vector<PatternMatch> terms = detect_terms(text, targets.terms);
        matches.insert(matches.end(), terms.begin(), terms.end());
    }
    if (targets.pii) {
        const std::vector<PatternMatch> pii = detect_pii(text);
        matches.insert(matches.end(), pii.begin(), pii.end());
    }
    std::sort(matches.begin(), matches.end(),
              [](const PatternMatch& a, const PatternMatch& b) { return a.begin < b.begin; });
    return matches;
}

}  // namespace

RedactionReport verify_document(Document& document, const RedactionTargets& targets,
                               Diagnostics& diagnostics) {
    RedactionReport report;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    report.pages_scanned = static_cast<int>(pages.size());
    for (std::size_t i = 0; i < pages.size(); ++i) {
        const PageAnalysis analysis = analyze_page(document, pages[i], static_cast<int>(i), TextOptions{},
                                                   diagnostics);
        if (!analysis.reliable) {
            report.warnings.push_back("page " + std::to_string(i + 1) +
                                      " has a font encoding that cannot be verified");
        }
        for (const PatternMatch& match : matches_for(analysis.text, targets)) {
            RedactionFinding finding;
            finding.page = static_cast<int>(i) + 1;
            finding.kind = match.kind;
            const std::size_t length = std::min<std::size_t>(match.end - match.begin, 120);
            finding.text = analysis.text.substr(match.begin, length);
            if (!analysis.run_of_byte.empty() && match.begin < analysis.run_of_byte.size()) {
                const std::uint32_t run_index = analysis.run_of_byte[match.begin];
                if (run_index < analysis.runs.size()) finding.box = analysis.runs[run_index].box;
            }
            report.remaining.push_back(std::move(finding));
        }
    }
    report.verified = report.remaining.empty();
    return report;
}

RedactionReport redact_document(Document& document, const RedactionTargets& targets,
                                Diagnostics& diagnostics) {
    RedactionReport report;
    const std::vector<std::uint32_t> page_numbers = collect_page_numbers(document, diagnostics);
    report.pages_scanned = static_cast<int>(page_numbers.size());
    if (page_numbers.empty()) {
        report.warnings.push_back("the document has no pages");
        return report;
    }
    const std::vector<int> selected = selected_pages(targets, static_cast<int>(page_numbers.size()));

    std::map<std::uint32_t, Bytes> stream_data;  // decoded content per stream object
    std::map<std::uint32_t, std::vector<Edit>> edits;
    std::set<std::tuple<std::uint32_t, std::size_t, std::size_t>> seen_edits;
    std::vector<std::pair<std::uint32_t, std::vector<Rect>>> page_boxes;

    for (int page_index : selected) {
        const std::uint32_t page_object = page_numbers[static_cast<std::size_t>(page_index)];
        PageAnalysis analysis = analyze_page(document, page_object, page_index, TextOptions{}, diagnostics);
        if (!analysis.reliable)
            report.warnings.push_back("page " + std::to_string(page_index + 1) +
                                      " uses a font encoding that cannot be decoded reliably");
        for (const TextStream& stream : analysis.streams) stream_data[stream.object_number] = stream.decoded;

        // Per-run text offsets, so a page-level match can be mapped to glyphs.
        // The table comes from the extractor: scanning run_of_byte would return
        // the separator before a run and shift every match by one glyph.
        const std::vector<std::size_t>& run_start = analysis.run_text_start;
        std::vector<std::vector<std::uint32_t>> glyph_at(analysis.runs.size());
        for (std::size_t r = 0; r < analysis.runs.size(); ++r) glyph_at[r] = glyph_offsets(analysis.runs[r]);
        std::vector<std::vector<bool>> marked(analysis.runs.size());
        for (std::size_t r = 0; r < analysis.runs.size(); ++r) marked[r].assign(analysis.runs[r].glyphs.size(), false);

        std::vector<RedactionFinding> findings;
        for (const PatternMatch& match : matches_for(analysis.text, targets)) {
            RedactionFinding finding;
            finding.page = page_index + 1;
            finding.kind = match.kind;
            finding.text = analysis.text.substr(match.begin, std::min<std::size_t>(match.end - match.begin, 120));
            for (std::size_t i = match.begin; i < match.end && i < analysis.run_of_byte.size(); ++i) {
                const std::uint32_t run = analysis.run_of_byte[i];
                if (run >= analysis.runs.size() || run_start[run] == std::string::npos) continue;
                const std::size_t offset = i - run_start[run];
                if (offset >= glyph_at[run].size()) continue;
                const std::uint32_t glyph = glyph_at[run][offset];
                marked[run][glyph] = true;
                finding.box = finding.box.united(analysis.runs[run].glyphs[glyph].box);
            }
            if (!finding.box.empty()) findings.push_back(finding);
        }

        // Rect targets: everything whose box intersects the box is removed.
        if (const auto found = targets.rects.find(page_index + 1); found != targets.rects.end()) {
            for (std::size_t r = 0; r < analysis.runs.size(); ++r) {
                for (std::size_t g = 0; g < analysis.runs[r].glyphs.size(); ++g) {
                    for (const Rect& rect : found->second) {
                        if (analysis.runs[r].glyphs[g].box.intersects(rect)) {
                            marked[r][g] = true;
                            RedactionFinding finding;
                            finding.page = page_index + 1;
                            finding.kind = "area";
                            finding.text = analysis.runs[r].glyphs[g].utf8;
                            finding.box = analysis.runs[r].glyphs[g].box;
                            findings.push_back(finding);
                            break;
                        }
                    }
                }
            }
        }

        std::vector<Rect> boxes;
        int removed = 0;
        for (std::size_t r = 0; r < analysis.runs.size(); ++r) {
            const TextRun& run = analysis.runs[r];
            bool any = false;
            for (bool value : marked[r]) any = any || value;
            if (!any) continue;
            if (run.stream_object == 0) {
                report.warnings.push_back("page " + std::to_string(page_index + 1) +
                                          ": text in an inline content stream cannot be rewritten");
                continue;
            }
            const auto source = stream_data.find(run.stream_object);
            if (source == stream_data.end() || source->second.size() < run.end) {
                report.warnings.push_back("page " + std::to_string(page_index + 1) +
                                          ": could not locate the content stream for a redaction");
                continue;
            }
            const std::string original = operand_bytes(view_of(source->second), run.begin, run.end);
            std::string rewritten;
            rewritten.reserve(original.size() + 8);
            for (std::size_t g = 0; g < run.glyphs.size(); ++g) {
                const Glyph& glyph = run.glyphs[g];
                const std::size_t length = glyph.byte_end - glyph.byte_start;
                if (length == 0 || glyph.byte_end > original.size()) continue;
                if (marked[r][g]) {
                    rewritten += space_filler(run.space_bytes, length);
                    ++removed;
                    boxes.push_back(glyph.box.expanded(0.5));
                } else {
                    rewritten.append(original, glyph.byte_start, length);
                }
            }
            const std::string replacement = "(" + escape_literal_string(rewritten) + ")";
            const auto key = std::make_tuple(run.stream_object, run.begin, run.end);
            if (seen_edits.insert(key).second)
                edits[run.stream_object].push_back(Edit{run.begin, run.end, replacement});
        }

        merge_boxes(boxes);
        if (boxes.empty() && removed == 0 && !findings.empty()) {
            // Findings without glyphs means the match was in a text layer we
            // could not rewrite; report it instead of silently claiming success.
            report.warnings.push_back("page " + std::to_string(page_index + 1) +
                                      ": matches were found but no glyph could be removed");
        }
        report.glyphs_removed += removed;
        report.found.insert(report.found.end(), findings.begin(), findings.end());
        if (!boxes.empty()) page_boxes.emplace_back(page_object, std::move(boxes));
    }

    // Apply content stream rewrites.
    for (auto& [stream_number, list] : edits) {
        auto source = stream_data.find(stream_number);
        if (source == stream_data.end()) continue;
        std::vector<Edit> ordered = list;
        std::sort(ordered.begin(), ordered.end(),
                  [](const Edit& a, const Edit& b) { return a.begin > b.begin; });
        std::string data(reinterpret_cast<const char*>(source->second.data()),
                         source->second.size());
        std::size_t previous_begin = data.size();
        bool valid = true;
        for (const Edit& edit : ordered) {
            if (edit.end > previous_begin) {
                valid = false;
                break;
            }
            if (edit.begin > data.size() || edit.end > data.size()) {
                valid = false;
                break;
            }
            data.replace(edit.begin, edit.end - edit.begin, edit.replacement);
            previous_begin = edit.begin;
        }
        if (!valid) {
            report.warnings.push_back("internal: overlapping redaction edits were discarded");
            continue;
        }
        Object* stream = document.mutable_object(stream_number);
        if (stream == nullptr || !stream->is_stream()) continue;
        const Bytes compressed = zlib_compress(data);
        stream->set_stream_data(compressed);
        stream->set("Filter", Object::name("FlateDecode"));
        stream->remove("DecodeParms");
        stream->set("Length", Object::integer(static_cast<std::int64_t>(compressed.size())));
    }

    // Paint opaque boxes as an extra content stream, painted last.
    if (targets.paint) {
        for (auto& [page_object, boxes] : page_boxes) {
            Object* page = document.mutable_object(page_object);
            if (page == nullptr || !page->is_dict_like()) continue;
            std::string content = "q\n0 g\n";
            for (const Rect& box : boxes) {
                char buffer[160];
                std::snprintf(buffer, sizeof(buffer), "%s %s %s %s re f\n",
                              format_pdf_real(box.x0).c_str(), format_pdf_real(box.y0).c_str(),
                              format_pdf_real(box.width()).c_str(),
                              format_pdf_real(box.height()).c_str());
                content += buffer;
            }
            content += "Q\n";
            Dict plain;
            const Bytes encoded = zlib_compress(content);
            plain.set("Filter", Object::name("FlateDecode"));
            plain.set("Length", Object::integer(static_cast<std::int64_t>(encoded.size())));
            const std::uint32_t stream_number = document.add_object(Object::stream(plain, encoded));

            const Object* contents = page->find("Contents");
            if (contents == nullptr) {
                page->set("Contents", Object::reference(stream_number));
            } else if (contents->is_array()) {
                Object& array = *page->find("Contents");
                array.items().push_back(Object::reference(stream_number));
            } else {
                std::vector<Object> items;
                items.push_back(*contents);
                items.push_back(Object::reference(stream_number));
                page->set("Contents", Object::array(std::move(items)));
            }
            report.boxes_painted += static_cast<int>(boxes.size());
        }
    }

    // Verification is not optional: re-extract and look again.
    const RedactionReport verification = verify_document(document, targets, diagnostics);
    report.remaining = verification.remaining;
    report.verified = verification.remaining.empty();
    for (const std::string& warning : verification.warnings) report.warnings.push_back(warning);
    return report;
}

}  // namespace scour

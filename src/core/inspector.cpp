// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// The inspector is deliberately paranoid and deliberately conservative. It only
// claims what it can show: every finding carries the bytes that produced it, and
// anything it could not verify (text baked into images, undecodable fonts,
// clipping paths it does not evaluate) is reported as a limitation rather than
// quietly ignored.
#include "scour/inspector.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "scour/bytes.hpp"
#include "scour/patterns.hpp"
#include "scour/pages.hpp"
#include "scour/text.hpp"

namespace scour {

namespace {

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------
constexpr std::size_t kEvidenceLimit = 96;
constexpr std::size_t kMaxObjectsWalked = 400000;
constexpr int kMaxDepth = 64;

std::string printable(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char raw : text) {
        const auto c = static_cast<unsigned char>(raw);
        if (c == '\n' || c == '\r' || c == '\t') {
            out.push_back(' ');
        } else if (c >= 0x20 && c < 0x7F) {
            out.push_back(static_cast<char>(c));
        } else if (c >= 0x80) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back(' ');
        }
    }
    return out;
}

std::string collapse_spaces(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    bool last_space = true;
    for (char c : text) {
        const bool space = c == ' ' || c == '\t' || c == '\r' || c == '\n';
        if (space) {
            if (!last_space) out.push_back(' ');
            last_space = true;
        } else {
            out.push_back(c);
            last_space = false;
        }
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

std::string snippet(std::string_view text, std::size_t limit = kEvidenceLimit) {
    std::string clean = collapse_spaces(printable(text));
    if (clean.size() <= limit) return clean;
    return clean.substr(0, limit - 1) + "\xE2\x80\xA6";  // U+2026
}

bool mostly_printable(std::string_view text) {
    if (text.size() < 6) return false;
    std::size_t printable_bytes = 0;
    for (char raw : text) {
        const auto c = static_cast<unsigned char>(raw);
        if (c >= 0x20 && c < 0x7F) ++printable_bytes;
    }
    return printable_bytes * 10 >= text.size() * 8;
}

std::string human_bytes(std::size_t bytes) {
    constexpr const char* kUnits[] = {"B", "KB", "MB", "GB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    char buffer[32];
    if (unit == 0)
        std::snprintf(buffer, sizeof(buffer), "%zu B", bytes);
    else
        std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, kUnits[unit]);
    return buffer;
}

std::string severity_label(Severity severity) {
    switch (severity) {
        case Severity::Debug: return "debug";
        case Severity::Info: return "note";
        case Severity::Warning: return "warning";
        case Severity::Error: return "error";
    }
    return "?";
}

int severity_points(Severity severity) {
    switch (severity) {
        case Severity::Debug: return 0;
        case Severity::Info: return 2;
        case Severity::Warning: return 9;
        case Severity::Error: return 20;
    }
    return 0;
}

/// Risk is intentionally not the sum of category percentages: a document with
/// one recoverable secret is dangerous even if every other category is clean.
/// Each finding contributes in severity order with a geometric decay, so the
/// first serious problem dominates and a long tail of notes cannot drown it.
double risk_weight(Severity severity) {
    switch (severity) {
        case Severity::Debug: return 1.0;
        case Severity::Info: return 4.0;
        case Severity::Warning: return 14.0;
        case Severity::Error: return 34.0;
    }
    return 0.0;
}

const std::unordered_map<std::string, int>& category_caps() {
    static const std::unordered_map<std::string, int> kCaps = {
        {"actions", 40},      {"annotations", 24}, {"embedded", 30},
        {"hidden-text", 42},  {"integrity", 22},   {"metadata", 28},
        {"pii", 36},          {"structure", 26},
    };
    return kCaps;
}

const std::array<std::string, 8>& category_order() {
    static const std::array<std::string, 8> kOrder = {"metadata", "hidden-text", "annotations",
                                                     "embedded", "actions", "structure", "pii",
                                                     "integrity"};
    return kOrder;
}

// ---------------------------------------------------------------------------
// Report assembly helpers
// ---------------------------------------------------------------------------
Finding& add_finding(InspectionReport& report, std::string id, std::string category,
                     Severity severity, std::string title, std::string detail) {
    report.findings.push_back(Finding{std::move(id), std::move(category), severity,
                                      std::move(title), std::move(detail), {}, 0, false, {}});
    return report.findings.back();
}

void set_evidence(Finding& finding, std::string evidence) {
    finding.evidence = snippet(evidence, kEvidenceLimit);
}

void set_location(Finding& finding, int page, const Rect& rect) {
    finding.page = page;
    finding.has_location = true;
    finding.location = rect;
}

bool title_present(std::string_view text) {
    for (char c : text) {
        if (c != ' ' && c != '\t' && c != '\0') return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Object graph walking
// ---------------------------------------------------------------------------
void walk_reachable(const Document& document, const Object& value,
                    std::unordered_set<std::uint32_t>& seen, int depth) {
    if (depth > kMaxDepth) return;
    if (value.is_ref()) {
        const std::uint32_t number = value.ref_number();
        if (number == 0 || !seen.insert(number).second) return;
        if (seen.size() > kMaxObjectsWalked) return;
        const Object* target = document.resolve_ref(number);
        if (target != nullptr) walk_reachable(document, *target, seen, depth + 1);
        return;
    }
    if (value.is_array()) {
        for (const Object& item : value.items()) walk_reachable(document, item, seen, depth + 1);
        return;
    }
    if (value.is_dict_like()) {
        for (const auto& [key, item] : value.dict().items) walk_reachable(document, item, seen, depth + 1);
    }
}

struct DeadObject {
    std::uint32_t number = 0;
    std::string sample;
};

std::vector<std::string> strings_in(const Object& value, int depth) {
    std::vector<std::string> found;
    if (depth > 16) return found;
    if (value.is_string()) {
        if (mostly_printable(value.as_string())) found.push_back(value.as_string());
        return found;
    }
    if (value.is_array()) {
        for (const Object& item : value.items()) {
            const std::vector<std::string> nested = strings_in(item, depth + 1);
            found.insert(found.end(), nested.begin(), nested.end());
        }
        return found;
    }
    if (value.is_dict_like()) {
        for (const auto& [key, item] : value.dict().items) {
            (void)key;
            const std::vector<std::string> nested = strings_in(item, depth + 1);
            found.insert(found.end(), nested.begin(), nested.end());
        }
    }
    return found;
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------
struct MetadataHits {
    std::string author;
    std::string title;
    std::string subject;
    std::string keywords;
    std::string creator;
    std::string producer;
    std::string created;
    std::string modified;
    std::vector<std::pair<std::string, std::string>> custom;
};

MetadataHits read_info(Document& document, const Object* info) {
    MetadataHits hits;
    if (info == nullptr || !info->is_dict_like()) return hits;
    for (const auto& [key, value] : info->dict().items) {
        std::string text;
        if (value.is_string()) {
            text = document.resolve_string(value);
        } else if (value.is_name()) {
            text = value.as_name();
        } else {
            continue;
        }
        if (!title_present(text)) continue;
        if (key == "Author") hits.author = text;
        else if (key == "Title") hits.title = text;
        else if (key == "Subject") hits.subject = text;
        else if (key == "Keywords") hits.keywords = text;
        else if (key == "Creator") hits.creator = text;
        else if (key == "Producer") hits.producer = text;
        else if (key == "CreationDate") hits.created = text;
        else if (key == "ModDate") hits.modified = text;
        else hits.custom.emplace_back(key, text);
    }
    return hits;
}

struct XmpHits {
    bool present = false;
    std::vector<std::pair<std::string, std::string>> fields;  // label, value
    bool history = false;
};

/// Extracts the human-readable text of an element, dropping nested tags. XMP
/// wraps every scalar in RDF containers, so returning the raw inner markup would
/// make the evidence unreadable exactly where it matters most.
std::string xml_text_of(std::string_view xml, std::string_view tag) {
    const std::string open = "<" + std::string(tag);
    const std::size_t start = xml.find(open);
    if (start == std::string_view::npos) return {};
    const std::size_t open_end = xml.find('>', start);
    if (open_end == std::string_view::npos) return {};
    const std::size_t close = xml.find("</" + std::string(tag), open_end);
    if (close == std::string_view::npos) return {};
    std::string inner(xml.substr(open_end + 1, close - open_end - 1));
    if (inner.find('<') == std::string::npos) return inner;

    // Prefer the first rdf:li text node, which is where XMP puts the value.
    const std::size_t item = inner.find("<rdf:li");
    if (item != std::string::npos) {
        const std::size_t item_open = inner.find('>', item);
        const std::size_t item_close = inner.find("</rdf:li", item_open);
        if (item_open != std::string::npos && item_close != std::string::npos) {
            std::string value = inner.substr(item_open + 1, item_close - item_open - 1);
            const std::size_t nested = value.find('<');
            if (nested != std::string::npos) value = value.substr(0, nested);
            return value;
        }
    }
    std::string out;
    bool in_tag = false;
    for (char c : inner) {
        if (c == '<') {
            in_tag = true;
            continue;
        }
        if (c == '>') {
            in_tag = false;
            out.push_back(' ');
            continue;
        }
        if (!in_tag) out.push_back(c);
    }
    return out;
}

XmpHits read_xmp(Document& document, const Object* metadata) {
    XmpHits hits;
    if (metadata == nullptr || !metadata->is_stream()) return hits;
    Bytes data;
    try {
        data = document.decode_stream(*metadata);
    } catch (const ScourError&) {
        return hits;
    }
    if (data.empty()) return hits;
    const std::string xml(reinterpret_cast<const char*>(data.data()), data.size());
    hits.present = true;
    const std::pair<const char*, const char*> kFields[] = {
        {"dc:creator", "creator"},     {"dc:title", "title"},
        {"xmp:CreatorTool", "tool"},   {"pdf:Producer", "producer"},
        {"xmp:CreateDate", "created"}, {"xmp:ModifyDate", "modified"},
        {"photoshop:AuthorsPosition", "role"},
    };
    for (const auto& [tag, label] : kFields) {
        std::string value = collapse_spaces(printable(xml_text_of(xml, tag)));
        if (!value.empty()) hits.fields.emplace_back(label, snippet(value, 80));
    }
    hits.history = xml.find("xmpMM:History") != std::string::npos ||
                   xml.find("stEvt:action") != std::string::npos ||
                   xml.find("xmpMM:DerivedFrom") != std::string::npos;
    return hits;
}

// ---------------------------------------------------------------------------
// Annotations, forms, attachments, actions
// ---------------------------------------------------------------------------
struct AnnotationSummary {
    int page = 0;
    std::string subtype;
    std::string contents;
    std::string author;
    bool hidden = false;
    bool attached_file = false;
    bool has_action = false;
    std::string action_kind;
    Rect rect;
    bool has_rect = false;
};

std::string join_samples(const std::vector<std::string>& samples, std::size_t limit = 3) {
    std::string out;
    for (std::size_t i = 0; i < samples.size() && i < limit; ++i) {
        if (!out.empty()) out += " | ";
        out += snippet(samples[i], 72);
    }
    if (samples.size() > limit) out += " | \xE2\x80\xA6";
    return out;
}

void scan_actions(const Document& document, const Object& value,
                  std::unordered_set<std::uint32_t>& seen, int depth,
                  std::map<std::string, std::vector<std::string>>& hits) {
    if (depth > 24) return;
    if (value.is_ref()) {
        const std::uint32_t number = value.ref_number();
        if (number == 0 || !seen.insert(number).second) return;
        const Object* target = document.resolve_ref(number);
        if (target != nullptr) scan_actions(document, *target, seen, depth + 1, hits);
        return;
    }
    if (value.is_array()) {
        for (const Object& item : value.items())
            scan_actions(document, item, seen, depth + 1, hits);
        return;
    }
    if (!value.is_dict_like()) return;

    const auto record = [&hits](const std::string& kind, const std::string& sample) {
        std::vector<std::string>& bucket = hits[kind];
        if (bucket.size() < 8 && !sample.empty()) bucket.push_back(sample);
    };

    for (const auto& [key, item] : value.dict().items) {
        if (key == "JavaScript" || key == "JS") {
            std::string sample;
            if (item.is_string()) sample = document.resolve_string(item);
            record("javascript", sample);
        } else if (key == "Launch") {
            record("launch", item.debug_string(1));
        } else if (key == "SubmitForm") {
            record("submit", item.debug_string(1));
        } else if (key == "GoToR") {
            record("remote", item.debug_string(1));
        } else if (key == "ImportData") {
            record("import", item.debug_string(1));
        } else if (key == "RichMedia") {
            record("rich-media", "");
        }
        scan_actions(document, item, seen, depth + 1, hits);
    }
}

std::vector<std::string> attachment_names(const Document& document, const Object* catalog) {
    std::vector<std::string> names;
    if (catalog == nullptr || !catalog->is_dict_like()) return names;
    // A file is commonly reachable twice: once from /Names/EmbeddedFiles and
    // once from the catalog's /AF array. Count the file, not the references.
    std::unordered_set<std::uint32_t> specs;
    std::unordered_set<std::string> direct_names;
    const auto add = [&names, &specs, &direct_names](const std::string& name,
                                                    const Object* reference) {
        if (reference != nullptr && reference->is_ref()) {
            if (!specs.insert(reference->ref_number()).second) return;
        } else {
            if (!direct_names.insert(name).second) return;
        }
        names.push_back(name);
    };
    const Object* names_object = catalog->find("Names");
    const Object* resolved_names = names_object != nullptr ? document.resolve(*names_object) : nullptr;
    if (resolved_names != nullptr && resolved_names->is_dict_like()) {
        const Object* tree = resolved_names->dict().find("EmbeddedFiles");
        const Object* resolved_tree = tree != nullptr ? document.resolve(*tree) : nullptr;
        if (resolved_tree != nullptr && resolved_tree->is_dict_like()) {
            const Object* array = resolved_tree->dict().find("Names");
            const Object* resolved_array = array != nullptr ? document.resolve(*array) : nullptr;
            if (resolved_array != nullptr && resolved_array->is_array()) {
                const std::vector<Object>& items = resolved_array->items();
                for (std::size_t i = 0; i + 1 < items.size(); i += 2) {
                    if (items[i].is_string())
                        add(document.resolve_string(items[i]), &items[i + 1]);
                }
            }
        }
    }
    const Object* af = catalog->find("AF");
    const Object* resolved_af = af != nullptr ? document.resolve(*af) : nullptr;
    if (resolved_af != nullptr && resolved_af->is_array()) {
        for (const Object& item : resolved_af->items()) {
            const Object* spec = document.resolve(item);
            if (spec == nullptr || !spec->is_dict_like()) continue;
            const std::string name = spec->dict().get_string("UF");
            add(name.empty() ? "unattached file" : name, &item);
        }
    }
    return names;
}

struct FormField {
    std::string name;
    std::string value;
};

void collect_fields(const Document& document, const Object& field, std::string prefix,
                    int depth, std::vector<FormField>& out) {
    if (depth > 16) return;
    const Object* resolved = document.resolve(field);
    if (resolved == nullptr || !resolved->is_dict_like()) return;
    std::string name = resolved->dict().get_string("T");
    if (!name.empty()) {
        name = document.resolve_string(*resolved->dict().find("T"));
        prefix = prefix.empty() ? name : prefix + "." + name;
    }
    if (const Object* value = resolved->dict().find("V"); value != nullptr) {
        std::string text;
        if (value->is_string())
            text = document.resolve_string(*value);
        else if (value->is_name())
            text = value->as_name();
        else if (value->is_array()) {
            for (const Object& item : value->items())
                if (item.is_string()) text += document.resolve_string(item) + " ";
        }
        if (title_present(text)) out.push_back(FormField{prefix, snippet(text, 60)});
    }
    if (const Object* kids = resolved->dict().find("Kids"); kids != nullptr) {
        const Object* array = document.resolve(*kids);
        if (array != nullptr && array->is_array()) {
            for (const Object& kid : array->items()) collect_fields(document, kid, prefix, depth + 1, out);
        }
    }
}

// ---------------------------------------------------------------------------
// Detection over the extracted text
// ---------------------------------------------------------------------------
struct PageScan {
    int page = 0;
    int invisible = 0;
    int off_page = 0;
    int tiny = 0;
    int covered = 0;
    int white = 0;
    bool covered_by_dark_box = false;
    std::string invisible_sample;
    std::string off_page_sample;
    std::string tiny_sample;
    std::string covered_sample;
    std::string white_sample;
    Rect covered_box;
    Rect off_page_box;
    bool has_text = false;
    bool has_images = false;
};

bool contains_rect(const Rect& outer, const Rect& inner) {
    constexpr double kTolerance = 0.5;
    return outer.x0 <= inner.x0 + kTolerance && outer.y0 <= inner.y0 + kTolerance &&
           outer.x1 >= inner.x1 - kTolerance && outer.y1 >= inner.y1 - kTolerance;
}

void analyse_page_glyphs(PageAnalysis& analysis, PageScan& scan) {
    for (const TextRun& run : analysis.runs) {
        for (const Glyph& glyph : run.glyphs) {
            if (glyph.utf8.empty() || glyph.utf8 == " " || glyph.utf8 == "\t") continue;
            if (glyph.render_mode == 3 || glyph.render_mode == 7) {
                ++scan.invisible;
                if (scan.invisible_sample.empty()) {
                    std::string line;
                    for (const Glyph& other : run.glyphs) line += other.utf8;
                    scan.invisible_sample = snippet(line);
                }
            }
            if (!analysis.box.empty() && !glyph.box.intersects(analysis.box)) {
                ++scan.off_page;
                if (scan.off_page_sample.empty()) scan.off_page_sample = snippet(run.text);
                if (scan.off_page_box.empty()) scan.off_page_box = glyph.box;
            }
            if (glyph.box.height() < 2.0) {
                ++scan.tiny;
                if (scan.tiny_sample.empty()) scan.tiny_sample = snippet(run.text);
            }
            bool covered = false;
            for (const PaintBox& paint : analysis.paint_boxes) {
                if (paint.order <= run.order) continue;
                if (!contains_rect(paint.box, glyph.box)) continue;
                covered = true;
                if (paint.gray < 0.35) scan.covered_by_dark_box = true;
                if (scan.covered_box.empty()) scan.covered_box = paint.box;
                break;
            }
            if (covered) {
                ++scan.covered;
                if (scan.covered_sample.empty()) scan.covered_sample = snippet(run.text);
            }
            if (glyph.fill_gray >= 0.93) {
                bool on_dark = false;
                for (const PaintBox& paint : analysis.paint_boxes) {
                    if (paint.order >= run.order) continue;
                    if (paint.gray < 0.4 && contains_rect(paint.box, glyph.box)) {
                        on_dark = true;
                        break;
                    }
                }
                if (!on_dark) {
                    ++scan.white;
                    if (scan.white_sample.empty()) scan.white_sample = snippet(run.text);
                }
            }
        }
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// InspectionReport
// ---------------------------------------------------------------------------
int InspectionReport::count(Severity severity) const noexcept {
    int total = 0;
    for (const Finding& finding : findings)
        if (finding.severity == severity) ++total;
    return total;
}

bool InspectionReport::has(std::string_view category) const noexcept {
    for (const Finding& finding : findings)
        if (finding.category == category) return true;
    return false;
}

std::string InspectionReport::to_text() const {
    std::ostringstream out;
    const std::string file = facts.path.empty() ? "(document)" : facts.path;
    out << "SCOUR REPORT\n";
    out << "============\n";
    out << file << "\n\n";
    out << "  Size        " << human_bytes(facts.size) << "\n";
    out << "  Format      PDF " << facts.version << "\n";
    out << "  Pages       " << facts.pages << "\n";
    out << "  Objects     " << facts.objects;
    if (facts.revisions > 1) out << " over " << facts.revisions << " revisions";
    out << "\n";
    out << "  Encryption  "
        << (facts.encrypted ? (facts.encryption.empty() ? "encrypted" : facts.encryption)
                            : std::string("none"))
        << "\n";
    if (!facts.author.empty()) out << "  Author      " << snippet(facts.author, 72) << "\n";
    if (!facts.title.empty()) out << "  Title       " << snippet(facts.title, 72) << "\n";
    if (!facts.producer.empty()) out << "  Producer    " << snippet(facts.producer, 72) << "\n";
    out << "  Text        " << facts.text_characters << " characters on " << facts.text_pages
        << " pages";
    if (facts.image_pages > 0) out << ", " << facts.image_pages << " with images";
    out << "\n";
    if (facts.embedded_files > 0) out << "  Attachments " << facts.embedded_files << "\n";
    if (facts.annotations > 0) out << "  Annotations " << facts.annotations << "\n";
    out << "\n";

    char score[64];
    std::snprintf(score, sizeof(score), "%3d/100", risk);
    out << "  RISK " << score << "  " << grade << "\n";
    if (!headline.empty()) out << "  " << headline << "\n";
    out << "\n";

    if (findings.empty()) {
        out << "No findings. Nothing in the metadata, text layer, annotations, attachments,\n";
        out << "actions or object graph looks like a leak.\n";
        return out.str();
    }

    for (const std::string& category : category_order()) {
        std::vector<const Finding*> bucket;
        for (const Finding& finding : findings)
            if (finding.category == category) bucket.push_back(&finding);
        if (bucket.empty()) continue;
        std::sort(bucket.begin(), bucket.end(), [](const Finding* a, const Finding* b) {
            if (a->severity != b->severity) return a->severity > b->severity;
            return a->page < b->page;
        });
        std::string header = category;
        for (char& c : header) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        out << header << "\n";
        for (const Finding* finding : bucket) {
            out << "  [" << severity_label(finding->severity) << "] " << finding->title;
            if (finding->page > 0) out << "  (page " << finding->page << ")";
            out << "\n";
            out << "      " << finding->detail << "\n";
            if (!finding->evidence.empty()) out << "      > " << finding->evidence << "\n";
        }
        out << "\n";
    }

    out << "Scores\n";
    for (const CategoryScore& score_line : scores) {
        if (score_line.findings == 0) continue;
        out << "  " << score_line.category << "  " << score_line.points << "/" << score_line.maximum
            << "  (" << score_line.findings << " finding" << (score_line.findings == 1 ? "" : "s")
            << ")\n";
    }
    out << "\n";
    out << "Run `scour scrub <file>` to remove what can be removed, then `scour verify` to\n";
    out << "prove the result no longer contains it.\n";
    return out.str();
}

namespace {

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (char raw : text) {
        const auto c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string json_string(std::string_view text) { return json_quote(text); }

}  // namespace

std::string json_quote(std::string_view text) { return "\"" + json_escape(text) + "\""; }

std::string InspectionReport::to_json() const {
    std::ostringstream out;
    out << "{\n";
    out << "  \"tool\": \"scour\",\n";
    out << "  \"format\": 1,\n";
    out << "  \"risk\": " << risk << ",\n";
    out << "  \"grade\": " << json_string(grade) << ",\n";
    out << "  \"headline\": " << json_string(headline) << ",\n";
    out << "  \"facts\": {\n";
    out << "    \"path\": " << json_string(facts.path) << ",\n";
    out << "    \"size\": " << facts.size << ",\n";
    out << "    \"version\": " << json_string(facts.version) << ",\n";
    out << "    \"pages\": " << facts.pages << ",\n";
    out << "    \"objects\": " << facts.objects << ",\n";
    out << "    \"revisions\": " << facts.revisions << ",\n";
    out << "    \"repaired\": " << (facts.repaired ? "true" : "false") << ",\n";
    out << "    \"encrypted\": " << (facts.encrypted ? "true" : "false") << ",\n";
    out << "    \"encryption\": " << json_string(facts.encryption) << ",\n";
    out << "    \"authenticated\": " << (facts.authenticated ? "true" : "false") << ",\n";
    out << "    \"author\": " << json_string(facts.author) << ",\n";
    out << "    \"title\": " << json_string(facts.title) << ",\n";
    out << "    \"subject\": " << json_string(facts.subject) << ",\n";
    out << "    \"keywords\": " << json_string(facts.keywords) << ",\n";
    out << "    \"creator\": " << json_string(facts.creator) << ",\n";
    out << "    \"producer\": " << json_string(facts.producer) << ",\n";
    out << "    \"created\": " << json_string(facts.created) << ",\n";
    out << "    \"modified\": " << json_string(facts.modified) << ",\n";
    out << "    \"xmp\": " << (facts.has_xmp ? "true" : "false") << ",\n";
    out << "    \"text_pages\": " << facts.text_pages << ",\n";
    out << "    \"image_pages\": " << facts.image_pages << ",\n";
    out << "    \"text_characters\": " << facts.text_characters << ",\n";
    out << "    \"embedded_files\": " << facts.embedded_files << ",\n";
    out << "    \"annotations\": " << facts.annotations << "\n";
    out << "  },\n";

    out << "  \"scores\": [";
    bool first = true;
    for (const CategoryScore& score_line : scores) {
        if (!first) out << ",";
        first = false;
        out << "\n    {\"category\": " << json_string(score_line.category)
            << ", \"points\": " << score_line.points << ", \"maximum\": " << score_line.maximum
            << ", \"findings\": " << score_line.findings << "}";
    }
    if (!scores.empty()) out << "\n  ";
    out << "],\n";

    out << "  \"findings\": [";
    first = true;
    for (const Finding& finding : findings) {
        if (!first) out << ",";
        first = false;
        out << "\n    {\n";
        out << "      \"id\": " << json_string(finding.id) << ",\n";
        out << "      \"category\": " << json_string(finding.category) << ",\n";
        out << "      \"severity\": " << json_string(severity_label(finding.severity)) << ",\n";
        out << "      \"title\": " << json_string(finding.title) << ",\n";
        out << "      \"detail\": " << json_string(finding.detail) << ",\n";
        out << "      \"evidence\": " << json_string(finding.evidence) << ",\n";
        out << "      \"page\": " << finding.page;
        if (finding.has_location) {
            out << ",\n      \"box\": [" << finding.location.x0 << ", " << finding.location.y0
                << ", " << finding.location.x1 << ", " << finding.location.y1 << "]";
        }
        out << "\n    }";
    }
    if (!findings.empty()) out << "\n  ";
    out << "]\n";
    out << "}\n";
    return out.str();
}

// ---------------------------------------------------------------------------
// inspect_document
// ---------------------------------------------------------------------------
InspectionReport inspect_document(Document& document, std::string path,
                                  const InspectOptions& options, Diagnostics& diagnostics) {
    InspectionReport report;
    report.facts.path = std::move(path);
    report.facts.size = document.file_size();
    report.facts.version = document.version_string();
    report.facts.objects = static_cast<int>(document.xref().size());
    report.facts.revisions = document.revision_count();
    report.facts.repaired = document.repaired();
    report.facts.encrypted = document.encrypted();

    if (document.encrypted()) {
        const EncryptionInfo& info = document.security().info();
        std::string method = std::string(to_string(info.stream_method));
        for (char& c : method) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (method == "RC4") method = "RC4";
        report.facts.encryption = method;
        if (info.key_bits > 0) report.facts.encryption += " " + std::to_string(info.key_bits) + "-bit";
        if (info.revision > 0) report.facts.encryption += " (R" + std::to_string(info.revision) + ")";
        if (info.owner_password_used) report.facts.encryption += ", owner password";
        report.facts.authenticated = info.authenticated;
        if (!info.failure.empty()) {
            Finding& finding = add_finding(
                report, "encryption.unreadable", "integrity", Severity::Error,
                "The document is encrypted and could not be opened",
                "Scour could not recover the file key, so nothing inside the file was inspected. "
                "Everything below describes the container only.");
            set_evidence(finding, info.failure);
        } else if (info.stream_method == CryptMethod::Rc4) {
            Finding& finding = add_finding(
                report, "encryption.weak", "integrity", Severity::Warning,
                "The encryption is RC4, which is broken",
                "RC4 keys of this generation can be recovered with off-the-shelf tools, and the "
                "encryption does not protect the text from a recipient who is allowed to open the "
                "file anyway. Treat protected text as readable.");
            set_evidence(finding, report.facts.encryption);
        } else if (info.stream_method == CryptMethod::Aes128) {
            add_finding(report, "encryption.aes128", "integrity", Severity::Info,
                        "Encryption is AES-128 (PDF 1.7)",
                        "AES-128 with revision 4 is acceptable but the older revisions of the "
                        "standard handler have known weaknesses. AES-256 (R6) is the modern bar.");
        }
        if (info.authenticated && !info.encrypt_metadata) {
            add_finding(report, "encryption.metadata-plaintext", "metadata", Severity::Warning,
                        "Metadata is not encrypted",
                        "/Encrypt has EncryptMetadata false, so the document information and XMP "
                        "packets are readable without the password.");
        }
    }

    // Pages and their text layer.
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    report.facts.pages = static_cast<int>(pages.size());        const Object* catalog = document.catalog();
    const Object* info_object = nullptr;
    if (const Object* info_ref = document.trailer().find("Info");
        info_ref != nullptr && (info_ref->is_ref() || info_ref->is_dict_like())) {
        info_object = info_ref->is_ref() ? document.resolve_ref(info_ref->ref_number())
                                         : document.resolve(*info_ref);
    }
    const MetadataHits metadata = read_info(document, info_object);
    report.facts.author = snippet(metadata.author, 120);
    report.facts.title = snippet(metadata.title, 120);
    report.facts.subject = snippet(metadata.subject, 120);
    report.facts.keywords = snippet(metadata.keywords, 120);
    report.facts.creator = snippet(metadata.creator, 120);
    report.facts.producer = snippet(metadata.producer, 120);
    report.facts.created = metadata.created;
    report.facts.modified = metadata.modified;

    if (options.read_metadata) {
        if (!metadata.author.empty()) {
            Finding& finding = add_finding(report, "metadata.author", "metadata", Severity::Warning,
                                           "The author name is embedded in the file",
                                           "The /Info dictionary names a person. It survives printing, "
                                           "conversion and most \"remove metadata\" settings in office "
                                           "software, and it is the first thing a recipient sees.");
            set_evidence(finding, metadata.author);
        }
        if (!metadata.title.empty() || !metadata.subject.empty() || !metadata.keywords.empty()) {
            std::string text = metadata.title;
            if (!metadata.subject.empty()) text += " | " + metadata.subject;
            if (!metadata.keywords.empty()) text += " | " + metadata.keywords;
            Finding& finding = add_finding(
                report, "metadata.descriptive", "metadata", Severity::Info,
                "Title, subject or keywords describe the document",
                "Descriptive metadata often contains a project name, a client or an internal "
                "codename that is not visible on the page.");
            set_evidence(finding, text);
        }
        if (!metadata.creator.empty() || !metadata.producer.empty()) {
            std::string text = metadata.creator;
            if (!metadata.producer.empty()) text += (text.empty() ? "" : " -> ") + metadata.producer;
            Finding& finding = add_finding(
                report, "metadata.software", "metadata", Severity::Info,
                "The producing software and version are recorded",
                "Creator/Producer strings fingerprint the workflow (and sometimes the machine) that "
                "made the file. They are not needed by a reader.");
            set_evidence(finding, text);
        }
        if (!metadata.created.empty() || !metadata.modified.empty()) {
            std::string text = metadata.created;
            if (!metadata.modified.empty()) text += " modified " + metadata.modified;
            Finding& finding = add_finding(report, "metadata.timestamps", "metadata", Severity::Info,
                                           "Creation and modification timestamps are present",
                                           "Timestamps can place a person at a desk at a particular "
                                           "hour and reveal how long a document was edited.");
            set_evidence(finding, text);
        }
        if (!metadata.custom.empty()) {
            std::string text;
            for (const auto& [key, value] : metadata.custom)
                text += (text.empty() ? "" : " | ") + key + "=" + value;
            Finding& finding = add_finding(
                report, "metadata.custom", "metadata", Severity::Warning,
                "Custom document properties carry extra data",
                "Custom /Info keys are written by templates, CRMs and document management systems. "
                "They commonly contain case numbers, client names and internal identifiers.");
            set_evidence(finding, text);
        }

        const Object* metadata_stream = nullptr;
        if (catalog != nullptr) {
            const Object* xmp = catalog->find("Metadata");
            if (xmp != nullptr) metadata_stream = document.resolve(*xmp);
        }
        const XmpHits xmp = read_xmp(document, metadata_stream);
        report.facts.has_xmp = xmp.present;
        if (xmp.present) {
            std::string text;
            for (const auto& [label, value] : xmp.fields)
                text += (text.empty() ? "" : " | ") + label + "=" + value;
            Finding& finding = add_finding(
                report, "metadata.xmp", "metadata",
                xmp.history ? Severity::Warning : Severity::Info,
                xmp.history ? "The XMP packet records editing history"
                            : "An XMP metadata packet is present",
                xmp.history
                    ? "XMP history entries name earlier versions, applications and sometimes file "
                      "paths. Stripping /Info alone leaves this behind."
                    : "XMP duplicates and extends /Info. Most metadata removers miss it because it "
                      "lives in a compressed stream.");
            set_evidence(finding, text.empty() ? "XMP packet, no human-readable fields" : text);
        }
    }

    // Attachments and annotations.
    const std::vector<std::string> attachments = attachment_names(document, catalog);
    report.facts.embedded_files = attachments.size();
    if (!attachments.empty()) {
        Finding& finding = add_finding(report, "embedded.files", "embedded", Severity::Error,
                                       "Files are embedded inside the PDF",
                                       "Embedded files are frequently the editable source document, a "
                                       "spreadsheet backing a chart, or a signing certificate chain. "
                                       "They are invisible on the page and travel with the PDF.");
        set_evidence(finding, join_samples(attachments));
    }

    if (!pages.empty() && catalog != nullptr) {
        std::vector<AnnotationSummary> annotations;
        std::unordered_set<std::uint32_t> seen_annotations;
        for (std::size_t i = 0; i < pages.size(); ++i) {
            const Object* page = document.resolve_ref(pages[i]);
            if (page == nullptr || !page->is_dict_like()) continue;
            const Object* annots = page->find("Annots");
            const Object* array = annots != nullptr ? document.resolve(*annots) : nullptr;
            if (array == nullptr || !array->is_array()) continue;
            for (const Object& item : array->items()) {
                // The same annotation can be referenced from more than one page
                // (and is in real files); report it once.
                if (item.is_ref() && !seen_annotations.insert(item.ref_number()).second) continue;
                const Object* annot = document.resolve(item);
                if (annot == nullptr || !annot->is_dict_like()) continue;
                AnnotationSummary summary;
                summary.page = static_cast<int>(i) + 1;
                summary.subtype = annot->dict().get_name("Subtype");
                if (const Object* contents = annot->dict().find("Contents");
                    contents != nullptr && contents->is_string())
                    summary.contents = document.resolve_string(*contents);
                if (const Object* author = annot->dict().find("T");
                    author != nullptr && author->is_string())
                    summary.author = document.resolve_string(*author);
                const std::int64_t flags = annot->dict().get_int("F", 0);
                summary.hidden = (flags & 0x2) != 0 || (flags & 0x20) != 0;
                summary.attached_file = summary.subtype == "FileAttachment";
                if (const Object* action = annot->dict().find("A");
                    action != nullptr) {
                    const Object* resolved_action = document.resolve(*action);
                    if (resolved_action != nullptr && resolved_action->is_dict_like()) {
                        summary.has_action = true;
                        summary.action_kind = resolved_action->dict().get_name("S");
                    }
                }
                if (const Object* rect = annot->dict().find("Rect");
                    rect != nullptr && rect->is_array() && rect->items().size() >= 4) {
                    summary.rect = Rect::from_corners(rect->items()[0].as_real(),
                                                     rect->items()[1].as_real(),
                                                     rect->items()[2].as_real(),
                                                     rect->items()[3].as_real());
                    summary.has_rect = true;
                }
                annotations.push_back(std::move(summary));
            }
        }
        report.facts.annotations = annotations.size();

        std::vector<std::string> comments;
        std::vector<std::string> authors;
        std::vector<std::string> hidden_annotations;
        std::vector<std::string> files;
        int first_page = 0;
        for (const AnnotationSummary& annotation : annotations) {
            if (!annotation.contents.empty()) {
                comments.push_back(annotation.contents);
                if (first_page == 0) first_page = annotation.page;
            }
            if (!annotation.author.empty()) authors.push_back(annotation.author);
            if (annotation.hidden) hidden_annotations.push_back(annotation.subtype);
            if (annotation.attached_file) files.push_back(annotation.subtype);
        }
        if (!comments.empty()) {
            Finding& finding = add_finding(
                report, "annotations.comments", "annotations", Severity::Warning,
                "Comments and notes are attached to the document",
                "Text annotations keep their full contents in the file even when the note icon is "
                "collapsed. A flat print or PDF export hides them; a recipient who opens the file "
                "sees every comment.");
            set_evidence(finding, join_samples(comments));
            finding.page = first_page;
        }
        if (!authors.empty()) {
            Finding& finding = add_finding(report, "annotations.authors", "annotations",
                                           Severity::Warning,
                                           "Comment authors are named",
                                           "The /T entry of an annotation is the display name of the "
                                           "reviewer, which is usually the person's real name or "
                                           "account name.");
            set_evidence(finding, join_samples(authors));
        }
        if (!hidden_annotations.empty()) {
            Finding& finding = add_finding(
                report, "annotations.hidden", "annotations", Severity::Warning,
                "Annotations are marked hidden or no-view",
                "The Hidden and NoView flags stop a viewer from drawing the annotation, but the "
                "content is still present and can be extracted or flipped back on.");
            set_evidence(finding, join_samples(hidden_annotations));
        }
        if (!files.empty()) {
            add_finding(report, "annotations.attachment", "embedded", Severity::Warning,
                        "File attachment annotations are present",
                        "A file attachment annotation embeds another file at a point on the page. "
                        "It is invisible in print and easy to miss in review.");
        }
        for (const AnnotationSummary& annotation : annotations) {
            if (!annotation.has_action) continue;
            const std::string kind = annotation.action_kind;
            if (kind == "JavaScript") {
                Finding& finding = add_finding(
                    report, "actions.annotation-javascript", "actions", Severity::Error,
                    "An annotation runs JavaScript",
                    "An annotation action can run code when the note is clicked. Scour never "
                    "executes it; it is reported because it is code a recipient may run on open.");
                finding.page = annotation.page;
                break;
            }
        }
    }

    // JavaScript and launch actions anywhere in the reachable graph.
    {
        std::map<std::string, std::vector<std::string>> hits;
        const Object* root = document.catalog();
        if (root != nullptr) {
            std::unordered_set<std::uint32_t> action_seen;
            scan_actions(document, *root, action_seen, 0, hits);
        }
        const auto add_action = [&](const std::string& kind, const std::string& id,
                                    Severity severity, const std::string& title,
                                    const std::string& detail) {
            const auto found = hits.find(kind);
            if (found == hits.end()) return;
            Finding& finding = add_finding(report, id, "actions", severity, title, detail);
            set_evidence(finding, join_samples(found->second));
        };
        add_action("javascript", "actions.javascript", Severity::Error,
                   "The document contains JavaScript",
                   "PDF JavaScript can exfiltrate form data, alter what is displayed and run on "
                   "open depending on the viewer. A document that never needed scripting should "
                   "not carry it.");
        add_action("launch", "actions.launch", Severity::Error,
                   "A launch action can start an external program",
                   "/Launch tells the viewer to execute a local file or program. It is a classic "
                   "malware vector and has no place in a document being shared.");
        add_action("submit", "actions.submit", Severity::Warning,
                   "A form action posts data to a remote server",
                   "/SubmitForm sends field values to a URL. In a reviewed contract this is either "
                   "a leftover template or a channel nobody audited.");
        add_action("remote", "actions.remote", Severity::Info,
                   "Links point to external documents",
                   "/GoToR opens a different PDF, often on a network share. Those paths reveal "
                   "internal drives and server names.");
        add_action("import", "actions.import", Severity::Warning,
                   "A form imports data from another file",
                   "/ImportData pulls values from a local or network file, which leaks a path and "
                   "depends on a machine the recipient does not have.");
        add_action("rich-media", "actions.rich-media", Severity::Warning,
                   "The document embeds rich media",
                   "Rich media annotations carry Flash or video payloads and are a well-known "
                   "attack surface.");
    }

    // Forms.
    if (catalog != nullptr) {
        const Object* acro = catalog->find("AcroForm");
        const Object* form = acro != nullptr ? document.resolve(*acro) : nullptr;
        if (form != nullptr && form->is_dict_like()) {
            std::vector<FormField> fields;
            if (const Object* field_array = form->dict().find("Fields"); field_array != nullptr) {
                const Object* array = document.resolve(*field_array);
                if (array != nullptr && array->is_array()) {
                    for (const Object& field_object : array->items())
                        collect_fields(document, field_object, "", 0, fields);
                }
            }
            if (!fields.empty()) {
                std::string text;
                for (const FormField& field : fields)
                    text += (text.empty() ? "" : " | ") + field.name + "=" + field.value;
                Finding& finding = add_finding(
                    report, "structure.form-values", "structure", Severity::Warning,
                    "Filled-in form values are stored in the file",
                    "A flattened form shows the values on the page, but the field dictionary keeps "
                    "them as data. Values that were typed and then hidden can be extracted without "
                    "rendering the page.");
                set_evidence(finding, text);
            }
        }
    }

    // Hidden optional content (layers).
    if (catalog != nullptr) {
        const Object* oc = catalog->find("OCProperties");
        const Object* properties = oc != nullptr ? document.resolve(*oc) : nullptr;
        if (properties != nullptr && properties->is_dict_like()) {
            if (const Object* defaults = properties->dict().find("D"); defaults != nullptr) {
                const Object* dictionary = document.resolve(*defaults);
                if (dictionary != nullptr && dictionary->is_dict_like()) {
                    if (const Object* off = dictionary->dict().find("OFF"); off != nullptr) {
                        const Object* array = document.resolve(*off);
                        if (array != nullptr && array->is_array() && !array->items().empty()) {
                            Finding& finding = add_finding(
                                report, "structure.hidden-layers", "structure", Severity::Warning,
                                "Layers are switched off by default",
                                "Optional content groups can hold a full copy of a page that is "
                                "hidden until a recipient turns the layer on. Reviewers who look "
                                "only at the rendered page never see it.");
                            set_evidence(finding, std::to_string(array->items().size()) +
                                                      " layer(s) off by default");
                        }
                    }
                }
            }
        }
    }

    // Incremental updates and dead objects.
    if (report.facts.revisions > 1) {
        Finding& finding = add_finding(
            report, "structure.revisions", "structure", Severity::Warning,
            "The file keeps " + std::to_string(report.facts.revisions) + " revisions",
            "Each incremental update appends a new copy of the changed objects and leaves the old "
            "ones in place. Text that was \"deleted\" in an earlier round is still in the file and "
            "can be recovered with a text editor or a parser.");
        finding.evidence = "incremental updates present";
    }

    {
        std::unordered_set<std::uint32_t> reachable;
        if (document.root_number() != 0)
            walk_reachable(document, Object::reference(document.root_number()), reachable, 0);
        if (const Object* info = document.trailer().find("Info");
            info != nullptr && info->is_ref())
            walk_reachable(document, *info, reachable, 0);

        std::vector<DeadObject> dead;
        int scanned = 0;
        for (const auto& [number, entry] : document.xref()) {
            if (entry.kind == XrefEntry::Kind::Free) continue;
            if (reachable.count(number) != 0) continue;
            if (scanned++ > 4000) break;
            DeadObject object;
            object.number = number;
            const Object* value = document.resolve_ref(number);
            if (value == nullptr) continue;
            const std::vector<std::string> strings = strings_in(*value, 0);
            std::vector<std::string> found;
            for (const std::string& text : strings) {
                if (text.size() < 8) continue;
                found.push_back(text);
                if (found.size() >= 3) break;
            }
            object.sample = found.empty() ? std::string() : join_samples(found, 3);
            if (object.sample.empty() && value->is_stream()) {
                // The interesting part of an orphaned content stream is the
                // stream body, not its dictionary. Decode it when it is small
                // enough to be a page and look for readable text.
                try {
                    const Bytes data = document.decode_stream(*value);
                    if (data.size() < (std::size_t{2} << 20)) {
                        const std::string raw(reinterpret_cast<const char*>(data.data()),
                                             data.size());
                        std::vector<std::string> literals;
                        std::size_t cursor = 0;
                        while (cursor < raw.size() && literals.size() < 4) {
                            const std::size_t text_start = raw.find('(', cursor);
                            if (text_start == std::string::npos) break;
                            const std::size_t text_end = raw.find(')', text_start);
                            if (text_end == std::string::npos) break;
                            cursor = text_end + 1;
                            if (text_end > text_start + 1) {
                                const std::string candidate =
                                    raw.substr(text_start + 1, text_end - text_start - 1);
                                if (mostly_printable(candidate)) literals.push_back(candidate);
                            }
                        }
                        if (!literals.empty()) object.sample = join_samples(literals, 4);
                    }
                } catch (const ScourError&) {
                }
            }
            dead.push_back(std::move(object));
        }
        if (!dead.empty()) {
            std::vector<std::string> samples;
            for (const DeadObject& object : dead) {
                if (!object.sample.empty()) samples.push_back(object.sample);
            }
            const std::string count = std::to_string(dead.size());
            Finding& finding = add_finding(
                report, "structure.dead-objects", "structure",
                samples.empty() ? Severity::Info : Severity::Error,
                count + (dead.size() == 1 ? " object is" : " objects are") +
                    " not reachable from the catalog",
                samples.empty()
                    ? "Unreachable objects are invisible to a viewer but stay in the file. They are "
                      "left behind by incremental saves and can contain earlier versions of pages."
                    : "Unreachable objects are still in the file, and some of them carry text. This "
                      "is what a recoverable \"deletion\" looks like: the page is gone from the "
                      "viewer, the words are not.");
            set_evidence(finding, join_samples(samples, 4));
        }
    }

    // Per-page text checks.
    std::map<std::string, std::vector<std::pair<int, std::string>>> pii_hits;
    std::vector<PageScan> scans;
    scans.reserve(pages.size());
    for (std::size_t i = 0; i < pages.size(); ++i) {
        PageAnalysis analysis = analyze_page(document, pages[i], static_cast<int>(i), TextOptions{},
                                             diagnostics);
        PageScan scan;
        scan.page = static_cast<int>(i) + 1;
        scan.has_text = analysis.has_text;
        scan.has_images = analysis.has_images;
        if (analysis.has_text) {
            ++report.facts.text_pages;
            report.facts.text_characters += analysis.text.size();
        }
        if (analysis.has_images) ++report.facts.image_pages;
        if (!analysis.reliable) {
            Finding& finding = add_finding(
                report, "integrity.font-" + std::to_string(i + 1), "integrity", Severity::Warning,
                "Text on page " + std::to_string(i + 1) + " uses a font Scour cannot decode",
                "The font has no usable ToUnicode map or encoding, so glyphs cannot be mapped to "
                "characters with confidence. A redaction cannot prove what it removed on this page.");
            finding.page = static_cast<int>(i) + 1;
        }
        analyse_page_glyphs(analysis, scan);

        if (scan.invisible > 0) {
            Finding& finding = add_finding(
                report, "hidden-text.invisible", "hidden-text", Severity::Error,
                "Invisible text is present on page " + std::to_string(scan.page),
                "Text rendered with mode 3 (or 7) is not painted, but it is in the text layer, it "
                "is selected when a reader selects all, and it is extracted by every indexer. "
                "This is how hidden watermarks, prompts and prior revisions travel.");
            finding.page = scan.page;
            set_evidence(finding, scan.invisible_sample);
            if (scan.invisible > 0) finding.detail += " (" + std::to_string(scan.invisible) +
                                                     " glyphs)";
        }
        if (scan.covered > 0) {
            Finding& finding = add_finding(
                report, "hidden-text.covered", "hidden-text",
                scan.covered_by_dark_box ? Severity::Error : Severity::Warning,
                "Text is still present underneath a filled box" +
                    std::string(" on page ") + std::to_string(scan.page),
                scan.covered_by_dark_box
                    ? "A dark rectangle is drawn on top of live glyphs. This is exactly what a "
                      "painted-on redaction looks like: the page shows a black bar, the text layer "
                      "still contains the words, and copy/paste or a parser recovers them."
                    : "A filled rectangle covers glyphs that are still in the content stream. "
                      "Whatever the box is for, the text underneath is not removed.");
            finding.page = scan.page;
            set_evidence(finding, scan.covered_sample);
            if (!scan.covered_box.empty()) set_location(finding, scan.page, scan.covered_box);
        }
        if (scan.white > 0) {
            Finding& finding = add_finding(
                report, "hidden-text.white", "hidden-text", Severity::Warning,
                "White text sits on an unpainted background on page " + std::to_string(scan.page),
                "Light glyphs on white paper are unreadable on screen but fully extractable, and "
                "they print as blank. This is a common way to carry a note past a visual review.");
            finding.page = scan.page;
            set_evidence(finding, scan.white_sample);
        }
        if (scan.off_page > 0) {
            Finding& finding = add_finding(
                report, "hidden-text.off-page", "hidden-text", Severity::Warning,
                "Glyphs are placed outside the page box on page " + std::to_string(scan.page),
                "Content outside the crop box is not shown, but it is parsed and extracted. Use "
                "the inspector's evidence to see whether the clipped text matters.");
            finding.page = scan.page;
            set_evidence(finding, scan.off_page_sample);
            if (!scan.off_page_box.empty()) set_location(finding, scan.page, scan.off_page_box);
        }
        if (scan.tiny > 0) {
            Finding& finding = add_finding(
                report, "hidden-text.tiny", "hidden-text", Severity::Info,
                "Sub-pixel text is present on page " + std::to_string(scan.page),
                "Glyphs smaller than two points are effectively invisible but remain searchable. "
                "This is occasionally a design choice and often a fingerprint.");
            finding.page = scan.page;
            set_evidence(finding, scan.tiny_sample);
        }
        if (!scan.has_text && scan.has_images) {
            Finding& finding = add_finding(
                report, "integrity.image-only", "integrity", Severity::Warning,
                "Page " + std::to_string(scan.page) + " has no text layer",
                "Everything on this page is drawn inside an image. Scour cannot read or redact "
                "pixels, so the only safe redaction is to replace the image or crop the page. "
                "This is a limitation, not a clean result.");
            finding.page = scan.page;
        }

        if (options.include_pii && !analysis.text.empty()) {
            for (const PatternMatch& match : detect_pii(analysis.text)) {
                pii_hits[match.kind].emplace_back(scan.page,
                                                  snippet(analysis.text.substr(
                                                              match.begin, match.end - match.begin),
                                                          60));
            }
        }
        scans.push_back(std::move(scan));
    }
    report.facts.scanned_pages = static_cast<int>(scans.size());

    // PII summary, one finding per detector.
    const std::map<std::string, std::pair<Severity, std::string>> kPiiMeta = {
        {"private-key", {Severity::Error, "A private key is embedded in the document"}},
        {"api-key", {Severity::Error, "API keys or access tokens appear in the text"}},
        {"card", {Severity::Error, "Payment card numbers appear in the text"}},
        {"iban", {Severity::Error, "Bank account numbers appear in the text"}},
        {"ssn", {Severity::Error, "US social security numbers appear in the text"}},
        {"email", {Severity::Warning, "Email addresses appear in the text"}},
        {"phone", {Severity::Warning, "Phone numbers appear in the text"}},
        {"ipv4", {Severity::Info, "Internal IP addresses appear in the text"}},
    };
    for (const auto& [kind, hits] : pii_hits) {
        const auto meta = kPiiMeta.find(kind);
        const Severity severity = meta == kPiiMeta.end() ? Severity::Warning : meta->second.first;
        const std::string title = meta == kPiiMeta.end()
                                      ? ("Detected " + kind + " values in the text")
                                      : meta->second.second;
        Finding& finding = add_finding(report, "pii." + kind, "pii", severity, title,
                                       "These values are in the visible text layer, which means "
                                       "they are also in the clipboard, the search index and every "
                                       "copy made from this file.");
        finding.page = hits.front().first;
        std::string evidence;
        for (std::size_t i = 0; i < hits.size() && i < 3; ++i) {
            if (!evidence.empty()) evidence += " | ";
            evidence += hits[i].second;
        }
        if (hits.size() > 3) evidence += " | \xE2\x80\xA6";
        set_evidence(finding, evidence);
    }

    // Parser diagnostics: defects are part of the risk picture.
    {
        std::vector<std::string> problems;
        for (const Diagnostic& diagnostic : diagnostics.items()) {
            if (diagnostic.severity == Severity::Warning || diagnostic.severity == Severity::Error)
                problems.push_back(diagnostic.code + ": " + diagnostic.message);
        }
        if (document.repaired()) problems.push_back("the cross-reference table had to be rebuilt");
        if (!problems.empty()) {
            Finding& finding = add_finding(
                report, "integrity.diagnostics", "integrity", Severity::Info,
                "The file did not parse cleanly",
                "Scour recovered the document, but a parser that is less forgiving may see a "
                "different page tree, different text or fail outright. Re-saving the file fixes "
                "the container without fixing the content.");
            set_evidence(finding, join_samples(problems, 2));
        }
    }

    // Scores -----------------------------------------------------------------
    std::unordered_map<std::string, int> points;
    std::unordered_map<std::string, int> counts;
    for (const Finding& finding : report.findings) {
        points[finding.category] += severity_points(finding.severity);
        ++counts[finding.category];
    }
    for (const std::string& category : category_order()) {
        CategoryScore score;
        score.category = category;
        score.maximum = category_caps().at(category);
        score.points = std::min(points[category], score.maximum);
        score.findings = counts[category];
        report.scores.push_back(score);
    }
    std::vector<double> weights;
    weights.reserve(report.findings.size());
    for (const Finding& finding : report.findings) weights.push_back(risk_weight(finding.severity));
    std::sort(weights.begin(), weights.end(), std::greater<>());
    double weighted = 0.0;
    for (std::size_t i = 0; i < weights.size(); ++i)
        weighted += weights[i] * std::pow(0.82, static_cast<double>(i));
    report.risk = static_cast<int>(std::lround(std::min(100.0, weighted)));
    if (report.findings.empty())
        report.risk = 0;
    else if (report.risk == 0)
        report.risk = 1;

    if (report.risk >= 80) report.grade = "critical";
    else if (report.risk >= 55) report.grade = "high";
    else if (report.risk >= 30) report.grade = "elevated";
    else if (report.risk >= 10) report.grade = "low";
    else report.grade = "clean";

    const int errors = report.count(Severity::Error);
    const int warnings = report.count(Severity::Warning);
    std::ostringstream headline;
    if (report.findings.empty()) {
        headline << "Nothing recoverable beyond what the pages show.";
    } else {
        headline << report.findings.size() << " finding" << (report.findings.size() == 1 ? "" : "s");
        if (errors > 0) headline << ", " << errors << " serious";
        if (warnings > 0) headline << ", " << warnings << " worth a look";
        if (report.has("hidden-text")) headline << ". Hidden text is recoverable";
        else if (report.has("structure")) headline << ". The file keeps more than it shows";
        else if (report.has("metadata")) headline << ". Identity and history are still in it";
        headline << ".";
    }
    report.headline = headline.str();

    return report;
}

}  // namespace scour

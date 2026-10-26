// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Text extraction is not a rendering engine. It reconstructs the glyph runs a
// redaction needs: decoded Unicode, the byte range that produced each glyph, and
// an approximate box. Everything is derived from the font's own /ToUnicode map,
// /Widths and encoding tables, so the result is only as good as the document's
// font metadata — which is exactly why the extractor reports `reliable` instead
// of pretending otherwise.
#include "scour/text.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "scour/lexer.hpp"
#include "scour/parser.hpp"
#include "scour/pages.hpp"

namespace scour {

namespace {

constexpr std::size_t kMaxStreamBytes = std::size_t{64} << 20;

struct Matrix {
    double a = 1.0, b = 0.0, c = 0.0, d = 1.0, e = 0.0, f = 0.0;
};

/// Row-vector composition: [x y 1] * (m * n) == ([x y 1] * m) * n.
Matrix multiply(const Matrix& m, const Matrix& n) {
    return Matrix{m.a * n.a + m.b * n.c, m.a * n.b + m.b * n.d,
                  m.c * n.a + m.d * n.c, m.c * n.b + m.d * n.d,
                  m.e * n.a + m.f * n.c + n.e, m.e * n.b + m.f * n.d + n.f};
}

Matrix translation(double x, double y) { return Matrix{1.0, 0.0, 0.0, 1.0, x, y}; }

void transform(const Matrix& m, double x, double y, double& out_x, double& out_y) {
    out_x = m.a * x + m.c * y + m.e;
    out_y = m.b * x + m.d * y + m.f;
}

Rect quad_bounds(const Matrix& m, double x0, double y0, double x1, double y1) {
    double xs[4];
    double ys[4];
    transform(m, x0, y0, xs[0], ys[0]);
    transform(m, x1, y0, xs[1], ys[1]);
    transform(m, x0, y1, xs[2], ys[2]);
    transform(m, x1, y1, xs[3], ys[3]);
    double min_x = xs[0], max_x = xs[0], min_y = ys[0], max_y = ys[0];
    for (int i = 1; i < 4; ++i) {
        min_x = std::min(min_x, xs[i]);
        max_x = std::max(max_x, xs[i]);
        min_y = std::min(min_y, ys[i]);
        max_y = std::max(max_y, ys[i]);
    }
    return Rect{min_x, min_y, max_x, max_y};
}

/// Approximate perceived luminance of a device colour; used to tell black text
/// on white paper from white text hidden on white paper.
double luminance(double r, double g, double b) {
    return std::clamp(0.299 * r + 0.587 * g + 0.114 * b, 0.0, 1.0);
}

// ---------------------------------------------------------------------------
// Unicode helpers
// ---------------------------------------------------------------------------
void append_utf16(std::string& out, std::uint32_t code) {
    if (code >= 0xD800 && code <= 0xDBFF) {
        append_utf8(out, 0xFFFD);
        return;
    }
    append_utf8(out, static_cast<char32_t>(code));
}

std::string utf16be_to_utf8(std::string_view bytes) {
    std::string out;
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 2) {
        std::uint32_t code = (static_cast<std::uint8_t>(bytes[i]) << 8) |
                             static_cast<std::uint8_t>(bytes[i + 1]);
        if (code >= 0xD800 && code <= 0xDBFF && i + 3 < bytes.size()) {
            const std::uint32_t low = (static_cast<std::uint8_t>(bytes[i + 2]) << 8) |
                                      static_cast<std::uint8_t>(bytes[i + 3]);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                i += 2;
            }
        }
        append_utf16(out, code);
    }
    return out;
}

std::uint32_t code_from_bytes(std::string_view bytes) {
    std::uint32_t code = 0;
    for (const char raw : bytes)
        code = (code << 8) | static_cast<unsigned char>(raw);
    return code;
}

char32_t winansi(std::uint8_t byte) {
    static constexpr char32_t kHigh[32] = {
        0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160,
        0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD, 0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022,
        0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178};
    if (byte >= 0x20 && byte <= 0x7E) return byte;
    if (byte >= 0x80 && byte <= 0x9F) return kHigh[byte - 0x80];
    return byte;
}

char32_t glyph_name_to_unicode(std::string_view raw_name) {
    std::string name(raw_name);
    const std::size_t dot = name.find('.');
    if (dot != std::string::npos) name = name.substr(0, dot);
    if (name.empty()) return 0;

    static const std::unordered_map<std::string, char32_t> kNames = {
        {"space", ' '},        {"exclam", '!'},       {"quotedbl", '"'},
        {"numbersign", '#'},   {"dollar", '$'},       {"percent", '%'},
        {"ampersand", '&'},    {"quotesingle", '\''}, {"parenleft", '('},
        {"parenright", ')'},   {"asterisk", '*'},     {"plus", '+'},
        {"comma", ','},        {"hyphen", '-'},       {"period", '.'},
        {"slash", '/'},        {"zero", '0'},         {"one", '1'},
        {"two", '2'},          {"three", '3'},        {"four", '4'},
        {"five", '5'},         {"six", '6'},          {"seven", '7'},
        {"eight", '8'},        {"nine", '9'},         {"colon", ':'},
        {"semicolon", ';'},    {"less", '<'},         {"equal", '='},
        {"greater", '>'},      {"question", '?'},     {"at", '@'},
        {"bracketleft", '['},  {"backslash", '\\'},   {"bracketright", ']'},
        {"asciicircum", '^'},  {"underscore", '_'},   {"grave", '`'},
        {"braceleft", '{'},    {"bar", '|'},          {"braceright", '}'},
        {"asciitilde", '~'},   {"endash", 0x2013},    {"emdash", 0x2014},
        {"bullet", 0x2022},    {"ellipsis", 0x2026},  {"quoteright", 0x2019},
        {"quoteleft", 0x2018}, {"quotedblleft", 0x201C}, {"quotedblright", 0x201D},
        {"fi", 0xFB01},        {"fl", 0xFB02},        {"ff", 0xFB00},
        {"ffi", 0xFB03},       {"ffl", 0xFB04},       {"dagger", 0x2020},
        {"daggerdbl", 0x2021}, {"section", 0xA7},     {"paragraph", 0xB6},
        {"germandbls", 0xDF},  {"eacute", 0xE9},      {"egrave", 0xE8},
        {"agrave", 0xE0},      {"ccedilla", 0xE7},    {"odieresis", 0xF6},
        {"udieresis", 0xFC},   {"adieresis", 0xE4},   {"Euro", 0x20AC},
        {"minus", 0x2212},     {"degree", 0xB0},      {"copyright", 0xA9},
        {"registered", 0xAE},  {"trademark", 0x2122}, {"nbspace", 0xA0},
    };
    if (const auto found = kNames.find(name); found != kNames.end()) return found->second;
    if (name.size() == 1) return static_cast<unsigned char>(name[0]);
    const auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    auto parse_hex = [&](std::string_view text, char32_t& out) {
        char32_t value = 0;
        if (text.empty()) return false;
        for (char c : text) {
            const int digit = hex_value(c);
            if (digit < 0) return false;
            value = (value << 4) | static_cast<char32_t>(digit);
        }
        out = value;
        return true;
    };
    char32_t parsed = 0;
    if (name.rfind("uni", 0) == 0 && name.size() == 7 && parse_hex(name.substr(3, 4), parsed))
        return parsed;
    if (name.rfind("u", 0) == 0 && name.size() >= 5 && name.size() <= 7 &&
        parse_hex(name.substr(1), parsed))
        return parsed;
    return 0;
}

// ---------------------------------------------------------------------------
// Font decoding
// ---------------------------------------------------------------------------
struct DecodedGlyph {
    std::string utf8;
    std::uint32_t bytes = 1;
    double width = 0.5;
};

class FontDecoder {
public:
    FontDecoder(Document& document, const Object& font) {
        if (!font.is_dict_like()) {
            reliable_ = false;
            return;
        }
        const Dict& dict = font.dict();
        type0_ = dict.get_name("Subtype") == "Type0";
        code_bytes_ = type0_ ? 2 : 1;
        simple_map_.fill(0);
        for (int i = 0; i < 256; ++i) simple_map_[static_cast<std::size_t>(i)] = winansi(static_cast<std::uint8_t>(i));

        if (const Object* encoding = dict.find("Encoding"); encoding != nullptr) {
            const Object* resolved = document.resolve(*encoding);
            std::string base = "WinAnsiEncoding";
            if (resolved != nullptr && resolved->is_name()) {
                base = resolved->as_name();
            } else if (resolved != nullptr && resolved->is_dict_like()) {
                base = resolved->dict().get_name("BaseEncoding", "WinAnsiEncoding");
            }
            if (base == "StandardEncoding" || base == "MacRomanEncoding") {
                // Both are close to Latin-1 in the printable range; below 0x80
                // they are identical to ASCII, which is what matters for PII.
            }
            if (resolved != nullptr && resolved->is_dict_like()) {
                apply_differences(document, resolved->dict());
            }
        }

        if (const Object* to_unicode = dict.find("ToUnicode"); to_unicode != nullptr) {
            const Object* resolved = document.resolve(*to_unicode);
            if (resolved != nullptr && resolved->is_stream()) parse_to_unicode(document, *resolved);
        } else if (type0_) {
            reliable_ = false;
        }

        read_widths(document, dict);

        if (const Object* base_font = dict.find("BaseFont"); base_font != nullptr &&
                                                                 base_font->is_name()) {
            const std::string& name = base_font->as_name();
            const std::size_t plus = name.find('+');
            if (plus != std::string::npos && plus == 6) {
                subset_prefix_ = name.substr(0, plus);
                base_name_ = name.substr(plus + 1);
            } else {
                base_name_ = name;
            }
        }
        compute_space_bytes();
    }

    [[nodiscard]] std::vector<DecodedGlyph> decode(std::string_view encoded) const {
        std::vector<DecodedGlyph> glyphs;
        const std::size_t step = static_cast<std::size_t>(code_bytes_);
        glyphs.reserve(encoded.size() / step + 1);
        for (std::size_t i = 0; i + step <= encoded.size(); i += step) {
            const std::uint32_t code =
                step == 1 ? static_cast<std::uint8_t>(encoded[i]) : code_from_bytes(encoded.substr(i, 2));
            DecodedGlyph glyph;
            glyph.bytes = static_cast<std::uint32_t>(step);
            if (const auto found = to_unicode_.find(code); found != to_unicode_.end() && !found->second.empty()) {
                glyph.utf8 = found->second;
            } else if (step == 1) {
                const char32_t cp = simple_map_[static_cast<std::size_t>(code & 0xFF)];
                append_utf8(glyph.utf8, cp != 0 ? cp : 0xFFFD);
            } else {
                append_utf8(glyph.utf8, 0xFFFD);
            }
            if (const auto found = widths_.find(code); found != widths_.end()) {
                glyph.width = found->second;
            } else {
                glyph.width = default_width_;
            }
            glyphs.push_back(std::move(glyph));
        }
        return glyphs;
    }

    [[nodiscard]] bool reliable() const noexcept { return reliable_; }
    [[nodiscard]] const std::string& subset_prefix() const noexcept { return subset_prefix_; }
    [[nodiscard]] const std::string& base_name() const noexcept { return base_name_; }

    /// The bytes that render a single space in this font. Deterministic: the
    /// lowest matching code wins, so two runs of Scour produce the same file.
    [[nodiscard]] const std::string& space_bytes() const { return space_bytes_; }

private:
    void compute_space_bytes() {
        std::uint32_t best = std::numeric_limits<std::uint32_t>::max();
        for (const auto& [code, text] : to_unicode_) {
            if (text == " " && code < best) best = code;
        }
        if (best == std::numeric_limits<std::uint32_t>::max() && code_bytes_ == 1) {
            for (std::uint32_t code = 0; code < 256; ++code) {
                if (simple_map_[static_cast<std::size_t>(code)] == U' ') {
                    best = code;
                    break;
                }
            }
        }
        if (best == std::numeric_limits<std::uint32_t>::max()) best = code_bytes_ == 2 ? 0x20 : 0x20;
        space_bytes_.clear();
        for (int i = code_bytes_ - 1; i >= 0; --i)
            space_bytes_.push_back(static_cast<char>((best >> (8 * i)) & 0xFF));
        if (space_bytes_.empty()) space_bytes_ = " ";
    }

private:
    void apply_differences(Document& document, const Dict& encoding) {
        const Object* differences = encoding.find("Differences");
        if (differences == nullptr) return;
        const Object* array = document.resolve(*differences);
        if (array == nullptr || !array->is_array()) return;
        int code = 0;
        for (const Object& item : array->items()) {
            if (item.is_int()) {
                code = static_cast<int>(item.as_int());
                continue;
            }
            if (item.is_name() && code >= 0 && code < 256) {
                const char32_t cp = glyph_name_to_unicode(item.as_name());
                simple_map_[static_cast<std::size_t>(code)] = cp != 0 ? cp : 0xFFFD;
                ++code;
            }
        }
    }

    void parse_to_unicode(Document& document, const Object& stream) {
        Bytes data;
        try {
            data = document.decode_stream(stream);
        } catch (const ScourError&) {
            reliable_ = false;
            return;
        }
        if (data.empty() || data.size() > kMaxStreamBytes) return;
        Lexer lexer(view_of(data));
        enum class Mode { None, Codespace, BfChar, BfRange } mode = Mode::None;
        std::vector<Token> pending;
        std::vector<std::string> array_values;
        int range_low = 0;
        int range_high = 0;

        auto finish_range = [&](const std::string& start_value) {
            if (range_low > range_high || range_high - range_low > 65535) return;
            for (int code = range_low; code <= range_high; ++code) {
                std::string value = start_value;
                if (code != range_low && !value.empty()) {
                    // Increment the last code unit of the destination.
                    const std::size_t last = value.size() >= 2 ? value.size() - 2 : 0;
                    std::uint32_t unit = (static_cast<std::uint8_t>(value[last]) << 8) |
                                         static_cast<std::uint8_t>(value[last + 1]);
                    unit = (unit + static_cast<std::uint32_t>(code - range_low)) & 0xFFFF;
                    value[last] = static_cast<char>(unit >> 8);
                    value[last + 1] = static_cast<char>(unit & 0xFF);
                }
                to_unicode_[static_cast<std::uint32_t>(code)] = utf16be_to_utf8(value);
            }
        };

        for (;;) {
            Token token = lexer.next();
            if (token.kind == TokenKind::Eof) break;
            if (token.kind == TokenKind::Word) {
                if (token.text == "begincodespacerange") {
                    mode = Mode::Codespace;
                } else if (token.text == "beginbfchar") {
                    mode = Mode::BfChar;
                } else if (token.text == "beginbfrange") {
                    mode = Mode::BfRange;
                } else if (token.text == "endcodespacerange" || token.text == "endbfchar" ||
                           token.text == "endbfrange") {
                    mode = Mode::None;
                }
                pending.clear();
                array_values.clear();
                continue;
            }
            if (mode == Mode::None) continue;
            if (token.kind == TokenKind::ArrayClose) {
                if (mode == Mode::BfRange && pending.size() >= 2) {
                    for (std::size_t i = 0; i < array_values.size(); ++i) {
                        const int code = range_low + static_cast<int>(i);
                        if (code > range_high) break;
                        to_unicode_[static_cast<std::uint32_t>(code)] =
                            utf16be_to_utf8(array_values[i]);
                    }
                    pending.clear();
                    array_values.clear();
                }
                continue;
            }
            if (token.kind == TokenKind::ArrayOpen) {
                if (mode == Mode::BfRange && pending.size() == 2) {
                    range_low = static_cast<int>(code_from_bytes(pending[0].text));
                    range_high = static_cast<int>(code_from_bytes(pending[1].text));
                    array_values.clear();
                }
                continue;
            }
            if (token.kind != TokenKind::HexString && token.kind != TokenKind::String) continue;

            if (mode == Mode::Codespace) {
                pending.push_back(std::move(token));
                if (pending.size() == 2) {
                    if (!pending[0].text.empty())
                        code_bytes_ = static_cast<int>(std::min<std::size_t>(pending[0].text.size(), 4));
                    pending.clear();
                }
            } else if (mode == Mode::BfChar) {
                pending.push_back(std::move(token));
                if (pending.size() == 2) {
                    to_unicode_[code_from_bytes(pending[0].text)] = utf16be_to_utf8(pending[1].text);
                    pending.clear();
                }
            } else {
                pending.push_back(std::move(token));
                if (pending.size() == 2) {
                    range_low = static_cast<int>(code_from_bytes(pending[0].text));
                    range_high = static_cast<int>(code_from_bytes(pending[1].text));
                } else if (pending.size() == 3) {
                    finish_range(pending[2].text);
                    pending.clear();
                }
            }
        }
    }

    void read_widths(Document& document, const Dict& dict) {
        if (type0_) {
            default_width_ = dict.get_real("DW", 1000.0) / 1000.0;
            const Object* descendants = dict.find("DescendantFonts");
            const Object* array = descendants != nullptr ? document.resolve(*descendants) : nullptr;
            if (array == nullptr || !array->is_array() || array->items().empty()) return;
            const Object* descendant = document.resolve(array->items()[0]);
            if (descendant == nullptr || !descendant->is_dict_like()) return;
            const Object* widths = descendant->dict().find("W");
            const Object* resolved = widths != nullptr ? document.resolve(*widths) : nullptr;
            if (resolved == nullptr || !resolved->is_array()) return;
            const std::vector<Object>& items = resolved->items();
            std::size_t i = 0;
            while (i < items.size()) {
                const int first = static_cast<int>(items[i].as_int());
                if (i + 1 >= items.size()) break;
                const Object* second = document.resolve(items[i + 1]);
                if (second != nullptr && second->is_array()) {
                    for (std::size_t k = 0; k < second->items().size(); ++k)
                        widths_[static_cast<std::uint32_t>(first + static_cast<int>(k))] =
                            second->items()[k].as_real(1000.0) / 1000.0;
                    i += 2;
                } else if (i + 2 < items.size()) {
                    const int last = static_cast<int>(items[i + 1].as_int());
                    const double width = items[i + 2].as_real(1000.0) / 1000.0;
                    if (last >= first && last - first < 65536) {
                        for (int code = first; code <= last; ++code)
                            widths_[static_cast<std::uint32_t>(code)] = width;
                    }
                    i += 3;
                } else {
                    break;
                }
            }
            return;
        }

        const Object* widths_object = dict.find("Widths");
        const Object* widths = widths_object != nullptr ? document.resolve(*widths_object) : nullptr;
        const int first_char = static_cast<int>(dict.get_int("FirstChar", 0));
        default_width_ = dict.get_real("MissingWidth", 500.0) / 1000.0;
        if (widths == nullptr || !widths->is_array()) return;
        for (std::size_t i = 0; i < widths->items().size(); ++i) {
            widths_[static_cast<std::uint32_t>(first_char + static_cast<int>(i))] =
                widths->items()[i].as_real(500.0) / 1000.0;
        }
    }

    int code_bytes_ = 1;
    bool type0_ = false;
    bool reliable_ = true;
    std::unordered_map<std::uint32_t, std::string> to_unicode_;
    std::unordered_map<std::uint32_t, double> widths_;
    std::array<char32_t, 256> simple_map_{};
    double default_width_ = 0.5;
    std::string subset_prefix_;
    std::string base_name_;
    std::string space_bytes_ = " ";
};

// ---------------------------------------------------------------------------
// Content stream parsing
// ---------------------------------------------------------------------------
struct Operand {
    Object value;
    std::size_t begin = 0;
    std::size_t end = 0;
    /// For array operands (a TJ array), the spans of the string elements in
    /// order, so a redaction can rewrite one element without touching the rest.
    std::vector<std::pair<std::size_t, std::size_t>> element_spans;
};

struct Operation {
    std::string name;
    std::vector<Operand> operands;
    bool inline_image = false;
};

std::vector<Operation> parse_content(std::string_view data, bool& has_images) {
    std::vector<Operation> operations;
    Lexer lexer(data);
    Operation current;
    while (true) {
        Token token = lexer.next();
        if (token.kind == TokenKind::Eof) break;
        if (token.kind == TokenKind::Word) {
            if (token.text == "BI") {
                has_images = true;
                Operation image;
                image.name = "BI";
                image.inline_image = true;
                operations.push_back(std::move(image));
                // Skip to the EI marker. Binary image data may contain any byte,
                // so the search is for a whitespace-delimited EI.
                std::size_t position = lexer.position();
                while (true) {
                    const std::size_t found = data.find("EI", position);
                    if (found == std::string_view::npos) {
                        position = data.size();
                        break;
                    }
                    const bool left_ok =
                        found == 0 || is_pdf_whitespace(data[found - 1]) || data[found - 1] == '>';
                    const bool right_ok = found + 2 >= data.size() || is_pdf_whitespace(data[found + 2]) ||
                                          data[found + 2] == '/';
                    if (left_ok && right_ok) {
                        position = found + 2;
                        break;
                    }
                    position = found + 2;
                }
                lexer.seek(position);
                current.operands.clear();
                continue;
            }
            current.name = token.text;
            operations.push_back(std::move(current));
            current = Operation{};
            continue;
        }

        Parser parser(data, token.begin, nullptr);
        try {
            Object value = parser.parse_object();
            Operand operand{std::move(value), token.begin, parser.position(), {}};
            if (operand.value.is_array()) {
                Lexer inner(data, operand.begin);
                for (;;) {
                    const Token element = inner.next();
                    if (element.kind == TokenKind::Eof || element.begin >= operand.end) break;
                    if (element.kind == TokenKind::String || element.kind == TokenKind::HexString)
                        operand.element_spans.emplace_back(element.begin, element.end);
                    if (element.kind == TokenKind::ArrayClose) break;
                }
            }
            current.operands.push_back(std::move(operand));
            lexer.seek(parser.position());
        } catch (const ScourError&) {
            // Skip an unparsable operand; the operator that follows still runs.
        }
    }
    return operations;
}

// ---------------------------------------------------------------------------
// Extractor
// ---------------------------------------------------------------------------
class Extractor {
public:
    Extractor(Document& document, PageAnalysis& page, Diagnostics& diagnostics,
              const TextOptions& options)
        : document_(document), page_(page), diagnostics_(diagnostics), options_(options) {}

    void run_page(std::uint32_t page_object) {
        page_.page_object = page_object;
        const Object* page = document_.resolve_ref(page_object);
        if (page == nullptr || !page->is_dict_like()) return;
        page_.box = page_box(document_, page_object);
        const Object* resources = inherited(page_object, "Resources");
        const Dict* resource_dict = resources != nullptr ? &resources->dict() : nullptr;
        resources_ = resource_dict;

        const Object* contents = page->dict().find("Contents");
        const Object* resolved = contents != nullptr ? document_.resolve(*contents) : nullptr;
        if (resolved == nullptr) return;
        if (resolved->is_array()) {
            for (const Object& item : resolved->items()) {
                const Object* stream = document_.resolve(item);
                if (stream == nullptr || !stream->is_stream()) continue;
                const std::uint32_t number = item.is_ref() ? item.ref_number() : 0;
                run_content(number, stream, false, 0);
            }
        } else if (resolved->is_stream()) {
            const std::uint32_t number = contents->is_ref() ? contents->ref_number() : 0;
            run_content(number, resolved, false, 0);
        }
    }

private:
    const Object* inherited(std::uint32_t page_number, std::string_view key) {
        const Object* node = document_.resolve_ref(page_number);
        for (int depth = 0; node != nullptr && node->is_dict_like() && depth < 64; ++depth) {
            if (const Object* value = node->find(key); value != nullptr) {
                const Object* resolved = document_.resolve(*value);
                return resolved != nullptr ? resolved : value;
            }
            const Object* parent = document_.resolve_ref(node->dict().get_ref("Parent"));
            if (parent == nullptr || parent == node) break;
            node = parent;
        }
        return nullptr;
    }

    FontDecoder* font_for(const std::string& name) {
        if (resources_ == nullptr) return nullptr;
        const Object* fonts = resources_->find("Font");
        const Object* resolved_fonts = fonts != nullptr ? document_.resolve(*fonts) : nullptr;
        if (resolved_fonts == nullptr || !resolved_fonts->is_dict_like()) return nullptr;
        const Object* entry = resolved_fonts->dict().find(name);
        if (entry == nullptr) return nullptr;
        const std::uint32_t cache_key = entry->is_ref() ? entry->ref_number() : 0;
        if (cache_key != 0) {
            if (const auto found = font_cache_.find(cache_key); found != font_cache_.end())
                return found->second.get();
        }
        const Object* font = document_.resolve(*entry);
        if (font == nullptr || !font->is_dict_like()) return nullptr;
        auto decoder = std::make_unique<FontDecoder>(document_, *font);
        if (!decoder->reliable()) page_.reliable = false;
        FontDecoder* raw = decoder.get();
        if (cache_key != 0) font_cache_[cache_key] = std::move(decoder);
        else standalone_fonts_.push_back(std::move(decoder));
        return raw;
    }

    void run_content(std::uint32_t object_number, const Object* stream, bool from_form, int depth) {
        if (depth > options_.max_form_depth) return;
        Bytes data;
        try {
            data = document_.decode_stream(*stream);
        } catch (const ScourError&) {
            return;
        }
        if (data.size() > kMaxStreamBytes) {
            diagnostics_.warn("pdf.text.stream-too-large", "content stream is too large to analyse",
                              page_.page_index + 1);
            return;
        }
        if (object_number != 0) {
            bool exists = false;
            for (const TextStream& existing : page_.streams) {
                if (existing.object_number == object_number) {
                    exists = true;
                    break;
                }
            }
            if (!exists) page_.streams.push_back(TextStream{object_number, data});
        } else if (from_form) {
            page_.reliable = false;
        }

        const State saved = state_;
        const Dict* saved_resources = resources_;
        if (from_form) page_.has_form_text = true;

        bool images = false;
        const std::vector<Operation> operations = parse_content(view_of(data), images);
        if (images) page_.has_images = true;

        for (const Operation& op : operations) {
            if (op.name == "q") {
                stack_.push_back(state_);
            } else if (op.name == "Q") {
                if (!stack_.empty()) {
                    state_ = stack_.back();
                    stack_.pop_back();
                }
            } else if (op.name == "cm" && op.operands.size() >= 6) {
                const Matrix m{op.operands[0].value.as_real(1), op.operands[1].value.as_real(0),
                               op.operands[2].value.as_real(0), op.operands[3].value.as_real(1),
                               op.operands[4].value.as_real(0), op.operands[5].value.as_real(0)};
                state_.ctm = multiply(m, state_.ctm);
            } else if (op.name == "BT") {
                state_.tm = Matrix{};
                state_.lm = Matrix{};
            } else if (op.name == "Tf" && op.operands.size() >= 2) {
                state_.font_name = op.operands[0].value.as_name();
                state_.font_size = op.operands[1].value.as_real(12.0);
            } else if (op.name == "Td" && op.operands.size() >= 2) {
                state_.lm = multiply(translation(op.operands[0].value.as_real(),
                                                 op.operands[1].value.as_real()),
                                     state_.lm);
                state_.tm = state_.lm;
            } else if (op.name == "TD" && op.operands.size() >= 2) {
                state_.leading = -op.operands[1].value.as_real();
                state_.lm = multiply(translation(op.operands[0].value.as_real(),
                                                 op.operands[1].value.as_real()),
                                     state_.lm);
                state_.tm = state_.lm;
            } else if (op.name == "Tm" && op.operands.size() >= 6) {
                state_.tm = Matrix{op.operands[0].value.as_real(1), op.operands[1].value.as_real(0),
                                   op.operands[2].value.as_real(0), op.operands[3].value.as_real(1),
                                   op.operands[4].value.as_real(0), op.operands[5].value.as_real(0)};
                state_.lm = state_.tm;
            } else if (op.name == "T*") {
                state_.lm = multiply(translation(0, -state_.leading), state_.lm);
                state_.tm = state_.lm;
            } else if (op.name == "TL" && !op.operands.empty()) {
                state_.leading = op.operands[0].value.as_real();
            } else if (op.name == "Tc" && !op.operands.empty()) {
                state_.char_spacing = op.operands[0].value.as_real();
            } else if (op.name == "Tw" && !op.operands.empty()) {
                state_.word_spacing = op.operands[0].value.as_real();
            } else if (op.name == "Tz" && !op.operands.empty()) {
                state_.scale = op.operands[0].value.as_real(100.0) / 100.0;
            } else if (op.name == "Ts" && !op.operands.empty()) {
                state_.rise = op.operands[0].value.as_real();
            } else if (op.name == "Tr" && !op.operands.empty()) {
                state_.render_mode = static_cast<int>(op.operands[0].value.as_int());
            } else if (op.name == "g" && !op.operands.empty()) {
                state_.fill_gray = std::clamp(op.operands[0].value.as_real(), 0.0, 1.0);
            } else if (op.name == "rg" && op.operands.size() >= 3) {
                state_.fill_gray = luminance(op.operands[0].value.as_real(), op.operands[1].value.as_real(),
                                             op.operands[2].value.as_real());
            } else if (op.name == "k" && op.operands.size() >= 4) {
                const double c = std::clamp(op.operands[0].value.as_real(), 0.0, 1.0);
                const double m = std::clamp(op.operands[1].value.as_real(), 0.0, 1.0);
                const double y = std::clamp(op.operands[2].value.as_real(), 0.0, 1.0);
                const double k = std::clamp(op.operands[3].value.as_real(), 0.0, 1.0);
                state_.fill_gray = luminance((1 - c) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k));
            } else if ((op.name == "sc" || op.name == "scn") && !op.operands.empty()) {
                if (op.operands.size() == 1) {
                    state_.fill_gray = std::clamp(op.operands[0].value.as_real(), 0.0, 1.0);
                } else if (op.operands.size() == 3) {
                    state_.fill_gray = luminance(op.operands[0].value.as_real(),
                                                 op.operands[1].value.as_real(),
                                                 op.operands[2].value.as_real());
                } else if (op.operands.size() >= 4) {
                    const double c = std::clamp(op.operands[0].value.as_real(), 0.0, 1.0);
                    const double m = std::clamp(op.operands[1].value.as_real(), 0.0, 1.0);
                    const double yy = std::clamp(op.operands[2].value.as_real(), 0.0, 1.0);
                    const double k = std::clamp(op.operands[3].value.as_real(), 0.0, 1.0);
                    state_.fill_gray =
                        luminance((1 - c) * (1 - k), (1 - m) * (1 - k), (1 - yy) * (1 - k));
                }
            } else if (op.name == "re" && op.operands.size() >= 4) {
                const double x = op.operands[0].value.as_real();
                const double y = op.operands[1].value.as_real();
                const double width = op.operands[2].value.as_real();
                const double height = op.operands[3].value.as_real();
                const Rect box = quad_bounds(state_.ctm, x, y, x + width, y + height);
                path_.push_back(box);
            } else if (op.name == "f" || op.name == "F" || op.name == "f*" || op.name == "B" ||
                       op.name == "B*") {
                for (const Rect& rect : path_) {
                    if (rect.width() > 0.0 && rect.height() > 0.0)
                        page_.paint_boxes.push_back(PaintBox{rect, state_.fill_gray, next_order()});
                }
                path_.clear();
            } else if (op.name == "n" || op.name == "S" || op.name == "s" || op.name == "b" ||
                       op.name == "b*") {
                path_.clear();
            } else if (op.name == "Tj" && !op.operands.empty()) {
                show_string(op.operands[0], object_number, from_form);
            } else if (op.name == "'" && !op.operands.empty()) {
                state_.lm = multiply(translation(0, -state_.leading), state_.lm);
                state_.tm = state_.lm;
                show_string(op.operands[0], object_number, from_form);
            } else if (op.name == "\"" && op.operands.size() >= 3) {
                state_.word_spacing = op.operands[0].value.as_real();
                state_.char_spacing = op.operands[1].value.as_real();
                state_.lm = multiply(translation(0, -state_.leading), state_.lm);
                state_.tm = state_.lm;
                show_string(op.operands[2], object_number, from_form);
            } else if (op.name == "TJ" && !op.operands.empty()) {
                const Object& array = op.operands[0].value;
                if (!array.is_array()) continue;
                std::size_t string_index = 0;
                for (const Object& element : array.items()) {
                    if (element.is_number()) {
                        const double shift = -element.as_real() / 1000.0 * state_.font_size * state_.scale;
                        state_.tm = multiply(translation(shift, 0), state_.tm);
                    } else if (element.is_string()) {
                        Operand operand;
                        operand.value = element;
                        if (string_index < op.operands[0].element_spans.size()) {
                            operand.begin = op.operands[0].element_spans[string_index].first;
                            operand.end = op.operands[0].element_spans[string_index].second;
                        }
                        show_string(operand, object_number, from_form);
                        ++string_index;
                    }
                }
            } else if (op.name == "Do" && !op.operands.empty()) {
                draw_xobject(op.operands[0].value.as_name(), depth);
            }
        }

        state_ = saved;
        resources_ = saved_resources;
    }

    void draw_xobject(const std::string& name, int depth) {
        if (resources_ == nullptr) return;
        const Object* xobjects = resources_->find("XObject");
        const Object* resolved = xobjects != nullptr ? document_.resolve(*xobjects) : nullptr;
        if (resolved == nullptr || !resolved->is_dict_like()) return;
        const Object* entry = resolved->dict().find(name);
        if (entry == nullptr) return;
        const Object* xobject = document_.resolve(*entry);
        if (xobject == nullptr || !xobject->is_stream()) return;
        const std::string subtype = xobject->dict().get_name("Subtype");
        if (subtype == "Image") {
            page_.has_images = true;
            return;
        }
        if (subtype != "Form" || !options_.include_forms) return;

        const Matrix saved_ctm = state_.ctm;
        const Dict* saved_resources = resources_;
        if (const Object* matrix_object = xobject->dict().find("Matrix");
            matrix_object != nullptr && matrix_object->is_array() &&
            matrix_object->items().size() >= 6) {
            const Matrix matrix{matrix_object->items()[0].as_real(1), matrix_object->items()[1].as_real(0),
                                matrix_object->items()[2].as_real(0), matrix_object->items()[3].as_real(1),
                                matrix_object->items()[4].as_real(0), matrix_object->items()[5].as_real(0)};
            state_.ctm = multiply(matrix, state_.ctm);
        }
        if (const Object* form_resources = xobject->dict().find("Resources");
            form_resources != nullptr && form_resources->is_dict_like()) {
            resources_ = &form_resources->dict();
        }
        const std::uint32_t number = entry->is_ref() ? entry->ref_number() : 0;
        run_content(number, xobject, true, depth + 1);
        resources_ = saved_resources;
        state_.ctm = saved_ctm;
    }

    void show_string(const Operand& operand, std::uint32_t object_number, bool from_form) {
        if (!operand.value.is_string()) return;
        const std::string& encoded = operand.value.as_string();
        if (encoded.empty()) return;
        FontDecoder* decoder = font_for(state_.font_name);
        if (decoder == nullptr) {
            state_.tm = multiply(translation(static_cast<double>(encoded.size()) * state_.font_size * 0.5 *
                                                 state_.scale,
                                             0),
                                 state_.tm);
            return;
        }

        const std::vector<DecodedGlyph> glyphs = decoder->decode(encoded);
        TextRun run;
        run.stream_object = object_number;
        run.begin = operand.begin;
        run.end = operand.end;
        run.from_form = from_form;
        run.space_bytes = decoder->space_bytes();
        run.box = Rect{};
        run.order = next_order();
        std::size_t byte_offset = 0;
        for (const DecodedGlyph& glyph : glyphs) {
            const double advance =
                (glyph.width * state_.font_size + state_.char_spacing +
                 (glyph.utf8 == " " ? state_.word_spacing : 0.0)) *
                state_.scale;
            const Matrix place = multiply(state_.tm, state_.ctm);
            const Rect box = quad_bounds(place, 0.0, -0.2 * state_.font_size + state_.rise, advance,
                                         0.8 * state_.font_size + state_.rise);
            Glyph out;
            out.utf8 = glyph.utf8;
            out.byte_start = static_cast<std::uint32_t>(byte_offset);
            out.byte_end = static_cast<std::uint32_t>(byte_offset + glyph.bytes);
            out.advance = advance;
            out.width = glyph.width;
            out.box = box;
            out.render_mode = state_.render_mode;
            out.fill_gray = state_.fill_gray;
            run.glyphs.push_back(std::move(out));
            run.text += glyph.utf8;
            run.box = run.box.united(box);
            byte_offset += glyph.bytes;
            state_.tm = multiply(translation(advance, 0.0), state_.tm);
        }
        if (run.text.empty()) return;
        page_.has_text = true;
        page_.runs.push_back(std::move(run));
    }

    struct State {
        Matrix ctm;
        Matrix tm;
        Matrix lm;
        double char_spacing = 0.0;
        double word_spacing = 0.0;
        double scale = 1.0;
        double leading = 0.0;
        double rise = 0.0;
        std::string font_name;
        double font_size = 12.0;
        double fill_gray = 0.0;
        int render_mode = 0;
    };

    std::size_t next_order() { return order_++; }

    Document& document_;
    PageAnalysis& page_;
    Diagnostics& diagnostics_;
    const TextOptions& options_;
    const Dict* resources_ = nullptr;
    State state_;
    std::vector<State> stack_;
    std::vector<Rect> path_;
    std::size_t order_ = 0;
    std::unordered_map<std::uint32_t, std::unique_ptr<FontDecoder>> font_cache_;
    std::vector<std::unique_ptr<FontDecoder>> standalone_fonts_;
};

void assemble_text(PageAnalysis& page) {
    page.text.clear();
    page.run_of_byte.clear();
    page.run_text_start.assign(page.runs.size(), std::string::npos);
    Rect previous;
    bool have_previous = false;
    const auto append_run_index = [&page](std::uint32_t index) {
        page.run_of_byte.push_back(index);
    };
    for (std::size_t index = 0; index < page.runs.size(); ++index) {
        const TextRun& run = page.runs[index];
        if (run.text.empty()) continue;
        const auto position = static_cast<std::uint32_t>(index);
        if (have_previous) {
            const double size = std::max(4.0, std::min(run.box.height(), previous.height()));
            const bool new_line = std::fabs(run.box.y0 - previous.y0) > size * 0.5;
            const bool new_word = run.box.x0 > previous.x1 + size * 0.2;
            if (new_line) {
                page.text.push_back('\n');
                append_run_index(position);
                previous = run.box;
            } else {
                if (new_word) {
                    page.text.push_back(' ');
                    append_run_index(position);
                }
                previous = previous.united(run.box);
            }
        } else {
            previous = run.box;
            have_previous = true;
        }
        page.run_text_start[index] = page.text.size();
        for (std::size_t i = 0; i < run.text.size(); ++i) append_run_index(position);
        page.text += run.text;
    }
}

}  // namespace

PageAnalysis analyze_page(Document& document, std::uint32_t page_object, int page_index,
                          const TextOptions& options, Diagnostics& diagnostics) {
    PageAnalysis page;
    page.page_index = page_index;
    Extractor extractor(document, page, diagnostics, options);
    extractor.run_page(page_object);
    assemble_text(page);
    return page;
}

std::string DocumentText::all_text() const {
    std::string out;
    for (std::size_t i = 0; i < pages.size(); ++i) {
        if (i != 0) out.push_back('\f');
        out += pages[i].text;
    }
    return out;
}

DocumentText analyze_document(Document& document, const TextOptions& options,
                              Diagnostics& diagnostics) {
    DocumentText result;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    result.pages.reserve(pages.size());
    for (std::size_t i = 0; i < pages.size(); ++i) {
        result.pages.push_back(analyze_page(document, pages[i], static_cast<int>(i), options, diagnostics));
        if (!result.pages.back().reliable) {
            diagnostics.warn("pdf.text.unreliable",
                             "page " + std::to_string(i + 1) +
                                 " uses a font encoding that cannot be decoded reliably",
                             static_cast<int>(i) + 1);
        }
        if (result.pages.back().has_images && !result.pages.back().has_text) {
            diagnostics.info("pdf.text.image-only",
                             "page " + std::to_string(i + 1) +
                                 " has no text layer (text inside images cannot be redacted)",
                             static_cast<int>(i) + 1);
        }
    }
    return result;
}

}  // namespace scour

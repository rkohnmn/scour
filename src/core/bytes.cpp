// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/bytes.hpp"

#include <cmath>
#include <cstdio>

namespace scour {

namespace {

bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

}  // namespace

std::vector<std::string> split(std::string_view text, char separator) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= text.size(); ++i) {
        if (i == text.size() || text[i] == separator) {
            parts.emplace_back(text.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

std::vector<std::string> split_whitespace(std::string_view text) {
    std::vector<std::string> parts;
    std::size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && is_space(text[i])) ++i;
        const std::size_t start = i;
        while (i < text.size() && !is_space(text[i])) ++i;
        if (i > start) parts.emplace_back(text.substr(start, i - start));
    }
    return parts;
}

std::string join(const std::vector<std::string>& parts, std::string_view separator) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) out.append(separator);
        out.append(parts[i]);
    }
    return out;
}

std::string collapse_whitespace(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    bool pending_space = false;
    for (char c : text) {
        if (is_space(c)) {
            pending_space = !out.empty();
            continue;
        }
        if (pending_space) out.push_back(' ');
        pending_space = false;
        out.push_back(c);
    }
    return out;
}

std::string to_hex(std::string_view raw) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(raw.size() * 2);
    for (const char raw_c : raw) {
        const auto c = static_cast<unsigned char>(raw_c);
        out.push_back(kDigits[c >> 4]);
        out.push_back(kDigits[c & 0x0F]);
    }
    return out;
}

Bytes from_hex(std::string_view hex) {
    auto value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    Bytes out;
    out.reserve(hex.size() / 2 + 1);
    int hi = -1;
    for (char c : hex) {
        const int v = value(c);
        if (v < 0) continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<Byte>((hi << 4) | v));
            hi = -1;
        }
    }
    if (hi >= 0) out.push_back(static_cast<Byte>(hi));
    return out;
}

std::string format_bytes(std::uint64_t bytes) {
    static constexpr const char* kUnits[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1000.0 && unit < 4) {
        value /= 1000.0;
        ++unit;
    }
    char buffer[32];
    if (unit == 0) {
        std::snprintf(buffer, sizeof(buffer), "%llu B", static_cast<unsigned long long>(bytes));
    } else if (value < 10.0) {
        std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, kUnits[unit]);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%.0f %s", value, kUnits[unit]);
    }
    return buffer;
}

std::string format_duration(double microseconds) {
    char buffer[32];
    if (microseconds < 1.0) {
        std::snprintf(buffer, sizeof(buffer), "%.0f ns", microseconds * 1000.0);
    } else if (microseconds < 1000.0) {
        std::snprintf(buffer, sizeof(buffer), "%.0f us", microseconds);
    } else if (microseconds < 1'000'000.0) {
        std::snprintf(buffer, sizeof(buffer), "%.1f ms", microseconds / 1000.0);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%.2f s", microseconds / 1'000'000.0);
    }
    return buffer;
}

void append_utf8(std::string& out, char32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::u32string decode_utf8(std::string_view text) {
    std::u32string out;
    out.reserve(text.size());
    std::size_t i = 0;
    while (i < text.size()) {
        const auto lead = static_cast<unsigned char>(text[i]);
        char32_t cp = 0xFFFD;
        std::size_t extra = 0;
        if (lead < 0x80) {
            cp = lead;
        } else if ((lead & 0xE0) == 0xC0) {
            cp = lead & 0x1F;
            extra = 1;
        } else if ((lead & 0xF0) == 0xE0) {
            cp = lead & 0x0F;
            extra = 2;
        } else if ((lead & 0xF8) == 0xF0) {
            cp = lead & 0x07;
            extra = 3;
        }
        if (i + extra >= text.size() && extra > 0) {
            out.push_back(0xFFFD);
            ++i;
            continue;
        }
        bool ok = true;
        for (std::size_t k = 1; k <= extra; ++k) {
            const auto cont = static_cast<unsigned char>(text[i + k]);
            if ((cont & 0xC0) != 0x80) {
                ok = false;
                break;
            }
            cp = (cp << 6) | (cont & 0x3F);
        }
        if (!ok) {
            out.push_back(0xFFFD);
            ++i;
            continue;
        }
        out.push_back(cp);
        i += extra + 1;
    }
    return out;
}

std::string encode_utf8(std::u32string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char32_t cp : text) append_utf8(out, cp);
    return out;
}

int codepoint_width(char32_t cp) noexcept {
    if (cp == 0) return 0;
    if (cp < 32 || (cp >= 0x7F && cp < 0xA0)) return 0;
    // Combining marks.
    if ((cp >= 0x0300 && cp <= 0x036F) || (cp >= 0x1AB0 && cp <= 0x1AFF) ||
        (cp >= 0x20D0 && cp <= 0x20FF) || (cp >= 0xFE20 && cp <= 0xFE2F))
        return 0;
    // Wide and fullwidth ranges.
    if ((cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) ||
        (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFE30 && cp <= 0xFE6F) || (cp >= 0xFF00 && cp <= 0xFF60) ||
        (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x1F300 && cp <= 0x1FAFF) ||
        (cp >= 0x20000 && cp <= 0x3FFFD))
        return 2;
    return 1;
}

int display_width(std::string_view text) noexcept {
    int width = 0;
    for (char32_t cp : decode_utf8(text)) width += codepoint_width(cp);
    return width;
}

std::string truncate_cells(std::string_view text, int max_cells) {
    if (max_cells <= 0) return {};
    if (display_width(text) <= max_cells) return std::string(text);
    std::string out;
    int width = 0;
    for (char32_t cp : decode_utf8(text)) {
        const int w = codepoint_width(cp);
        if (width + w > max_cells - 1) break;
        append_utf8(out, cp);
        width += w;
    }
    append_utf8(out, U'\u2026');
    return out;
}

std::size_t count_occurrences(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return 0;
    std::size_t count = 0;
    std::size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string_view::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

}  // namespace scour

// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_BYTES_HPP
#define SCOUR_BYTES_HPP

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace scour {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;

inline char as_char(Byte b) noexcept { return static_cast<char>(b); }

inline std::string_view view_of(const Bytes& bytes) noexcept {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

inline Bytes bytes_of(std::string_view text) {
    Bytes out(text.size());
    if (!text.empty()) std::memcpy(out.data(), text.data(), text.size());
    return out;
}

inline void append(Bytes& dst, std::string_view text) {
    dst.insert(dst.end(), text.begin(), text.end());
}

inline void append(Bytes& dst, const Bytes& src) { dst.insert(dst.end(), src.begin(), src.end()); }

inline bool ascii_ieq(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

inline std::string to_lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

inline std::string to_upper_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
    }
    return out;
}

inline bool starts_with(std::string_view text, std::string_view prefix) noexcept {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(std::string_view text, std::string_view suffix) noexcept {
    return text.size() >= suffix.size() &&
           text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline std::string_view trim_left(std::string_view text) noexcept {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r' ||
                             text.front() == '\n'))
        text.remove_prefix(1);
    return text;
}

inline std::string_view trim_right(std::string_view text) noexcept {
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r' ||
                             text.back() == '\n'))
        text.remove_suffix(1);
    return text;
}

inline std::string_view trim(std::string_view text) noexcept {
    return trim_right(trim_left(text));
}

/// Splits on a single character, keeping empty fields (so "a,,b" yields 3 parts).
std::vector<std::string> split(std::string_view text, char separator);
std::vector<std::string> split_whitespace(std::string_view text);

std::string join(const std::vector<std::string>& parts, std::string_view separator);

inline std::string replace_all(std::string text, std::string_view from, std::string_view to) {
    if (from.empty()) return text;
    std::size_t pos = 0;
    while ((pos = text.find(from, pos)) != std::string::npos) {
        text.replace(pos, from.size(), to);
        pos += to.size();
    }
    return text;
}

/// Collapses every run of whitespace (including newlines) into one space.
std::string collapse_whitespace(std::string_view text);

/// Human friendly byte count: 812 B, 4.2 KB, 13.7 MB. Uses SI units, because
/// this string ends up next to file sizes shown by operating systems.
std::string format_bytes(std::uint64_t bytes);

/// Human friendly duration from microseconds (e.g. "1.8 ms").
std::string format_duration(double microseconds);

std::string to_hex(std::string_view raw);
Bytes from_hex(std::string_view hex);

/// Appends one Unicode code point as UTF-8.
void append_utf8(std::string& out, char32_t cp);

/// Decodes UTF-8 into code points; invalid bytes become U+FFFD.
std::u32string decode_utf8(std::string_view text);
std::string encode_utf8(std::u32string_view text);

/// Approximate number of terminal cells occupied by a code point. Scour's UI is
/// deliberately Latin/box-drawing centric, so the table covers the wide East
/// Asian ranges and combining marks and treats everything else as width 1.
int codepoint_width(char32_t cp) noexcept;

/// Visible width of a UTF-8 string in terminal cells.
int display_width(std::string_view text) noexcept;

/// Truncates to `max_cells` terminal cells, appending an ellipsis when cut.
std::string truncate_cells(std::string_view text, int max_cells);

std::size_t count_occurrences(std::string_view haystack, std::string_view needle);

}  // namespace scour

#endif  // SCOUR_BYTES_HPP

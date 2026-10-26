// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "screen.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

namespace scour::tui {

bool operator==(const Rgb& a, const Rgb& b) noexcept {
    return a.r == b.r && a.g == b.g && a.b == b.b;
}

bool operator!=(const Rgb& a, const Rgb& b) noexcept { return !(a == b); }

bool Style::operator==(const Style& other) const noexcept {
    return fg == other.fg && bg == other.bg && bold == other.bold && dim == other.dim;
}

const Palette& dark_palette() {
    static const Palette kPalette{
        "midnight",
        Rgb{13, 16, 23},      // background
        Rgb{20, 25, 36},      // panel
        Rgb{26, 32, 45},      // panel_alt
        Rgb{45, 55, 72},      // border
        Rgb{70, 86, 112},     // border_strong
        Rgb{214, 222, 235},   // text
        Rgb{150, 162, 184},   // text_dim
        Rgb{120, 131, 153},   // text_faint
        Rgb{122, 162, 247},   // accent
        Rgb{56, 76, 118},     // accent_soft
        Rgb{104, 211, 145},   // ok
        Rgb{229, 192, 123},   // warn
        Rgb{245, 139, 122},   // danger
        Rgb{255, 99, 132},    // critical
        Rgb{42, 54, 78},      // selection
        Rgb{236, 242, 255},   // selection_text
    };
    return kPalette;
}

const Palette& light_palette() {
    static const Palette kPalette{
        "paper",
        Rgb{246, 244, 239},   // background
        Rgb{255, 255, 252},   // panel
        Rgb{238, 235, 227},   // panel_alt
        Rgb{208, 202, 190},   // border
        Rgb{170, 162, 148},   // border_strong
        Rgb{40, 40, 38},      // text
        Rgb{84, 80, 72},      // text_dim
        Rgb{116, 110, 98},    // text_faint
        Rgb{36, 88, 168},     // accent
        Rgb{190, 205, 230},   // accent_soft
        Rgb{38, 122, 74},     // ok
        Rgb{140, 96, 4},      // warn
        Rgb{178, 58, 46},     // danger
        Rgb{160, 30, 60},     // critical
        Rgb{222, 230, 244},   // selection
        Rgb{20, 30, 48},      // selection_text
    };
    return kPalette;
}

char32_t decode_utf8(std::string_view text, std::size_t& position) {
    if (position >= text.size()) return 0;
    const auto byte = static_cast<unsigned char>(text[position]);
    if (byte < 0x80) {
        ++position;
        return byte;
    }
    int extra = 0;
    char32_t code = 0;
    if ((byte & 0xE0) == 0xC0) {
        extra = 1;
        code = byte & 0x1F;
    } else if ((byte & 0xF0) == 0xE0) {
        extra = 2;
        code = byte & 0x0F;
    } else if ((byte & 0xF8) == 0xF0) {
        extra = 3;
        code = byte & 0x07;
    } else {
        ++position;
        return 0xFFFD;
    }
    for (int i = 0; i < extra; ++i) {
        if (position + static_cast<std::size_t>(i) + 1 >= text.size()) {
            position = text.size();
            return 0xFFFD;
        }
        const auto continuation = static_cast<unsigned char>(text[position + static_cast<std::size_t>(i) + 1]);
        if ((continuation & 0xC0) != 0x80) {
            ++position;
            return 0xFFFD;
        }
        code = (code << 6) | (continuation & 0x3F);
    }
    position += static_cast<std::size_t>(extra) + 1;
    return code;
}

int codepoint_width(char32_t code) {
    if (code == 0) return 0;
    if (code < 32 || (code >= 0x7F && code < 0xA0)) return 0;
    // Combining marks.
    if ((code >= 0x0300 && code <= 0x036F) || (code >= 0x1AB0 && code <= 0x1AFF) ||
        (code >= 0x20D0 && code <= 0x20FF) || (code >= 0xFE20 && code <= 0xFE2F))
        return 0;
    // East Asian wide and emoji.
    if ((code >= 0x1100 && code <= 0x115F) || (code >= 0x2E80 && code <= 0xA4CF) ||
        (code >= 0xAC00 && code <= 0xD7A3) || (code >= 0xF900 && code <= 0xFAFF) ||
        (code >= 0xFE10 && code <= 0xFE19) || (code >= 0xFE30 && code <= 0xFE6F) ||
        (code >= 0xFF00 && code <= 0xFF60) || (code >= 0xFFE0 && code <= 0xFFE6) ||
        (code >= 0x1F300 && code <= 0x1FAFF) || (code >= 0x1F000 && code <= 0x1F02F))
        return 2;
    return 1;
}

int display_width(std::string_view text) {
    std::size_t position = 0;
    int width = 0;
    while (position < text.size()) {
        width += codepoint_width(decode_utf8(text, position));
    }
    return width;
}

Screen::Screen(int width, int height) { resize(width, height); }

void Screen::resize(int width, int height) {
    width_ = std::max(1, width);
    height_ = std::max(1, height);
    cells_.assign(static_cast<std::size_t>(width_ * height_), Cell{});
}

void Screen::clear(const Rgb& background) {
    Style style;
    style.bg = background;
    for (Cell& cell_value : cells_) {
        cell_value.glyph = " ";
        cell_value.style = style;
        cell_value.continuation = false;
    }
}

void Screen::fill(int x, int y, int width, int height, const Rgb& background) {
    Style style;
    style.bg = background;
    for (int row = y; row < y + height; ++row) {
        for (int column = x; column < x + width; ++column) {
            if (!inside(column, row)) continue;
            Cell& target = cell(column, row);
            target.glyph = " ";
            target.style = style;
            target.continuation = false;
        }
    }
}

namespace {

/// A PDF can map a glyph to a control character. Writing that byte to the
/// terminal would let a document inject escape sequences into the UI, so the
/// cell buffer only ever stores printable text.
std::string safe_glyph(std::string_view glyph) {
    std::string out;
    std::size_t position = 0;
    while (position < glyph.size()) {
        const std::size_t start = position;
        const char32_t code = decode_utf8(glyph, position);
        if (code < 0x20 || (code >= 0x7F && code < 0xA0) || code == 0x2028 || code == 0x2029) {
            out.push_back(' ');
        } else {
            out.append(glyph.substr(start, position - start));
        }
    }
    return out;
}

}  // namespace

void Screen::put(int x, int y, std::string_view glyph, const Style& style) {
    if (!inside(x, y)) return;
    const std::string cleaned = safe_glyph(glyph);
    glyph = cleaned;
    const int width = display_width(glyph);
    if (width <= 0) return;
    Cell& target = cell(x, y);
    target.glyph = std::string(glyph);
    target.style = style;
    target.continuation = false;
    if (width == 2 && inside(x + 1, y)) {
        Cell& continuation = cell(x + 1, y);
        continuation.glyph.clear();
        continuation.style = style;
        continuation.continuation = true;
    }
}

int Screen::text(int x, int y, int max_width, std::string_view value, const Style& style) {
    if (max_width <= 0) return x;
    int column = x;
    std::size_t position = 0;
    while (position < value.size()) {
        const std::size_t start = position;
        const char32_t code = decode_utf8(value, position);
        if (code == '\n' || code == '\r') break;
        const int width = codepoint_width(code);
        if (width == 0) {
            // Combining mark: append to the previous cell when possible.
            if (column > x && inside(column - 1, y)) {
                cell(column - 1, y).glyph.append(value.substr(start, position - start));
            }
            continue;
        }
        if (column + width > x + max_width) break;
        put(column, y, value.substr(start, position - start), style);
        column += width;
    }
    return column;
}

void Screen::text_padded(int x, int y, int width, std::string_view value, const Style& style) {
    fill(x, y, width, 1, style.bg);
    const int end = text(x, y, width, value, style);
    if (end < x + width) fill(end, y, x + width - end, 1, style.bg);
    // fill() resets the style of the padded cells to the default foreground; fix
    // them so a selection background spans the full row.
    for (int column = std::max(x, end); column < x + width && inside(column, y); ++column) {
        cell(column, y).style = style;
    }
}

void Screen::hline(int x, int y, int width, std::string_view glyph, const Style& style) {
    for (int column = 0; column < width; ++column) put(x + column, y, glyph, style);
}

void Screen::vline(int x, int y, int height, std::string_view glyph, const Style& style) {
    for (int row = 0; row < height; ++row) put(x, y + row, glyph, style);
}

void Screen::panel(int x, int y, int width, int height, std::string_view title,
                   const Style& style) {
    if (width < 4 || height < 3) return;
    fill(x, y, width, height, style.bg);
    Style border = style;
    border.fg = style.fg;
    put(x, y, "\u256D", border);
    put(x + width - 1, y, "\u256E", border);
    put(x, y + height - 1, "\u2570", border);
    put(x + width - 1, y + height - 1, "\u256F", border);
    for (int column = 1; column < width - 1; ++column) {
        put(x + column, y, "\u2500", border);
        put(x + column, y + height - 1, "\u2500", border);
    }
    for (int row = 1; row < height - 1; ++row) {
        put(x, y + row, "\u2502", border);
        put(x + width - 1, y + row, "\u2502", border);
    }
    if (!title.empty() && width > 6) {
        Style title_style = style;
        title_style.bold = true;
        text(x + 2, y, width - 4, " " + std::string(title) + " ", title_style);
    }
}

void Screen::shadow(int x, int y, int width, int height) {
    for (int row = 1; row <= height; ++row) {
        for (int column = 1; column <= width; ++column) {
            const bool edge = row == height || column == width;
            if (!edge) continue;
            const int px = x + column;
            const int py = y + row;
            if (!inside(px, py)) continue;
            Cell& target = cell(px, py);
            Rgb bg = target.style.bg;
            bg.r = static_cast<std::uint8_t>(bg.r * 0.55);
            bg.g = static_cast<std::uint8_t>(bg.g * 0.55);
            bg.b = static_cast<std::uint8_t>(bg.b * 0.55);
            target.style.bg = bg;
        }
    }
}

void Screen::dim(double factor) {
    const double clamped = std::clamp(factor, 0.0, 1.0);
    for (Cell& cell_value : cells_) {
        const auto scale = [clamped](std::uint8_t value) {
            return static_cast<std::uint8_t>(static_cast<double>(value) * clamped);
        };
        cell_value.style.fg.r = scale(cell_value.style.fg.r);
        cell_value.style.fg.g = scale(cell_value.style.fg.g);
        cell_value.style.fg.b = scale(cell_value.style.fg.b);
        cell_value.style.bg.r = scale(cell_value.style.bg.r);
        cell_value.style.bg.g = scale(cell_value.style.bg.g);
        cell_value.style.bg.b = scale(cell_value.style.bg.b);
    }
}

const Cell& Screen::at(int x, int y) const {
    static const Cell kEmpty;
    if (!inside(x, y)) return kEmpty;
    return cells_[static_cast<std::size_t>(y * width_ + x)];
}

namespace {

/// Selects `style`. In monochrome mode colour is dropped entirely and
/// intensity is the only channel: bold still marks the selection, dim still
/// marks de-emphasised text, and nothing depends on a colour the terminal may
/// not have.
void append_sgr(std::string& out, const Style& style, bool mono) {
    // 22 is "normal intensity" and cancels both bold and dim, so only the
    // attributes that are on are emitted. Emitting "1;22" would silently
    // disable the bold it just requested.
    std::string sgr = "\x1b[";
    if (style.bold) sgr += "1;";
    if (style.dim) sgr += "2;";
    if (mono) {
        if (sgr.size() > 2)
            sgr.pop_back();  // trailing separator
        else
            sgr += "0";  // no attributes: reset whatever the last cell set
        sgr += "m";
        out += sgr;
        return;
    }
    char colors[96];
    std::snprintf(colors, sizeof(colors), "38;2;%d;%d;%d;48;2;%d;%d;%dm", style.fg.r,
                  style.fg.g, style.fg.b, style.bg.r, style.bg.g, style.bg.b);
    sgr += colors;
    out += sgr;
}

/// Colour changes are irrelevant in monochrome, and re-emitting SGR for every
/// colour-only difference would make the frame noisy for no visual gain.
[[nodiscard]] bool same_style(const Style& a, const Style& b, bool mono) {
    if (mono) return a.bold == b.bold && a.dim == b.dim;
    return a == b;
}

}  // namespace

std::string Screen::to_ansi(bool mono) const {
    std::string out;
    out.reserve(static_cast<std::size_t>(width_ * height_ * 8));
    Style current;
    current.bg = Rgb{1, 1, 1};
    bool have_style = false;
    for (int y = 0; y < height_; ++y) {
        char cursor[32];
        std::snprintf(cursor, sizeof(cursor), "\x1b[%d;1H", y + 1);
        out += cursor;
        for (int x = 0; x < width_; ++x) {
            const Cell& cell_value = at(x, y);
            if (cell_value.continuation) continue;
            if (!have_style || !same_style(cell_value.style, current, mono)) {
                append_sgr(out, cell_value.style, mono);
                current = cell_value.style;
                have_style = true;
            }
            out += cell_value.glyph.empty() ? " " : cell_value.glyph;
        }
    }
    out += "\x1b[0m";
    return out;
}

std::string Screen::to_plain() const {
    std::string out;
    for (int y = 0; y < height_; ++y) {
        for (int x = 0; x < width_; ++x) {
            const Cell& cell_value = at(x, y);
            if (cell_value.continuation) continue;
            out += cell_value.glyph.empty() ? " " : cell_value.glyph;
        }
        out.push_back('\n');
    }
    return out;
}

std::string truncate_text(std::string_view text, int width) {
    if (width <= 0) return {};
    if (display_width(text) <= width) return std::string(text);
    std::string out;
    std::size_t position = 0;
    int used = 0;
    while (position < text.size()) {
        const std::size_t start = position;
        const char32_t code = decode_utf8(text, position);
        const int cell_width = codepoint_width(code);
        if (used + cell_width > width - 1) break;
        out.append(text.substr(start, position - start));
        used += cell_width;
    }
    out += "\u2026";
    return out;
}

namespace {

/// Appends whole code points from `text` while they fit in `budget` columns,
/// starting at `position`; returns the columns used.
int take_columns(std::string_view text, std::size_t& position, int budget, std::string& out) {
    int used = 0;
    while (position < text.size()) {
        const std::size_t start = position;
        const char32_t code = decode_utf8(text, position);
        const int cell_width = codepoint_width(code);
        if (used + cell_width > budget) {
            position = start;
            break;
        }
        out.append(text.substr(start, position - start));
        used += cell_width;
    }
    return used;
}

}  // namespace

std::string truncate_middle(std::string_view text, int width) {
    if (width <= 0) return {};
    if (display_width(text) <= width) return std::string(text);
    if (width <= 1) return "\u2026";
    const int budget = width - 1;  // one cell for the ellipsis
    const int head_budget = (budget + 1) / 2;
    const int tail_budget = budget - head_budget;

    std::size_t head_position = 0;
    std::string out;
    take_columns(text, head_position, head_budget, out);
    out += "\u2026";

    // The tail is measured from the end, so walk the string to collect the last
    // code points that fit rather than slicing bytes (UTF-8 aware).
    std::vector<std::pair<std::size_t, int>> codepoints;
    std::size_t position = head_position;
    while (position < text.size()) {
        const std::size_t start = position;
        const int cell_width = codepoint_width(decode_utf8(text, position));
        codepoints.emplace_back(start, cell_width);
    }
    std::size_t tail_start = text.size();
    int used = 0;
    for (std::size_t index = codepoints.size(); index > 0; --index) {
        const auto [start, cell_width] = codepoints[index - 1];
        if (used + cell_width > tail_budget) break;
        used += cell_width;
        tail_start = start;
    }
    out.append(text.substr(tail_start));
    return out;
}

std::vector<std::string> wrap_text(std::string_view text, int width) {
    std::vector<std::string> lines;
    if (width <= 0) return lines;
    std::size_t position = 0;
    std::string line;
    int line_width = 0;
    const auto flush = [&]() {
        lines.push_back(line);
        line.clear();
        line_width = 0;
    };
    while (position < text.size()) {
        if (text[position] == '\n') {
            flush();
            ++position;
            continue;
        }
        const std::size_t word_start = position;
        while (position < text.size() && text[position] != ' ' && text[position] != '\n') {
            ++position;
        }
        std::string_view word = text.substr(word_start, position - word_start);
        const int word_width = display_width(word);
        const bool need_space = !line.empty();
        if (line_width + (need_space ? 1 : 0) + word_width > width) {
            if (line.empty()) {
                // Break the long word.
                std::string piece;
                int piece_width = 0;
                std::size_t inner = 0;
                while (inner < word.size()) {
                    const std::size_t start = inner;
                    const char32_t code = decode_utf8(word, inner);
                    const int cell_width = codepoint_width(code);
                    if (piece_width + cell_width > width) {
                        lines.push_back(piece);
                        piece.clear();
                        piece_width = 0;
                    }
                    piece.append(word.substr(start, inner - start));
                    piece_width += cell_width;
                }
                line = piece;
                line_width = piece_width;
            } else {
                flush();
                line = std::string(word);
                line_width = word_width;
            }
        } else {
            if (need_space) {
                line.push_back(' ');
                ++line_width;
            }
            line += word;
            line_width += word_width;
        }
        while (position < text.size() && text[position] == ' ') ++position;
    }
    if (!line.empty()) lines.push_back(line);
    if (lines.empty()) lines.push_back("");
    return lines;
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------
namespace {

termios g_saved{};
bool g_raw = false;

void write_all(const std::string& data) {
    std::size_t written = 0;
    while (written < data.size()) {
        const ssize_t result = ::write(STDOUT_FILENO, data.data() + written, data.size() - written);
        if (result <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        written += static_cast<std::size_t>(result);
    }
}

}  // namespace

void set_raw_mode(bool enabled) {
    if (enabled && !g_raw) {
        if (::tcgetattr(STDIN_FILENO, &g_saved) != 0) return;
        termios raw = g_saved;
        raw.c_iflag &= static_cast<tcflag_t>(~(BRKINT | ICRNL | INPCK | ISTRIP | IXON));
        raw.c_oflag &= static_cast<tcflag_t>(~(OPOST));
        raw.c_cflag |= CS8;
        raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON | IEXTEN | ISIG));
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == 0) g_raw = true;
    } else if (!enabled && g_raw) {
        ::tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved);
        g_raw = false;
    }
}

Terminal::~Terminal() { leave(); }

bool Terminal::enter() {
    if (active_) return true;
    if (::isatty(STDIN_FILENO) == 0) return false;
    set_raw_mode(true);
    active_ = true;
    std::string sequence = "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H";
    write_all(sequence);
    return true;
}

void Terminal::leave() {
    if (!active_) return;
    const std::string sequence = "\x1b[0m\x1b[?25h\x1b[?1049l";
    write_all(sequence);
    set_raw_mode(false);
    active_ = false;
    previous_.clear();
    previous_width_ = 0;
    previous_height_ = 0;
}

void Terminal::present(const Screen& screen, bool mono) {
    if (!active_) return;
    const bool resized = screen.width() != previous_width_ || screen.height() != previous_height_ ||
                         previous_.size() != screen.cells().size();
    if (resized) {
        previous_.assign(screen.cells().size(), Cell{});
        for (Cell& cell_value : previous_) cell_value.glyph = "\x00";
        previous_width_ = screen.width();
        previous_height_ = screen.height();
        pending_ += "\x1b[2J";
    }

    Style current;
    current.fg = Rgb{0, 0, 0};
    current.bg = Rgb{0, 0, 0};
    bool have_style = false;
    int cursor_x = -1;
    int cursor_y = -1;

    for (int y = 0; y < screen.height(); ++y) {
        for (int x = 0; x < screen.width(); ++x) {
            const std::size_t index =
                static_cast<std::size_t>(y * screen.width() + x);
            const Cell& cell_value = screen.cells()[index];
            if (cell_value.continuation) continue;
            if (cell_value == previous_[index]) continue;
            previous_[index] = cell_value;
            if (x == 0 && y > 0) {
                // A full row rewrite should also clear the previous last cell if
                // the row now ends earlier; the width is constant, so nothing
                // special is needed.
            }
            if (!have_style || !same_style(cell_value.style, current, mono)) {
                append_sgr(pending_, cell_value.style, mono);
                current = cell_value.style;
                have_style = true;
            }
            if (cursor_y != y || cursor_x != x) {
                char position[32];
                std::snprintf(position, sizeof(position), "\x1b[%d;%dH", y + 1, x + 1);
                pending_ += position;
            }
            pending_ += cell_value.glyph.empty() ? " " : cell_value.glyph;
            cursor_x = x + 1;
            cursor_y = y;
        }
    }
    if (!pending_.empty()) {
        pending_ += "\x1b[0m\x1b[?25l";
        write_all(pending_);
        pending_.clear();
    }
}

int Terminal::query_width() {
    winsize size{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0) return size.ws_col;
    return 100;
}

int Terminal::query_height() {
    winsize size{};
    if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_row > 0) return size.ws_row;
    return 32;
}

namespace {

bool decode_escape(std::string& key, const std::vector<unsigned char>& bytes, std::size_t start) {
    if (start + 1 >= bytes.size()) return false;
    if (bytes[start] != 0x1B || bytes[start + 1] != '[') return false;
    std::size_t end = start + 2;
    while (end < bytes.size() && (std::isdigit(bytes[end]) != 0 || bytes[end] == ';')) ++end;
    if (end >= bytes.size()) return false;
    const char final = static_cast<char>(bytes[end]);
    std::string params;
    for (std::size_t i = start + 2; i < end; ++i) params.push_back(static_cast<char>(bytes[i]));
    if (final == 'A') key = "up";
    else if (final == 'B') key = "down";
    else if (final == 'C') key = "right";
    else if (final == 'D') key = "left";
    else if (final == 'H') key = "home";
    else if (final == 'F') key = "end";
    else if (final == '~') {
        if (params == "1" || params == "7") key = "home";
        else if (params == "4" || params == "8") key = "end";
        else if (params == "5") key = "pageup";
        else if (params == "6") key = "pagedown";
        else if (params == "3") key = "delete";
        else key = "escape";
    } else {
        key = "escape";
    }
    return true;
}

}  // namespace

bool read_key_timeout(std::string& key, int timeout_ms) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(STDIN_FILENO, &set);
    timeval timeout{};
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    timeval* timeout_pointer = timeout_ms < 0 ? nullptr : &timeout;
    const int ready = ::select(STDIN_FILENO + 1, &set, nullptr, nullptr, timeout_pointer);
    if (ready <= 0) return false;

    unsigned char bytes[8] = {};
    const ssize_t count = ::read(STDIN_FILENO, bytes, sizeof(bytes));
    if (count <= 0) return false;
    const std::vector<unsigned char> buffer(bytes, bytes + count);
    if (buffer.size() >= 3 && decode_escape(key, buffer, 0)) return true;
    if (buffer[0] == 0x1B) {
        key = "escape";
        return true;
    }
    if (buffer[0] == '\r' || buffer[0] == '\n') {
        key = "enter";
        return true;
    }
    if (buffer[0] == '\t') {
        key = "tab";
        return true;
    }
    if (buffer[0] == 0x7F || buffer[0] == 0x08) {
        key = "backspace";
        return true;
    }
    if (buffer[0] == 0x03) {
        key = "ctrl-c";
        return true;
    }
    if (buffer[0] == 0x10) {
        key = "ctrl-p";
        return true;
    }
    if (buffer[0] < 0x20) {
        key = std::string("ctrl-") + static_cast<char>('a' + buffer[0] - 1);
        return true;
    }
    std::size_t position = 0;
    std::string glyph;
    while (position < buffer.size()) {
        const std::size_t start = position;
        std::string_view view(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        (void)decode_utf8(view, position);
        glyph.append(view.substr(start, position - start));
    }
    key = glyph;
    return true;
}

bool read_key(std::string& key) { return read_key_timeout(key, -1); }

}  // namespace scour::tui

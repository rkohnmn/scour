// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// A tiny cell screen and a diffing terminal writer. Nothing here knows what a
// PDF is: the TUI renders into a grid, the grid is diffed against the previous
// frame, and only the changed runs are written. That is what keeps the interface
// from flickering over SSH, and it makes `--dump` free: a frame is just a grid.
#ifndef SCOUR_TUI_SCREEN_HPP
#define SCOUR_TUI_SCREEN_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace scour::tui {

struct Rgb {
    std::uint8_t r = 0;
    std::uint8_t g = 0;
    std::uint8_t b = 0;
};

[[nodiscard]] bool operator==(const Rgb& a, const Rgb& b) noexcept;
[[nodiscard]] bool operator!=(const Rgb& a, const Rgb& b) noexcept;

struct Style {
    Rgb fg{216, 222, 233};
    Rgb bg{15, 18, 26};
    bool bold = false;
    bool dim = false;

    [[nodiscard]] bool operator==(const Style& other) const noexcept;
};

struct Palette {
    std::string name;
    Rgb background;
    Rgb panel;
    Rgb panel_alt;
    Rgb border;
    Rgb border_strong;
    Rgb text;
    Rgb text_dim;
    Rgb text_faint;
    Rgb accent;
    Rgb accent_soft;
    Rgb ok;
    Rgb warn;
    Rgb danger;
    Rgb critical;
    Rgb selection;
    Rgb selection_text;
};

[[nodiscard]] const Palette& dark_palette();
[[nodiscard]] const Palette& light_palette();

struct Cell {
    std::string glyph{" "};
    Style style;
    bool continuation = false;

    [[nodiscard]] bool operator==(const Cell& other) const noexcept {
        return glyph == other.glyph && style == other.style &&
               continuation == other.continuation;
    }
};

/// Decodes one UTF-8 code point starting at `position`; advances `position`.
[[nodiscard]] char32_t decode_utf8(std::string_view text, std::size_t& position);
/// Terminal column width of a code point (0 for combining marks, 2 for CJK).
[[nodiscard]] int codepoint_width(char32_t code);
/// Display width of a UTF-8 string.
[[nodiscard]] int display_width(std::string_view text);

class Screen {
public:
    Screen(int width, int height);

    void resize(int width, int height);
    void clear(const Rgb& background);
    void fill(int x, int y, int width, int height, const Rgb& background);
    void put(int x, int y, std::string_view glyph, const Style& style);
    /// Draws text clipped to `max_width` columns, returns the column after the
    /// last glyph. Never wraps; callers wrap explicitly with `wrap_text`.
    int text(int x, int y, int max_width, std::string_view text, const Style& style);
    /// Draws text and pads the remainder of the span with `style.bg`.
    void text_padded(int x, int y, int width, std::string_view text, const Style& style);
    void hline(int x, int y, int width, std::string_view glyph, const Style& style);
    void vline(int x, int y, int height, std::string_view glyph, const Style& style);
    /// Rounded panel with an optional title in the top border.
    void panel(int x, int y, int width, int height, std::string_view title, const Style& style);
    /// Cheap depth: a one-cell shadow behind a panel.
    void shadow(int x, int y, int width, int height);
    /// Darkens the whole grid; used to put the page behind a modal.
    void dim(double factor);

    [[nodiscard]] int width() const noexcept { return width_; }
    [[nodiscard]] int height() const noexcept { return height_; }
    [[nodiscard]] const Cell& at(int x, int y) const;
    [[nodiscard]] const std::vector<Cell>& cells() const noexcept { return cells_; }

    /// Renders the whole grid as ANSI. Used by `--dump` and by tests. With
    /// `mono`, colour is omitted and only bold/dim survives, which is what a
    /// monochrome terminal or NO_COLOR gets.
    [[nodiscard]] std::string to_ansi(bool mono = false) const;
    /// Renders the grid without escape codes, for golden-file tests.
    [[nodiscard]] std::string to_plain() const;

private:
    [[nodiscard]] bool inside(int x, int y) const noexcept {
        return x >= 0 && y >= 0 && x < width_ && y < height_;
    }
    [[nodiscard]] Cell& cell(int x, int y) { return cells_[static_cast<std::size_t>(y * width_ + x)]; }

    int width_ = 0;
    int height_ = 0;
    std::vector<Cell> cells_;
};

/// Wraps text into lines no wider than `width` columns. Explicit newlines are
/// preserved; long words are broken rather than overflowing.
[[nodiscard]] std::vector<std::string> wrap_text(std::string_view text, int width);

/// Truncates to `width` columns, appending U+2026 when something was cut.
[[nodiscard]] std::string truncate_text(std::string_view text, int width);

/// Truncates in the middle, keeping the start and the end. File names share
/// prefixes and distinguish themselves by extension, so a tail is worth more
/// than a longer head.
[[nodiscard]] std::string truncate_middle(std::string_view text, int width);

/// A minimal raw-mode terminal with an alternate screen and diffed repaints.
class Terminal {
public:
    Terminal() = default;
    ~Terminal();
    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;

    bool enter();
    void leave();
    [[nodiscard]] bool active() const noexcept { return active_; }

    void present(const Screen& screen, bool mono = false);
    [[nodiscard]] static int query_width();
    [[nodiscard]] static int query_height();

private:
    bool active_ = false;
    std::vector<Cell> previous_;
    int previous_width_ = 0;
    int previous_height_ = 0;
    std::string pending_;
};

/// Reads one key press from stdin. Returns false when stdin is closed.
/// Escape sequences are normalised to names: "up", "down", "left", "right",
/// "home", "end", "pageup", "pagedown", "enter", "tab", "escape", "backspace",
/// "delete", or the literal character.
[[nodiscard]] bool read_key(std::string& key);
/// Same, but waits at most `timeout_ms` milliseconds.
[[nodiscard]] bool read_key_timeout(std::string& key, int timeout_ms);
void set_raw_mode(bool enabled);

}  // namespace scour::tui

#endif  // SCOUR_TUI_SCREEN_HPP

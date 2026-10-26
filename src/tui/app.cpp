// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "app.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <csignal>

#include "scour/document.hpp"
#include "scour/error.hpp"
#include "scour/inspector.hpp"
#include "scour/pages.hpp"
#include "scour/sanitize.hpp"
#include "scour/text.hpp"
#include "scour/version.hpp"
#include "scour/writer.hpp"
#include "screen.hpp"

namespace scour::tui {

namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

volatile std::sig_atomic_t g_resized = 0;

void on_winch(int) { g_resized = 1; }

std::string human_size(std::size_t bytes) {
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

Rgb severity_color(const Palette& palette, Severity severity) {
    switch (severity) {
        case Severity::Error: return palette.critical;
        case Severity::Warning: return palette.warn;
        case Severity::Info: return palette.accent;
        case Severity::Debug: return palette.text_faint;
    }
    return palette.text_faint;
}

const char* severity_name(Severity severity) {
    switch (severity) {
        case Severity::Error: return "ERROR";
        case Severity::Warning: return "WARN";
        case Severity::Info: return "NOTE";
        case Severity::Debug: return "TRACE";
    }
    return "?";
}

int severity_rank(Severity severity) {
    switch (severity) {
        case Severity::Error: return 3;
        case Severity::Warning: return 2;
        case Severity::Info: return 1;
        case Severity::Debug: return 0;
    }
    return 0;
}

std::string lower(std::string_view text) {
    std::string out(text);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return lower(haystack).find(lower(needle)) != std::string::npos;
}

std::string category_label(std::string_view key) {
    if (key == "metadata") return "Metadata";
    if (key == "hidden-text") return "Hidden text";
    if (key == "annotations") return "Annotations";
    if (key == "embedded") return "Embedded files";
    if (key == "actions") return "Scripts & actions";
    if (key == "structure") return "File structure";
    if (key == "pii") return "Personal data";
    if (key == "integrity") return "Limits & integrity";
    return std::string(key);
}

struct Category {
    std::string key;
    std::string label;
    int count = 0;
    Severity worst = Severity::Debug;
};

enum class Overlay { None, Help, Palette, Prompt, Detail };

enum class PromptKind { Filter, Term };

struct PaletteAction {
    std::string label;
    std::string hint;
    std::string key;
};

struct App {
    TuiOptions options;
    std::unique_ptr<Document> document;
    InspectionReport report;
    std::string load_error;
    std::string source_path;

    bool light = false;
    bool mono = false;
    std::vector<Category> categories;
    int category = 0;
    int selected = 0;
    int scroll = 0;
    int detail_scroll = 0;
    std::string filter;

    Overlay overlay = Overlay::None;
    int palette_index = 0;
    std::string palette_query;
    PromptKind prompt_kind = PromptKind::Filter;
    std::string prompt_label;
    std::string prompt_text;

    int help_scroll = 0;

    std::string toast;
    Clock::time_point toast_at;
    bool quit = false;
    bool busy = false;

    [[nodiscard]] const Palette& palette() const {
        return light ? light_palette() : dark_palette();
    }

    void notify(std::string message) {
        toast = std::move(message);
        toast_at = Clock::now();
    }

    [[nodiscard]] bool toast_visible() const {
        return !toast.empty() && Clock::now() - toast_at < std::chrono::seconds(6);
    }
};

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------
void rebuild_categories(App& app) {
    app.categories.clear();
    app.categories.push_back(Category{"all", "All findings", 0, Severity::Debug});
    const std::vector<std::pair<std::string, std::string>> kOrder = {
        {"metadata", "Metadata"},
        {"hidden-text", "Hidden text"},
        {"annotations", "Annotations"},
        {"embedded", "Embedded files"},
        {"actions", "Scripts & actions"},
        {"structure", "File structure"},
        {"pii", "Personal data"},
        {"integrity", "Limits"},
    };
    for (const auto& [key, label] : kOrder) {
        Category category;
        category.key = key;
        category.label = label;
        for (const Finding& finding : app.report.findings) {
            if (finding.category != key) continue;
            ++category.count;
            if (severity_rank(finding.severity) > severity_rank(category.worst))
                category.worst = finding.severity;
        }
        app.categories.push_back(std::move(category));
    }
    for (const Finding& finding : app.report.findings) {
        ++app.categories[0].count;
        if (severity_rank(finding.severity) > severity_rank(app.categories[0].worst))
            app.categories[0].worst = finding.severity;
    }
    app.category = std::clamp(app.category, 0, static_cast<int>(app.categories.size()) - 1);
    app.selected = 0;
    app.scroll = 0;
    app.detail_scroll = 0;
}

const std::vector<const Finding*>& visible_findings(const App& app,
                                                    std::vector<const Finding*>& storage) {
    storage.clear();
    const std::string key = app.categories[static_cast<std::size_t>(app.category)].key;
    for (const Finding& finding : app.report.findings) {
        if (key != "all" && finding.category != key) continue;
        if (!app.filter.empty()) {
            const bool hit = contains_ci(finding.title, app.filter) ||
                             contains_ci(finding.detail, app.filter) ||
                             contains_ci(finding.evidence, app.filter) ||
                             contains_ci(finding.id, app.filter);
            if (!hit) continue;
        }
        storage.push_back(&finding);
    }
    std::sort(storage.begin(), storage.end(), [](const Finding* a, const Finding* b) {
        if (a->severity != b->severity) return severity_rank(a->severity) > severity_rank(b->severity);
        if (a->page != b->page) return a->page < b->page;
        return a->title < b->title;
    });
    return storage;
}

void clamp_selection(App& app, std::size_t count) {
    if (count == 0) {
        app.selected = 0;
        app.scroll = 0;
        return;
    }
    app.selected = std::clamp(app.selected, 0, static_cast<int>(count) - 1);
}

// ---------------------------------------------------------------------------
// Scrub from the dashboard
// ---------------------------------------------------------------------------
std::string output_for(const std::string& input, const std::string& suffix) {
    const fs::path path(input);
    const fs::path parent = path.parent_path();
    return (parent / (path.stem().string() + suffix + ".pdf")).string();
}

void reload(App& app, const std::string& path) {
    Diagnostics diagnostics;
    LoadOptions load_options;
    load_options.password = app.options.password;
    try {
        Bytes bytes;
        std::ifstream stream(path, std::ios::binary);
        if (!stream) throw ScourError("io.open", "cannot open " + path);
        stream.seekg(0, std::ios::end);
        const std::streamoff size = stream.tellg();
        if (size < 0) throw ScourError("io.read", "cannot measure " + path);
        stream.seekg(0, std::ios::beg);
        bytes.resize(static_cast<std::size_t>(size));
        if (size > 0) stream.read(reinterpret_cast<char*>(bytes.data()), size);
        app.document = std::make_unique<Document>(Document::load(bytes, load_options, diagnostics));
        app.source_path = path;
        InspectOptions inspect_options;
        app.report = inspect_document(*app.document, path, inspect_options, diagnostics);
        rebuild_categories(app);
    } catch (const ScourError& error) {
        app.notify(std::string("reload failed: ") + error.what());
    }
}

bool perform_scrub(App& app, const std::string& term, bool use_pii) {
    if (app.document == nullptr) return false;
    Diagnostics diagnostics;
    ScrubOptions scrub_options;
    scrub_options.targets.terms = term.empty() ? std::vector<std::string>{} : std::vector<std::string>{term};
    scrub_options.targets.pii = use_pii;
    scrub_options.redact = use_pii || !term.empty();
    scrub_options.targets.paint = true;

    const int before = app.report.risk;
    const ScrubReport scrub = scrub_document(*app.document, scrub_options, diagnostics);
    WriteOptions write_options;
    write_options.deterministic_id = true;
    const WriteResult written = write_document(*app.document, write_options, diagnostics);
    const std::string output = output_for(app.source_path, ".scrubbed");
    {
        std::ofstream stream(output, std::ios::binary | std::ios::trunc);
        if (!stream) {
            app.notify("cannot write " + output);
            reload(app, app.source_path);
            return false;
        }
        stream.write(reinterpret_cast<const char*>(written.bytes.data()),
                     static_cast<std::streamsize>(written.bytes.size()));
    }
    reload(app, output);
    std::ostringstream message;
    message << "wrote " << fs::path(output).filename().string();
    if (scrub.redacted)
        message << "  ·  " << scrub.redaction.glyphs_removed << " glyphs removed";
    message << "  ·  risk " << before << " -> " << app.report.risk;
    app.notify(message.str());
    return true;
}

void write_json_report(App& app) {
    const fs::path source(app.source_path);
    const std::string json_name =
        (source.parent_path() / (source.stem().string() + ".report.json")).string();
    std::ofstream stream(json_name, std::ios::trunc);
    if (!stream) {
        app.notify("cannot write " + json_name);
        return;
    }
    stream << app.report.to_json();
    app.notify("wrote " + fs::path(json_name).filename().string());
}

// ---------------------------------------------------------------------------
// Palette
// ---------------------------------------------------------------------------
const std::vector<PaletteAction>& palette_actions() {
    static const std::vector<PaletteAction> kActions = {
        {"Inspect again", "re-read the file", "inspect"},
        {"Scrub hidden data", "metadata, scripts", "scrub"},
        {"Redact a term", "from the text", "term"},
        {"Redact detected personal data", "emails, cards", "pii"},
        {"Export JSON report", "for CI or a ticket", "json"},
        {"Toggle theme", "midnight / paper", "theme"},
        {"Toggle monochrome", "no colour at all", "mono"},
        {"Keyboard help", "every binding", "help"},
        {"Quit", "back to the shell", "quit"},
    };
    return kActions;
}

std::vector<const PaletteAction*> filtered_actions(const App& app) {
    std::vector<const PaletteAction*> actions;
    for (const PaletteAction& action : palette_actions()) {
        if (!app.palette_query.empty() && !contains_ci(action.label, app.palette_query) &&
            !contains_ci(action.hint, app.palette_query))
            continue;
        actions.push_back(&action);
    }
    return actions;
}

void start_prompt(App& app, PromptKind kind, std::string label, std::string initial) {
    app.overlay = Overlay::Prompt;
    app.prompt_kind = kind;
    app.prompt_label = std::move(label);
    app.prompt_text = std::move(initial);
}

void run_action(App& app, const std::string& key) {
    if (key == "inspect") {
        reload(app, app.source_path);
        app.notify("re-inspected " + fs::path(app.source_path).filename().string());
    } else if (key == "scrub") {
        if (perform_scrub(app, "", false))
            app.overlay = Overlay::None;
    } else if (key == "term") {
        start_prompt(app, PromptKind::Term, "Term to remove (case-insensitive)", "");
    } else if (key == "pii") {
        if (perform_scrub(app, "", true)) app.overlay = Overlay::None;
    } else if (key == "json") {
        write_json_report(app);
    } else if (key == "theme") {
        app.light = !app.light;
        app.notify(app.light ? "paper theme" : "midnight theme");
    } else if (key == "mono") {
        app.mono = !app.mono;
        app.notify(app.mono ? "monochrome on" : "colour on");
    } else if (key == "help") {
        app.help_scroll = 0;
        app.overlay = Overlay::Help;
    } else if (key == "quit") {
        app.quit = true;
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------
Style make_style([[maybe_unused]] const Palette& palette, Rgb fg, Rgb bg) {
    Style style;
    style.fg = fg;
    style.bg = bg;
    return style;
}

void draw_chip(Screen& screen, int x, int y, std::string_view text, Rgb color, Rgb background) {
    Style style;
    style.fg = background;
    style.bg = color;
    style.bold = true;
    screen.text_padded(x, y, static_cast<int>(display_width(text)) + 2, " " + std::string(text) + " ",
                       style);
}

void draw_header(App& app, Screen& screen) {
    const Palette& palette = app.palette();
    const int width = screen.width();
    screen.fill(0, 0, width, 3, palette.panel);

    Style wordmark = make_style(palette, palette.accent, palette.panel);
    wordmark.bold = true;
    screen.put(2, 0, "\u2588", wordmark);
    screen.text(3, 0, 12, " SCOUR", wordmark);
    Style version = make_style(palette, palette.text_faint, palette.panel);
    screen.text(10, 0, 12, std::string(" ") + std::string(kVersion), version);

    const fs::path path(app.report.facts.path);
    Style file = make_style(palette, palette.text, palette.panel);
    file.bold = true;
    const int file_start = 20;
    const int file_width = width - file_start - 34;
    const std::string file_name = path.empty() ? "(no document)" : path.filename().string();
    screen.text(file_start, 0, file_width, truncate_middle(file_name, file_width), file);

    std::ostringstream facts;
    facts << app.report.facts.pages << " pages  ·  " << human_size(app.report.facts.size) << "  ·  PDF "
          << app.report.facts.version;
    if (app.report.facts.revisions > 1) facts << "  ·  " << app.report.facts.revisions << " revisions";
    if (app.report.facts.encrypted) facts << "  ·  encrypted";
    Style fact_style = make_style(palette, palette.text_dim, palette.panel);
    screen.text(file_start, 1, width - file_start - 34, facts.str(), fact_style);

    // Risk badge, laid out right to left so the columns can never overlap.
    const std::string score = std::to_string(app.report.risk);
    Rgb risk_color = palette.ok;
    if (app.report.risk >= 80) risk_color = palette.critical;
    else if (app.report.risk >= 55) risk_color = palette.danger;
    else if (app.report.risk >= 30) risk_color = palette.warn;
    const std::string grade = lower(app.report.grade);
    int right = width - 2;
    const auto token = [&](const std::string& text, const Style& style) {
        const int token_width = display_width(text);
        right -= token_width;
        screen.text(right, 0, token_width, text, style);
    };
    token(grade, make_style(palette, risk_color, palette.panel));
    token(" /100  ", make_style(palette, palette.text_faint, palette.panel));
    Style score_style = make_style(palette, risk_color, palette.panel);
    score_style.bold = true;
    token(score, score_style);
    token("  RISK  ", make_style(palette, palette.text_faint, palette.panel));

    Style rule = make_style(palette, palette.border, palette.background);
    screen.hline(0, 2, width, "\u2500", rule);
}

void draw_sidebar(App& app, Screen& screen, int x, int y, int width, int height,
                  std::size_t finding_count) {
    const Palette& palette = app.palette();
    Style panel_style = make_style(palette, palette.border, palette.panel);
    screen.panel(x, y, width, height, "NAVIGATE", panel_style);

    int row = y + 2;
    int index = 0;
    for (const Category& category : app.categories) {
        if (row >= y + height - 1) break;
        const bool active = index == app.category;
        Style row_style = make_style(palette, palette.text, active ? palette.selection : palette.panel);
        if (active) {
            row_style.fg = palette.selection_text;
            row_style.bold = true;
        }
        screen.text_padded(x + 1, row, width - 2, "", row_style);
        if (active)        screen.put(x + 1, row, "\u258C", make_style(palette, palette.accent, palette.selection));
        const char* bullet = category.count == 0 ? "\u00B7" : "\u25CF";
        Rgb dot_color = category.count == 0 ? palette.text_faint
                                            : severity_color(palette, category.worst);
        screen.put(x + 3, row, bullet, make_style(palette, dot_color, row_style.bg));
        const int label_width = width - 10;
        screen.text(x + 5, row, label_width,
                    truncate_text(category.label, label_width), row_style);
        if (category.count > 0) {
            const std::string count = std::to_string(category.count);
            screen.text(x + width - 2 - static_cast<int>(count.size()), row,
                        static_cast<int>(count.size()), count,
                        make_style(palette, active ? palette.selection_text : palette.text_dim,
                                   row_style.bg));
        }
        ++index;
        ++row;
    }

    // Document facts block, anchored to the bottom of the sidebar.
    int fact_row = y + height - 9;
    if (fact_row > row) {
        screen.hline(x + 1, fact_row - 1, width - 2, "\u2500", make_style(palette, palette.border, palette.panel));
        Style label = make_style(palette, palette.text_faint, palette.panel);
        screen.text(x + 2, fact_row, width - 4, "DOCUMENT", label);
        ++fact_row;
        const auto line = [&](std::string_view key, std::string_view value) {
            if (fact_row >= y + height - 1) return;
            screen.text(x + 2, fact_row, 9, std::string(key), make_style(palette, palette.text_faint, palette.panel));
            screen.text(x + 11, fact_row, width - 13, value, make_style(palette, palette.text_dim, palette.panel));
            ++fact_row;
        };
        line("objects", std::to_string(app.report.facts.objects));
        line("text", std::to_string(app.report.facts.text_characters) + " chars");
        line("images", std::to_string(app.report.facts.image_pages) + " pages");
        if (app.report.facts.annotations > 0)
            line("notes", std::to_string(app.report.facts.annotations));
        if (app.report.facts.embedded_files > 0)
            line("files", std::to_string(app.report.facts.embedded_files));
    }
    (void)finding_count;
}

void draw_list(App& app, Screen& screen, int x, int y, int width, int height,
               const std::vector<const Finding*>& findings) {
    const Palette& palette = app.palette();
    std::string title = "FINDINGS";
    if (!app.filter.empty()) title += "  /" + app.filter;
    Style panel_style = make_style(palette, palette.border, palette.background);
    screen.panel(x, y, width, height, title, panel_style);

    const int inner_height = height - 2;
    const int row_height = 2;
    const int visible_rows = std::max(1, inner_height / row_height);
    if (app.selected < app.scroll) app.scroll = app.selected;
    if (app.selected >= app.scroll + visible_rows) app.scroll = app.selected - visible_rows + 1;
    app.scroll = std::clamp(app.scroll, 0, std::max(0, static_cast<int>(findings.size()) - visible_rows));

    if (findings.empty()) {
        Style empty = make_style(palette, palette.text_dim, palette.background);
        screen.text(x + 3, y + 3, width - 6,
                    app.report.findings.empty() ? "Nothing to report. This file is clean."
                                                : "No finding matches this filter.",
                    empty);
        return;
    }

    int row = y + 1;
    for (int index = app.scroll;
         index < static_cast<int>(findings.size()) && row + 1 < y + height - 1; ++index) {
        const Finding& finding = *findings[static_cast<std::size_t>(index)];
        const bool active = index == app.selected;
        Rgb row_bg = active ? palette.selection : palette.background;
        Style base = make_style(palette, active ? palette.selection_text : palette.text, row_bg);
        if (active) base.bold = true;
        screen.text_padded(x + 1, row, width - 2, "", base);
        screen.text_padded(x + 1, row + 1, width - 2, "", make_style(
            palette, active ? palette.selection_text : palette.text_dim, row_bg));

        if (active) {
            for (int r = 0; r < 2; ++r)
                screen.put(x + 1, row + r, "\u258C", make_style(palette, palette.accent, row_bg));
        }
        const Rgb color = severity_color(palette, finding.severity);
        draw_chip(screen, x + 3, row, severity_name(finding.severity), color,
                  active ? palette.selection : palette.background);
        const int title_x = x + 12;
        const int page_width = finding.page > 0 ? 5 : 0;
        const int title_width = width - (title_x - x) - page_width - 2;
        screen.text(title_x, row, title_width, truncate_text(finding.title, title_width), base);
        if (finding.page > 0) {
            const std::string page = "p." + std::to_string(finding.page);
            screen.text(x + width - 2 - static_cast<int>(page.size()), row,
                        static_cast<int>(page.size()), page,
                        make_style(palette, active ? palette.selection_text : palette.text_faint, row_bg));
        }
        std::string second = finding.evidence.empty() ? finding.detail : finding.evidence;
        if (!finding.evidence.empty()) second = "\u201C" + second + "\u201D";
        screen.text(x + 6, row + 1, width - 8, truncate_text(second, width - 8),
                    make_style(palette, active ? palette.selection_text : palette.text_dim, row_bg));
        row += row_height;
    }

    if (findings.size() > static_cast<std::size_t>(visible_rows)) {
        Style hint = make_style(palette, palette.text_faint, palette.background);
        const std::string counter =
            std::to_string(app.selected + 1) + "/" + std::to_string(findings.size());
        screen.text(x + width - 2 - static_cast<int>(counter.size()), y,
                    static_cast<int>(counter.size()), counter, hint);

        // Thin scroll indicator on the right edge of the panel.
        const int track_top = y + 1;
        const int track_height = height - 2;
        const int thumb_height = std::max(1, track_height * visible_rows /
                                                 static_cast<int>(findings.size()));
        const int max_scroll = static_cast<int>(findings.size()) - visible_rows;
        const int thumb_top = track_top + (max_scroll > 0 ? (track_height - thumb_height) *
                                                               app.scroll / max_scroll
                                                         : 0);
        for (int r = 0; r < track_height; ++r) {
            const bool in_thumb = track_top + r >= thumb_top &&
                                  track_top + r < thumb_top + thumb_height;
            screen.put(x + width - 1, track_top + r, "\u2502",
                       make_style(palette, in_thumb ? palette.border_strong : palette.border,
                                  palette.background));
        }
    }
}

void draw_detail(App& app, Screen& screen, int x, int y, int width, int height,
                 const std::vector<const Finding*>& findings) {
    const Palette& palette = app.palette();
    Style panel_style = make_style(palette, palette.border, palette.panel);
    screen.panel(x, y, width, height, "DETAIL", panel_style);
    if (findings.empty()) {
        screen.text(x + 2, y + 2, width - 4, "Select a finding to see the evidence.",
                    make_style(palette, palette.text_dim, palette.panel));
        return;
    }
    const Finding& finding = *findings[static_cast<std::size_t>(app.selected)];
    int row = y + 2;
    const int inner_width = width - 4;
    const auto line = [&](std::string_view text, Style style) {
        if (row >= y + height - 1) return;
        screen.text(x + 2, row, inner_width, text, style);
        ++row;
    };
    const auto wrapped = [&](std::string_view text, Style style, int indent) {
        for (const std::string& part : wrap_text(text, inner_width - indent)) {
            if (row >= y + height - 1) return;
            screen.text(x + 2 + indent, row, inner_width - indent, part, style);
            ++row;
        }
    };

    draw_chip(screen, x + 2, row, severity_name(finding.severity),
              severity_color(palette, finding.severity), palette.panel);
    Style cat = make_style(palette, palette.text_faint, palette.panel);
    screen.text(x + 12, row, inner_width - 10, category_label(finding.category), cat);
    ++row;
    ++row;
    Style title_style = make_style(palette, palette.text, palette.panel);
    title_style.bold = true;
    wrapped(finding.title, title_style, 0);
    ++row;
    Style detail_style = make_style(palette, palette.text_dim, palette.panel);
    wrapped(finding.detail, detail_style, 0);
    ++row;

    if (!finding.evidence.empty()) {
        line("EVIDENCE", make_style(palette, palette.accent, palette.panel));
        Style evidence = make_style(palette, palette.text, palette.panel_alt);
        int evidence_row = row;
        const std::vector<std::string> parts = wrap_text("\u201C" + finding.evidence + "\u201D",
                                                         inner_width - 4);
        const int box_height = static_cast<int>(parts.size()) + 2;
        if (evidence_row + box_height < y + height) {
            screen.fill(x + 2, evidence_row, inner_width, box_height, palette.panel_alt);
            for (int i = 0; i < box_height; ++i)
                screen.put(x + 2, evidence_row + i, "\u258F",
                           make_style(palette, palette.accent, palette.panel_alt));
            int r = evidence_row + 1;
            for (const std::string& part : parts) {
                screen.text(x + 4, r++, inner_width - 4, part, evidence);
            }
            row = evidence_row + box_height + 1;
        } else {
            wrapped("\u201C" + finding.evidence + "\u201D", evidence, 2);
        }
    }

    if (finding.has_location) {
        char box[96];
        std::snprintf(box, sizeof(box), "box %.0f,%.0f \u2192 %.0f,%.0f", finding.location.x0,
                      finding.location.y0, finding.location.x1, finding.location.y1);
        line(box, make_style(palette, palette.text_faint, palette.panel));
    }
    line(finding.id, make_style(palette, palette.text_faint, palette.panel));
}

void draw_footer(App& app, Screen& screen) {
    const Palette& palette = app.palette();
    const int width = screen.width();
    const int height = screen.height();
    screen.fill(0, height - 2, width, 2, palette.panel);
    Style rule = make_style(palette, palette.border, palette.panel);
    screen.hline(0, height - 2, width, "\u2500", rule);

    const std::vector<std::pair<std::string, std::string>> keys = {
        {"\u2191\u2193", "move"}, {"\u2190\u2192", "category"}, {"enter", "expand"},
        {"p", "actions"}, {"/", "filter"}, {"t", "theme"}, {"?", "help"}, {"q", "quit"},
    };
    int x = 2;
    for (const auto& [key, label] : keys) {
        if (x + 12 >= width) break;
        Style key_style = make_style(palette, palette.text, palette.panel_alt);
        key_style.bold = true;
        screen.text_padded(x, height - 1, static_cast<int>(display_width(key)) + 2,
                           " " + key + " ", key_style);
        x += static_cast<int>(display_width(key)) + 3;
        Style label_style = make_style(palette, palette.text_dim, palette.panel);
        screen.text(x, height - 1, 12, label, label_style);
        x += static_cast<int>(display_width(label)) + 2;
    }

    if (app.toast_visible()) {
        const int text_width = std::min(width - 6, static_cast<int>(display_width(app.toast)) + 4);
        const int box_x = width - text_width - 2;
        Style toast_style = make_style(palette, palette.background, palette.accent);
        toast_style.bold = true;
        screen.text_padded(box_x, height - 1, text_width, " " + truncate_text(app.toast, text_width - 2) + " ",
                           toast_style);
    } else if (app.busy) {
        screen.text(width - 12, height - 1, 10, "working\u2026", make_style(palette, palette.accent, palette.panel));
    }
}

void draw_help(App& app, Screen& screen) {
    const Palette& palette = app.palette();
    // A help screen is read, not glanced at. Clear the dashboard instead of
    // leaving half-covered panels around the card: it makes the two-column
    // reference the only thing on screen.
    screen.clear(palette.background);
    const int width = std::min(94, screen.width() - 4);
    const int height = std::min(16, screen.height() - 4);
    const int x = (screen.width() - width) / 2;
    const int y = (screen.height() - height) / 2;
    screen.shadow(x, y, width, height);
    Style panel_style = make_style(palette, palette.border_strong, palette.panel);
    screen.panel(x, y, width, height, "KEYBOARD", panel_style);

    const std::vector<std::pair<std::string, std::string>> bindings = {
        {"\u2191 / k", "previous finding"},
        {"\u2193 / j", "next finding"},
        {"\u2190 / \u2192", "change category"},
        {"home / end", "first / last finding"},
        {"pgup / pgdn", "page through findings"},
        {"tab", "next category with hits"},
        {"enter", "expand the finding"},
        {"p  /  ctrl-p", "command palette"},
        {"/", "filter findings"},
        {"esc", "close panel / clear filter"},
        {"t", "toggle midnight / paper"},
        {"m", "toggle monochrome"},
        {"s", "scrub hidden data"},
        {"e", "export the JSON report"},
        {"r", "re-inspect the file"},
        {"?", "this help"},
        {"q  /  ctrl-c", "quit"},
    };
    // Two columns need room for a 14-cell key column plus a readable label. On
    // a narrow terminal the same list becomes one scrollable column, so no
    // binding and no label is ever cut in half to make the layout fit.
    const bool two_columns = width >= 86;
    const int columns = two_columns ? 2 : 1;
    const int column_width = (width - 6) / columns;
    constexpr int kKeyWidth = 14;
    const int visible = std::max(1, height - 4);
    const int per_column =
        two_columns ? (static_cast<int>(bindings.size()) + 1) / 2
                    : static_cast<int>(bindings.size());
    const int max_scroll = std::max(0, per_column - visible);
    app.help_scroll = std::clamp(app.help_scroll, 0, max_scroll);

    for (int line_index = app.help_scroll; line_index < per_column; ++line_index) {
        const int row = y + 2 + (line_index - app.help_scroll);
        if (row > y + height - 3) break;
        Style key_style = make_style(palette, palette.accent, palette.panel);
        key_style.bold = true;
        const int label_width = column_width - kKeyWidth - 2;
        for (int col = 0; col < columns; ++col) {
            const std::size_t index = static_cast<std::size_t>(line_index + col * per_column);
            if (index >= bindings.size()) continue;
            const int column = x + 3 + col * column_width;
            screen.text(column, row, kKeyWidth, bindings[index].first, key_style);
            screen.text(column + kKeyWidth + 1, row, label_width,
                        truncate_text(bindings[index].second, label_width),
                        make_style(palette, palette.text_dim, palette.panel));
        }
    }

    std::string footer_text =
        "esc closes  \u00B7  scour " + std::string(kVersion) + "  \u00B7  no network";
    if (width >= 86) {
        footer_text = "esc closes this panel  \u00B7  scour " + std::string(kVersion) +
                      " never opens a network connection";
    }
    if (max_scroll > 0) {
        footer_text = "\u2191\u2193 " + std::to_string(app.help_scroll + 1) + "/" +
                      std::to_string(max_scroll + 1) + "  \u00B7  " + footer_text;
    }
    screen.text(x + 3, y + height - 2, width - 6, footer_text,
                make_style(palette, palette.text_faint, palette.panel));
}

void draw_palette(App& app, Screen& screen) {
    const Palette& palette = app.palette();
    const std::vector<const PaletteAction*> actions = filtered_actions(app);
    const int width = std::min(64, screen.width() - 8);
    const int height = std::min(18, screen.height() - 4);
    const int x = (screen.width() - width) / 2;
    const int y = (screen.height() - height) / 2;
    screen.shadow(x, y, width, height);
    Style panel_style = make_style(palette, palette.border_strong, palette.panel);
    screen.panel(x, y, width, height, "ACTIONS", panel_style);

    Style input = make_style(palette, palette.text, palette.panel_alt);
    screen.text_padded(x + 2, y + 2, width - 4, "> " + app.palette_query + "\u2588", input);

    app.palette_index = actions.empty()
                            ? 0
                            : std::clamp(app.palette_index, 0, static_cast<int>(actions.size()) - 1);
    if (actions.empty()) {
        screen.text(x + 4, y + 4, width - 8, "No action matches that query.",
                    make_style(palette, palette.text_dim, palette.panel));
        screen.text(x + 4, y + 5, width - 8, "Backspace to widen the search, esc to close.",
                    make_style(palette, palette.text_faint, palette.panel));
    }
    int row = y + 4;
    for (std::size_t index = 0; index < actions.size(); ++index) {
        if (row >= y + height - 2) break;
        const bool active = static_cast<int>(index) == app.palette_index;
        const Rgb bg = active ? palette.selection : palette.panel;
        Style style = make_style(palette, active ? palette.selection_text : palette.text, bg);
        screen.text_padded(x + 2, row, width - 4, "", style);
        if (active) screen.put(x + 2, row, "\u258C", make_style(palette, palette.accent, bg));
        screen.text(x + 4, row, width - 24, actions[index]->label, style);
        const std::string hint = truncate_text(actions[index]->hint, 18);
        screen.text(x + width - 2 - static_cast<int>(display_width(hint)), row, 18, hint,
                    make_style(palette, active ? palette.selection_text : palette.text_faint, bg));
        ++row;
    }
    screen.text(x + 3, y + height - 2, width - 6,
                "\u2191\u2193 select \u00B7 enter run \u00B7 esc close",
                make_style(palette, palette.text_faint, palette.panel));
}

void draw_prompt(App& app, Screen& screen) {
    const Palette& palette = app.palette();
    const int width = std::min(66, screen.width() - 8);
    const int height = 7;
    const int x = (screen.width() - width) / 2;
    const int y = (screen.height() - height) / 2;
    screen.shadow(x, y, width, height);
    Style panel_style = make_style(palette, palette.border_strong, palette.panel);
    screen.panel(x, y, width, height, app.prompt_kind == PromptKind::Filter ? "FILTER" : "REDACT TERM",
                 panel_style);
    screen.text(x + 2, y + 2, width - 4, app.prompt_label,
                make_style(palette, palette.text_dim, palette.panel));
    Style input = make_style(palette, palette.text, palette.panel_alt);
    screen.text_padded(x + 2, y + 3, width - 4, " " + app.prompt_text + "\u2588", input);
    screen.text(x + 2, y + 5, width - 4,
                "enter confirm \u00B7 esc cancel",
                make_style(palette, palette.text_faint, palette.panel));
}

struct DetailLine {
    std::string text;
    Style style;
    int indent = 0;
};

void draw_detail_overlay(App& app, Screen& screen, const std::vector<const Finding*>& findings) {
    const Palette& palette = app.palette();
    const int width = std::min(90, screen.width() - 4);
    const int height = std::min(30, screen.height() - 3);
    const int x = (screen.width() - width) / 2;
    const int y = (screen.height() - height) / 2;
    screen.shadow(x, y, width, height);
    Style panel_style = make_style(palette, palette.border_strong, palette.panel);
    screen.panel(x, y, width, height, "FINDING", panel_style);
    if (findings.empty()) return;
    const Finding& finding = *findings[static_cast<std::size_t>(app.selected)];

    // The whole body scrolls as one block. A long finding is exactly the case
    // where the last lines matter, so the panel never drops content silently.
    std::vector<DetailLine> lines;
    const auto add = [&](std::string text, const Style& style, int indent) {
        lines.push_back(DetailLine{std::move(text), style, indent});
    };
    Style title_style = make_style(palette, palette.text, palette.panel);
    title_style.bold = true;
    for (const std::string& line : wrap_text(finding.title, width - 6)) add(line, title_style, 2);
    add("", title_style, 0);
    for (const std::string& line : wrap_text(finding.detail, width - 6))
        add(line, make_style(palette, palette.text_dim, palette.panel), 2);
    if (!finding.evidence.empty()) {
        add("", title_style, 0);
        add("EVIDENCE", make_style(palette, palette.accent, palette.panel), 2);
        for (const std::string& line : wrap_text(finding.evidence, width - 8))
            add(line, make_style(palette, palette.text, palette.panel_alt), 3);
    }
    if (finding.page > 0) {
        add("", title_style, 0);
        add("PAGE " + std::to_string(finding.page) + "  \u00B7  " + category_label(finding.category),
            make_style(palette, palette.text_faint, palette.panel), 2);
    }

    const int chip_row = y + 2;
    const int first_row = chip_row + 2;
    const int last_row = y + height - 3;
    const int visible = std::max(1, last_row - first_row + 1);
    const int max_scroll = std::max(0, static_cast<int>(lines.size()) - visible);
    app.detail_scroll = std::clamp(app.detail_scroll, 0, max_scroll);

    draw_chip(screen, x + 2, chip_row, severity_name(finding.severity),
              severity_color(palette, finding.severity), palette.panel);
    screen.text(x + 12, chip_row, width - 14, category_label(finding.category),
                make_style(palette, palette.text_faint, palette.panel));
    int row = first_row;
    for (int index = app.detail_scroll;
         index < static_cast<int>(lines.size()) && row <= last_row; ++index) {
        const DetailLine& line = lines[static_cast<std::size_t>(index)];
        if (!line.text.empty()) {
            screen.text(x + 1 + line.indent, row, width - line.indent - 3, line.text, line.style);
        }
        ++row;
    }

    std::string hint = "esc closes";
    if (max_scroll > 0) {
        hint = "\u2191\u2193 scroll  " + std::to_string(app.detail_scroll + 1) + "/" +
               std::to_string(max_scroll + 1) + "  \u00B7  " + hint;
    }
    screen.text(x + 2, y + height - 2, width - 4, hint,
                make_style(palette, palette.text_faint, palette.panel));
}

void draw_error(App& app, Screen& screen) {
    const Palette& palette = app.palette();
    screen.clear(palette.background);
    const int width = std::min(78, screen.width() - 6);
    const int height = 10;
    const int x = (screen.width() - width) / 2;
    const int y = (screen.height() - height) / 2;
    Style panel_style = make_style(palette, palette.border_strong, palette.panel);
    screen.panel(x, y, width, height, "CANNOT OPEN", panel_style);
    screen.text(x + 3, y + 2, width - 6, app.options.path,
                make_style(palette, palette.text, palette.panel));
    int row = y + 4;
    for (const std::string& line : wrap_text(app.load_error, width - 6)) {
        screen.text(x + 3, row++, width - 6, line, make_style(palette, palette.danger, palette.panel));
    }
    screen.text(x + 3, y + height - 2, width - 6, "q or enter quits",
                make_style(palette, palette.text_faint, palette.panel));
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// Below this the sidebar, list and detail columns cannot be drawn side by side
/// without collapsing into each other. Saying so is better than printing a
/// mangled frame the user has to decode, and a resize recovers immediately.
constexpr int kMinWidth = 64;
constexpr int kMinHeight = 18;

void draw_too_small(const App& app, Screen& screen) {
    const Palette& palette = app.palette();
    const int width = std::max(20, screen.width() - 4);
    const int height = std::clamp(screen.height() - 2, 7, 10);
    const int x = std::max(1, (screen.width() - width) / 2);
    const int y = std::max(1, (screen.height() - height) / 2);
    Style panel_style = make_style(palette, palette.border_strong, palette.panel);
    screen.panel(x, y, width, height, "WINDOW TOO SMALL", panel_style);

    const int inner = std::max(4, width - 6);
    int row = y + 2;
    const auto line = [&](const std::string& text, const Style& style) {
        for (const std::string& part : wrap_text(text, inner)) {
            if (row >= y + height - 3) return;
            screen.text(x + 3, row++, inner, part, style);
        }
    };
    line("Needs " + std::to_string(kMinWidth) + "\u00D7" + std::to_string(kMinHeight) +
             " cells. This terminal is " + std::to_string(screen.width()) + "\u00D7" +
             std::to_string(screen.height()) + ".",
         make_style(palette, palette.text, palette.panel));
    line("Resize the window, or press q.",
         make_style(palette, palette.text_dim, palette.panel));
    screen.text(x + 3, y + height - 2, inner, "scour inspect FILE for details",
                make_style(palette, palette.text_faint, palette.panel));
}

Screen render(App& app, int width, int height) {
    Screen screen(width, height);
    if (!app.load_error.empty()) {
        draw_error(app, screen);
        return screen;
    }
    const Palette& palette = app.palette();
    screen.clear(palette.background);
    if (width < kMinWidth || height < kMinHeight) {
        draw_too_small(app, screen);
        return screen;
    }
    draw_header(app, screen);

    std::vector<const Finding*> findings;
    visible_findings(app, findings);
    clamp_selection(app, findings.size());

    const int content_y = 3;
    const int content_height = std::max(6, height - 5);
    const int sidebar_width = std::clamp(width / 4, 26, 30);
    const int gap = 1;
    const bool show_detail = width >= 104;
    const int detail_width = show_detail ? std::clamp(width / 3, 38, 52) : 0;
    const int list_width = width - sidebar_width - gap - (show_detail ? detail_width + gap : 0);
    const int list_x = sidebar_width + gap;

    draw_sidebar(app, screen, 0, content_y, sidebar_width, content_height, findings.size());
    draw_list(app, screen, list_x, content_y, list_width, content_height, findings);
    if (show_detail)
        draw_detail(app, screen, list_x + list_width + gap, content_y, detail_width,
                    content_height, findings);
    draw_footer(app, screen);

    if (app.overlay != Overlay::None) screen.dim(0.24);
    if (app.overlay == Overlay::Help) draw_help(app, screen);
    else if (app.overlay == Overlay::Palette) draw_palette(app, screen);
    else if (app.overlay == Overlay::Prompt) draw_prompt(app, screen);
    else if (app.overlay == Overlay::Detail) draw_detail_overlay(app, screen, findings);
    return screen;
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------
void move_category(App& app, int delta) {
    app.category = std::clamp(app.category + delta, 0,
                              static_cast<int>(app.categories.size()) - 1);
    app.selected = 0;
    app.scroll = 0;
}

void handle_key(App& app, const std::string& key) {
    if (!app.load_error.empty()) {
        if (key == "q" || key == "enter" || key == "ctrl-c" || key == "escape") app.quit = true;
        return;
    }

    if (app.overlay == Overlay::Prompt) {
        if (key == "escape") {
            app.overlay = Overlay::None;
        } else if (key == "enter") {
            if (app.prompt_kind == PromptKind::Filter) {
                app.filter = app.prompt_text;
                for (std::size_t i = 0; i < app.categories.size(); ++i) {
                    if (app.categories[i].count > 0) {
                        app.category = static_cast<int>(i);
                        break;
                    }
                }
                app.selected = 0;
                app.scroll = 0;
                app.overlay = Overlay::None;
            } else {
                const std::string term = app.prompt_text;
                app.overlay = Overlay::None;
                if (!term.empty()) perform_scrub(app, term, false);
            }
        } else if (key == "backspace") {
            if (!app.prompt_text.empty()) app.prompt_text.pop_back();
        } else if (key.size() == 1 && static_cast<unsigned char>(key[0]) >= 0x20 &&
                   static_cast<unsigned char>(key[0]) < 0x7F) {
            app.prompt_text += key;
        }
        return;
    }

    if (app.overlay == Overlay::Palette) {
        const std::vector<const PaletteAction*> actions = filtered_actions(app);
        if (key == "escape") {
            app.overlay = Overlay::None;
        } else if (key == "up" || key == "k") {
            app.palette_index = std::max(0, app.palette_index - 1);
        } else if (key == "down" || key == "j") {
            app.palette_index = std::min(std::max(0, static_cast<int>(actions.size()) - 1),
                                         app.palette_index + 1);
        } else if (key == "enter") {
            if (!actions.empty()) {
                const std::string action = actions[static_cast<std::size_t>(app.palette_index)]->key;
                app.overlay = Overlay::None;
                run_action(app, action);
            }
        } else if (key == "backspace") {
            if (!app.palette_query.empty()) app.palette_query.pop_back();
            app.palette_index = 0;
        } else if (key.size() == 1 && static_cast<unsigned char>(key[0]) >= 0x20) {
            app.palette_query += key;
            app.palette_index = 0;
        }
        return;
    }

    if (app.overlay == Overlay::Help) {
        if (key == "escape" || key == "?" || key == "enter" || key == "q") {
            app.overlay = Overlay::None;
        } else if (key == "down" || key == "j") {
            ++app.help_scroll;  // clamped by the render pass
        } else if (key == "up" || key == "k") {
            app.help_scroll = std::max(0, app.help_scroll - 1);
        } else if (key == "pagedown") {
            app.help_scroll += 10;
        } else if (key == "pageup") {
            app.help_scroll = std::max(0, app.help_scroll - 10);
        } else if (key == "home") {
            app.help_scroll = 0;
        } else if (key == "end") {
            app.help_scroll = 1 << 20;
        }
        return;
    }
    if (app.overlay == Overlay::Detail) {
        if (key == "escape" || key == "?" || key == "enter" || key == "q") {
            app.overlay = Overlay::None;
        } else if (key == "down" || key == "j") {
            ++app.detail_scroll;  // clamped by the render pass
        } else if (key == "up" || key == "k") {
            app.detail_scroll = std::max(0, app.detail_scroll - 1);
        } else if (key == "pagedown") {
            app.detail_scroll += 10;
        } else if (key == "pageup") {
            app.detail_scroll = std::max(0, app.detail_scroll - 10);
        } else if (key == "home") {
            app.detail_scroll = 0;
        } else if (key == "end") {
            app.detail_scroll = 1 << 20;
        }
        return;
    }

    if (key == "q" || key == "ctrl-c") {
        app.quit = true;
        return;
    }
    if (key == "?" || key == "h") {
        app.help_scroll = 0;
        app.overlay = Overlay::Help;
        return;
    }
    if (key == "p" || key == "ctrl-p" || key == ":") {
        app.overlay = Overlay::Palette;
        app.palette_query.clear();
        app.palette_index = 0;
        return;
    }
    if (key == "/") {
        start_prompt(app, PromptKind::Filter, "Show findings containing", app.filter);
        return;
    }
    if (key == "escape") {
        if (!app.filter.empty()) {
            app.filter.clear();
            app.selected = 0;
        } else {
            app.overlay = Overlay::None;
        }
        return;
    }
    if (key == "t") {
        app.light = !app.light;
        app.notify(app.light ? "paper theme" : "midnight theme");
        return;
    }
    if (key == "m") {
        app.mono = !app.mono;
        app.notify(app.mono ? "monochrome on" : "colour on");
        return;
    }
    if (key == "s") {
        perform_scrub(app, "", false);
        return;
    }
    if (key == "e") {
        write_json_report(app);
        return;
    }
    if (key == "r") {
        reload(app, app.source_path);
        app.notify("re-inspected");
        return;
    }

    std::vector<const Finding*> findings;
    visible_findings(app, findings);
    const int count = static_cast<int>(findings.size());
    if (key == "up" || key == "k") app.selected = std::max(0, app.selected - 1);
    else if (key == "down" || key == "j") app.selected = std::min(std::max(0, count - 1), app.selected + 1);
    else if (key == "left" || key == "shift-tab") move_category(app, -1);
    else if (key == "right") move_category(app, 1);
    else if (key == "tab") {
        int next = app.category;
        for (std::size_t step = 0; step < app.categories.size(); ++step) {
            next = (next + 1) % static_cast<int>(app.categories.size());
            if (app.categories[static_cast<std::size_t>(next)].count > 0 || next == 0) break;
        }
        move_category(app, next - app.category);
    } else if (key == "home" || key == "g") {
        app.selected = 0;
    } else if (key == "end" || key == "G") {
        app.selected = std::max(0, count - 1);
    } else if (key == "pageup") {
        app.selected = std::max(0, app.selected - 8);
    } else if (key == "pagedown") {
        app.selected = std::min(std::max(0, count - 1), app.selected + 8);
    } else if (key == "enter") {
        if (!findings.empty()) {
            app.detail_scroll = 0;
            app.overlay = Overlay::Detail;
        }
    }
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------
void load_document(App& app) {
    Diagnostics diagnostics;
    LoadOptions options;
    options.password = app.options.password;
    try {
        std::ifstream stream(app.options.path, std::ios::binary);
        if (!stream) throw ScourError("io.open", "no such file");
        stream.seekg(0, std::ios::end);
        const std::streamoff size = stream.tellg();
        if (size < 0) throw ScourError("io.read", "cannot measure the file");
        stream.seekg(0, std::ios::beg);
        Bytes bytes(static_cast<std::size_t>(size));
        if (size > 0) stream.read(reinterpret_cast<char*>(bytes.data()), size);
        app.document =
            std::make_unique<Document>(Document::load(bytes, options, diagnostics));
        if (app.document->encrypted() && !app.document->security().valid()) {
            throw ScourError("pdf.encrypted",
                             options.password.empty()
                                 ? "this document is encrypted; reopen it with -p PASSWORD"
                                 : "this document is encrypted and the password did not open it");
        }
        app.source_path = app.options.path;
        InspectOptions inspect_options;
        app.report = inspect_document(*app.document, app.options.path, inspect_options, diagnostics);
        rebuild_categories(app);
    } catch (const ScourError& error) {
        app.load_error = error.what();
    }
}

void apply_keys(App& app, const std::string& keys) {
    for (const char c : keys) {
        std::string key(1, c);
        if (c == '\n') key = "enter";
        else if (c == '\t') key = "tab";
        else if (c == '\x1b') key = "escape";
        handle_key(app, key);
        if (app.quit) break;
    }
}

}  // namespace

int run(const TuiOptions& options) {
    App app;
    app.options = options;
    app.light = options.theme == "paper" || options.theme == "light";
    app.mono = options.mono;
    load_document(app);

    if (options.dump) {
        app.options.keys = options.keys;
        apply_keys(app, options.keys);
        const Screen screen = render(app, options.dump_width, options.dump_height);
        std::string output = options.ansi ? screen.to_ansi(app.mono) : screen.to_plain();
        if (output.empty() || output.back() != '\n') output.push_back('\n');
        std::fwrite(output.data(), 1, output.size(), stdout);
        return app.load_error.empty() ? 0 : 3;
    }

    if (!app.load_error.empty()) {
        // There is nothing useful to browse, but the error still deserves the
        // same treatment as any other screen.
        set_raw_mode(false);
        Screen screen(Terminal::query_width(), std::min(14, Terminal::query_height()));
        const Screen frame = render(app, screen.width(), screen.height());
        const std::string rendered = frame.to_ansi(app.mono);
        std::fwrite(rendered.data(), 1, rendered.size(), stdout);
        std::fwrite("\n", 1, 1, stdout);
        return 3;
    }

    Terminal terminal;
    if (!terminal.enter()) {
        std::fprintf(stderr, "scour: tui needs a terminal (try `scour inspect` or `--dump`)\n");
        return 2;
    }
    std::signal(SIGWINCH, on_winch);
    int width = Terminal::query_width();
    int height = Terminal::query_height();
    int exit_code = 0;

    while (!app.quit) {
        if (g_resized != 0) {
            g_resized = 0;
            width = Terminal::query_width();
            height = Terminal::query_height();
        }
        Screen screen = render(app, width, height);
        terminal.present(screen, app.mono);
        std::string key;
        const bool got = read_key_timeout(key, 250);
        if (got) handle_key(app, key);
    }

    if (!app.load_error.empty()) exit_code = 3;
    terminal.leave();
    return exit_code;
}

}  // namespace scour::tui

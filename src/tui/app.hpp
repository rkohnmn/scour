// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_TUI_APP_HPP
#define SCOUR_TUI_APP_HPP

#include <string>

namespace scour::tui {

struct TuiOptions {
    std::string path;
    std::string password;
    std::string theme = "midnight";
    /// Replay these keystrokes, render one frame and exit. Used by the snapshot
    /// generator and by the end-to-end tests.
    std::string keys;
    bool dump = false;
    bool ansi = false;
    /// Draw without colour. Set by --no-color or NO_COLOR; toggled at runtime
    /// with `m`.
    bool mono = false;
    int dump_width = 108;
    int dump_height = 34;
};

/// Runs the dashboard. Returns 0 on success, 1 if the document could not be
/// opened, 2 on usage problems.
int run(const TuiOptions& options);

}  // namespace scour::tui

#endif  // SCOUR_TUI_APP_HPP

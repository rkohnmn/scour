// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/error.hpp"

namespace scour {

std::string_view to_string(Severity s) noexcept {
    switch (s) {
        case Severity::Debug: return "debug";
        case Severity::Info: return "info";
        case Severity::Warning: return "warning";
        case Severity::Error: return "error";
    }
    return "unknown";
}

std::size_t Diagnostics::count(Severity s) const noexcept {
    std::size_t n = 0;
    for (const auto& d : items_) {
        if (d.severity == s) ++n;
    }
    return n;
}

void throw_parse(std::string code, std::string_view what, std::size_t offset) {
    std::string message(what);
    message += " (at byte ";
    message += std::to_string(offset);
    message += ')';
    throw ParseError(std::move(code), std::move(message), offset);
}

}  // namespace scour

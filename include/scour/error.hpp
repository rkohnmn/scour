// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_ERROR_HPP
#define SCOUR_ERROR_HPP

#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace scour {

/// Severity of a non-fatal problem encountered while reading or writing a file.
enum class Severity { Debug, Info, Warning, Error };

[[nodiscard]] std::string_view to_string(Severity s) noexcept;

/// A recoverable problem. Scour never silently ignores a defect: everything the
/// parser or the writer had to paper over ends up in the diagnostic list, and
/// `scour inspect` surfaces it.
struct Diagnostic {
    Severity severity = Severity::Warning;
    std::string code;     ///< stable machine-readable code, e.g. "pdf.xref.rebuilt"
    std::string message;  ///< human readable detail
    int page = -1;        ///< 1-based page number when known, else -1

    Diagnostic() = default;
    Diagnostic(Severity sev, std::string c, std::string msg, int p = -1)
        : severity(sev), code(std::move(c)), message(std::move(msg)), page(p) {}
};

/// Ordered collection of diagnostics with a few aggregate helpers.
class Diagnostics {
public:
    void add(Severity severity, std::string code, std::string message, int page = -1) {
        items_.emplace_back(severity, std::move(code), std::move(message), page);
    }
    void debug(std::string code, std::string message, int page = -1) {
        add(Severity::Debug, std::move(code), std::move(message), page);
    }
    void info(std::string code, std::string message, int page = -1) {
        add(Severity::Info, std::move(code), std::move(message), page);
    }
    void warn(std::string code, std::string message, int page = -1) {
        add(Severity::Warning, std::move(code), std::move(message), page);
    }
    void error(std::string code, std::string message, int page = -1) {
        add(Severity::Error, std::move(code), std::move(message), page);
    }

    [[nodiscard]] const std::vector<Diagnostic>& items() const noexcept { return items_; }
    [[nodiscard]] bool empty() const noexcept { return items_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return items_.size(); }
    [[nodiscard]] std::size_t count(Severity s) const noexcept;
    [[nodiscard]] bool has_errors() const noexcept { return count(Severity::Error) != 0; }
    [[nodiscard]] bool has_warnings() const noexcept { return count(Severity::Warning) != 0; }
    void clear() noexcept { items_.clear(); }
    void append(const Diagnostics& other) {
        items_.insert(items_.end(), other.items_.begin(), other.items().end());
    }

private:
    std::vector<Diagnostic> items_;
};

/// Fatal, unrecoverable failure. `code` is stable and safe to branch on.
class ScourError : public std::runtime_error {
public:
    ScourError(std::string code, std::string message)
        : std::runtime_error(message), code_(std::move(code)) {}

    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

/// Thrown by the object parser when a token stream is not valid PDF.
class ParseError : public ScourError {
public:
    ParseError(std::string code, std::string message, std::size_t offset)
        : ScourError(std::move(code), std::move(message)), offset_(offset) {}

    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

private:
    std::size_t offset_;
};

/// Builds a ParseError with a consistent "at byte N" suffix.
[[noreturn]] void throw_parse(std::string code, std::string_view what, std::size_t offset);

}  // namespace scour

#endif  // SCOUR_ERROR_HPP

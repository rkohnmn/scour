// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_PARSER_HPP
#define SCOUR_PARSER_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "scour/bytes.hpp"
#include "scour/error.hpp"
#include "scour/lexer.hpp"
#include "scour/object.hpp"

namespace scour {

/// Recursive-descent parser for PDF objects and indirect objects.
///
/// It is deliberately forgiving in the places where real files are broken
/// (missing `endstream`, wrong /Length, stray delimiters) and strict where a
/// wrong guess would corrupt data (string escapes, dictionary structure).
class Parser {
public:
    Parser(std::string_view source, std::size_t position = 0,
           const ObjectSource* resolver = nullptr);

    /// Parses one object. Throws ParseError on malformed input.
    Object parse_object(int depth = 0);

    /// Parses `N G obj ... endobj`. Returns false at a clean end of input.
    bool parse_indirect(std::uint32_t& number, std::uint16_t& generation, Object& value);

    /// Parses a bare dictionary starting at the next `<<`.
    Dict parse_dict(int depth = 0);

    [[nodiscard]] std::size_t position() const noexcept { return lexer_.position(); }
    void seek(std::size_t position) noexcept { lexer_.seek(position); }
    [[nodiscard]] std::string_view source() const noexcept { return lexer_.source(); }
    [[nodiscard]] bool at_end() noexcept { return lexer_.at_end(); }

    /// Reads a stream body given an already-parsed stream dictionary. `position`
    /// must point just after the `stream` keyword.
    Object parse_stream_body(Object dictionary);

private:
    Object parse_from_token(const Token& token, int depth);

    Lexer lexer_;
    const ObjectSource* resolver_ = nullptr;
};

/// Parses an object from a standalone buffer (content streams, object streams).
Object parse_object_string(std::string_view data, std::size_t& consumed);

}  // namespace scour

#endif  // SCOUR_PARSER_HPP

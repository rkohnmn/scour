// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_LEXER_HPP
#define SCOUR_LEXER_HPP

#include <cstdint>
#include <string>
#include <string_view>

#include "scour/bytes.hpp"

namespace scour {

enum class TokenKind : std::uint8_t {
    Eof,
    Number,
    String,      // (literal) with escapes resolved
    HexString,   // <48656c6c6f>
    Name,        // /Name with #xx escapes resolved
    ArrayOpen,
    ArrayClose,
    DictOpen,
    DictClose,
    BraceOpen,
    BraceClose,
    Word,        // keywords and content stream operators
};

struct Token {
    TokenKind kind = TokenKind::Eof;
    std::size_t begin = 0;
    std::size_t end = 0;
    bool is_integer = false;
    std::int64_t integer = 0;
    double number = 0.0;
    std::string text;  ///< decoded bytes for strings, name without slash, word bytes
};

/// Tokenizer for PDF syntax. Shared by the object parser and the content stream
/// reader, which is why it never assumes top-level grammar: it just returns
/// tokens and lets the caller decide what they mean.
class Lexer {
public:
    Lexer(std::string_view source, std::size_t position = 0);

    Token next();

    [[nodiscard]] std::size_t position() const noexcept { return position_; }
    void seek(std::size_t position) noexcept { position_ = position; }
    [[nodiscard]] std::string_view source() const noexcept { return source_; }
    [[nodiscard]] bool at_end() const noexcept { return position_ >= source_.size(); }

private:
    void skip_space_and_comments() noexcept;

    std::string_view source_;
    std::size_t position_ = 0;
};

[[nodiscard]] bool is_pdf_whitespace(char c) noexcept;
[[nodiscard]] bool is_pdf_delimiter(char c) noexcept;

}  // namespace scour

#endif  // SCOUR_LEXER_HPP

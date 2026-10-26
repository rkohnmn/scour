// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/lexer.hpp"

#include <cstdlib>
#include <limits>

namespace scour {

bool is_pdf_whitespace(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\0';
}

bool is_pdf_delimiter(char c) noexcept {
    switch (c) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '[':
        case ']':
        case '{':
        case '}':
        case '/':
        case '%':
            return true;
        default:
            return false;
    }
}

namespace {

bool is_regular(char c) noexcept { return !is_pdf_whitespace(c) && !is_pdf_delimiter(c); }

int hex_value(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

Lexer::Lexer(std::string_view source, std::size_t position)
    : source_(source), position_(position) {}

void Lexer::skip_space_and_comments() noexcept {
    while (position_ < source_.size()) {
        const char c = source_[position_];
        if (is_pdf_whitespace(c)) {
            ++position_;
        } else if (c == '%') {
            while (position_ < source_.size() && source_[position_] != '\r' &&
                   source_[position_] != '\n')
                ++position_;
        } else {
            break;
        }
    }
}

Token Lexer::next() {
    Token token;
    skip_space_and_comments();
    if (position_ >= source_.size()) {
        token.kind = TokenKind::Eof;
        token.begin = token.end = position_;
        return token;
    }

    token.begin = position_;
    const char c = source_[position_];

    switch (c) {
        case '[':
            ++position_;
            token.kind = TokenKind::ArrayOpen;
            token.end = position_;
            return token;
        case ']':
            ++position_;
            token.kind = TokenKind::ArrayClose;
            token.end = position_;
            return token;
        case '{':
            ++position_;
            token.kind = TokenKind::BraceOpen;
            token.end = position_;
            return token;
        case '}':
            ++position_;
            token.kind = TokenKind::BraceClose;
            token.end = position_;
            return token;
        case '<':
            if (position_ + 1 < source_.size() && source_[position_ + 1] == '<') {
                position_ += 2;
                token.kind = TokenKind::DictOpen;
                token.end = position_;
                return token;
            }
            ++position_;
            {
                std::string bytes;
                int high = -1;
                while (position_ < source_.size() && source_[position_] != '>') {
                    const int value = hex_value(source_[position_]);
                    ++position_;
                    if (value < 0) continue;  // whitespace and junk are ignored
                    if (high < 0) {
                        high = value;
                    } else {
                        bytes.push_back(static_cast<char>((high << 4) | value));
                        high = -1;
                    }
                }
                if (high >= 0) bytes.push_back(static_cast<char>(high << 4));
                if (position_ < source_.size()) ++position_;  // consume '>'
                token.kind = TokenKind::HexString;
                token.text = std::move(bytes);
            }
            token.end = position_;
            return token;
        case '>':
            ++position_;
            if (position_ < source_.size() && source_[position_] == '>') {
                ++position_;
                token.kind = TokenKind::DictClose;
            } else {
                // A lone '>' is invalid, but refusing to parse a whole document
                // over it would be worse: report it as an empty word.
                token.kind = TokenKind::Word;
                token.text = ">";
            }
            token.end = position_;
            return token;
        case '(': {
            ++position_;
            std::string text;
            int depth = 1;
            while (position_ < source_.size() && depth > 0) {
                char ch = source_[position_++];
                if (ch == '\\') {
                    if (position_ >= source_.size()) break;
                    const char escaped = source_[position_++];
                    switch (escaped) {
                        case 'n': text.push_back('\n'); break;
                        case 'r': text.push_back('\r'); break;
                        case 't': text.push_back('\t'); break;
                        case 'b': text.push_back('\b'); break;
                        case 'f': text.push_back('\f'); break;
                        case '(': text.push_back('('); break;
                        case ')': text.push_back(')'); break;
                        case '\\': text.push_back('\\'); break;
                        case '\r':
                            if (position_ < source_.size() && source_[position_] == '\n')
                                ++position_;
                            break;
                        case '\n': break;
                        default:
                            if (escaped >= '0' && escaped <= '7') {
                                int value = escaped - '0';
                                for (int i = 0; i < 2 && position_ < source_.size(); ++i) {
                                    const char digit = source_[position_];
                                    if (digit < '0' || digit > '7') break;
                                    value = value * 8 + (digit - '0');
                                    ++position_;
                                }
                                text.push_back(static_cast<char>(value & 0xFF));
                            } else {
                                text.push_back(escaped);
                            }
                            break;
                    }
                    continue;
                }
                if (ch == '(') {
                    ++depth;
                    text.push_back(ch);
                } else if (ch == ')') {
                    --depth;
                    if (depth > 0) text.push_back(ch);
                } else if (ch == '\r') {
                    // An end-of-line inside a literal string is a single LF.
                    if (position_ < source_.size() && source_[position_] == '\n') ++position_;
                    text.push_back('\n');
                } else {
                    text.push_back(ch);
                }
            }
            token.kind = TokenKind::String;
            token.text = std::move(text);
            token.end = position_;
            return token;
        }
        case ')':
            // Unbalanced ')' at top level: skip it rather than fail the file.
            ++position_;
            token.end = position_;
            return next();
        case '/': {
            ++position_;
            std::string name;
            while (position_ < source_.size() && is_regular(source_[position_])) {
                const char ch = source_[position_];
                if (ch == '#' && position_ + 2 < source_.size()) {
                    const int hi = hex_value(source_[position_ + 1]);
                    const int lo = hex_value(source_[position_ + 2]);
                    if (hi >= 0 && lo >= 0) {
                        name.push_back(static_cast<char>((hi << 4) | lo));
                        position_ += 3;
                        continue;
                    }
                }
                name.push_back(ch);
                ++position_;
            }
            token.kind = TokenKind::Name;
            token.text = std::move(name);
            token.end = position_;
            return token;
        }
        default:
            break;
    }

    if (c == '+' || c == '-' || c == '.' || (c >= '0' && c <= '9')) {
        std::size_t p = position_;
        bool negative = false;
        if (source_[p] == '+' || source_[p] == '-') {
            negative = source_[p] == '-';
            ++p;
        }
        std::int64_t integer = 0;
        double fraction = 0.0;
        double scale = 0.1;
        bool any_digit = false;
        bool is_real = false;
        while (p < source_.size() && source_[p] >= '0' && source_[p] <= '9') {
            // Saturate instead of wrapping: a hostile file can spell a thousand
            // digits, and a wrapped value would silently become a plausible
            // offset or object number. Everything downstream range-checks, so a
            // clamped maximum is rejected where a wrapped value might be used.
            const std::int64_t digit = source_[p] - '0';
            if (integer > (std::numeric_limits<std::int64_t>::max() - digit) / 10) {
                integer = std::numeric_limits<std::int64_t>::max();
            } else {
                integer = integer * 10 + digit;
            }
            any_digit = true;
            ++p;
        }
        if (p < source_.size() && source_[p] == '.') {
            is_real = true;
            ++p;
            while (p < source_.size() && source_[p] >= '0' && source_[p] <= '9') {
                fraction += static_cast<double>(source_[p] - '0') * scale;
                scale *= 0.1;
                any_digit = true;
                ++p;
            }
            // A second '.' means the producer wrote a broken number like 1.2.3;
            // the trailing part is ignored, matching what viewers do.
        }
        if (any_digit) {
            token.kind = TokenKind::Number;
            token.is_integer = !is_real;
            const std::int64_t magnitude = integer;
            token.integer = negative ? -magnitude : magnitude;
            const double value = static_cast<double>(magnitude) + fraction;
            token.number = negative ? -value : value;
            position_ = p;
            token.end = position_;
            return token;
        }
        // Not a number after all (a stray '+' or '-'): fall through to a word.
        position_ = token.begin;
    }

    {
        std::string word;
        while (position_ < source_.size() && is_regular(source_[position_])) {
            word.push_back(source_[position_]);
            ++position_;
        }
        if (word.empty()) {
            // A delimiter we do not model; consume it to guarantee progress.
            ++position_;
            token.kind = TokenKind::Word;
        } else {
            token.kind = TokenKind::Word;
            token.text = std::move(word);
        }
        token.end = position_;
        return token;
    }
}

}  // namespace scour

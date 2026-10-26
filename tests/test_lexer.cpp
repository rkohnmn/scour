// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <limits>

#include "scour/lexer.hpp"

using namespace scour;

namespace {

std::vector<Token> tokenize(std::string_view source) {
    Lexer lexer(source);
    std::vector<Token> tokens;
    for (;;) {
        Token token = lexer.next();
        if (token.kind == TokenKind::Eof) break;
        tokens.push_back(std::move(token));
    }
    return tokens;
}

}  // namespace

SCOUR_TEST(lexer, basic_tokens) {
    const auto tokens = tokenize("1 0 R /Type /Page [ ] << >> 1.5 -2");
    CHECK_EQ(tokens.size(), std::size_t{11});
    CHECK(tokens[0].kind == TokenKind::Number && tokens[0].is_integer);
    CHECK_EQ(tokens[2].text, std::string("R"));
    CHECK(tokens[3].kind == TokenKind::Name);
    CHECK_EQ(tokens[3].text, std::string("Type"));
    CHECK(tokens[5].kind == TokenKind::ArrayOpen);
    CHECK(tokens[7].kind == TokenKind::DictOpen);
    CHECK(tokens[9].kind == TokenKind::Number);
    CHECK_EQ(tokens[9].number, 1.5);
    CHECK_EQ(tokens[10].integer, std::int64_t{-2});
}

SCOUR_TEST(lexer, names_decode_hash_escapes) {
    const auto tokens = tokenize("/A#23B /Simple /With#20Space");
    CHECK_EQ(tokens.size(), std::size_t{3});
    CHECK_EQ(tokens[0].text, std::string("A#B"));
    CHECK_EQ(tokens[1].text, std::string("Simple"));
    CHECK_EQ(tokens[2].text, std::string("With Space"));
}

SCOUR_TEST(lexer, literal_strings) {
    const auto tokens = tokenize("(plain) (a\\(b\\)c) (nested (parens) here) (esc\\n\\101\\t)");
    CHECK_EQ(tokens.size(), std::size_t{4});
    CHECK_EQ(tokens[0].text, std::string("plain"));
    CHECK_EQ(tokens[1].text, std::string("a(b)c"));
    CHECK_EQ(tokens[2].text, std::string("nested (parens) here"));
    CHECK_EQ(tokens[3].text, std::string("esc\nA\t"));
}

SCOUR_TEST(lexer, string_line_continuation) {
    const auto tokens = tokenize("(line\\\ncontinued) (crlf\\\r\njoin)");
    CHECK_EQ(tokens[0].text, std::string("linecontinued"));
    CHECK_EQ(tokens[1].text, std::string("crlfjoin"));
}

SCOUR_TEST(lexer, hex_strings) {
    const auto tokens = tokenize("<48656C6C6F> <4 8 6 5> <41424>");
    CHECK_EQ(tokens[0].text, std::string("Hello"));
    CHECK_EQ(tokens[1].text, std::string("He"));
    CHECK_EQ(tokens[2].text, std::string("AB@"));
}

SCOUR_TEST(lexer, comments_and_whitespace) {
    const auto tokens = tokenize("% leading comment\n12 % trailing\n%\r\n34");
    CHECK_EQ(tokens.size(), std::size_t{2});
    CHECK_EQ(tokens[0].integer, std::int64_t{12});
    CHECK_EQ(tokens[1].integer, std::int64_t{34});
}

SCOUR_TEST(lexer, content_stream_operators) {
    const auto tokens = tokenize("BT /F1 12 Tf 72 720 Td (Hi) Tj ET");
    CHECK_EQ(tokens.size(), std::size_t{10});
    CHECK_EQ(tokens[0].text, std::string("BT"));
    CHECK_EQ(tokens[6].text, std::string("Td"));
    CHECK_EQ(tokens[7].text, std::string("Hi"));
    CHECK_EQ(tokens[8].text, std::string("Tj"));
    CHECK_EQ(tokens[9].text, std::string("ET"));
}

SCOUR_TEST(lexer, stray_delimiters_do_not_stall) {
    const auto tokens = tokenize(") ] 5");
    CHECK_EQ(tokens.size(), std::size_t{2});
    CHECK_EQ(tokens[0].kind, TokenKind::ArrayClose);
    CHECK_EQ(tokens[1].integer, std::int64_t{5});
}

// Found by the mutation fuzzer: a number long enough to overflow int64 wrapped
// around, which could turn a hostile /Length or offset into a plausible-looking
// value. The lexer saturates instead, and every consumer range-checks.
SCOUR_TEST(lexer, absurd_integers_saturate) {
    const std::string digits(4000, '9');
    const auto tokens = tokenize(digits + " -" + digits);
    CHECK_EQ(tokens.size(), std::size_t{2});
    CHECK_EQ(tokens[0].integer, std::numeric_limits<std::int64_t>::max());
    CHECK_EQ(tokens[1].integer, -std::numeric_limits<std::int64_t>::max());
    CHECK(tokens[0].number > 1e18);
    CHECK(tokens[1].number < -1e18);

    // A saturated value must not become a small one through truncation further
    // along the chain either: 200 digits is well past any real offset.
    const auto just_over = tokenize("92233720368547758079223372036854775807");
    CHECK_EQ(just_over.size(), std::size_t{1});
    CHECK_EQ(just_over[0].integer, std::numeric_limits<std::int64_t>::max());
}

SCOUR_TEST(lexer, positions_are_byte_offsets) {
    Lexer lexer("   /Name 42");
    const Token name = lexer.next();
    CHECK_EQ(name.begin, std::size_t{3});
    CHECK_EQ(name.end, std::size_t{8});
    lexer.seek(0);
    CHECK_EQ(lexer.next().kind, TokenKind::Name);
}

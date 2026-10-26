// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include "scour/bytes.hpp"

using namespace scour;

SCOUR_TEST(bytes, split_and_join) {
    const auto parts = split("a,b,,c", ',');
    CHECK_EQ(parts.size(), std::size_t{4});
    CHECK_EQ(parts[0], std::string("a"));
    CHECK_EQ(parts[2], std::string(""));
    CHECK_EQ(join(parts, "|"), std::string("a|b||c"));

    const auto words = split_whitespace("  alpha\tbeta\n gamma ");
    CHECK_EQ(words.size(), std::size_t{3});
    CHECK_EQ(words[2], std::string("gamma"));
}

SCOUR_TEST(bytes, hex_roundtrip) {
    const std::string raw("\x00\x01\x7f\x80\xff", 5);
    const std::string hex = to_hex(raw);
    CHECK_EQ(hex, std::string("00017f80ff"));
    const Bytes decoded = from_hex(hex);
    CHECK_EQ(view_of(decoded), std::string_view(raw));
    CHECK_EQ(from_hex("abc").size(), std::size_t{2});
}

SCOUR_TEST(bytes, format_bytes_uses_si_units) {
    CHECK_EQ(format_bytes(512), std::string("512 B"));
    CHECK_EQ(format_bytes(1000), std::string("1.0 KB"));
    CHECK_EQ(format_bytes(1234567), std::string("1.2 MB"));
    CHECK_EQ(format_bytes(0), std::string("0 B"));
}

SCOUR_TEST(bytes, whitespace_collapse) {
    CHECK_EQ(collapse_whitespace("  hello \n\t world  "), std::string("hello world"));
    CHECK_EQ(collapse_whitespace(""), std::string(""));
}

SCOUR_TEST(bytes, utf8_roundtrip_and_width) {
    std::string text;
    append_utf8(text, U'H');
    append_utf8(text, U'\u00e9');
    append_utf8(text, U'\u251c');
    append_utf8(text, U'\U0001F600');
    CHECK_EQ(text.size(), std::size_t{1 + 2 + 3 + 4});
    CHECK_EQ(encode_utf8(decode_utf8(text)), text);
    CHECK_EQ(display_width("abc"), 3);
    CHECK_EQ(display_width("\u251c\u2500\u2500"), 3);
    CHECK_EQ(display_width("\U0001F600"), 2);
}

SCOUR_TEST(bytes, truncate_cells_adds_ellipsis) {
    CHECK_EQ(truncate_cells("abcdef", 4), std::string("abc\u2026"));
    CHECK_EQ(truncate_cells("abc", 3), std::string("abc"));
    CHECK_EQ(truncate_cells("abcdef", 0), std::string(""));
    CHECK_EQ(display_width(truncate_cells("abcdefghij", 5)), 5);
}

SCOUR_TEST(bytes, invalid_utf8_is_replaced) {
    const std::u32string decoded = decode_utf8(std::string("\xff\xfe", 2));
    CHECK_EQ(decoded.size(), std::size_t{2});
    CHECK_EQ(decoded[0], char32_t{0xFFFD});
}

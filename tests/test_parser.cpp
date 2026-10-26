// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include "scour/parser.hpp"

using namespace scour;

SCOUR_TEST(parser, dictionary_with_references) {
    const std::string source = "<< /Type /Page /Count 3 /Kids [1 0 R 2 0 R] /Flag true /Empty null >>";
    Parser parser(source);
    const Object value = parser.parse_object();
    CHECK(value.is_dict());
    CHECK_EQ(value.dict().get_name("Type"), std::string("Page"));
    CHECK_EQ(value.dict().get_int("Count"), std::int64_t{3});
    CHECK(value.dict().get_bool("Flag"));
    CHECK(value.find("Empty")->is_null());
    const Object* kids = value.find("Kids");
    CHECK(kids != nullptr && kids->is_array());
    CHECK_EQ(kids->items().size(), std::size_t{2});
    CHECK_EQ(kids->items()[1].ref_number(), std::uint32_t{2});
}

SCOUR_TEST(parser, bare_integer_is_not_a_reference) {
    Parser parser("42");
    const Object value = parser.parse_object();
    CHECK(value.is_int());
    CHECK_EQ(value.as_int(), std::int64_t{42});
}

SCOUR_TEST(parser, negative_and_real_numbers) {
    Parser parser("-12 0.5 1.25e");
    CHECK_EQ(parser.parse_object().as_int(), std::int64_t{-12});
    CHECK_EQ(parser.parse_object().as_real(), 0.5);
    CHECK_EQ(parser.parse_object().as_real(), 1.25);
}

SCOUR_TEST(parser, empty_containers) {
    Parser parser("[] << >>");
    CHECK(parser.parse_object().items().empty());
    CHECK(parser.parse_object().dict().empty());
}

SCOUR_TEST(parser, indirect_stream_uses_length) {
    const std::string source = "7 0 obj\n<< /Length 5 >>\nstream\nhello\nendstream\nendobj";
    Parser parser(source);
    std::uint32_t number = 0;
    std::uint16_t generation = 0;
    Object value;
    CHECK(parser.parse_indirect(number, generation, value));
    CHECK_EQ(number, std::uint32_t{7});
    CHECK(value.is_stream());
    CHECK_EQ(view_of(value.stream_data()), std::string_view("hello"));
}

SCOUR_TEST(parser, indirect_stream_recovers_from_wrong_length) {
    const std::string source =
        "7 0 obj\n<< /Length 500 >>\nstream\nshort body\nendstream\nendobj\n8 0 obj\n1\nendobj";
    Parser parser(source);
    std::uint32_t number = 0;
    std::uint16_t generation = 0;
    Object value;
    CHECK(parser.parse_indirect(number, generation, value));
    CHECK(value.is_stream());
    CHECK_EQ(view_of(value.stream_data()), std::string_view("short body"));

    Object next;
    CHECK(parser.parse_indirect(number, generation, next));
    CHECK_EQ(number, std::uint32_t{8});
    CHECK_EQ(next.as_int(), std::int64_t{1});
}

SCOUR_TEST(parser, indirect_stream_without_trailing_eol) {
    const std::string source = "1 0 obj\n<< /Length 3 >>\nstream\nabcendstream\nendobj";
    Parser parser(source);
    std::uint32_t number = 0;
    std::uint16_t generation = 0;
    Object value;
    CHECK(parser.parse_indirect(number, generation, value));
    CHECK_EQ(view_of(value.stream_data()), std::string_view("abc"));
}

SCOUR_TEST(parser, stream_with_crlf_after_keyword) {
    const std::string source = "1 0 obj\r\n<< /Length 3 >>\r\nstream\r\nabc\r\nendstream\r\nendobj\r\n";
    Parser parser(source);
    std::uint32_t number = 0;
    std::uint16_t generation = 0;
    Object value;
    CHECK(parser.parse_indirect(number, generation, value));
    CHECK_EQ(view_of(value.stream_data()), std::string_view("abc"));
}

SCOUR_TEST(parser, rejects_broken_syntax) {
    {
        Parser parser("<< /Type /Page");
        CHECK_THROWS(parser.parse_object(), "pdf.syntax");
    }
    {
        Parser parser("[1 2 3");
        CHECK_THROWS(parser.parse_object(), "pdf.syntax");
    }
    {
        Parser parser("notakeyword");
        CHECK_THROWS(parser.parse_object(), "pdf.syntax");
    }
}

SCOUR_TEST(parser, dictionary_tolerates_junk_keys) {
    Parser parser("<< 5 (orphan) /Type /Page >>");
    const Object value = parser.parse_object();
    CHECK(value.is_dict());
    CHECK_EQ(value.dict().get_name("Type"), std::string("Page"));
}

SCOUR_TEST(parser, deep_nesting_is_rejected) {
    std::string source;
    for (int i = 0; i < 200; ++i) source.push_back('[');
    Parser parser(source);
    CHECK_THROWS(parser.parse_object(), "too-deep");
}

SCOUR_TEST(parser, parse_object_string_reports_consumed_bytes) {
    const std::string source = "1 0 R trailing garbage";
    std::size_t consumed = 0;
    const Object value = parse_object_string(source, consumed);
    CHECK(value.is_ref());
    CHECK_LT(consumed, source.size());
}

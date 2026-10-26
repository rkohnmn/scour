// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/parser.hpp"

#include <algorithm>
#include <cstring>

namespace scour {

namespace {

constexpr int kMaxDepth = 96;

/// Finds "endstream" at or after `from`, ignoring matches inside string or
/// stream garbage is not attempted: a wrong short read is recovered by the
/// caller re-reading with the scanned length.
std::size_t find_endstream(std::string_view source, std::size_t from) {
    static constexpr std::string_view kMarker = "endstream";
    const std::size_t found = source.find(kMarker, from);
    return found;
}

}  // namespace

Parser::Parser(std::string_view source, std::size_t position, const ObjectSource* resolver)
    : lexer_(source, position), resolver_(resolver) {}

Object Parser::parse_object(int depth) {
    if (depth > kMaxDepth) throw_parse("pdf.syntax.too-deep", "object nesting is too deep", position());
    Token token = lexer_.next();
    return parse_from_token(token, depth);
}

Dict Parser::parse_dict(int depth) {
    Token open = lexer_.next();
    if (open.kind != TokenKind::DictOpen) {
        lexer_.seek(open.begin);
        throw_parse("pdf.syntax.expected-dict", "expected '<<'", open.begin);
    }
    Dict dict;
    for (;;) {
        Token key = lexer_.next();
        if (key.kind == TokenKind::DictClose) break;
        if (key.kind == TokenKind::Eof)
            throw_parse("pdf.syntax.unterminated-dict", "unterminated dictionary", key.begin);
        if (key.kind != TokenKind::Name) {
            // Best effort: if the value is a number or array we cannot recover the
            // key, so skip it rather than reject the file.
            Object skipped = parse_from_token(key, depth + 1);
            (void)skipped;
            continue;
        }
        Object value = parse_object(depth + 1);
        dict.set(key.text, std::move(value));
    }
    return dict;
}

Object Parser::parse_from_token(const Token& token, int depth) {
    if (depth > kMaxDepth) {
        throw_parse("pdf.syntax.too-deep", "object nesting is too deep", token.begin);
    }
    switch (token.kind) {
        case TokenKind::Number: {
            if (token.is_integer) {
                const std::size_t after_first = lexer_.position();
                Token second = lexer_.next();
                if (second.kind == TokenKind::Number && second.is_integer) {
                    const std::size_t after_second = lexer_.position();
                    Token third = lexer_.next();
                    if (third.kind == TokenKind::Word && third.text == "R") {
                        if (token.integer >= 0 && second.integer >= 0) {
                            return Object::reference(static_cast<std::uint32_t>(token.integer),
                                                     static_cast<std::uint16_t>(second.integer));
                        }
                    }
                    lexer_.seek(after_second);
                }
                lexer_.seek(after_first);
                return Object::integer(token.integer);
            }
            return Object::real(token.number);
        }
        case TokenKind::String:
        case TokenKind::HexString:
            return Object::string(token.text);
        case TokenKind::Name:
            return Object::name(token.text);
        case TokenKind::ArrayOpen: {
            std::vector<Object> items;
            for (;;) {
                Token item = lexer_.next();
                if (item.kind == TokenKind::ArrayClose) break;
                if (item.kind == TokenKind::Eof)
                    throw_parse("pdf.syntax.unterminated-array", "unterminated array", item.begin);
                items.push_back(parse_from_token(item, depth + 1));
            }
            return Object::array(std::move(items));
        }
        case TokenKind::DictOpen: {
            Dict dict;
            for (;;) {
                Token key = lexer_.next();
                if (key.kind == TokenKind::DictClose) break;
                if (key.kind == TokenKind::Eof)
                    throw_parse("pdf.syntax.unterminated-dict", "unterminated dictionary", key.begin);
                if (key.kind != TokenKind::Name) {
                    Object skipped = parse_from_token(key, depth + 1);
                    (void)skipped;
                    continue;
                }
                dict.set(key.text, parse_object(depth + 1));
            }
            return Object::dictionary(std::move(dict));
        }
        case TokenKind::Word:
            if (token.text == "true") return Object::boolean(true);
            if (token.text == "false") return Object::boolean(false);
            if (token.text == "null") return Object::null();
            throw_parse("pdf.syntax.unexpected-keyword",
                        "unexpected keyword '" + token.text + "'", token.begin);
        case TokenKind::BraceOpen:
        case TokenKind::BraceClose:
            // PostScript calculator function bodies are not valid objects.
            throw_parse("pdf.syntax.unexpected-brace", "unexpected brace", token.begin);
        case TokenKind::Eof:
            throw_parse("pdf.syntax.unexpected-eof", "unexpected end of file", token.begin);
        case TokenKind::ArrayClose:
        case TokenKind::DictClose:
            throw_parse("pdf.syntax.unexpected-close", "unexpected closing delimiter", token.begin);
    }
    throw_parse("pdf.syntax.unexpected-token", "unexpected token", token.begin);
}

Object Parser::parse_stream_body(Object dictionary) {
    // Position is just past the `stream` keyword. The spec allows CRLF or LF;
    // a lone CR appears in the wild and is accepted too.
    std::size_t start = lexer_.position();
    const std::string_view source = lexer_.source();
    if (start < source.size() && source[start] == '\r') {
        ++start;
        if (start < source.size() && source[start] == '\n') ++start;
    } else if (start < source.size() && source[start] == '\n') {
        ++start;
    }

    std::int64_t declared_length = -1;
    if (const Object* length = dictionary.find("Length"); length != nullptr) {
        if (length->is_int()) {
            declared_length = length->as_int();
        } else if (length->is_ref() && resolver_ != nullptr) {
            const Object* resolved = resolver_->resolve_ref(length->ref_number());
            if (resolved != nullptr && resolved->is_int()) declared_length = resolved->as_int();
        }
    }

    std::size_t data_end = std::string_view::npos;
    std::size_t after_marker = std::string_view::npos;
    auto accept_length = [&](std::int64_t length) -> bool {
        if (length < 0) return false;
        const auto end = start + static_cast<std::size_t>(length);
        if (end > source.size()) return false;
        std::size_t probe = end;
        while (probe < source.size() && (source[probe] == '\r' || source[probe] == '\n')) ++probe;
        if (source.compare(probe, 9, "endstream") != 0) return false;
        data_end = end;
        after_marker = probe + 9;
        return true;
    };

    if (!accept_length(declared_length)) {
        // Wrong or indirect-unavailable /Length: scan for the marker and trim
        // the end-of-line that precedes it.
        const std::size_t marker = find_endstream(source, start);
        if (marker == std::string_view::npos) {
            data_end = source.size();
            after_marker = source.size();
        } else {
            data_end = marker;
            if (data_end > start && source[data_end - 1] == '\n') {
                --data_end;
                if (data_end > start && source[data_end - 1] == '\r') --data_end;
            } else if (data_end > start && source[data_end - 1] == '\r') {
                --data_end;
            }
            after_marker = marker + 9;
        }
    }

    Bytes encoded = bytes_of(source.substr(start, data_end - start));
    lexer_.seek(after_marker);
    return Object::stream(std::move(dictionary.dict()), std::move(encoded));
}

bool Parser::parse_indirect(std::uint32_t& number, std::uint16_t& generation, Object& value) {
    Token first = lexer_.next();
    if (first.kind == TokenKind::Eof) return false;
    if (first.kind != TokenKind::Number || !first.is_integer || first.integer < 0) {
        throw_parse("pdf.syntax.bad-object-header", "expected an object number", first.begin);
    }
    Token second = lexer_.next();
    if (second.kind != TokenKind::Number || !second.is_integer) {
        throw_parse("pdf.syntax.bad-object-header", "expected an object generation", second.begin);
    }
    Token keyword = lexer_.next();
    if (keyword.kind != TokenKind::Word || keyword.text != "obj") {
        throw_parse("pdf.syntax.bad-object-header", "expected 'obj'", keyword.begin);
    }

    number = static_cast<std::uint32_t>(first.integer);
    generation = static_cast<std::uint16_t>(std::max<std::int64_t>(0, second.integer));
    value = parse_object();

    const std::size_t before_probe = lexer_.position();
    Token probe = lexer_.next();
    if (probe.kind == TokenKind::Word && probe.text == "stream") {
        value = parse_stream_body(std::move(value));
        const std::size_t after_stream = lexer_.position();
        Token trailing = lexer_.next();
        if (!(trailing.kind == TokenKind::Word && trailing.text == "endobj")) {
            lexer_.seek(after_stream);
        }
        return true;
    }
    if (probe.kind == TokenKind::Word && probe.text == "endobj") return true;
    lexer_.seek(before_probe);
    return true;
}

Object parse_object_string(std::string_view data, std::size_t& consumed) {
    Parser parser(data, 0, nullptr);
    Object value = parser.parse_object();
    consumed = parser.position();
    return value;
}

}  // namespace scour

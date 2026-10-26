// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/document.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>

#include "scour/parser.hpp"

namespace scour {

namespace {

std::uint64_t read_be(const Bytes& data, std::size_t& position, int width) {
    std::uint64_t value = 0;
    for (int i = 0; i < width; ++i) {
        value = (value << 8) | data[position];
        ++position;
    }
    return value;
}

}  // namespace

Document::Document() = default;

std::string Document::version_string() const {
    return std::to_string(version_major_) + "." + std::to_string(version_minor_);
}

void Document::read_header(Diagnostics& diagnostics) {
    const std::string_view source = view_of(file_);
    const std::size_t limit = std::min<std::size_t>(source.size(), 4096);
    const std::size_t found = source.substr(0, limit).find("%PDF-");
    if (found == std::string_view::npos) {
        diagnostics.warn("pdf.header.missing", "the file does not start with a %PDF- header");
        return;
    }
    version_major_ = 1;
    version_minor_ = 7;
    if (found + 6 < source.size() && source[found + 5] >= '0' && source[found + 5] <= '9') {
        version_major_ = source[found + 5] - '0';
        if (found + 6 < source.size() && source[found + 6] == '.' && found + 7 < source.size() &&
            source[found + 7] >= '0' && source[found + 7] <= '9') {
            version_minor_ = source[found + 7] - '0';
        }
    }
}

std::uint64_t Document::find_startxref() const {
    const std::string_view source = view_of(file_);
    std::size_t position = source.rfind("startxref");
    if (position == std::string_view::npos) return 0;
    position += 9;
    while (position < source.size() && is_pdf_whitespace(source[position])) ++position;
    std::uint64_t value = 0;
    bool any = false;
    while (position < source.size() && source[position] >= '0' && source[position] <= '9') {
        value = value * 10 + static_cast<std::uint64_t>(source[position] - '0');
        ++position;
        any = true;
        if (value > (std::uint64_t{1} << 48)) return 0;
    }
    return any ? value : 0;
}

bool Document::read_xref_section(std::uint64_t offset, Dict& trailer,
                                 std::unordered_map<std::uint32_t, XrefEntry>& entries,
                                 Diagnostics& diagnostics) const {
    const std::string_view source = view_of(file_);
    if (offset == 0 || offset >= source.size()) return false;

    Lexer lexer(source, static_cast<std::size_t>(offset));
    Token head = lexer.next();
    if (head.kind == TokenKind::Word && head.text == "xref") {
        for (;;) {
            Token token = lexer.next();
            if (token.kind == TokenKind::Eof) return false;
            if (token.kind == TokenKind::Word && token.text == "trailer") break;
            if (token.kind != TokenKind::Number || !token.is_integer) return false;
            const std::int64_t first = token.integer;
            Token count_token = lexer.next();
            if (count_token.kind != TokenKind::Number || !count_token.is_integer) return false;
            const std::int64_t count = count_token.integer;
            if (count < 0 || count > 10'000'000 || first < 0) return false;
            for (std::int64_t i = 0; i < count; ++i) {
                Token offset_token = lexer.next();
                Token generation_token = lexer.next();
                Token kind_token = lexer.next();
                if (offset_token.kind != TokenKind::Number || generation_token.kind != TokenKind::Number ||
                    kind_token.kind != TokenKind::Word)
                    return false;
                const auto number = static_cast<std::uint32_t>(first + i);
                if (entries.count(number) != 0) continue;
                XrefEntry entry;
                entry.generation = static_cast<std::uint16_t>(
                    std::max<std::int64_t>(0, generation_token.integer));
                if (kind_token.text == "n") {
                    entry.kind = XrefEntry::Kind::InUse;
                    entry.offset = static_cast<std::uint64_t>(std::max<std::int64_t>(0, offset_token.integer));
                } else {
                    entry.kind = XrefEntry::Kind::Free;
                }
                entries.emplace(number, entry);
            }
        }

        Parser parser(source, lexer.position(), this);
        try {
            Object value = parser.parse_object();
            if (!value.is_dict()) return false;
            trailer = value.dict();
        } catch (const ScourError&) {
            return false;
        }
        return true;
    }

    // Cross-reference stream.
    Parser parser(source, static_cast<std::size_t>(offset), this);
    std::uint32_t number = 0;
    std::uint16_t generation = 0;
    Object value;
    try {
        if (!parser.parse_indirect(number, generation, value)) return false;
    } catch (const ScourError&) {
        return false;
    }
    if (!value.is_stream() || value.dict().get_name("Type") != "XRef") return false;

    const Object* widths_object = value.dict().find("W");
    if (widths_object == nullptr || !widths_object->is_array() ||
        widths_object->items().size() < 3)
        return false;
    int widths[3] = {0, 0, 0};
    int total_width = 0;
    for (int i = 0; i < 3; ++i) {
        widths[i] = static_cast<int>(widths_object->items()[static_cast<std::size_t>(i)].as_int(0));
        if (widths[i] < 0 || widths[i] > 8) return false;
        total_width += widths[i];
    }
    if (total_width == 0) return false;

    const Bytes data = decode_stream(value, -1);
    if (data.empty()) return false;

    std::vector<std::pair<std::int64_t, std::int64_t>> ranges;
    if (const Object* index_object = value.dict().find("Index");
        index_object != nullptr && index_object->is_array() &&
        index_object->items().size() % 2 == 0) {
        for (std::size_t i = 0; i + 1 < index_object->items().size(); i += 2)
            ranges.emplace_back(index_object->items()[i].as_int(0),
                                index_object->items()[i + 1].as_int(0));
    } else {
        ranges.emplace_back(0, value.dict().get_int("Size", 0));
    }

    std::size_t position = 0;
    for (const auto& [first, count] : ranges) {
        if (count < 0 || count > 10'000'000 || first < 0) return false;
        for (std::int64_t i = 0; i < count; ++i) {
            if (position + static_cast<std::size_t>(total_width) > data.size()) break;
            std::uint64_t fields[3] = {1, 0, 0};
            for (int field = 0; field < 3; ++field) {
                if (widths[field] == 0) {
                    fields[field] = field == 0 ? 1 : 0;
                } else {
                    fields[field] = read_be(data, position, widths[field]);
                }
            }
            const auto object_number = static_cast<std::uint32_t>(first + i);
            if (entries.count(object_number) != 0) continue;
            XrefEntry entry;
            if (fields[0] == 0) {
                entry.kind = XrefEntry::Kind::Free;
                entry.generation = static_cast<std::uint16_t>(fields[2] & 0xFFFF);
            } else if (fields[0] == 1) {
                entry.kind = XrefEntry::Kind::InUse;
                entry.offset = fields[1];
                entry.generation = static_cast<std::uint16_t>(fields[2] & 0xFFFF);
            } else if (fields[0] == 2) {
                entry.kind = XrefEntry::Kind::Compressed;
                entry.container = static_cast<std::uint32_t>(fields[1]);
                entry.index = static_cast<std::uint32_t>(fields[2]);
            } else {
                continue;
            }
            entries.emplace(object_number, entry);
        }
    }

    trailer = value.dict();
    (void)diagnostics;
    return true;
}

bool Document::read_xref_chain(Diagnostics& diagnostics) {
    std::uint64_t start = find_startxref();
    if (start == 0) {
        diagnostics.warn("pdf.xref.missing", "no startxref pointer was found");
        return false;
    }
    std::unordered_set<std::uint64_t> visited;
    Dict merged;
    bool any = false;
    while (start != 0 && start < file_.size() && visited.size() < 128 && visited.insert(start).second) {
        Dict section_trailer;
        std::unordered_map<std::uint32_t, XrefEntry> entries;
        if (!read_xref_section(start, section_trailer, entries, diagnostics)) break;
        for (auto& [number, entry] : entries) xref_.emplace(number, entry);
        for (auto& [key, value] : section_trailer.items) {
            if (!merged.contains(key)) merged.set(key, value);
        }
        if (const std::int64_t hybrid = section_trailer.get_int("XRefStm", 0); hybrid > 0) {
            Dict hybrid_trailer;
            std::unordered_map<std::uint32_t, XrefEntry> hybrid_entries;
            if (read_xref_section(static_cast<std::uint64_t>(hybrid), hybrid_trailer, hybrid_entries,
                                  diagnostics)) {
                for (auto& [number, entry] : hybrid_entries) xref_.emplace(number, entry);
            }
        }
        ++revision_count_;
        any = true;
        const std::int64_t previous = section_trailer.get_int("Prev", 0);
        start = previous > 0 ? static_cast<std::uint64_t>(previous) : 0;
    }
    if (!any) return false;
    trailer_ = merged;
    if (!trailer_.contains("Root")) {
        diagnostics.warn("pdf.xref.no-root", "the trailer chain has no /Root entry");
        return false;
    }
    return true;
}

void Document::rebuild_from_scan(Diagnostics& diagnostics) {
    if (repaired_) return;
    repaired_ = true;
    xref_.clear();
    cache_.clear();
    loading_.clear();
    trailer_ = Dict{};

    const std::string_view source = view_of(file_);
    Lexer lexer(source);
    Dict trailer_candidate;
    std::size_t parsed = 0;

    while (true) {
        Token token = lexer.next();
        if (token.kind == TokenKind::Eof) break;
        if (token.kind == TokenKind::Word && token.text == "trailer") {
            Parser parser(source, lexer.position(), this);
            try {
                Object value = parser.parse_object();
                if (value.is_dict()) {
                    for (auto& [key, entry] : value.dict().items) trailer_candidate.set(key, entry);
                    lexer.seek(parser.position());
                }
            } catch (const ScourError&) {
            }
            continue;
        }
        if (token.kind != TokenKind::Number || !token.is_integer) continue;
        const std::size_t after_first = lexer.position();
        Token second = lexer.next();
        if (second.kind != TokenKind::Number || !second.is_integer) {
            lexer.seek(after_first);
            continue;
        }
        const std::size_t after_second = lexer.position();
        Token keyword = lexer.next();
        if (!(keyword.kind == TokenKind::Word && keyword.text == "obj")) {
            lexer.seek(after_second);
            continue;
        }

        Parser parser(source, token.begin, this);
        std::uint32_t number = 0;
        std::uint16_t generation = 0;
        Object value;
        try {
            if (parser.parse_indirect(number, generation, value)) {
                // Later definitions win: incremental updates append objects.
                xref_[number] = XrefEntry{XrefEntry::Kind::InUse, token.begin, generation, 0, 0};
                cache_[number] = std::move(value);
                lexer.seek(parser.position());
                ++parsed;
                if (parsed > 2'000'000) {
                    diagnostics.warn("pdf.repair.truncated",
                                     "stopped scanning after two million objects");
                    break;
                }
            }
        } catch (const ScourError&) {
        }
    }

    // Expand object streams, then recover the trailer keys from xref streams.
    std::vector<std::uint32_t> containers;
    for (const auto& [number, entry] : xref_) {
        if (entry.kind != XrefEntry::Kind::InUse) continue;
        const Object* object_value = object(number);
        if (object_value == nullptr) continue;
        if (object_value->is_stream() && object_value->dict().get_name("Type") == "ObjStm")
            containers.push_back(number);
        if (object_value->is_stream() && object_value->dict().get_name("Type") == "XRef") {
            for (const auto& [key, value] : object_value->dict().items)
                if (!trailer_candidate.contains(key)) trailer_candidate.set(key, value);
        }
    }
    for (std::uint32_t container : containers) expand_objstm(container);

    std::uint32_t largest = 0;
    for (const auto& [number, entry] : xref_) largest = std::max(largest, number);

    if (!trailer_candidate.contains("Root")) {
        for (const auto& [number, entry] : xref_) {
            const Object* object_value = object(number);
            if (object_value != nullptr && object_value->is_dict_like() &&
                object_value->dict().get_name("Type") == "Catalog") {
                trailer_candidate.set("Root", Object::reference(number));
                break;
            }
        }
    }
    if (!trailer_candidate.contains("Size"))
        trailer_candidate.set("Size", Object::integer(static_cast<std::int64_t>(largest) + 1));
    trailer_ = trailer_candidate;
    if (!trailer_.contains("Root")) {
        diagnostics.error("pdf.repair.no-catalog", "no document catalog could be recovered");
    } else {
        diagnostics.warn("pdf.xref.rebuilt",
                         "the cross-reference table was missing or damaged and was rebuilt by scanning");
    }
}

void Document::expand_objstm(std::uint32_t container) const {
    if (!objstm_expanded_.insert(container).second) return;
    const Object* stream = object(container);
    if (stream == nullptr || !stream->is_stream()) return;
    Bytes data;
    try {
        data = decode_stream(*stream);
    } catch (const ScourError&) {
        return;
    }
    const std::int64_t count = stream->dict().get_int("N", 0);
    const std::int64_t first = stream->dict().get_int("First", 0);
    if (count <= 0 || first < 0 || static_cast<std::size_t>(first) > data.size()) return;

    const std::string_view all = view_of(data);
    Lexer header(all.substr(0, static_cast<std::size_t>(first)));
    std::vector<std::pair<std::uint32_t, std::int64_t>> pairs;
    pairs.reserve(static_cast<std::size_t>(std::min<std::int64_t>(count, 1000000)));
    for (std::int64_t i = 0; i < count; ++i) {
        Token number = header.next();
        Token offset = header.next();
        if (number.kind != TokenKind::Number || offset.kind != TokenKind::Number) break;
        pairs.emplace_back(static_cast<std::uint32_t>(std::max<std::int64_t>(0, number.integer)),
                           offset.integer);
    }
    for (const auto& [number, offset] : pairs) {
        if (cache_.count(number) != 0) continue;
        const std::size_t start = static_cast<std::size_t>(first) + static_cast<std::size_t>(offset);
        if (start >= all.size()) continue;
        try {
            std::size_t consumed = 0;
            Object value = parse_object_string(all.substr(start), consumed);
            cache_.emplace(number, std::move(value));
        } catch (const ScourError&) {
        }
    }
}

const Object* Document::object(std::uint32_t number) const {
    if (const auto cached = cache_.find(number); cached != cache_.end()) return &cached->second;
    const auto entry_it = xref_.find(number);
    if (entry_it == xref_.end()) return nullptr;
    if (loading_.count(number) != 0) return nullptr;

    const XrefEntry entry = entry_it->second;
    if (entry.kind == XrefEntry::Kind::Compressed) {
        expand_objstm(entry.container);
        const auto loaded = cache_.find(number);
        return loaded == cache_.end() ? nullptr : &loaded->second;
    }
    if (entry.kind != XrefEntry::Kind::InUse || entry.offset >= file_.size()) {
        cache_.emplace(number, Object::null());
        return &cache_.find(number)->second;
    }

    loading_.insert(number);
    Object value;
    bool parsed = false;
    try {
        Parser parser(view_of(file_), static_cast<std::size_t>(entry.offset), this);
        std::uint32_t parsed_number = 0;
        std::uint16_t parsed_generation = 0;
        Object result;
        if (parser.parse_indirect(parsed_number, parsed_generation, result)) {
            if (parsed_number != number) {
                diagnostics_.warn("pdf.object.number-mismatch",
                                  "object " + std::to_string(number) + " at offset " +
                                      std::to_string(entry.offset) + " declares number " +
                                      std::to_string(parsed_number));
            }
            value = std::move(result);
            parsed = true;
        }
    } catch (const ScourError& error) {
        diagnostics_.warn("pdf.object.parse-failed",
                          "object " + std::to_string(number) + " could not be parsed: " + error.what());
    }
    loading_.erase(number);

    if (!parsed) value = Object::null();
    const auto [inserted, added] = cache_.emplace(number, std::move(value));
    (void)added;
    if (parsed && security_.valid()) decrypt_object(inserted->second, number, entry.generation);
    return &inserted->second;
}

Object* Document::mutable_object(std::uint32_t number) {
    const Object* value = object(number);
    if (value == nullptr) return nullptr;
    return &cache_.find(number)->second;
}

void Document::set_object(std::uint32_t number, Object value) {
    cache_[number] = std::move(value);
    if (xref_.find(number) == xref_.end())
        xref_[number] = XrefEntry{XrefEntry::Kind::InUse, 0, 0, 0, 0};
    next_number_ = std::max(next_number_, number + 1);
}

std::uint32_t Document::add_object(Object value) {
    std::uint32_t number = std::max<std::uint32_t>(next_number_, 1);
    while (cache_.count(number) != 0 || xref_.count(number) != 0) ++number;
    set_object(number, std::move(value));
    next_number_ = number + 1;
    return number;
}

bool Document::erase_object(std::uint32_t number) {
    cache_.erase(number);
    return xref_.erase(number) != 0;
}

const Object* Document::catalog() const { return resolve_ref(root_number()); }

Object* Document::mutable_catalog() { return mutable_object(root_number()); }

std::string Document::file_id0() const {
    const Object* id = trailer_.find("ID");
    if (id == nullptr) return {};
    const Object* resolved = resolve(*id);
    if (resolved == nullptr || !resolved->is_array() || resolved->items().empty()) return {};
    const Object* first = resolve(resolved->items()[0]);
    return first != nullptr && first->is_string() ? first->as_string() : std::string();
}

const Object* Document::resolve(const Object& value) const {
    if (!value.is_ref()) return &value;
    return object(value.ref_number());
}

const Object* Document::resolve_ref(std::uint32_t number) const { return object(number); }

DecodeResult Document::decode_stream_info(const Object& stream, int page) const {
    if (!stream.is_stream()) return {};
    const std::vector<FilterSpec> filters = resolve_filters(stream.dict(), *this);
    return decode_stream_data(view_of(stream.stream_data()), filters, diagnostics_, page);
}

Bytes Document::decode_stream(const Object& stream, int page) const {
    return decode_stream_info(stream, page).data;
}

std::string Document::resolve_string(const Object& object) const {
    const Object* value = resolve(object);
    return value != nullptr && value->is_string() ? value->as_string() : std::string();
}

bool Document::is_xref_stream(const Object& object) const {
    return object.is_stream() && object.dict().get_name("Type") == "XRef";
}

void Document::decrypt_object(Object& object, std::uint32_t number,
                             std::uint16_t generation) const {
    if (!security_.valid()) return;
    if (number == encrypt_object_number_) return;

    switch (object.type()) {
        case ObjType::String:
            object = Object::string(security_.decrypt_string(object.as_string(), number, generation));
            break;
        case ObjType::Array:
            for (Object& item : object.items()) decrypt_object(item, number, generation);
            break;
        case ObjType::Dict:
            for (auto& [key, value] : object.dict().items) decrypt_object(value, number, generation);
            break;
        case ObjType::Stream:
            if (!is_xref_stream(object)) {
                object.set_stream_data(security_.decrypt_stream(view_of(object.stream_data()),
                                                               number, generation));
            }
            for (auto& [key, value] : object.dict().items) decrypt_object(value, number, generation);
            break;
        default:
            break;
    }
}

void Document::setup_encryption(const LoadOptions& options, Diagnostics& diagnostics) {
    const Object* encrypt_entry = trailer_.find("Encrypt");
    if (encrypt_entry == nullptr) return;
    encrypted_ = true;

    const Object* encrypt_dict = nullptr;
    if (encrypt_entry->is_ref()) {
        encrypt_object_number_ = encrypt_entry->ref_number();
        encrypt_dict = object(encrypt_object_number_);
    } else {
        encrypt_dict = encrypt_entry;
    }
    if (encrypt_dict == nullptr || !encrypt_dict->is_dict_like()) {
        diagnostics.error("pdf.encrypt.missing", "the trailer references a missing /Encrypt dictionary");
        return;
    }

    security_ = SecurityHandler::create(*encrypt_dict, file_id0(), options.password, diagnostics);
    if (!security_.valid() && !security_.info().failure.empty()) {
        diagnostics.warn("pdf.encrypt.locked",
                         "the document is encrypted and could not be opened: " +
                             security_.info().failure);
    }
}

Document Document::load(Bytes file, const LoadOptions& options, Diagnostics& diagnostics) {
    Document document;
    document.file_ = std::move(file);
    document.read_header(diagnostics);

    bool usable = document.read_xref_chain(diagnostics);
    if (!usable || !document.trailer_.contains("Root")) {
        if (options.repair) document.rebuild_from_scan(diagnostics);
    }
    if (!document.trailer_.contains("Root")) {
        throw ScourError("pdf.load.no-root",
                         "no document catalog was found; this is not a usable PDF");
    }
    document.setup_encryption(options, diagnostics);

    if (document.resolve_ref(document.root_number()) == nullptr && options.repair &&
        !document.repaired_) {
        document.rebuild_from_scan(diagnostics);
        document.setup_encryption(options, diagnostics);
    }
    if (document.resolve_ref(document.root_number()) == nullptr) {
        throw ScourError("pdf.load.broken-catalog",
                         "the document catalog could not be loaded; the file is too damaged");
    }
    return document;
}

std::size_t Document::collect_garbage(const std::vector<std::string>& trailer_keys) {
    std::unordered_set<std::uint32_t> reachable;
    std::vector<std::uint32_t> stack;
    for (const std::string& key : trailer_keys) {
        const Object* value = trailer_.find(key);
        if (value == nullptr) continue;
        if (value->is_ref()) stack.push_back(value->ref_number());
    }

    while (!stack.empty()) {
        const std::uint32_t number = stack.back();
        stack.pop_back();
        if (!reachable.insert(number).second) continue;
        const Object* value = object(number);
        if (value == nullptr) continue;
        std::vector<Object> pending{*value};
        while (!pending.empty()) {
            Object current = std::move(pending.back());
            pending.pop_back();
            if (current.is_ref()) {
                if (reachable.insert(current.ref_number()).second) {
                    const Object* child = object(current.ref_number());
                    if (child != nullptr) pending.push_back(*child);
                }
            } else if (current.is_array()) {
                for (const Object& item : current.items()) pending.push_back(item);
            } else if (current.is_dict_like()) {
                for (const auto& [key, item] : current.dict().items) pending.push_back(item);
            }
        }
    }

    std::size_t removed = 0;
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (reachable.count(it->first) == 0) {
            xref_.erase(it->first);
            it = cache_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    return removed;
}

}  // namespace scour

// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// The writer always produces a *fresh* file: a flat object space, a classic
// cross-reference table, and no incremental update section. That is the whole
// point of a scrubber — an incremental update keeps the bytes you thought you
// deleted, and a reader can still reach them.
#include "scour/writer.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

#include "scour/deflate.hpp"
#include "scour/hash.hpp"

namespace scour {

namespace {

constexpr std::size_t kMaxDepth = 96;

std::size_t non_printable_ratio(std::string_view bytes) {
    if (bytes.empty()) return 0;
    std::size_t count = 0;
    for (const char raw : bytes) {
        const auto c = static_cast<unsigned char>(raw);
        if (c < 32 || c > 126) ++count;
    }
    return (count * 100) / bytes.size();
}

class Serializer {
public:
    Serializer(const std::unordered_map<std::uint32_t, std::uint32_t>& mapping,
               const WriteOptions& options, std::size_t& stream_saved)
        : mapping_(mapping), options_(options), stream_saved_(stream_saved) {}

    std::string object(const Object& value, std::size_t depth) {
        if (depth > kMaxDepth) return "null";
        switch (value.type()) {
            case ObjType::Null: return "null";
            case ObjType::Bool: return value.as_bool() ? "true" : "false";
            case ObjType::Int: return std::to_string(value.as_int());
            case ObjType::Real: return format_pdf_real(value.as_real());
            case ObjType::String: return string(value.as_string());
            case ObjType::Name: return "/" + escape_name(value.as_name());
            case ObjType::Array: {
                std::string out = "[";
                for (std::size_t i = 0; i < value.items().size(); ++i) {
                    if (i != 0) out.push_back(' ');
                    out += object(value.items()[i], depth + 1);
                }
                out.push_back(']');
                return out;
            }
            case ObjType::Ref: {
                const auto found = mapping_.find(value.ref_number());
                if (found == mapping_.end()) return "null";
                return std::to_string(found->second) + " 0 R";
            }
            case ObjType::Dict: return dictionary(value.dict(), depth, nullptr);
            case ObjType::Stream: return stream(value, depth);
        }
        return "null";
    }

private:
    std::string string(const std::string& bytes) {
        if (non_printable_ratio(bytes) > 25) return "<" + to_hex(bytes) + ">";
        return "(" + escape_literal_string(bytes) + ")";
    }

    std::string dictionary(const Dict& dict, std::size_t depth,
                           const std::string* length_value) {
        std::string out = "<<";
        for (const auto& [key, value] : dict.items) {
            if (length_value != nullptr && key == "Length") continue;
            out.push_back('/');
            out += escape_name(key);
            out.push_back(' ');
            out += object(value, depth + 1);
            out.push_back(' ');
        }
        if (length_value != nullptr) {
            out += "/Length ";
            out += *length_value;
        }
        out += ">>";
        return out;
    }

    std::string stream(const Object& value, std::size_t depth) {
        std::string data(reinterpret_cast<const char*>(value.stream_data().data()),
                         value.stream_data().size());
        bool compressed = false;

        const bool has_filter = value.dict().contains("Filter");
        if (options_.compress_streams && !has_filter && data.size() > 128 &&
            value.dict().get_name("Subtype") != "Image") {
            const Bytes candidate = zlib_compress(data);
            if (candidate.size() + 32 < data.size()) {
                stream_saved_ += data.size() - candidate.size();
                data.assign(reinterpret_cast<const char*>(candidate.data()), candidate.size());
                compressed = true;
            }
        }

        Dict dict = value.dict();
        if (compressed) {
            dict.set("Filter", Object::name("FlateDecode"));
            dict.erase("DecodeParms");
        }
        const std::string length = std::to_string(data.size());
        std::string out = dictionary(dict, depth, &length);
        out += "\nstream\n";
        out.append(data);
        out += "\nendstream";
        return out;
    }

    const std::unordered_map<std::uint32_t, std::uint32_t>& mapping_;
    const WriteOptions& options_;
    std::size_t& stream_saved_;
};

/// True when `number` is reachable from `value`'s subgraph (used to decide
/// whether a dangling reference can be dropped silently).
void collect_refs(const Object& value, std::vector<std::uint32_t>& out) {
    std::vector<Object> pending{value};
    std::size_t guard = 0;
    while (!pending.empty() && guard < 4'000'000) {
        Object current = std::move(pending.back());
        pending.pop_back();
        ++guard;
        if (current.is_ref()) {
            out.push_back(current.ref_number());
        } else if (current.is_array()) {
            for (const Object& item : current.items()) pending.push_back(item);
        } else if (current.is_dict_like()) {
            for (const auto& [key, item] : current.dict().items) pending.push_back(item);
        }
    }
}

}  // namespace

std::string format_pdf_real(double value) {
    if (!std::isfinite(value)) return "0";
    char buffer[64];
    const auto result = std::to_chars(buffer, buffer + sizeof(buffer), value);
    std::string text(buffer, result.ptr);
    if (text.find('e') != std::string::npos || text.find('E') != std::string::npos) {
        std::snprintf(buffer, sizeof(buffer), "%.10f", value);
        text = buffer;
    }
    if (text.find('.') != std::string::npos) {
        while (!text.empty() && text.back() == '0') text.pop_back();
        if (!text.empty() && text.back() == '.') text.pop_back();
    }
    if (text == "-0" || text.empty()) text = "0";
    return text;
}

std::string escape_literal_string(std::string_view bytes) {
    std::string out;
    out.reserve(bytes.size() + 8);
    for (const char raw : bytes) {
        const auto c = static_cast<unsigned char>(raw);
        switch (c) {
            case '(': out += "\\("; break;
            case ')': out += "\\)"; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 32 || c > 126) {
                    char buffer[8];
                    std::snprintf(buffer, sizeof(buffer), "\\%03o", c);
                    out += buffer;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

std::string escape_name(std::string_view name) {
    std::string out;
    out.reserve(name.size());
    for (const char raw : name) {
        const auto c = static_cast<unsigned char>(raw);
        const bool needs_escape = c == '(' || c == ')' || c == '<' || c == '>' || c == '[' ||
                                  c == ']' || c == '{' || c == '}' || c == '/' || c == '%' ||
                                  c == '#' || c <= 32 || c > 126;
        if (needs_escape) {
            char buffer[8];
            std::snprintf(buffer, sizeof(buffer), "#%02X", c);
            out += buffer;
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

WriteResult write_document(Document& document, const WriteOptions& options,
                           Diagnostics& diagnostics) {
    WriteResult result;

    // 1. Walk everything reachable from the chosen roots.
    std::unordered_set<std::uint32_t> reachable;
    std::vector<std::uint32_t> pending;
    for (const std::string& key : options.trailer_keys) {
        const Object* value = document.trailer().find(key);
        if (value == nullptr) continue;
        collect_refs(*value, pending);
    }
    while (!pending.empty()) {
        const std::uint32_t number = pending.back();
        pending.pop_back();
        if (!reachable.insert(number).second) continue;
        const Object* value = document.resolve_ref(number);
        if (value == nullptr) {
            diagnostics.warn("pdf.write.dangling-ref",
                             "object " + std::to_string(number) +
                                 " is referenced but missing; the reference becomes null");
            continue;
        }
        collect_refs(*value, pending);
    }

    // 2. Fresh, contiguous object numbers in a deterministic order.
    std::vector<std::uint32_t> ordered;
    ordered.reserve(reachable.size());
    for (std::uint32_t number : reachable) {
        if (document.resolve_ref(number) != nullptr) ordered.push_back(number);
    }
    std::sort(ordered.begin(), ordered.end());
    std::unordered_map<std::uint32_t, std::uint32_t> mapping;
    std::uint32_t next = 1;
    for (std::uint32_t number : ordered) mapping[number] = next++;
    result.objects_written = ordered.size();
    const std::size_t cached = document.cached_object_count();
    result.objects_dropped = cached > ordered.size() ? cached - ordered.size() : 0;

    // 3. Body.
    const int major = options.version_major != 0
                          ? options.version_major
                          : std::clamp(document.version_major(), 1, 2);
    const int minor = options.version_minor != 0
                          ? options.version_minor
                          : (major >= 2 ? 0 : std::max(document.version_minor(), 4));

    Bytes output;
    output.reserve(document.file_size() > 0 ? document.file_size() : 4096);
    append(output, "%PDF-" + std::to_string(major) + "." + std::to_string(minor) + "\n");
    append(output, std::string("%\xE2\xE3\xCF\xD3\n", 6));

    std::vector<std::size_t> offsets(ordered.size() + 1, 0);
    Serializer serializer(mapping, options, result.stream_bytes_saved);
    for (std::uint32_t number : ordered) {
        const Object* value = document.resolve_ref(number);
        if (value == nullptr) continue;
        const std::uint32_t new_number = mapping[number];
        offsets[new_number] = output.size();
        append(output, std::to_string(new_number) + " 0 obj\n");
        append(output, serializer.object(*value, 0));
        append(output, "\nendobj\n");
    }

    // 4. Cross-reference table and trailer.
    const std::size_t xref_offset = output.size();
    const std::size_t size = ordered.size() + 1;
    append(output, "xref\n0 " + std::to_string(size) + "\n");
    append(output, "0000000000 65535 f \n");
    for (std::size_t i = 1; i < size; ++i) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "%010zu 00000 n \n", offsets[i]);
        append(output, buffer);
    }

    std::string id_hex;
    if (options.deterministic_id) {
        const auto digest = sha256(view_of(output));
        id_hex = to_hex(std::string_view(reinterpret_cast<const char*>(digest.data()), 16));
    } else {
        id_hex = to_hex(view_of(random_bytes(16)));
    }
    const std::uint32_t root_number = document.root_number();
    if (mapping.find(root_number) == mapping.end()) {
        throw ScourError("pdf.write.no-root", "the document catalog is not reachable");
    }

    const Bytes id_bytes = from_hex(id_hex);
    const std::string id_string(reinterpret_cast<const char*>(id_bytes.data()), id_bytes.size());

    Dict trailer;
    trailer.set("Size", Object::integer(static_cast<std::int64_t>(size)));
    trailer.set("Root", Object::reference(root_number));
    // Carry the other selected trailer entries (/Info) across. The serializer
    // remaps their references, so this stays consistent with the new numbering.
    for (const std::string& key : options.trailer_keys) {
        if (key == "Root" || key == "Size" || key == "ID" || key == "Encrypt" || key == "Prev") continue;
        if (const Object* value = document.trailer().find(key); value != nullptr)
            trailer.set(key, *value);
    }
    trailer.set("ID", Object::array({Object::string(id_string), Object::string(id_string)}));
    if (document.encrypted())
        diagnostics.info("pdf.write.decrypted",
                         "the output is written without encryption; the source encryption was "
                         "removed so the rewritten file opens everywhere");
    const std::string trailer_text = serializer.object(Object::dictionary(trailer), 0);

    append(output, "trailer\n" + trailer_text + "\nstartxref\n" +
                       std::to_string(xref_offset) + "\n%%EOF\n");
    result.bytes = std::move(output);
    return result;
}

}  // namespace scour

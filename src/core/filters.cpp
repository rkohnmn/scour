// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/filters.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "scour/inflate.hpp"

namespace scour {

namespace {

bool is_image_filter(std::string_view name) {
    return name == "DCTDecode" || name == "DCT" || name == "JPXDecode" || name == "CCITTFaxDecode" ||
           name == "CCF" || name == "JBIG2Decode";
}

bool is_identity(std::string_view name) {
    return name == "Crypt" || name == "Identity" || name.empty();
}

Bytes ascii_hex_decode(std::string_view raw) {
    Bytes out;
    out.reserve(raw.size() / 2 + 1);
    int high = -1;
    for (char c : raw) {
        int value = -1;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
        } else if (c == '>') {
            break;
        } else {
            continue;
        }
        if (high < 0) {
            high = value;
        } else {
            out.push_back(static_cast<Byte>((high << 4) | value));
            high = -1;
        }
    }
    if (high >= 0) out.push_back(static_cast<Byte>(high << 4));
    return out;
}

Bytes ascii85_decode(std::string_view raw) {
    Bytes out;
    std::uint64_t tuple = 0;
    int count = 0;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '~') break;
        if (c == 'z' && count == 0) {
            out.insert(out.end(), 4, 0);
            continue;
        }
        if (c < '!' || c > 'u') continue;
        tuple = tuple * 85 + static_cast<std::uint64_t>(c - '!');
        if (++count == 5) {
            for (int shift = 24; shift >= 0; shift -= 8)
                out.push_back(static_cast<Byte>((tuple >> shift) & 0xFF));
            tuple = 0;
            count = 0;
        }
    }
    if (count > 1) {
        for (int i = count; i < 5; ++i) tuple = tuple * 85 + 84;
        for (int shift = 24, produced = 0; shift >= 0 && produced < count - 1; shift -= 8, ++produced)
            out.push_back(static_cast<Byte>((tuple >> shift) & 0xFF));
    }
    return out;
}

Bytes run_length_decode(std::string_view raw) {
    Bytes out;
    std::size_t i = 0;
    while (i < raw.size()) {
        const int length = static_cast<unsigned char>(raw[i++]);
        if (length == 128) break;
        if (length < 128) {
            const std::size_t count = static_cast<std::size_t>(length) + 1;
            const std::size_t take = std::min(count, raw.size() - i);
            out.insert(out.end(), raw.begin() + static_cast<std::ptrdiff_t>(i),
                       raw.begin() + static_cast<std::ptrdiff_t>(i + take));
            i += take;
        } else {
            if (i >= raw.size()) break;
            const auto value = static_cast<unsigned char>(raw[i++]);
            out.insert(out.end(), static_cast<std::size_t>(257 - length), value);
        }
    }
    return out;
}

Bytes lzw_decode(std::string_view raw, int early_change) {
    Bytes out;
    std::vector<Bytes> table;
    table.reserve(4096);
    auto reset = [&table] {
        table.clear();
        table.reserve(4096);
        for (int i = 0; i < 256; ++i) table.push_back(Bytes{static_cast<Byte>(i)});
        table.push_back({});  // 256 clear
        table.push_back({});  // 257 EOD
    };
    reset();
    int code_width = 9;
    std::uint32_t bit_buffer = 0;
    int bit_count = 0;
    std::size_t pos = 0;
    Bytes previous;

    auto read_code = [&]() -> int {
        while (bit_count < code_width) {
            if (pos >= raw.size()) return -1;
            bit_buffer = (bit_buffer << 8) | static_cast<unsigned char>(raw[pos++]);
            bit_count += 8;
        }
        const int code = static_cast<int>((bit_buffer >> (bit_count - code_width)) &
                                          ((1u << code_width) - 1));
        bit_count -= code_width;
        return code;
    };

    for (;;) {
        const int code = read_code();
        if (code < 0 || code == 257) break;
        if (code == 256) {
            reset();
            code_width = 9;
            previous.clear();
            continue;
        }
        Bytes entry;
        if (code < static_cast<int>(table.size())) {
            entry = table[static_cast<std::size_t>(code)];
        } else if (code == static_cast<int>(table.size()) && !previous.empty()) {
            entry = previous;
            entry.push_back(previous.front());
        } else {
            break;
        }
        out.insert(out.end(), entry.begin(), entry.end());
        if (!previous.empty()) {
            Bytes addition = previous;
            addition.push_back(entry.front());
            if (table.size() < 4096) table.push_back(std::move(addition));
        }
        previous = std::move(entry);

        const std::size_t limit = table.size() + static_cast<std::size_t>(early_change ? 1 : 0);
        if (limit >= (1u << code_width) && code_width < 12) ++code_width;
    }
    return out;
}

int param_int(const Dict& params, std::string_view key, int fallback) {
    const Object* value = params.find(key);
    return value != nullptr ? static_cast<int>(value->as_int(fallback)) : fallback;
}

}  // namespace

Bytes apply_predictor(const Bytes& data, const Dict& params) {
    const int predictor = param_int(params, "Predictor", 1);
    if (predictor <= 1) return data;
    const int colors = std::max(1, param_int(params, "Colors", 1));
    const int bits = std::max(1, param_int(params, "BitsPerComponent", 8));
    const int columns = std::max(1, param_int(params, "Columns", 1));
    const int bytes_per_pixel = std::max(1, (colors * bits + 7) / 8);
    const std::size_t row_bytes =
        static_cast<std::size_t>((static_cast<long long>(columns) * colors * bits + 7) / 8);

    if (predictor == 2) {  // TIFF predictor, 8-bit components only
        if (bits != 8) return data;
        Bytes out = data;
        for (std::size_t row = 0; row + row_bytes <= out.size(); row += row_bytes) {
            for (std::size_t i = static_cast<std::size_t>(bytes_per_pixel); i < row_bytes; ++i)
                out[row + i] = static_cast<Byte>(out[row + i] + out[row + i - static_cast<std::size_t>(bytes_per_pixel)]);
        }
        return out;
    }
    if (predictor < 10) return data;

    Bytes out;
    out.reserve(data.size());
    Bytes previous(row_bytes, 0);
    Bytes current(row_bytes, 0);
    std::size_t pos = 0;
    while (pos < data.size()) {
        const int type = static_cast<unsigned char>(data[pos++]);
        const std::size_t available = std::min(row_bytes, data.size() - pos);
        std::fill(current.begin(), current.end(), 0);
        std::memcpy(current.data(), data.data() + pos, available);
        pos += available;
        for (std::size_t i = 0; i < row_bytes; ++i) {
            const int left = i >= static_cast<std::size_t>(bytes_per_pixel)
                                 ? current[i - static_cast<std::size_t>(bytes_per_pixel)]
                                 : 0;
            const int up = previous[i];
            const int up_left = i >= static_cast<std::size_t>(bytes_per_pixel)
                                    ? previous[i - static_cast<std::size_t>(bytes_per_pixel)]
                                    : 0;
            int value = current[i];
            switch (type) {
                case 1: value += left; break;
                case 2: value += up; break;
                case 3: value += (left + up) / 2; break;
                case 4: {
                    const int p = left + up - up_left;
                    const int pa = std::abs(p - left);
                    const int pb = std::abs(p - up);
                    const int pc = std::abs(p - up_left);
                    value += (pa <= pb && pa <= pc) ? left : (pb <= pc ? up : up_left);
                    break;
                }
                default: break;
            }
            current[i] = static_cast<Byte>(value & 0xFF);
        }
        out.insert(out.end(), current.begin(), current.begin() + static_cast<std::ptrdiff_t>(row_bytes));
        previous = current;
    }
    return out;
}

DecodeResult decode_stream_data(std::string_view raw, const std::vector<FilterSpec>& filters,
                                Diagnostics& diagnostics, int page) {
    DecodeResult result;
    Bytes data = bytes_of(raw);
    for (const FilterSpec& filter : filters) {
        if (is_identity(filter.name)) continue;
        if (is_image_filter(filter.name)) {
            result.image = true;
            result.data = std::move(data);
            return result;
        }
        if (data.size() > (std::size_t{1} << 31)) {
            diagnostics.error("pdf.stream.too-large", "stream expands beyond the 2 GiB safety limit", page);
            break;
        }
        try {
            if (filter.name == "FlateDecode" || filter.name == "Fl") {
                bool checksum_ok = true;
                data = inflate(view_of(data), std::size_t{1} << 30, &checksum_ok);
                if (!checksum_ok) {
                    result.checksum_failed = true;
                    diagnostics.warn("pdf.stream.adler-mismatch",
                                     "a Flate stream failed its Adler-32 check; the data may be damaged",
                                     page);
                }
                data = apply_predictor(data, filter.params);
            } else if (filter.name == "LZWDecode" || filter.name == "LZW") {
                data = lzw_decode(view_of(data), param_int(filter.params, "EarlyChange", 1));
                data = apply_predictor(data, filter.params);
            } else if (filter.name == "ASCIIHexDecode" || filter.name == "AHx") {
                data = ascii_hex_decode(view_of(data));
            } else if (filter.name == "ASCII85Decode" || filter.name == "A85") {
                data = ascii85_decode(view_of(data));
            } else if (filter.name == "RunLengthDecode" || filter.name == "RL") {
                data = run_length_decode(view_of(data));
            } else if (filter.name == "Crypt") {
                continue;  // decryption already happened at the object level
            } else {
                result.unsupported = true;
                diagnostics.warn("pdf.filter.unsupported",
                                 "stream uses unsupported filter /" + filter.name, page);
                break;
            }
        } catch (const ScourError& error) {
            diagnostics.warn("pdf.stream.decode-failed",
                             "could not decode a /" + filter.name + " stream: " + error.what(), page);
            break;
        }
    }
    result.data = std::move(data);
    return result;
}

std::vector<FilterSpec> resolve_filters(const Dict& stream_dict, const ObjectSource& source) {
    std::vector<FilterSpec> specs;
    const Object* filter_object = stream_dict.find("Filter");
    const Object* params_object = stream_dict.find("DecodeParms");
    if (filter_object == nullptr) return specs;

    const Object* resolved_filter = source.resolve(*filter_object);
    const Object* resolved_params = params_object != nullptr ? source.resolve(*params_object) : nullptr;

    if (filter_object->is_name()) {
        specs.push_back(FilterSpec{filter_object->as_name(), {}});
        if (resolved_params != nullptr && resolved_params->is_dict())
            specs.back().params = resolved_params->dict();
        return specs;
    }
    if (resolved_filter == nullptr || !resolved_filter->is_array()) return specs;

    const std::vector<Object>& names = resolved_filter->items();
    for (std::size_t i = 0; i < names.size(); ++i) {
        const Object* name_object = source.resolve(names[i]);
        if (name_object == nullptr || !name_object->is_name()) continue;
        FilterSpec spec{name_object->as_name(), {}};
        if (resolved_params != nullptr) {
            if (resolved_params->is_array() && i < resolved_params->items().size()) {
                const Object* entry = source.resolve(resolved_params->items()[i]);
                if (entry != nullptr && entry->is_dict()) spec.params = entry->dict();
            } else if (i == 0 && resolved_params->is_dict()) {
                spec.params = resolved_params->dict();
            }
        }
        specs.push_back(std::move(spec));
    }
    return specs;
}

}  // namespace scour

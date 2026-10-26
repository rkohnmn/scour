// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// A self-contained DEFLATE decoder. It is deliberately small and auditable:
// canonical Huffman tables, a 512-entry fast lookup for short codes, and a
// bit-by-bit fallback for the rare long codes. No allocation happens per
// symbol; the output buffer grows geometrically.
#include "scour/inflate.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

#include "scour/error.hpp"

namespace scour {

namespace {

constexpr int kMaxBits = 15;
constexpr int kFastBits = 9;
constexpr int kFastSize = 1 << kFastBits;

// Length codes 257..285: base lengths and extra bits.
constexpr std::uint16_t kLengthBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,
                                           15, 17, 19, 23, 27, 31, 35, 43, 51,  59,
                                           67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::uint8_t kLengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                           2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};

// Distance codes 0..29.
constexpr std::uint16_t kDistBase[30] = {1,    2,    3,    4,    5,    7,     9,
                                         13,   17,   25,   33,   49,   65,    97,
                                         129,  193,  257,  385,  513,  769,   1025,
                                         1537, 2049, 3073, 4097, 6145, 8193,  12289,
                                         16385, 24577};
constexpr std::uint8_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                                         6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

[[noreturn]] void corrupt(const char* detail) {
    throw ScourError("pdf.deflate.corrupt", std::string("corrupt DEFLATE stream: ") + detail);
}

class BitReader {
public:
    BitReader(const std::uint8_t* data, std::size_t size) : data_(data), size_(size) {}

    /// Pushes more bytes into the accumulator. Returns false at end of input.
    bool refill() {
        while (count_ <= 56 && pos_ < size_) {
            bits_ |= static_cast<std::uint64_t>(data_[pos_++]) << count_;
            count_ += 8;
        }
        return true;
    }

    bool need(int n) {
        while (count_ < n) {
            if (pos_ >= size_) return false;
            bits_ |= static_cast<std::uint64_t>(data_[pos_++]) << count_;
            count_ += 8;
        }
        return true;
    }

    std::uint32_t take(int n) {
        if (n == 0) return 0;
        if (!need(n)) corrupt("unexpected end of input");
        const std::uint32_t value = static_cast<std::uint32_t>(bits_ & ((std::uint64_t{1} << n) - 1));
        bits_ >>= n;
        count_ -= n;
        return value;
    }

    void align_to_byte() {
        const int drop = count_ & 7;
        bits_ >>= drop;
        count_ -= drop;
    }

    /// Returns the next `kFastBits` bits without consuming them (zero padded).
    std::uint32_t peek_fast() const {
        return static_cast<std::uint32_t>(bits_ & (kFastSize - 1));
    }

    void drop(int n) {
        bits_ >>= n;
        count_ -= n;
    }

    [[nodiscard]] std::size_t position() const noexcept { return pos_; }
    [[nodiscard]] int buffered_bits() const noexcept { return count_; }

private:
    const std::uint8_t* data_;
    std::size_t size_;
    std::size_t pos_ = 0;
    std::uint64_t bits_ = 0;
    int count_ = 0;
};

constexpr std::uint32_t reverse_bits(std::uint32_t code, int length) noexcept {
    std::uint32_t out = 0;
    for (int i = 0; i < length; ++i) {
        out = (out << 1) | (code & 1u);
        code >>= 1;
    }
    return out;
}

struct Huffman {
    std::array<std::uint16_t, kMaxBits + 1> counts{};
    std::array<std::uint16_t, 288> symbols{};
    std::array<std::uint16_t, kFastSize> fast_symbol{};
    std::array<std::uint8_t, kFastSize> fast_length{};
    int symbol_count = 0;

    void build(const std::uint8_t* lengths, int n) {
        counts.fill(0);
        fast_symbol.fill(0);
        fast_length.fill(0);
        for (int i = 0; i < n; ++i) counts[lengths[i]]++;
        counts[0] = 0;

        // Reject over-subscribed and incomplete codes (incomplete is allowed
        // only for a single-code alphabet, which we handle below).
        int left = 1;
        for (int len = 1; len <= kMaxBits; ++len) {
            left <<= 1;
            left -= counts[static_cast<std::size_t>(len)];
            if (left < 0) corrupt("over-subscribed Huffman code");
        }

        symbol_count = 0;
        std::array<std::uint16_t, kMaxBits + 1> offsets{};
        for (int len = 1; len <= kMaxBits; ++len) {
            offsets[static_cast<std::size_t>(len)] = static_cast<std::uint16_t>(symbol_count);
            symbol_count += counts[static_cast<std::size_t>(len)];
        }
        std::array<std::uint16_t, kMaxBits + 1> next = offsets;
        for (int i = 0; i < n; ++i) {
            if (lengths[i] != 0) symbols[next[lengths[i]]++] = static_cast<std::uint16_t>(i);
        }

        // Fast lookup table. DEFLATE packs Huffman codes most-significant-bit
        // first while the bit reader hands back the first bit in bit 0, so the
        // table is indexed by the bit-reversed code. A code of `len` bits owns
        // every 9-bit lookahead whose low `len` bits match, i.e. a stride fill.
        std::uint32_t code = 0;
        int index = 0;
        for (int len = 1; len <= kMaxBits; ++len) {
            for (int k = 0; k < counts[static_cast<std::size_t>(len)]; ++k) {
                const std::uint16_t symbol = symbols[static_cast<std::size_t>(index++)];
                if (len <= kFastBits) {
                    const std::uint32_t reversed = reverse_bits(code, len);
                    const std::uint32_t stride = 1u << len;
                    const std::uint32_t span = 1u << (kFastBits - len);
                    for (std::uint32_t r = 0; r < span; ++r) {
                        const std::uint32_t slot = reversed | (r * stride);
                        fast_symbol[slot] = symbol;
                        fast_length[slot] = static_cast<std::uint8_t>(len);
                    }
                }
                ++code;
            }
            code <<= 1;
        }
    }

    int decode(BitReader& br) const {
        if (br.need(kFastBits)) {
            const std::uint32_t key = br.peek_fast();
            const std::uint8_t len = fast_length[key];
            if (len != 0) {
                br.drop(len);
                return fast_symbol[key];
            }
        }
        int code = 0;
        int first = 0;
        int index = 0;
        for (int len = 1; len <= kMaxBits; ++len) {
            code |= static_cast<int>(br.take(1));
            const int count = counts[static_cast<std::size_t>(len)];
            if (code - first < count) return symbols[static_cast<std::size_t>(index + (code - first))];
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        corrupt("invalid Huffman code");
    }
};

void build_fixed(Huffman& literal, Huffman& distance) {
    std::array<std::uint8_t, 288> lengths{};
    for (int i = 0; i < 144; ++i) lengths[static_cast<std::size_t>(i)] = 8;
    for (int i = 144; i < 256; ++i) lengths[static_cast<std::size_t>(i)] = 9;
    for (int i = 256; i < 280; ++i) lengths[static_cast<std::size_t>(i)] = 7;
    for (int i = 280; i < 288; ++i) lengths[static_cast<std::size_t>(i)] = 8;
    literal.build(lengths.data(), 288);

    std::array<std::uint8_t, 30> dist_lengths{};
    dist_lengths.fill(5);
    distance.build(dist_lengths.data(), 30);
}

void build_dynamic(BitReader& br, Huffman& literal, Huffman& distance) {
    const int hlit = static_cast<int>(br.take(5)) + 257;
    const int hdist = static_cast<int>(br.take(5)) + 1;
    const int hclen = static_cast<int>(br.take(4)) + 4;
    if (hlit > 286 || hdist > 30) corrupt("bad dynamic block header");

    static constexpr std::uint8_t kOrder[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                                11, 4,  12, 3, 13, 2, 14, 1, 15};
    std::array<std::uint8_t, 19> code_lengths{};
    for (int i = 0; i < hclen; ++i) code_lengths[kOrder[i]] = static_cast<std::uint8_t>(br.take(3));

    Huffman length_code;
    length_code.build(code_lengths.data(), 19);

    std::array<std::uint8_t, 288 + 30> lengths{};
    int i = 0;
    while (i < hlit + hdist) {
        const int symbol = length_code.decode(br);
        if (symbol < 16) {
            lengths[static_cast<std::size_t>(i++)] = static_cast<std::uint8_t>(symbol);
        } else if (symbol == 16) {
            if (i == 0) corrupt("repeat with no previous length");
            const std::uint8_t previous = lengths[static_cast<std::size_t>(i - 1)];
            const int repeat = static_cast<int>(br.take(2)) + 3;
            if (i + repeat > hlit + hdist) corrupt("length repeat overflow");
            for (int k = 0; k < repeat; ++k) lengths[static_cast<std::size_t>(i++)] = previous;
        } else if (symbol == 17) {
            const int repeat = static_cast<int>(br.take(3)) + 3;
            if (i + repeat > hlit + hdist) corrupt("zero repeat overflow");
            i += repeat;
        } else {
            const int repeat = static_cast<int>(br.take(7)) + 11;
            if (i + repeat > hlit + hdist) corrupt("long zero repeat overflow");
            i += repeat;
        }
    }
    if (lengths[256] == 0) corrupt("missing end-of-block code");
    literal.build(lengths.data(), hlit);
    distance.build(lengths.data() + hlit, hdist);
}

void inflate_raw(const std::uint8_t* data, std::size_t size, Bytes& out, std::size_t max_output) {
    BitReader br(data, size);
    Huffman fixed_literal;
    Huffman fixed_distance;
    build_fixed(fixed_literal, fixed_distance);

    const std::size_t base_size = out.size();
    bool final_block = false;
    while (!final_block) {
        final_block = br.take(1) == 1;
        const int type = static_cast<int>(br.take(2));
        if (type == 0) {
            br.align_to_byte();
            const std::uint32_t len = br.take(16);
            const std::uint32_t nlen = br.take(16);
            if ((len ^ 0xFFFFu) != nlen) corrupt("stored block length mismatch");
            for (std::uint32_t k = 0; k < len; ++k) {
                if (out.size() - base_size >= max_output)
                    throw ScourError("pdf.deflate.too-large", "decompressed stream too large");
                out.push_back(static_cast<Byte>(br.take(8)));
            }
            continue;
        }
        if (type == 3) corrupt("reserved block type");

        const Huffman* literal = &fixed_literal;
        const Huffman* distance = &fixed_distance;
        Huffman dynamic_literal;
        Huffman dynamic_distance;
        if (type == 2) {
            build_dynamic(br, dynamic_literal, dynamic_distance);
            literal = &dynamic_literal;
            distance = &dynamic_distance;
        }

        for (;;) {
            const int symbol = literal->decode(br);
            if (symbol < 256) {
                if (out.size() - base_size >= max_output)
                    throw ScourError("pdf.deflate.too-large", "decompressed stream too large");
                out.push_back(static_cast<Byte>(symbol));
                continue;
            }
            if (symbol == 256) break;
            const int length_index = symbol - 257;
            if (length_index < 0 || length_index >= 29) corrupt("bad length symbol");
            const std::size_t length = kLengthBase[length_index] + br.take(kLengthExtra[length_index]);

            const int dist_symbol = distance->decode(br);
            if (dist_symbol < 0 || dist_symbol >= 30) corrupt("bad distance symbol");
            const std::size_t distance_value =
                kDistBase[dist_symbol] + br.take(kDistExtra[dist_symbol]);
            if (distance_value == 0 || distance_value > out.size() - base_size)
                corrupt("distance beyond start of output");

            if (out.size() - base_size + length > max_output)
                throw ScourError("pdf.deflate.too-large", "decompressed stream too large");
            const std::size_t from = out.size() - distance_value;
            for (std::size_t k = 0; k < length; ++k) out.push_back(out[from + k]);
        }
    }
}

}  // namespace

bool looks_like_zlib(std::string_view input) noexcept {
    if (input.size() < 2) return false;
    const auto cmf = static_cast<unsigned char>(input[0]);
    const auto flg = static_cast<unsigned char>(input[1]);
    if ((cmf & 0x0F) != 8) return false;             // compression method must be DEFLATE
    if ((cmf >> 4) > 7) return false;                // window size <= 32K
    return ((static_cast<unsigned>(cmf) << 8) | flg) % 31 == 0;
}

std::uint32_t adler32(std::string_view data) noexcept {
    std::uint32_t a = 1;
    std::uint32_t b = 0;
    for (const char raw : data) {
        const auto c = static_cast<unsigned char>(raw);
        a = (a + c) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

Bytes inflate(std::string_view input, std::size_t max_output, bool* checksum_ok) {
    Bytes out;
    if (checksum_ok != nullptr) *checksum_ok = true;
    if (input.empty()) return out;
    out.reserve(std::min<std::size_t>(max_output, input.size() * 4));
    const auto* data = reinterpret_cast<const std::uint8_t*>(input.data());

    if (looks_like_zlib(input)) {
        inflate_raw(data + 2, input.size() - 2, out, max_output);
        if (input.size() >= 6) {
            const std::size_t trailer = input.size() - 4;
            const std::uint32_t expected = (static_cast<std::uint32_t>(data[trailer]) << 24) |
                                           (static_cast<std::uint32_t>(data[trailer + 1]) << 16) |
                                           (static_cast<std::uint32_t>(data[trailer + 2]) << 8) |
                                           static_cast<std::uint32_t>(data[trailer + 3]);
            const std::uint32_t actual = adler32(view_of(out));
            // Some producers write a zero or stale Adler checksum. The data is
            // still usable, so this is a signal for the caller, not an error.
            if (checksum_ok != nullptr) *checksum_ok = (expected == actual);
        }
        return out;
    }
    inflate_raw(data, input.size(), out, max_output);
    return out;
}

}  // namespace scour

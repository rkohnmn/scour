// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/deflate.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "scour/inflate.hpp"

namespace scour {

namespace {

constexpr int kWindow = 32768;
constexpr int kWindowMask = kWindow - 1;
constexpr int kHashBits = 15;
constexpr int kHashSize = 1 << kHashBits;
constexpr int kMinMatch = 3;
constexpr int kMaxMatch = 258;

constexpr std::uint16_t kLenBase[29] = {3,  4,  5,  6,  7,  8,  9,  10, 11,  13,
                                        15, 17, 19, 23, 27, 31, 35, 43, 51,  59,
                                        67, 83, 99, 115, 131, 163, 195, 227, 258};
constexpr std::uint8_t kLenExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                        2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
constexpr std::uint16_t kDistBase[30] = {1,    2,    3,    4,    5,     7,     9,
                                         13,   17,   25,   33,   49,    65,    97,
                                         129,  193,  257,  385,  513,   769,   1025,
                                         1537, 2049, 3073, 4097, 6145,  8193,  12289,
                                         16385, 24577};
constexpr std::uint8_t kDistExtra[30] = {0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
                                         6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

constexpr std::uint32_t reverse_bits(std::uint32_t code, int length) noexcept {
    std::uint32_t out = 0;
    for (int i = 0; i < length; ++i) {
        out = (out << 1) | (code & 1u);
        code >>= 1;
    }
    return out;
}

class BitWriter {
public:
    void put(std::uint32_t value, int bits) {
        bits_ |= static_cast<std::uint64_t>(value) << count_;
        count_ += bits;
        while (count_ >= 8) {
            out_.push_back(static_cast<Byte>(bits_ & 0xFF));
            bits_ >>= 8;
            count_ -= 8;
        }
    }
    void put_reversed(std::uint32_t value, int bits) { put(reverse_bits(value, bits), bits); }

    void align() {
        if (count_ > 0) {
            out_.push_back(static_cast<Byte>(bits_ & 0xFF));
            bits_ = 0;
            count_ = 0;
        }
    }
    void put_bytes(std::string_view raw) {
        out_.insert(out_.end(), raw.begin(), raw.end());
    }

    [[nodiscard]] std::size_t size() const noexcept { return out_.size(); }
    Bytes take() {
        align();
        return std::move(out_);
    }

private:
    Bytes out_;
    std::uint64_t bits_ = 0;
    int count_ = 0;
};

void put_fixed_literal(BitWriter& w, int symbol) {
    if (symbol <= 143) {
        w.put_reversed(static_cast<std::uint32_t>(0x30 + symbol), 8);
    } else if (symbol <= 255) {
        w.put_reversed(static_cast<std::uint32_t>(0x190 + symbol - 144), 9);
    } else if (symbol <= 279) {
        w.put_reversed(static_cast<std::uint32_t>(symbol - 256), 7);
    } else {
        w.put_reversed(static_cast<std::uint32_t>(0xC0 + symbol - 280), 8);
    }
}

int length_code(int length) {
    for (int i = 28; i >= 0; --i) {
        if (length >= kLenBase[i]) return i;
    }
    return 0;
}

int distance_code(int distance) {
    for (int i = 29; i >= 0; --i) {
        if (distance >= kDistBase[i]) return i;
    }
    return 0;
}

void put_match(BitWriter& w, int length, int distance) {
    const int lc = length_code(length);
    put_fixed_literal(w, 257 + lc);
    if (kLenExtra[lc] != 0) w.put(static_cast<std::uint32_t>(length - kLenBase[lc]), kLenExtra[lc]);
    const int dc = distance_code(distance);
    w.put_reversed(static_cast<std::uint32_t>(dc), 5);
    if (kDistExtra[dc] != 0)
        w.put(static_cast<std::uint32_t>(distance - kDistBase[dc]), kDistExtra[dc]);
}

void put_stored(BitWriter& w, std::string_view raw, bool final_block) {
    w.put(final_block ? 1u : 0u, 1);
    w.put(0u, 2);
    w.align();
    const auto length = static_cast<std::uint16_t>(raw.size());
    w.put(length, 16);
    w.put(static_cast<std::uint32_t>(length) ^ 0xFFFFu, 16);
    w.put_bytes(raw);
}

struct Token {
    std::uint16_t length;    // 0 for a literal
    std::uint16_t distance;  // literal byte when length == 0
};

struct Matcher {
    std::array<std::int32_t, kHashSize> head{};
    std::array<std::int32_t, kWindow> previous{};

    Matcher() {
        head.fill(-1);
        previous.fill(-1);
    }

    static int hash(const Byte* p) noexcept {
        const std::uint32_t h = (static_cast<std::uint32_t>(p[0]) << 10) ^
                                (static_cast<std::uint32_t>(p[1]) << 5) ^
                                static_cast<std::uint32_t>(p[2]);
        return static_cast<int>(h & (kHashSize - 1));
    }

    /// Adds `pos` to the hash chain and returns the previous chain head, which
    /// is where a match search must start (searching from `head` would find the
    /// position itself).
    std::int32_t insert(const Byte* data, std::size_t size, std::size_t pos) {
        if (pos + kMinMatch > size) return -1;
        const int h = hash(data + pos);
        const std::int32_t previous_head = head[static_cast<std::size_t>(h)];
        previous[pos & kWindowMask] = previous_head;
        head[static_cast<std::size_t>(h)] = static_cast<std::int32_t>(pos);
        return previous_head;
    }

    /// Looks for a match without touching the hash chains, for lazy probing.
    void probe(const Byte* data, std::size_t size, std::size_t pos, int max_chain, int& best_len,
               int& best_dist) const {
        if (pos + kMinMatch > size) {
            best_len = 0;
            best_dist = 0;
            return;
        }
        find(data, size, pos, head[static_cast<std::size_t>(hash(data + pos))], max_chain, best_len,
             best_dist);
    }

    /// Finds the longest match for `pos`, bounded by `max_chain` visits.
    void find(const Byte* data, std::size_t size, std::size_t pos, std::int32_t candidate,
              int max_chain, int& best_len, int& best_dist) const {
        best_len = 0;
        best_dist = 0;
        if (pos + kMinMatch > size) return;
        const std::size_t limit = size - pos;
        const int max_len = static_cast<int>(std::min<std::size_t>(kMaxMatch, limit));
        int chain = 0;
        while (candidate >= 0 && chain < max_chain) {
            const auto c = static_cast<std::size_t>(candidate);
            if (pos <= c) break;
            const std::size_t dist = pos - c;
            if (dist > static_cast<std::size_t>(kWindow)) break;
            if (best_len < max_len && data[c + static_cast<std::size_t>(best_len)] ==
                                          data[pos + static_cast<std::size_t>(best_len)]) {
                int len = 0;
                while (len < max_len && data[c + static_cast<std::size_t>(len)] ==
                                            data[pos + static_cast<std::size_t>(len)])
                    ++len;
                if (len > best_len) {
                    best_len = len;
                    best_dist = static_cast<int>(dist);
                    if (len >= max_len) break;
                }
            }
            candidate = previous[c & kWindowMask];
            ++chain;
        }
        if (best_len < kMinMatch) {
            best_len = 0;
            best_dist = 0;
        }
    }
};

Bytes encode_fixed(const Byte* data, std::size_t size) {
    BitWriter out;
    Matcher matcher;
    std::vector<Token> tokens;
    tokens.reserve(size / 2 + 16);

    std::size_t pos = 0;
    while (pos < size) {
        int length = 0;
        int distance = 0;
        if (pos + kMinMatch <= size) {
            const std::int32_t previous_head = matcher.insert(data, size, pos);
            matcher.find(data, size, pos, previous_head, 96, length, distance);
        }
        // Lazy matching: if the next position starts a longer match, emit a
        // literal here instead. This reliably buys a few percent on text. The
        // probe does not insert pos + 1, so the next iteration cannot chain a
        // position to itself.
        if (length >= kMinMatch && length < kMaxMatch && pos + 1 < size) {
            int next_length = 0;
            int next_distance = 0;
            matcher.probe(data, size, pos + 1, 32, next_length, next_distance);
            if (next_length > length) {
                tokens.push_back(Token{0, data[pos]});
                ++pos;
                continue;
            }
        }
        if (length >= kMinMatch) {
            tokens.push_back(Token{static_cast<std::uint16_t>(length),
                                   static_cast<std::uint16_t>(distance)});
            for (int i = 1; i < length; ++i)
                matcher.insert(data, size, pos + static_cast<std::size_t>(i));
            pos += static_cast<std::size_t>(length);
        } else {
            tokens.push_back(Token{0, data[pos]});
            ++pos;
        }
    }

    out.put(1, 1);  // BFINAL
    out.put(1, 2);  // fixed Huffman block
    for (const Token& token : tokens) {
        if (token.length == 0) {
            put_fixed_literal(out, token.distance);
        } else {
            put_match(out, token.length, token.distance);
        }
    }
    put_fixed_literal(out, 256);
    return out.take();
}

Bytes encode_stored(const Byte* data, std::size_t size) {
    BitWriter out;
    std::size_t pos = 0;
    if (size == 0) {
        put_stored(out, {}, true);
        return out.take();
    }
    while (pos < size) {
        const std::size_t take = std::min<std::size_t>(65535, size - pos);
        const bool final_block = pos + take >= size;
        put_stored(out, std::string_view(reinterpret_cast<const char*>(data + pos), take),
                   final_block);
        pos += take;
    }
    return out.take();
}

Bytes deflate_impl(std::string_view input) {
    const auto* data = reinterpret_cast<const Byte*>(input.data());
    // Incompressible data (already-compressed images, encrypted blobs) would be
    // inflated by a Huffman block, so fall back to stored blocks for it.
    Bytes compressed = encode_fixed(data, input.size());
    if (compressed.size() <= input.size() + 5) return compressed;
    return encode_stored(data, input.size());
}

}  // namespace

Bytes deflate_raw(std::string_view input) { return deflate_impl(input); }

Bytes zlib_compress(std::string_view input) {
    Bytes body = deflate_impl(input);
    Bytes out;
    out.reserve(body.size() + 6);
    out.push_back(0x78);
    out.push_back(0x9C);
    append(out, view_of(body));
    const std::uint32_t sum = adler32(input);
    out.push_back(static_cast<Byte>(sum >> 24));
    out.push_back(static_cast<Byte>(sum >> 16));
    out.push_back(static_cast<Byte>(sum >> 8));
    out.push_back(static_cast<Byte>(sum));
    return out;
}

Bytes deflate(std::string_view input) { return zlib_compress(input); }

}  // namespace scour

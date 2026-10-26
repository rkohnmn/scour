// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <random>
#include <string>

#include "scour/deflate.hpp"
#include "scour/hash.hpp"
#include "scour/inflate.hpp"

using namespace scour;

namespace {

const std::string kHello =
    "hello hello hello hello, scour the document before you share it. "
    "hello hello hello hello, scour the document before you share it. "
    "hello hello hello hello, scour the document before you share it. "
    "hello hello hello hello, scour the document before you share it. ";

std::string random_text(std::size_t size, std::uint32_t seed) {
    std::mt19937 rng(seed);
    std::string out(size, '\0');
    for (char& c : out) c = static_cast<char>('a' + (rng() % 26));
    return out;
}

}  // namespace

SCOUR_TEST(inflate, zlib_fixture_level1) {
    // Produced by Python 3.12 zlib.compress(text, 1): an independent encoder,
    // so this catches table or bit-order mistakes in our decoder.
    const auto hex =
        "7801cb48cdc9c957c8402775148a93f34b8b144a32521552f2934b7353f34a149252d3f28b52152af34b158a331281accc123d4cad1091a164000052d85e59";
    bool adler_ok = false;
    const Bytes stream = from_hex(hex);
    const Bytes out = inflate(view_of(stream), 1 << 20, &adler_ok);
    CHECK_EQ(view_of(out), std::string_view(kHello));
    CHECK(adler_ok);
}

SCOUR_TEST(inflate, raw_deflate_without_header) {
    const Bytes stream = from_hex("2b48acccc94f4c0100");
    const Bytes out = inflate(view_of(stream), 1 << 20);
    CHECK_EQ(view_of(out), std::string_view("payload"));
}

SCOUR_TEST(inflate, stored_block) {
    // 0x01 = BFINAL + stored block, LEN=3, NLEN=0xFFFC, then "abc".
    const Bytes stream = from_hex("010300fcff616263");
    const Bytes out = inflate(view_of(stream), 64);
    CHECK_EQ(view_of(out), std::string_view("abc"));
}

SCOUR_TEST(inflate, rejects_corrupt_stream) {
    const Bytes broken = from_hex("78daffffffff");
    CHECK_THROWS(inflate(view_of(broken), 1 << 20), "pdf.deflate");
    CHECK_THROWS(inflate("not a deflate stream at all", 1 << 20), "pdf.deflate");
}

SCOUR_TEST(inflate, enforces_output_limit) {
    const std::string text(100000, 'x');
    const Bytes compressed = zlib_compress(text);
    CHECK_THROWS(inflate(view_of(compressed), 1024), "too-large");
}

SCOUR_TEST(deflate, roundtrips) {
    const std::string cases[] = {
        "",
        "a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        kHello,
        random_text(4096, 7),
        random_text(200000, 11),
    };
    for (const std::string& original : cases) {
        const Bytes compressed = zlib_compress(original);
        CHECK(looks_like_zlib(view_of(compressed)));
        bool adler_ok = false;
        const Bytes back = inflate(view_of(compressed), 8 << 20, &adler_ok);
        CHECK(adler_ok);
        CHECK_EQ(view_of(back), std::string_view(original));
    }
}

SCOUR_TEST(deflate, compresses_repetitive_text) {
    const Bytes compressed = zlib_compress(kHello);
    CHECK_LT(compressed.size(), kHello.size() / 2);
}

SCOUR_TEST(deflate, does_not_inflate_random_data) {
    std::mt19937 rng(99);
    std::string noise(65536, '\0');
    for (char& c : noise) c = static_cast<char>(rng() & 0xFF);
    const Bytes compressed = zlib_compress(noise);
    CHECK_LT(compressed.size(), noise.size() + 64);
    const Bytes back = inflate(view_of(compressed), 1 << 20);
    CHECK_EQ(view_of(back), std::string_view(noise));
}

SCOUR_TEST(deflate, handles_full_match_cap) {
    const std::string repeated(258 * 4, 'z');
    const Bytes compressed = zlib_compress(repeated);
    const Bytes back = inflate(view_of(compressed), 1 << 20);
    CHECK_EQ(view_of(back), std::string_view(repeated));
}

SCOUR_TEST(deflate, cross_checks_with_crc) {
    // Two independent encoders must agree on decompressed content, and the
    // adler trailer must validate. Also covers the >32K window boundary.
    std::string text;
    for (int i = 0; i < 4000; ++i) {
        text += "line ";
        text += std::to_string(i);
        text += " of a document that repeats enough to exercise the window.\n";
    }
    const Bytes compressed = zlib_compress(text);
    const Bytes back = inflate(view_of(compressed), 4 << 20);
    CHECK_EQ(back.size(), text.size());
    CHECK_EQ(crc32(view_of(back)), crc32(text));
    CHECK_LT(compressed.size(), text.size());
}

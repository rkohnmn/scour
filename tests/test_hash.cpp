// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/hash.hpp"

using namespace scour;

namespace {

template <std::size_t N>
std::string hex_of(const std::array<std::uint8_t, N>& digest) {
    return to_hex(std::string_view(reinterpret_cast<const char*>(digest.data()), digest.size()));
}

}  // namespace

SCOUR_TEST(hash, md5_vectors) {
    CHECK_EQ(hex_of(md5("")), std::string("d41d8cd98f00b204e9800998ecf8427e"));
    CHECK_EQ(hex_of(md5("abc")), std::string("900150983cd24fb0d6963f7d28e17f72"));
    CHECK_EQ(hex_of(md5("The quick brown fox jumps over the lazy dog")),
             std::string("9e107d9d372bb6826bd81d3542a419d6"));
}

SCOUR_TEST(hash, md5_streaming_matches_one_shot) {
    const std::string million(1000000, 'a');
    Md5 streamed;
    for (int chunk = 0; chunk < 1000; ++chunk)
        streamed.update(std::string_view(million).substr(0, 1000));
    const auto a = streamed.finish();
    CHECK_EQ(a, md5(million));
    CHECK_EQ(hex_of(a), std::string("7707d6ae4e027c70eea2a935c2296f21"));
}

SCOUR_TEST(hash, sha256_vectors) {
    CHECK_EQ(hex_of(sha256("abc")),
             std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(hex_of(sha256("")),
             std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(hex_of(sha256(std::string(1000000, 'a'))),
             std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

SCOUR_TEST(hash, crc32_known_answer) {
    CHECK_EQ(crc32("123456789"), std::uint32_t{0xCBF43926});
    CHECK_EQ(crc32(""), std::uint32_t{0});
    CHECK_EQ(crc32("The quick brown fox jumps over the lazy dog"), std::uint32_t{0x414FA339});
}

SCOUR_TEST(hash, random_bytes_are_not_constant) {
    const Bytes a = random_bytes(32);
    const Bytes b = random_bytes(32);
    CHECK_EQ(a.size(), std::size_t{32});
    CHECK_NE(a, b);
}

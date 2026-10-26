// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <cstring>
#include <string>

#include "scour/crypt.hpp"
#include "scour/hash.hpp"

using namespace scour;

namespace {

template <std::size_t N>
std::string hex_of(const std::array<std::uint8_t, N>& digest) {
    return to_hex(std::string_view(reinterpret_cast<const char*>(digest.data()), digest.size()));
}

}  // namespace

SCOUR_TEST(crypt, rc4_known_answer) {
    // RFC 6229 / classic test vector: key "Key", plaintext "Plaintext".
    const Bytes key = bytes_of("Key");
    const Bytes out = rc4(key, "Plaintext");
    CHECK_EQ(to_hex(view_of(out)), std::string("bbf316e8d940af0ad3"));
    Bytes roundtrip = out;
    rc4_inplace(key, roundtrip);
    CHECK_EQ(view_of(roundtrip), std::string_view("Plaintext"));
}

SCOUR_TEST(crypt, aes128_block_fips197) {
    Bytes key;
    for (int i = 0; i < 16; ++i) key.push_back(static_cast<Byte>(i));
    Bytes plain;
    for (int i = 0; i < 16; ++i) plain.push_back(static_cast<Byte>(i * 0x11));
    Aes aes(key);
    std::uint8_t out[16];
    aes.encrypt_block(plain.data(), out);
    CHECK_EQ(to_hex(std::string_view(reinterpret_cast<const char*>(out), 16)),
             std::string("69c4e0d86a7b0430d8cdb78070b4c55a"));
    std::uint8_t back[16];
    aes.decrypt_block(out, back);
    CHECK_EQ(std::memcmp(back, plain.data(), 16), 0);
}

SCOUR_TEST(crypt, aes256_block_fips197) {
    Bytes key;
    for (int i = 0; i < 32; ++i) key.push_back(static_cast<Byte>(i));
    Bytes plain;
    for (int i = 0; i < 16; ++i) plain.push_back(static_cast<Byte>(i * 0x11));
    Aes aes(key);
    std::uint8_t out[16];
    aes.encrypt_block(plain.data(), out);
    CHECK_EQ(to_hex(std::string_view(reinterpret_cast<const char*>(out), 16)),
             std::string("8ea2b7ca516745bfeafc49904b496089"));
}

SCOUR_TEST(crypt, aes_cbc_padding_roundtrip) {
    const Bytes key(16, 0x2B);
    const Bytes iv(16, 0x0E);
    for (const std::string& plain : {std::string(), std::string("x"),
                                     std::string("0123456789abcdef"), std::string(1000, 'q')}) {
        const Bytes cipher = aes_cbc_encrypt(key, iv, plain);
        CHECK_EQ(cipher.size() % 16, std::size_t{0});
        CHECK_GT(cipher.size(), plain.size());
        const Bytes back = aes_cbc_decrypt(key, iv, view_of(cipher));
        CHECK_EQ(view_of(back), std::string_view(plain));
    }
}

SCOUR_TEST(crypt, sha512_and_sha384_vectors) {
    CHECK_EQ(hex_of(sha512("abc")),
             std::string("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                         "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
    CHECK_EQ(hex_of(sha384("abc")),
             std::string("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                         "8086072ba1e7cc2358baeca134c825a7"));
    CHECK_EQ(hex_of(sha384("")),
             std::string("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                         "274edebfe76f65fbd51ad2f14898b95b"));
}

SCOUR_TEST(crypt, r6_hash_is_deterministic) {
    const Bytes a = hash_r6("secret", "saltsalt", "", 6);
    const Bytes b = hash_r6("secret", "saltsalt", "", 6);
    const Bytes c = hash_r6("secret", "saltsalt", "", 5);
    CHECK_EQ(a.size(), std::size_t{32});
    CHECK_EQ(a, b);
    CHECK_NE(a, c);
    CHECK_EQ(hash_r6("secret", "saltsalt", "", 5).size(), std::size_t{32});
}

SCOUR_TEST(crypt, rejects_bad_key_size) {
    CHECK_THROWS(Aes(Bytes(5, 0)), "pdf.crypt.bad-key");
}

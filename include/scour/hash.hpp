// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_HASH_HPP
#define SCOUR_HASH_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "scour/bytes.hpp"

namespace scour {

/// CRC-32 (IEEE 802.3), used by PNG/TIFF stream predictors and ZIP containers.
std::uint32_t crc32(std::string_view data, std::uint32_t seed = 0) noexcept;

/// MD5, required by the PDF standard security handler revisions 2-4.
class Md5 {
public:
    Md5();
    void update(std::string_view data);
    void update(const void* data, std::size_t size);
    [[nodiscard]] std::array<std::uint8_t, 16> finish();

private:
    void block(const std::uint8_t* p);
    std::array<std::uint32_t, 4> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t length_ = 0;
    std::size_t buffered_ = 0;
};

std::array<std::uint8_t, 16> md5(std::string_view data);

/// SHA-256, used by PDF 2.0 (AES-256) encryption and for reproducible file IDs.
class Sha256 {
public:
    Sha256();
    void update(std::string_view data);
    void update(const void* data, std::size_t size);
    [[nodiscard]] std::array<std::uint8_t, 32> finish();

private:
    void block(const std::uint8_t* p);
    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::uint64_t length_ = 0;
    std::size_t buffered_ = 0;
};

std::array<std::uint8_t, 32> sha256(std::string_view data);

/// SHA-512 and SHA-384, required by the PDF 2.0 hardened hash (Algorithm 2.B).
std::array<std::uint8_t, 64> sha512(std::string_view data);
std::array<std::uint8_t, 48> sha384(std::string_view data);

/// Cryptographically strong random bytes (getrandom / BCryptGenRandom, falling
/// back to std::random_device). Used for encryption keys and /ID salts.
Bytes random_bytes(std::size_t count);

}  // namespace scour

#endif  // SCOUR_HASH_HPP

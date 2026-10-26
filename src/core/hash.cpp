// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/hash.hpp"

#include <cstring>
#include <random>

#include "sha512_table.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#include <sys/random.h>
#endif

namespace scour {

namespace {

constexpr std::uint32_t rotl32(std::uint32_t x, int n) noexcept {
    return (x << n) | (x >> (32 - n));
}
constexpr std::uint32_t rotr32(std::uint32_t x, int n) noexcept {
    return (x >> n) | (x << (32 - n));
}
constexpr std::uint32_t read_le32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
constexpr std::uint32_t read_be32(const std::uint8_t* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
inline void write_le32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}
inline void write_be32(std::uint8_t* p, std::uint32_t v) noexcept {
    p[0] = static_cast<std::uint8_t>(v >> 24);
    p[1] = static_cast<std::uint8_t>(v >> 16);
    p[2] = static_cast<std::uint8_t>(v >> 8);
    p[3] = static_cast<std::uint8_t>(v);
}

constexpr std::uint32_t kCrcTable[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535,
    0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD,
    0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D,
    0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4,
    0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 0x26D930AC,
    0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB,
    0xB6662D3D, 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F,
    0x9FBFE4A5, 0xE8B8D433, 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB,
    0x086D3D2D, 0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA,
    0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 0x4DB26158, 0x3AB551CE,
    0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A,
    0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409,
    0xCE61E49F, 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739,
    0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 0xF00F9344, 0x8708A3D2, 0x1E01F268,
    0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0,
    0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8,
    0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF,
    0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703,
    0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7,
    0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE,
    0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 0x88085AE6,
    0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D,
    0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5,
    0x47B2CF7F, 0x30B5FFE9, 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605,
    0xCDD70693, 0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D};

constexpr std::uint32_t kMd5Shift[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,
    14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

constexpr std::uint32_t kMd5Table[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
    0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
    0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
    0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
    0xeb86d391};

constexpr std::uint32_t kSha256Table[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

}  // namespace

std::uint32_t crc32(std::string_view data, std::uint32_t seed) noexcept {
    std::uint32_t crc = seed ^ 0xFFFFFFFFu;
    for (const char raw : data) {
        const auto c = static_cast<unsigned char>(raw);
        crc = kCrcTable[(crc ^ c) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

Md5::Md5() {
    state_[0] = 0x67452301;
    state_[1] = 0xefcdab89;
    state_[2] = 0x98badcfe;
    state_[3] = 0x10325476;
}

void Md5::block(const std::uint8_t* p) {
    std::uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = read_le32(p + i * 4);

    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t f = 0;
        int g = 0;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        const std::uint32_t tmp = d;
        d = c;
        c = b;
        const std::uint32_t sum = a + f + kMd5Table[i] + m[g];
        b = b + rotl32(sum, static_cast<int>(kMd5Shift[i]));
        a = tmp;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
}

void Md5::update(const void* data, std::size_t size) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    length_ += size;
    if (buffered_ != 0) {
        const std::size_t need = 64 - buffered_;
        const std::size_t take = size < need ? size : need;
        std::memcpy(buffer_.data() + buffered_, p, take);
        buffered_ += take;
        p += take;
        size -= take;
        if (buffered_ == 64) {
            block(buffer_.data());
            buffered_ = 0;
        }
    }
    while (size >= 64) {
        block(p);
        p += 64;
        size -= 64;
    }
    if (size != 0) {
        std::memcpy(buffer_.data(), p, size);
        buffered_ = size;
    }
}

void Md5::update(std::string_view data) { update(data.data(), data.size()); }

std::array<std::uint8_t, 16> Md5::finish() {
    const std::uint64_t bits = length_ * 8;
    std::uint8_t padding[72] = {0x80};
    const std::size_t pad_len = (buffered_ < 56) ? (56 - buffered_) : (120 - buffered_);
    update(padding, pad_len);
    std::uint8_t tail[8];
    for (int i = 0; i < 8; ++i) tail[i] = static_cast<std::uint8_t>(bits >> (8 * i));
    update(tail, 8);

    std::array<std::uint8_t, 16> out{};
    for (std::size_t i = 0; i < 4; ++i)
        write_le32(out.data() + i * 4, state_[i]);
    return out;
}

std::array<std::uint8_t, 16> md5(std::string_view data) {
    Md5 h;
    h.update(data);
    return h.finish();
}

Sha256::Sha256() {
    state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
}

void Sha256::block(const std::uint8_t* p) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = read_be32(p + i * 4);
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + s1 + ch + kSha256Table[i] + w[i];
        const std::uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
}

void Sha256::update(const void* data, std::size_t size) {
    const auto* p = static_cast<const std::uint8_t*>(data);
    length_ += size;
    if (buffered_ != 0) {
        const std::size_t need = 64 - buffered_;
        const std::size_t take = size < need ? size : need;
        std::memcpy(buffer_.data() + buffered_, p, take);
        buffered_ += take;
        p += take;
        size -= take;
        if (buffered_ == 64) {
            block(buffer_.data());
            buffered_ = 0;
        }
    }
    while (size >= 64) {
        block(p);
        p += 64;
        size -= 64;
    }
    if (size != 0) {
        std::memcpy(buffer_.data(), p, size);
        buffered_ = size;
    }
}

void Sha256::update(std::string_view data) { update(data.data(), data.size()); }

std::array<std::uint8_t, 32> Sha256::finish() {
    const std::uint64_t bits = length_ * 8;
    std::uint8_t padding[72] = {0x80};
    const std::size_t pad_len = (buffered_ < 56) ? (56 - buffered_) : (120 - buffered_);
    update(padding, pad_len);
    std::uint8_t tail[8];
    for (int i = 0; i < 8; ++i) tail[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
    update(tail, 8);

    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 8; ++i)
        write_be32(out.data() + i * 4, state_[i]);
    return out;
}

std::array<std::uint8_t, 32> sha256(std::string_view data) {
    Sha256 h;
    h.update(data);
    return h.finish();
}

namespace {

constexpr std::uint64_t rotr64(std::uint64_t x, int n) noexcept {
    return (x >> n) | (x << (64 - n));
}
constexpr std::uint64_t read_be64(const std::uint8_t* p) noexcept {
    std::uint64_t value = 0;
    for (int i = 0; i < 8; ++i) value = (value << 8) | p[i];
    return value;
}
inline void write_be64(std::uint8_t* p, std::uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
}

class Sha512Core {
public:
    explicit Sha512Core(const std::uint64_t iv[8]) {
        for (int i = 0; i < 8; ++i) state_[static_cast<std::size_t>(i)] = iv[i];
    }

    void update(const void* data, std::size_t size) {
        const auto* p = static_cast<const std::uint8_t*>(data);
        length_ += size;
        if (buffered_ != 0) {
            const std::size_t need = 128 - buffered_;
            const std::size_t take = size < need ? size : need;
            std::memcpy(buffer_.data() + buffered_, p, take);
            buffered_ += take;
            p += take;
            size -= take;
            if (buffered_ == 128) {
                block(buffer_.data());
                buffered_ = 0;
            }
        }
        while (size >= 128) {
            block(p);
            p += 128;
            size -= 128;
        }
        if (size != 0) {
            std::memcpy(buffer_.data(), p, size);
            buffered_ = size;
        }
    }

    std::array<std::uint8_t, 64> finish() {
        const std::uint64_t bits = length_ * 8;
        std::uint8_t padding[256] = {0x80};
        const std::size_t pad_len = (buffered_ < 112) ? (112 - buffered_) : (240 - buffered_);
        update(padding, pad_len);
        std::uint8_t tail[16] = {};
        // The high 64 bits of the 128-bit length are always zero here: a single
        // document stream is nowhere near 2^61 bytes.
        write_be64(tail + 8, bits);
        update(tail, 16);

        std::array<std::uint8_t, 64> out{};
        for (int i = 0; i < 8; ++i)
            write_be64(out.data() + i * 8, state_[static_cast<std::size_t>(i)]);
        return out;
    }

private:
    void block(const std::uint8_t* p) {
        std::uint64_t w[80];
        for (int i = 0; i < 16; ++i) w[i] = read_be64(p + i * 8);
        for (int i = 16; i < 80; ++i) {
            const std::uint64_t s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
            const std::uint64_t s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint64_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        std::uint64_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int i = 0; i < 80; ++i) {
            const std::uint64_t s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
            const std::uint64_t ch = (e & f) ^ (~e & g);
            const std::uint64_t t1 = h + s1 + ch + sha512_constants::kRoundConstants[i] + w[i];
            const std::uint64_t s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
            const std::uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint64_t t2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        const std::uint64_t add[8] = {a, b, c, d, e, f, g, h};
        for (int i = 0; i < 8; ++i) state_[static_cast<std::size_t>(i)] += add[i];
    }

    std::array<std::uint64_t, 8> state_{};
    std::array<std::uint8_t, 128> buffer_{};
    std::uint64_t length_ = 0;
    std::size_t buffered_ = 0;
};

}  // namespace

std::array<std::uint8_t, 64> sha512(std::string_view data) {
    Sha512Core core(sha512_constants::kInitial512);
    core.update(data.data(), data.size());
    return core.finish();
}

std::array<std::uint8_t, 48> sha384(std::string_view data) {
    Sha512Core core(sha512_constants::kInitial384);
    core.update(data.data(), data.size());
    const auto full = core.finish();
    std::array<std::uint8_t, 48> out{};
    std::memcpy(out.data(), full.data(), out.size());
    return out;
}

Bytes random_bytes(std::size_t count) {
    Bytes out(count);
#if defined(_WIN32)
    if (BCryptGenRandom(nullptr, out.data(), static_cast<ULONG>(count),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0)
        return out;
#endif
#if defined(__linux__)
    std::size_t filled = 0;
    while (filled < count) {
        const ssize_t n = ::getrandom(out.data() + filled, count - filled, 0);
        if (n <= 0) break;
        filled += static_cast<std::size_t>(n);
    }
    if (filled == count) return out;
#endif
    static thread_local std::mt19937_64 engine{std::random_device{}()};
    for (std::size_t i = 0; i < count; ++i)
        out[i] = static_cast<Byte>(engine() & 0xFFu);
    return out;
}

}  // namespace scour

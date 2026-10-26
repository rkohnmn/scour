// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Cryptographic primitives written for this project: RC4, AES-128/256 in CBC
// mode, and the PDF standard security handler revisions 2-6. Only the standard
// handler is supported, because it is the only one in wide use; everything else
// is reported as unsupported rather than silently mishandled.
#include "scour/crypt.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

#include "scour/hash.hpp"
#include "scour/object.hpp"

namespace scour {

const std::array<std::uint8_t, 32> kPasswordPadding = {
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A};

std::string_view to_string(CryptMethod method) noexcept {
    switch (method) {
        case CryptMethod::Identity: return "none";
        case CryptMethod::Rc4: return "RC4";
        case CryptMethod::Aes128: return "AES-128";
        case CryptMethod::Aes256: return "AES-256";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// RC4
// ---------------------------------------------------------------------------
namespace {

struct Rc4State {
    std::array<std::uint8_t, 256> s{};
    std::uint8_t i = 0;
    std::uint8_t j = 0;
};

Rc4State rc4_init(const Bytes& key) {
    Rc4State state;
    for (std::size_t i = 0; i < 256; ++i) state.s[i] = static_cast<std::uint8_t>(i);
    if (key.empty()) return state;
    std::size_t j = 0;
    for (std::size_t i = 0; i < 256; ++i) {
        j = (j + state.s[i] + static_cast<unsigned char>(key[i % key.size()])) & 0xFF;
        std::swap(state.s[i], state.s[j]);
    }
    return state;
}

void rc4_apply(Rc4State& state, char* data, std::size_t size) {
    for (std::size_t k = 0; k < size; ++k) {
        state.i = static_cast<std::uint8_t>(state.i + 1);
        state.j = static_cast<std::uint8_t>(state.j + state.s[state.i]);
        std::swap(state.s[state.i], state.s[state.j]);
        const std::uint8_t byte =
            state.s[static_cast<std::size_t>((state.s[state.i] + state.s[state.j]) & 0xFF)];
        data[k] = static_cast<char>(static_cast<std::uint8_t>(data[k]) ^ byte);
    }
}

}  // namespace

void rc4_inplace(const Bytes& key, Bytes& data) {
    if (data.empty()) return;
    Rc4State state = rc4_init(key);
    rc4_apply(state, reinterpret_cast<char*>(data.data()), data.size());
}

Bytes rc4(const Bytes& key, std::string_view data) {
    Bytes out = bytes_of(data);
    rc4_inplace(key, out);
    return out;
}

// ---------------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------------
namespace {

constexpr std::uint8_t xtime(std::uint8_t x) noexcept {
    return static_cast<std::uint8_t>((x << 1) ^ ((x >> 7) * 0x1B));
}

std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t product = 0;
    for (int i = 0; i < 8; ++i) {
        if ((b & 1) != 0) product ^= a;
        const bool high = (a & 0x80) != 0;
        a = static_cast<std::uint8_t>(a << 1);
        if (high) a ^= 0x1B;
        b = static_cast<std::uint8_t>(b >> 1);
    }
    return product;
}

std::uint8_t gf_inverse(std::uint8_t a) noexcept {
    if (a == 0) return 0;
    // a^254 == a^-1 in GF(2^8).
    std::uint8_t result = 1;
    std::uint8_t base = a;
    int exponent = 254;
    while (exponent > 0) {
        if ((exponent & 1) != 0) result = gf_mul(result, base);
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    return result;
}

struct AesTables {
    std::array<std::uint8_t, 256> sbox{};
    std::array<std::uint8_t, 256> inverse_sbox{};

    AesTables() {
        for (int i = 0; i < 256; ++i) {
            const auto inv = gf_inverse(static_cast<std::uint8_t>(i));
            // Affine transform: b ^ rotl(b,1) ^ rotl(b,2) ^ rotl(b,3) ^ rotl(b,4) ^ 0x63.
            const std::uint8_t rotated =
                static_cast<std::uint8_t>(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^
                                          rotl8(inv, 4));
            const auto value = static_cast<std::uint8_t>(rotated ^ 0x63);
            sbox[static_cast<std::size_t>(i)] = value;
            inverse_sbox[value] = static_cast<std::uint8_t>(i);
        }
    }

    static std::uint8_t rotl8(std::uint8_t value, int n) noexcept {
        return static_cast<std::uint8_t>((value << n) | (value >> (8 - n)));
    }
};

const AesTables& aes_tables() {
    static const AesTables tables;
    return tables;
}

void add_round_key(std::uint8_t state[16], const std::uint8_t* round_key) noexcept {
    for (int i = 0; i < 16; ++i) state[i] ^= round_key[i];
}

void sub_bytes(std::uint8_t state[16]) noexcept {
    const auto& sbox = aes_tables().sbox;
    for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

void inverse_sub_bytes(std::uint8_t state[16]) noexcept {
    const auto& sbox = aes_tables().inverse_sbox;
    for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
}

// State is column-major: state[row + 4 * column].
void shift_rows(std::uint8_t state[16]) noexcept {
    std::uint8_t copy[16];
    std::memcpy(copy, state, 16);
    for (int row = 1; row < 4; ++row) {
        for (int column = 0; column < 4; ++column) {
            state[static_cast<std::size_t>(row + 4 * column)] =
                copy[static_cast<std::size_t>(row + 4 * ((column + row) % 4))];
        }
    }
}

void inverse_shift_rows(std::uint8_t state[16]) noexcept {
    std::uint8_t copy[16];
    std::memcpy(copy, state, 16);
    for (int row = 1; row < 4; ++row) {
        for (int column = 0; column < 4; ++column) {
            state[static_cast<std::size_t>(row + 4 * column)] =
                copy[static_cast<std::size_t>(row + 4 * ((column - row + 4) % 4))];
        }
    }
}

void mix_columns(std::uint8_t state[16]) noexcept {
    for (int column = 0; column < 4; ++column) {
        const std::size_t base = static_cast<std::size_t>(column * 4);
        const std::uint8_t a0 = state[base];
        const std::uint8_t a1 = state[base + 1];
        const std::uint8_t a2 = state[base + 2];
        const std::uint8_t a3 = state[base + 3];
        state[base] = static_cast<std::uint8_t>(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
        state[base + 1] = static_cast<std::uint8_t>(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
        state[base + 2] = static_cast<std::uint8_t>(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
        state[base + 3] = static_cast<std::uint8_t>(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
    }
}

void inverse_mix_columns(std::uint8_t state[16]) noexcept {
    for (int column = 0; column < 4; ++column) {
        const std::size_t base = static_cast<std::size_t>(column * 4);
        const std::uint8_t a0 = state[base];
        const std::uint8_t a1 = state[base + 1];
        const std::uint8_t a2 = state[base + 2];
        const std::uint8_t a3 = state[base + 3];
        state[base] = static_cast<std::uint8_t>(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^
                                               gf_mul(a3, 9));
        state[base + 1] = static_cast<std::uint8_t>(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^
                                                    gf_mul(a2, 11) ^ gf_mul(a3, 13));
        state[base + 2] = static_cast<std::uint8_t>(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^
                                                    gf_mul(a2, 14) ^ gf_mul(a3, 11));
        state[base + 3] = static_cast<std::uint8_t>(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^
                                                    gf_mul(a2, 9) ^ gf_mul(a3, 14));
    }
}

Bytes cbc_run(const Bytes& key, const Bytes& iv, std::string_view data, bool encrypt,
              bool pad_input) {
    if (key.size() != 16 && key.size() != 32)
        throw ScourError("pdf.crypt.bad-key", "AES key must be 16 or 32 bytes");
    if (iv.size() != 16) throw ScourError("pdf.crypt.bad-iv", "AES IV must be 16 bytes");
    Aes aes(key);
    Bytes input = bytes_of(data);
    if (encrypt && pad_input) {
        const std::size_t padding = 16 - (input.size() % 16);
        input.insert(input.end(), padding, static_cast<Byte>(padding));
    }
    if (input.size() % 16 != 0) {
        if (encrypt) throw ScourError("pdf.crypt.bad-length", "AES plaintext is not block aligned");
        input.resize(input.size() - (input.size() % 16));
    }
    Bytes out(input.size());
    std::uint8_t previous[16];
    std::memcpy(previous, iv.data(), 16);
    std::uint8_t block[16];
    for (std::size_t offset = 0; offset < input.size(); offset += 16) {
        if (encrypt) {
            for (int i = 0; i < 16; ++i)
                block[i] = static_cast<std::uint8_t>(input[offset + static_cast<std::size_t>(i)] ^ previous[i]);
            aes.encrypt_block(block, out.data() + offset);
            std::memcpy(previous, out.data() + offset, 16);
        } else {
            aes.decrypt_block(input.data() + offset, block);
            for (int i = 0; i < 16; ++i)
                out[offset + static_cast<std::size_t>(i)] = static_cast<Byte>(block[i] ^ previous[i]);
            std::memcpy(previous, input.data() + offset, 16);
        }
    }
    if (!encrypt && pad_input && !out.empty()) {
        const auto padding = static_cast<std::size_t>(out.back());
        if (padding >= 1 && padding <= 16 && padding <= out.size()) {
            bool valid = true;
            for (std::size_t i = 0; i < padding; ++i) {
                if (out[out.size() - 1 - i] != static_cast<Byte>(padding)) {
                    valid = false;
                    break;
                }
            }
            if (valid) out.resize(out.size() - padding);
        }
    }
    return out;
}

}  // namespace

Aes::Aes(const Bytes& key) { expand_key(key); }

void Aes::expand_key(const Bytes& key) {
    if (key.size() != 16 && key.size() != 32)
        throw ScourError("pdf.crypt.bad-key", "AES key must be 16 or 32 bytes");
    key_size_ = key.size();
    const int nk = static_cast<int>(key_size_ / 4);
    rounds_ = nk + 6;
    const auto& sbox = aes_tables().sbox;
    const int total_words = 4 * (rounds_ + 1);
    std::vector<std::uint8_t> words(static_cast<std::size_t>(total_words) * 4, 0);
    std::memcpy(words.data(), key.data(), key.size());

    std::uint8_t rcon = 1;
    for (int i = nk; i < total_words; ++i) {
        std::uint8_t temp[4];
        const std::size_t previous = static_cast<std::size_t>(i - 1) * 4;
        std::memcpy(temp, words.data() + previous, 4);
        if (i % nk == 0) {
            const std::uint8_t first = temp[0];
            temp[0] = static_cast<std::uint8_t>(sbox[temp[1]] ^ rcon);
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[first];
            rcon = xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (std::uint8_t& byte : temp) byte = sbox[byte];
        }
        const std::size_t from = static_cast<std::size_t>(i - nk) * 4;
        const std::size_t to = static_cast<std::size_t>(i) * 4;
        for (int k = 0; k < 4; ++k) words[to + static_cast<std::size_t>(k)] =
                static_cast<std::uint8_t>(words[from + static_cast<std::size_t>(k)] ^ temp[k]);
    }
    std::memcpy(round_keys_.data(), words.data(),
                static_cast<std::size_t>(total_words) * 4);
}

void Aes::encrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const {
    std::uint8_t state[16];
    std::memcpy(state, in, 16);
    add_round_key(state, round_keys_.data());
    for (int round = 1; round < rounds_; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys_.data() + static_cast<std::size_t>(round) * 16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys_.data() + static_cast<std::size_t>(rounds_) * 16);
    std::memcpy(out, state, 16);
}

void Aes::decrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const {
    std::uint8_t state[16];
    std::memcpy(state, in, 16);
    add_round_key(state, round_keys_.data() + static_cast<std::size_t>(rounds_) * 16);
    for (int round = rounds_ - 1; round >= 1; --round) {
        inverse_shift_rows(state);
        inverse_sub_bytes(state);
        add_round_key(state, round_keys_.data() + static_cast<std::size_t>(round) * 16);
        inverse_mix_columns(state);
    }
    inverse_shift_rows(state);
    inverse_sub_bytes(state);
    add_round_key(state, round_keys_.data());
    std::memcpy(out, state, 16);
}

Bytes aes_cbc_encrypt(const Bytes& key, const Bytes& iv, std::string_view plain) {
    return cbc_run(key, iv, plain, true, true);
}

Bytes aes_cbc_decrypt(const Bytes& key, const Bytes& iv, std::string_view cipher) {
    return cbc_run(key, iv, cipher, false, true);
}

Bytes aes_cbc_encrypt_raw(const Bytes& key, const Bytes& iv, std::string_view plain) {
    return cbc_run(key, iv, plain, true, false);
}

Bytes aes_cbc_decrypt_raw(const Bytes& key, const Bytes& iv, std::string_view cipher) {
    return cbc_run(key, iv, cipher, false, false);
}

Bytes aes_256_cbc_zero_iv(const Bytes& key, std::string_view cipher) {
    const Bytes iv(16, 0);
    return cbc_run(key, iv, cipher, false, false);
}

// ---------------------------------------------------------------------------
// Security handler
// ---------------------------------------------------------------------------
namespace {

Bytes pad_password(std::string_view password) {
    Bytes padded(kPasswordPadding.begin(), kPasswordPadding.end());
    for (std::size_t i = 0; i < password.size() && i < padded.size(); ++i)
        padded[i] = static_cast<Byte>(password[i]);
    return padded;
}

Bytes digest_to_bytes(const std::array<std::uint8_t, 16>& digest) {
    return Bytes(digest.begin(), digest.end());
}

Bytes first_bytes(const Bytes& data, std::size_t count) {
    if (data.size() <= count) return data;
    return Bytes(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(count));
}

Bytes hash_sha256(std::string_view password, std::string_view salt, std::string_view user_data) {
    Sha256 hash;
    hash.update(password);
    hash.update(salt);
    hash.update(user_data);
    const auto digest = hash.finish();
    return Bytes(digest.begin(), digest.end());
}

std::string_view substring(std::string_view text, std::size_t offset, std::size_t count) {
    if (offset >= text.size()) return {};
    return text.substr(offset, count);
}

}  // namespace

Bytes hash_r6(std::string_view password, std::string_view salt, std::string_view user_data,
              int revision) {
    Bytes k = hash_sha256(password, salt, user_data);
    if (revision <= 5) return k;

    const Bytes password_bytes = bytes_of(password);
    const Bytes user_bytes = bytes_of(user_data);
    int round = 0;
    for (;;) {
        Bytes block;
        block.reserve((password_bytes.size() + k.size() + user_bytes.size()) * 64);
        for (int i = 0; i < 64; ++i) {
            append(block, view_of(password_bytes));
            append(block, view_of(k));
            append(block, view_of(user_bytes));
        }
        const Bytes key(k.begin(), k.begin() + 16);
        const Bytes iv(k.begin() + 16, k.begin() + 32);
        const Bytes e = aes_cbc_encrypt_raw(key, iv, view_of(block));

        std::uint32_t sum = 0;
        for (int i = 0; i < 16; ++i) sum += e[static_cast<std::size_t>(i)];
        const int selector = static_cast<int>(sum % 3);
        if (selector == 0) {
            const auto digest = sha256(view_of(e));
            k.assign(digest.begin(), digest.end());
        } else if (selector == 1) {
            const auto digest = sha384(view_of(e));
            k.assign(digest.begin(), digest.end());
        } else {
            const auto digest = sha512(view_of(e));
            k.assign(digest.begin(), digest.end());
        }
        ++round;
        if (round >= 64 && !e.empty() && e.back() <= static_cast<Byte>(round - 32)) break;
        if (round > 512) break;  // defensive: never loop forever on hostile input
    }
    return first_bytes(k, 32);
}

CryptMethod SecurityHandler::method_for_name(std::string_view name, const Dict* cf) const {
    if (name.empty() || name == "Identity") return CryptMethod::Identity;
    if (cf != nullptr) {
        if (const Object* filter = cf->find(name); filter != nullptr && filter->is_dict()) {
            const std::string method = filter->dict().get_name("CFM", "None");
            if (method == "V2") return CryptMethod::Rc4;
            if (method == "AESV2") return CryptMethod::Aes128;
            if (method == "AESV3") return CryptMethod::Aes256;
            if (method == "None") return CryptMethod::Identity;
        }
    }
    return CryptMethod::Rc4;
}

Bytes SecurityHandler::file_key_from_password(std::string_view password) const {
    const Bytes padded = pad_password(password);
    Md5 hash;
    hash.update(view_of(padded));
    hash.update(o_);
    const auto permissions = static_cast<std::uint32_t>(info_.permissions);
    const std::uint8_t p[4] = {
        static_cast<std::uint8_t>(permissions), static_cast<std::uint8_t>(permissions >> 8),
        static_cast<std::uint8_t>(permissions >> 16), static_cast<std::uint8_t>(permissions >> 24)};
    hash.update(p, 4);
    hash.update(id0_);
    if (info_.revision >= 4 && !info_.encrypt_metadata) {
        const std::uint8_t marker[4] = {0xFF, 0xFF, 0xFF, 0xFF};
        hash.update(marker, 4);
    }
    Bytes digest = digest_to_bytes(hash.finish());
    if (info_.revision >= 3) {
        for (int i = 0; i < 50; ++i) {
            const auto again = md5(view_of(first_bytes(digest, file_key_size_)));
            digest.assign(again.begin(), again.end());
        }
    }
    return first_bytes(digest, file_key_size_);
}

bool SecurityHandler::check_user_password(std::string_view password, const Bytes& key) const {
    const Bytes padded = pad_password(password);
    if (info_.revision == 2) {
        const Bytes result = rc4(key, view_of(padded));
        return result.size() >= u_.size() && std::memcmp(result.data(), u_.data(), u_.size()) == 0;
    }
    Md5 hash;
    hash.update(view_of(padded));
    hash.update(id0_);
    Bytes value = digest_to_bytes(hash.finish());
    value = rc4(key, view_of(value));
    for (int i = 1; i <= 19; ++i) {
        Bytes iteration_key = key;
        for (Byte& byte : iteration_key) byte = static_cast<Byte>(byte ^ static_cast<Byte>(i));
        value = rc4(iteration_key, view_of(value));
    }
    return value.size() >= 16 && u_.size() >= 16 && std::memcmp(value.data(), u_.data(), 16) == 0;
}

bool SecurityHandler::init_r2_r4(const Dict&, std::string_view, std::string_view password,
                                 Diagnostics& diagnostics) {
    file_key_size_ = info_.revision == 2 ? 5 : std::clamp<std::size_t>(
                                                     static_cast<std::size_t>(info_.key_bits / 8), 5, 16);
    info_.key_bits = static_cast<int>(file_key_size_ * 8);
    if (o_.size() < 32 || u_.size() < 16) {
        info_.failure = "encryption dictionary is missing /O or /U";
        diagnostics.error("pdf.encrypt.malformed", info_.failure);
        return false;
    }

    std::vector<std::string> candidates;
    candidates.emplace_back(password);
    if (!password.empty()) candidates.emplace_back();

    for (const std::string& candidate : candidates) {
        Bytes key = file_key_from_password(candidate);
        if (check_user_password(candidate, key)) {
            std::memcpy(file_key_.data(), key.data(), std::min<std::size_t>(key.size(), 32));
            valid_ = true;
            info_.authenticated = true;
            return true;
        }
    }

    // Owner authentication: /O decrypts to the padded user password.
    for (const std::string& candidate : candidates) {
        Md5 hash;
        hash.update(view_of(pad_password(candidate)));
        Bytes owner_key = digest_to_bytes(hash.finish());
        if (info_.revision >= 3) {
            for (int i = 0; i < 50; ++i) {
                const auto again = md5(view_of(first_bytes(owner_key, file_key_size_)));
                owner_key.assign(again.begin(), again.end());
            }
        }
        owner_key = first_bytes(owner_key, file_key_size_);

        Bytes user_password = bytes_of(o_);
        if (info_.revision == 2) {
            user_password = rc4(owner_key, view_of(user_password));
        } else {
            for (int i = 19; i >= 0; --i) {
                Bytes iteration_key = owner_key;
                for (Byte& byte : iteration_key)
                    byte = static_cast<Byte>(byte ^ static_cast<Byte>(i));
                user_password = rc4(iteration_key, view_of(user_password));
            }
        }
        const std::string recovered(reinterpret_cast<const char*>(user_password.data()),
                                    user_password.size());
        Bytes key = file_key_from_password(recovered);
        if (check_user_password(recovered, key)) {
            std::memcpy(file_key_.data(), key.data(), std::min<std::size_t>(key.size(), 32));
            valid_ = true;
            info_.authenticated = true;
            info_.owner_password_used = true;
            return true;
        }
    }

    info_.failure = "a document open password is required";
    diagnostics.warn("pdf.encrypt.password", info_.failure);
    return false;
}

bool SecurityHandler::init_r5_r6(const Dict&, std::string_view, std::string_view password,
                                 Diagnostics& diagnostics) {
    file_key_size_ = 32;
    info_.key_bits = 256;
    if (u_.size() < 48 || o_.size() < 48 || ue_.size() < 32 || oe_.size() < 32) {
        info_.failure = "AES-256 encryption dictionary is incomplete";
        diagnostics.error("pdf.encrypt.malformed", info_.failure);
        return false;
    }
    const int revision = info_.revision;

    auto hash_password = [&](std::string_view pw, std::string_view salt,
                             std::string_view user_data) {
        return hash_r6(pw, salt, user_data, revision);
    };

    std::vector<std::string> candidates;
    candidates.emplace_back(password);
    if (!password.empty()) candidates.emplace_back();

    for (const std::string& candidate : candidates) {
        const Bytes validation = hash_password(candidate, substring(u_, 32, 8), {});
        if (validation.size() >= 32 && std::memcmp(validation.data(), u_.data(), 32) == 0) {
            const Bytes intermediate = hash_password(candidate, substring(u_, 40, 8), {});
            const Bytes key = aes_256_cbc_zero_iv(intermediate, substring(ue_, 0, 32));
            if (key.size() != 32) continue;
            std::memcpy(file_key_.data(), key.data(), 32);
            valid_ = true;
            info_.authenticated = true;
            return true;
        }
    }

    for (const std::string& candidate : candidates) {
        const std::string_view user_48(u_.data(), 48);
        const Bytes validation = hash_password(candidate, substring(o_, 32, 8), user_48);
        if (validation.size() < 32 || std::memcmp(validation.data(), o_.data(), 32) != 0) continue;
        const Bytes intermediate = hash_password(candidate, substring(o_, 40, 8), user_48);
        const Bytes key = aes_256_cbc_zero_iv(intermediate, substring(oe_, 0, 32));
        if (key.size() != 32) continue;
        std::memcpy(file_key_.data(), key.data(), 32);
        valid_ = true;
        info_.authenticated = true;
        info_.owner_password_used = true;
        return true;
    }

    info_.failure = "a document open password is required";
    diagnostics.warn("pdf.encrypt.password", info_.failure);
    return false;
}

SecurityHandler SecurityHandler::create(const Object& encrypt_dict, std::string_view id0,
                                        std::string_view password, Diagnostics& diagnostics) {
    SecurityHandler handler;
    handler.id0_ = std::string(id0);
    handler.info_.encrypted = true;

    const Dict& dict = encrypt_dict.dict();
    handler.info_.filter = dict.get_name("Filter", "Standard");
    handler.info_.version = static_cast<int>(dict.get_int("V", 0));
    handler.info_.revision = static_cast<int>(dict.get_int("R", 0));
    handler.info_.key_bits = static_cast<int>(dict.get_int("Length", 40));
    handler.info_.permissions = static_cast<std::int32_t>(dict.get_int("P", 0));
    handler.info_.encrypt_metadata = dict.get_bool("EncryptMetadata", true);

    if (handler.info_.revision == 0) {
        // Broken writers omit /R. Infer the revision from /V.
        handler.info_.revision = handler.info_.version >= 5 ? 6
                                 : handler.info_.version == 4 ? 4
                                 : handler.info_.version == 2 ? 3
                                                              : 2;
    }

    const Object* o = dict.find("O");
    const Object* u = dict.find("U");
    handler.o_ = o != nullptr ? o->as_string() : std::string();
    handler.u_ = u != nullptr ? u->as_string() : std::string();
    // /O and /U are binary strings; a producer that wrote them as a name is
    // broken, but we can still recover the bytes.
    if (handler.o_.empty() && o != nullptr && o->is_name()) handler.o_ = o->as_name();
    if (handler.u_.empty() && u != nullptr && u->is_name()) handler.u_ = u->as_name();
    if (const Object* oe = dict.find("OE"); oe != nullptr) handler.oe_ = oe->as_string();
    if (const Object* ue = dict.find("UE"); ue != nullptr) handler.ue_ = ue->as_string();

    const Object* cf_object = dict.find("CF");
    const Dict* cf = (cf_object != nullptr && cf_object->is_dict()) ? &cf_object->dict() : nullptr;
    const std::string stream_filter = dict.get_name("StmF", handler.info_.version >= 4 ? "Identity" : "V2");
    const std::string string_filter = dict.get_name("StrF", stream_filter);
    handler.info_.stream_method = handler.method_for_name(stream_filter, cf);
    handler.info_.string_method = handler.method_for_name(string_filter, cf);

    if (!ascii_ieq(handler.info_.filter, "Standard")) {
        handler.info_.failure = "unsupported security handler /" + handler.info_.filter;
        diagnostics.error("pdf.encrypt.unsupported", handler.info_.failure);
        return handler;
    }

    const bool ok = handler.info_.revision >= 5
                        ? handler.init_r5_r6(dict, id0, password, diagnostics)
                        : handler.init_r2_r4(dict, id0, password, diagnostics);
    if (!ok) {
        handler.valid_ = false;
        handler.info_.authenticated = false;
    }
    return handler;
}

Bytes SecurityHandler::object_key(std::uint32_t number, std::uint16_t generation,
                                  CryptMethod method) const {
    if (method == CryptMethod::Identity) return {};
    if (info_.revision >= 5) return Bytes(file_key_.begin(), file_key_.begin() + 32);
    if (method == CryptMethod::Aes256) return Bytes(file_key_.begin(), file_key_.begin() + 32);

    Md5 hash;
    hash.update(reinterpret_cast<const char*>(file_key_.data()), file_key_size_);
    const std::uint8_t identity[5] = {
        static_cast<std::uint8_t>(number & 0xFF), static_cast<std::uint8_t>((number >> 8) & 0xFF),
        static_cast<std::uint8_t>((number >> 16) & 0xFF),
        static_cast<std::uint8_t>(generation & 0xFF),
        static_cast<std::uint8_t>((generation >> 8) & 0xFF)};
    hash.update(identity, 5);
    if (method == CryptMethod::Aes128) hash.update("sAlT", 4);
    const Bytes digest = digest_to_bytes(hash.finish());
    return first_bytes(digest, std::min<std::size_t>(file_key_size_ + 5, 16));
}

Bytes SecurityHandler::decrypt_stream(std::string_view data, std::uint32_t number,
                                      std::uint16_t generation) const {
    if (!valid_ || info_.stream_method == CryptMethod::Identity || data.empty()) return bytes_of(data);
    const CryptMethod method = info_.stream_method;
    const Bytes key = object_key(number, generation, method);
    if (method == CryptMethod::Rc4) return rc4(key, data);
    if (data.size() < 32) return {};
    const Bytes iv = bytes_of(data.substr(0, 16));
    return aes_cbc_decrypt(key, iv, data.substr(16));
}

std::string SecurityHandler::decrypt_string(std::string_view data, std::uint32_t number,
                                            std::uint16_t generation) const {
    if (!valid_ || info_.string_method == CryptMethod::Identity || data.empty())
        return std::string(data);
    const CryptMethod method = info_.string_method;
    const Bytes key = object_key(number, generation, method);
    if (method == CryptMethod::Rc4) {
        const Bytes out = rc4(key, data);
        return std::string(reinterpret_cast<const char*>(out.data()), out.size());
    }
    if (data.size() < 32) return {};
    const Bytes iv = bytes_of(data.substr(0, 16));
    const Bytes out = aes_cbc_decrypt(key, iv, data.substr(16));
    return std::string(reinterpret_cast<const char*>(out.data()), out.size());
}

}  // namespace scour

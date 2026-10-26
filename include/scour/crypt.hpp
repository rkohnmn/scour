// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_CRYPT_HPP
#define SCOUR_CRYPT_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "scour/bytes.hpp"
#include "scour/error.hpp"

namespace scour {

class Object;
struct Dict;

// ---------------------------------------------------------------------------
// RC4 (PDF 1.1-1.6, revisions 2-4)
// ---------------------------------------------------------------------------
Bytes rc4(const Bytes& key, std::string_view data);
void rc4_inplace(const Bytes& key, Bytes& data);

// ---------------------------------------------------------------------------
// AES-128 / AES-256 (FIPS-197), CBC mode with PKCS#7 padding for streams
// ---------------------------------------------------------------------------
class Aes {
public:
    explicit Aes(const Bytes& key);  // 16 or 32 bytes

    void encrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const;
    void decrypt_block(const std::uint8_t in[16], std::uint8_t out[16]) const;

    [[nodiscard]] std::size_t key_size() const noexcept { return key_size_; }
    [[nodiscard]] int rounds() const noexcept { return rounds_; }

private:
    void expand_key(const Bytes& key);
    std::array<std::uint8_t, 240> round_keys_{};
    std::size_t key_size_ = 16;
    int rounds_ = 10;
};

/// AES-CBC with PKCS#7 padding (PDF stream/string encryption).
Bytes aes_cbc_encrypt(const Bytes& key, const Bytes& iv, std::string_view plain);
Bytes aes_cbc_decrypt(const Bytes& key, const Bytes& iv, std::string_view cipher);

/// AES-CBC without padding; input size must be a multiple of 16.
Bytes aes_cbc_encrypt_raw(const Bytes& key, const Bytes& iv, std::string_view plain);
Bytes aes_cbc_decrypt_raw(const Bytes& key, const Bytes& iv, std::string_view cipher);

/// AES-256 in CBC with an all-zero IV, no padding (used for /UE and /OE).
Bytes aes_256_cbc_zero_iv(const Bytes& key, std::string_view cipher);

// ---------------------------------------------------------------------------
// PDF standard security handler
// ---------------------------------------------------------------------------
enum class CryptMethod { Identity, Rc4, Aes128, Aes256 };

[[nodiscard]] std::string_view to_string(CryptMethod method) noexcept;

/// Everything `scour inspect` wants to say about a document's encryption.
struct EncryptionInfo {
    bool encrypted = false;
    std::string filter;              ///< e.g. "Standard"
    int revision = 0;                ///< /R
    int version = 0;                 ///< /V
    int key_bits = 0;
    std::int32_t permissions = 0;
    bool encrypt_metadata = true;
    bool authenticated = false;      ///< file key recovered
    bool owner_password_used = false;
    CryptMethod stream_method = CryptMethod::Identity;
    CryptMethod string_method = CryptMethod::Identity;
    std::string failure;             ///< set when the document cannot be decrypted

    /// Per-permission flags, decoded from /P.
    [[nodiscard]] bool allow_print() const noexcept { return (permissions & 0x0004) != 0; }
    [[nodiscard]] bool allow_modify() const noexcept { return (permissions & 0x0008) != 0; }
    [[nodiscard]] bool allow_copy() const noexcept { return (permissions & 0x0010) != 0; }
    [[nodiscard]] bool allow_annotate() const noexcept { return (permissions & 0x0020) != 0; }
    [[nodiscard]] bool allow_forms() const noexcept { return (permissions & 0x0100) != 0; }
    [[nodiscard]] bool allow_assemble() const noexcept { return (permissions & 0x0400) != 0; }
    [[nodiscard]] bool allow_accessibility() const noexcept { return (permissions & 0x0200) != 0; }
};

/// Implements password validation and per-object key derivation for the PDF
/// standard security handler, revisions 2 through 6. Scour never guesses at a
/// password: an empty user password is tried first (the common
/// "protected but opens" case), then /O based owner authentication, then the
/// password supplied on the command line.
class SecurityHandler {
public:
    SecurityHandler() = default;

    /// Builds a handler from the document's /Encrypt dictionary. `id0` is the
    /// first element of the trailer /ID (may be empty for broken files).
    static SecurityHandler create(const Object& encrypt_dict, std::string_view id0,
                                  std::string_view password, Diagnostics& diagnostics);

    [[nodiscard]] bool valid() const noexcept { return valid_; }
    [[nodiscard]] const EncryptionInfo& info() const noexcept { return info_; }

    [[nodiscard]] Bytes object_key(std::uint32_t number, std::uint16_t generation,
                                   CryptMethod method) const;
    Bytes decrypt_stream(std::string_view data, std::uint32_t number,
                         std::uint16_t generation) const;
    std::string decrypt_string(std::string_view data, std::uint32_t number,
                               std::uint16_t generation) const;

private:
    bool init_r2_r4(const Dict& dict, std::string_view id0, std::string_view password,
                    Diagnostics& diagnostics);
    bool init_r5_r6(const Dict& dict, std::string_view id0, std::string_view password,
                    Diagnostics& diagnostics);
    [[nodiscard]] CryptMethod method_for_name(std::string_view name, const Dict* cf) const;
    [[nodiscard]] Bytes file_key_from_password(std::string_view password) const;
    [[nodiscard]] bool check_user_password(std::string_view password, const Bytes& key) const;

    bool valid_ = false;
    EncryptionInfo info_;
    std::array<std::uint8_t, 32> file_key_{};
    std::size_t file_key_size_ = 0;
    std::string o_;
    std::string u_;
    std::string oe_;
    std::string ue_;
    std::string id0_;
};

/// The 32 byte password padding string from ISO 32000-1, Algorithm 2.
extern const std::array<std::uint8_t, 32> kPasswordPadding;

/// R6 hardened hash, Algorithm 2.B. Exposed for tests.
Bytes hash_r6(std::string_view password, std::string_view salt, std::string_view user_data,
              int revision);

}  // namespace scour

#endif  // SCOUR_CRYPT_HPP

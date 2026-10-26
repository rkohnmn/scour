// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_DOCUMENT_HPP
#define SCOUR_DOCUMENT_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "scour/bytes.hpp"
#include "scour/crypt.hpp"
#include "scour/error.hpp"
#include "scour/filters.hpp"
#include "scour/object.hpp"

namespace scour {

struct LoadOptions {
    std::string password;   ///< document open password, empty by default
    bool repair = true;     ///< rebuild a damaged cross-reference table by scanning
};

struct XrefEntry {
    enum class Kind : std::uint8_t { Free, InUse, Compressed };
    Kind kind = Kind::Free;
    std::uint64_t offset = 0;   ///< byte offset for InUse entries
    std::uint16_t generation = 0;
    std::uint32_t container = 0;  ///< object stream number for Compressed entries
    std::uint32_t index = 0;
};

/// An in-memory PDF: the cross-reference table, the object store, the trailer,
/// and the security handler. Objects are parsed lazily; the cache is mutable so
/// `const Document&` can still hand out stable pointers, which keeps the
/// inspector and extractor signatures honest.
class Document : public ObjectSource {
public:
    Document();

    static Document load(Bytes file, const LoadOptions& options, Diagnostics& diagnostics);

    // ObjectSource ---------------------------------------------------------
    [[nodiscard]] const Object* resolve(const Object& object) const override;
    [[nodiscard]] const Object* resolve_ref(std::uint32_t number) const override;

    // Object access --------------------------------------------------------
    [[nodiscard]] const Object* object(std::uint32_t number) const;
    [[nodiscard]] Object* mutable_object(std::uint32_t number);
    void set_object(std::uint32_t number, Object value);
    [[nodiscard]] std::uint32_t add_object(Object value);
    bool erase_object(std::uint32_t number);
    [[nodiscard]] std::size_t cached_object_count() const noexcept { return cache_.size(); }
    [[nodiscard]] const std::unordered_map<std::uint32_t, XrefEntry>& xref() const noexcept {
        return xref_;
    }

    // Structure ------------------------------------------------------------
    [[nodiscard]] const Dict& trailer() const noexcept { return trailer_; }
    [[nodiscard]] Dict& trailer() noexcept { return trailer_; }
    [[nodiscard]] const Object* catalog() const;
    [[nodiscard]] Object* mutable_catalog();
    [[nodiscard]] std::uint32_t root_number() const { return trailer_.get_ref("Root"); }
    [[nodiscard]] std::string file_id0() const;

    // Streams --------------------------------------------------------------
    [[nodiscard]] DecodeResult decode_stream_info(const Object& stream, int page = -1) const;
    [[nodiscard]] Bytes decode_stream(const Object& stream, int page = -1) const;
    [[nodiscard]] std::string resolve_string(const Object& object) const;

    // Diagnostics and metadata --------------------------------------------
    [[nodiscard]] const Diagnostics& diagnostics() const noexcept { return diagnostics_; }
    [[nodiscard]] Diagnostics& diagnostics() noexcept { return diagnostics_; }
    [[nodiscard]] int version_major() const noexcept { return version_major_; }
    [[nodiscard]] int version_minor() const noexcept { return version_minor_; }
    [[nodiscard]] std::string version_string() const;
    [[nodiscard]] bool repaired() const noexcept { return repaired_; }
    [[nodiscard]] int revision_count() const noexcept { return revision_count_; }
    [[nodiscard]] bool encrypted() const noexcept { return encrypted_; }
    [[nodiscard]] const SecurityHandler& security() const noexcept { return security_; }
    [[nodiscard]] const Bytes& file_bytes() const noexcept { return file_; }
    [[nodiscard]] std::size_t file_size() const noexcept { return file_.size(); }

    /// Overrides the catalog number when building a new document.
    void set_root_number(std::uint32_t number) { trailer_.set("Root", Object::reference(number)); }

    /// Drops every object that is not referenced from the trailer values given
    /// (usually /Root). Returns the number of objects removed.
    std::size_t collect_garbage(const std::vector<std::string>& trailer_keys = {"Root"});

    /// Drops parsed-but-unreachable objects from the in-memory cache. Used after
    /// a rewrite to prove the output only contains what the caller asked for.
    void clear_cache() noexcept { cache_.clear(); }

private:
    void read_header(Diagnostics& diagnostics);
    bool read_xref_chain(Diagnostics& diagnostics);
    bool read_xref_section(std::uint64_t offset, Dict& trailer,
                           std::unordered_map<std::uint32_t, XrefEntry>& entries,
                           Diagnostics& diagnostics) const;
    void rebuild_from_scan(Diagnostics& diagnostics);
    void setup_encryption(const LoadOptions& options, Diagnostics& diagnostics);
    void decrypt_object(Object& object, std::uint32_t number, std::uint16_t generation) const;
    [[nodiscard]] bool is_xref_stream(const Object& object) const;
    void expand_objstm(std::uint32_t container) const;
    [[nodiscard]] std::uint64_t find_startxref() const;

    Bytes file_;
    std::unordered_map<std::uint32_t, XrefEntry> xref_;
    mutable std::unordered_map<std::uint32_t, Object> cache_;
    mutable std::unordered_set<std::uint32_t> loading_;
    mutable std::unordered_set<std::uint32_t> objstm_expanded_;
    Dict trailer_;
    SecurityHandler security_;
    mutable Diagnostics diagnostics_;
    std::uint32_t encrypt_object_number_ = 0;
    std::uint32_t next_number_ = 1;
    int version_major_ = 1;
    int version_minor_ = 7;
    int revision_count_ = 0;
    bool encrypted_ = false;
    bool repaired_ = false;
};

}  // namespace scour

#endif  // SCOUR_DOCUMENT_HPP

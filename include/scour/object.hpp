// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_OBJECT_HPP
#define SCOUR_OBJECT_HPP

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "scour/bytes.hpp"

namespace scour {

enum class ObjType : std::uint8_t { Null, Bool, Int, Real, String, Name, Array, Dict, Stream, Ref };

[[nodiscard]] std::string_view to_string(ObjType type) noexcept;

class Object;
struct Dict;

/// A PDF object: a small discriminated union with value semantics.
///
/// Two deliberate choices:
///  * dictionaries keep insertion order, so a rewritten file reads back in a
///    predictable order and diffs between two scrubs stay small;
///  * streams keep their *encoded* bytes. Scour only decodes a stream when it
///    truly has to look inside (text, images for inspection). Copying a
///    document therefore never risks silently re-encoding a JPEG.
class Object {
public:
    Object();
    Object(const Object& other);
    Object(Object&& other) noexcept;
    Object& operator=(const Object& other);
    Object& operator=(Object&& other) noexcept;
    ~Object();

    // Factories ------------------------------------------------------------
    static Object null();
    static Object boolean(bool value);
    static Object integer(std::int64_t value);
    static Object real(double value);
    static Object string(std::string bytes);
    static Object name(std::string name);
    static Object array(std::vector<Object> items = {});
    static Object dictionary(Dict dict);
    static Object stream(Dict dict, Bytes encoded);
    static Object reference(std::uint32_t number, std::uint16_t generation = 0);

    // Type inspection ------------------------------------------------------
    [[nodiscard]] ObjType type() const noexcept { return type_; }
    [[nodiscard]] bool is_null() const noexcept { return type_ == ObjType::Null; }
    [[nodiscard]] bool is_bool() const noexcept { return type_ == ObjType::Bool; }
    [[nodiscard]] bool is_int() const noexcept { return type_ == ObjType::Int; }
    [[nodiscard]] bool is_real() const noexcept { return type_ == ObjType::Real; }
    [[nodiscard]] bool is_number() const noexcept { return is_int() || is_real(); }
    [[nodiscard]] bool is_string() const noexcept { return type_ == ObjType::String; }
    [[nodiscard]] bool is_name() const noexcept { return type_ == ObjType::Name; }
    [[nodiscard]] bool is_array() const noexcept { return type_ == ObjType::Array; }
    [[nodiscard]] bool is_dict() const noexcept { return type_ == ObjType::Dict; }
    [[nodiscard]] bool is_stream() const noexcept { return type_ == ObjType::Stream; }
    [[nodiscard]] bool is_dict_like() const noexcept { return is_dict() || is_stream(); }
    [[nodiscard]] bool is_ref() const noexcept { return type_ == ObjType::Ref; }

    // Scalar accessors (never throw; return the fallback on type mismatch) --
    [[nodiscard]] bool as_bool(bool fallback = false) const noexcept;
    [[nodiscard]] std::int64_t as_int(std::int64_t fallback = 0) const noexcept;
    [[nodiscard]] double as_real(double fallback = 0.0) const noexcept;
    [[nodiscard]] double as_number(double fallback = 0.0) const noexcept;
    [[nodiscard]] const std::string& as_string() const noexcept;
    [[nodiscard]] const std::string& as_name() const noexcept;
    [[nodiscard]] std::uint32_t ref_number() const noexcept { return ref_number_; }
    [[nodiscard]] std::uint16_t ref_generation() const noexcept { return ref_generation_; }

    // Containers -----------------------------------------------------------
    [[nodiscard]] std::vector<Object>& items();              // arrays
    [[nodiscard]] const std::vector<Object>& items() const;  // arrays
    [[nodiscard]] Dict& dict();                              // dicts and streams
    [[nodiscard]] const Dict& dict() const;
    [[nodiscard]] const Dict* dict_if_any() const noexcept;

    /// Encoded (still filtered) stream bytes.
    [[nodiscard]] Bytes& stream_data();
    [[nodiscard]] const Bytes& stream_data() const;
    void set_stream_data(Bytes data);

    // Mutation shortcuts ---------------------------------------------------
    void set(std::string key, Object value);
    [[nodiscard]] const Object* find(std::string_view key) const;
    [[nodiscard]] Object* find(std::string_view key);
    bool remove(std::string_view key);

    [[nodiscard]] bool equals(const Object& other) const;

    /// Compact single-line rendering for diagnostics and tests ("/Type /Page").
    [[nodiscard]] std::string debug_string(int depth = 0) const;

private:
    void copy_from(const Object& other);

    ObjType type_ = ObjType::Null;
    bool bool_ = false;
    std::int64_t int_ = 0;
    double real_ = 0.0;
    std::string text_;                  // string bytes or name
    std::vector<Object> array_;
    std::unique_ptr<Dict> dict_;
    std::unique_ptr<Bytes> stream_;
    std::uint32_t ref_number_ = 0;
    std::uint16_t ref_generation_ = 0;
};

/// Ordered dictionary. Lookup is linear: real PDF dictionaries have fewer than a
/// dozen keys, and an unordered_map costs more in allocation than it saves.
struct Dict {
    std::vector<std::pair<std::string, Object>> items;

    [[nodiscard]] const Object* find(std::string_view key) const;
    [[nodiscard]] Object* find(std::string_view key);
    [[nodiscard]] bool contains(std::string_view key) const { return find(key) != nullptr; }
    Object& set(std::string key, Object value);
    bool erase(std::string_view key);
    [[nodiscard]] std::size_t size() const noexcept { return items.size(); }
    [[nodiscard]] bool empty() const noexcept { return items.empty(); }

    [[nodiscard]] std::int64_t get_int(std::string_view key, std::int64_t fallback = 0) const;
    [[nodiscard]] double get_real(std::string_view key, double fallback = 0.0) const;
    [[nodiscard]] bool get_bool(std::string_view key, bool fallback = false) const;
    [[nodiscard]] std::string get_name(std::string_view key, std::string_view fallback = {}) const;
    [[nodiscard]] std::string get_string(std::string_view key,
                                         std::string_view fallback = {}) const;
    [[nodiscard]] std::uint32_t get_ref(std::string_view key) const;  // 0 when absent
    [[nodiscard]] Object* get_array(std::string_view key);
    [[nodiscard]] Object* get_dict(std::string_view key);
    [[nodiscard]] std::string debug_string(int depth = 0) const;
};

/// Resolves references through a document store. Implemented by Document; kept
/// abstract so the inspector and text extractor can be tested with plain maps.
class ObjectSource {
public:
    virtual ~ObjectSource() = default;
    [[nodiscard]] virtual const Object* resolve(const Object& object) const = 0;
    [[nodiscard]] virtual const Object* resolve_ref(std::uint32_t number) const = 0;
};

}  // namespace scour

#endif  // SCOUR_OBJECT_HPP

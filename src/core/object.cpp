// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/object.hpp"

#include <cmath>
#include <cstdio>

namespace scour {

std::string_view to_string(ObjType type) noexcept {
    switch (type) {
        case ObjType::Null: return "null";
        case ObjType::Bool: return "bool";
        case ObjType::Int: return "int";
        case ObjType::Real: return "real";
        case ObjType::String: return "string";
        case ObjType::Name: return "name";
        case ObjType::Array: return "array";
        case ObjType::Dict: return "dict";
        case ObjType::Stream: return "stream";
        case ObjType::Ref: return "ref";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------
Object::Object() = default;
Object::~Object() = default;

Object::Object(const Object& other) { copy_from(other); }

Object::Object(Object&& other) noexcept = default;

Object& Object::operator=(const Object& other) {
    if (this != &other) copy_from(other);
    return *this;
}

Object& Object::operator=(Object&& other) noexcept = default;

void Object::copy_from(const Object& other) {
    type_ = other.type_;
    bool_ = other.bool_;
    int_ = other.int_;
    real_ = other.real_;
    text_ = other.text_;
    array_ = other.array_;
    dict_ = other.dict_ ? std::make_unique<Dict>(*other.dict_) : nullptr;
    stream_ = other.stream_ ? std::make_unique<Bytes>(*other.stream_) : nullptr;
    ref_number_ = other.ref_number_;
    ref_generation_ = other.ref_generation_;
}

Object Object::null() { return Object(); }

Object Object::boolean(bool value) {
    Object o;
    o.type_ = ObjType::Bool;
    o.bool_ = value;
    return o;
}

Object Object::integer(std::int64_t value) {
    Object o;
    o.type_ = ObjType::Int;
    o.int_ = value;
    return o;
}

Object Object::real(double value) {
    Object o;
    o.type_ = ObjType::Real;
    o.real_ = value;
    return o;
}

Object Object::string(std::string bytes) {
    Object o;
    o.type_ = ObjType::String;
    o.text_ = std::move(bytes);
    return o;
}

Object Object::name(std::string value) {
    Object o;
    o.type_ = ObjType::Name;
    o.text_ = std::move(value);
    return o;
}

Object Object::array(std::vector<Object> items) {
    Object o;
    o.type_ = ObjType::Array;
    o.array_ = std::move(items);
    return o;
}

Object Object::dictionary(Dict dict_value) {
    Object o;
    o.type_ = ObjType::Dict;
    o.dict_ = std::make_unique<Dict>(std::move(dict_value));
    return o;
}

Object Object::stream(Dict dict_value, Bytes encoded) {
    Object o;
    o.type_ = ObjType::Stream;
    o.dict_ = std::make_unique<Dict>(std::move(dict_value));
    o.stream_ = std::make_unique<Bytes>(std::move(encoded));
    return o;
}

Object Object::reference(std::uint32_t number, std::uint16_t generation) {
    Object o;
    o.type_ = ObjType::Ref;
    o.ref_number_ = number;
    o.ref_generation_ = generation;
    return o;
}

bool Object::as_bool(bool fallback) const noexcept {
    return type_ == ObjType::Bool ? bool_ : fallback;
}

std::int64_t Object::as_int(std::int64_t fallback) const noexcept {
    switch (type_) {
        case ObjType::Int: return int_;
        case ObjType::Real: return static_cast<std::int64_t>(real_);
        case ObjType::Bool: return bool_ ? 1 : 0;
        default: return fallback;
    }
}

double Object::as_real(double fallback) const noexcept {
    switch (type_) {
        case ObjType::Real: return real_;
        case ObjType::Int: return static_cast<double>(int_);
        default: return fallback;
    }
}

double Object::as_number(double fallback) const noexcept {
    return (type_ == ObjType::Int || type_ == ObjType::Real) ? as_real(fallback) : fallback;
}

const std::string& Object::as_string() const noexcept {
    static const std::string kEmpty;
    return type_ == ObjType::String ? text_ : kEmpty;
}

const std::string& Object::as_name() const noexcept {
    static const std::string kEmpty;
    return type_ == ObjType::Name ? text_ : kEmpty;
}

std::vector<Object>& Object::items() {
    static std::vector<Object> kEmpty;
    return type_ == ObjType::Array ? array_ : kEmpty;
}

const std::vector<Object>& Object::items() const {
    static const std::vector<Object> kEmpty;
    return type_ == ObjType::Array ? array_ : kEmpty;
}

Dict& Object::dict() {
    if (!dict_) dict_ = std::make_unique<Dict>();
    return *dict_;
}

const Dict& Object::dict() const {
    static const Dict kEmpty;
    return dict_ ? *dict_ : kEmpty;
}

const Dict* Object::dict_if_any() const noexcept { return dict_.get(); }

Bytes& Object::stream_data() {
    if (!stream_) stream_ = std::make_unique<Bytes>();
    return *stream_;
}

const Bytes& Object::stream_data() const {
    static const Bytes kEmpty;
    return stream_ ? *stream_ : kEmpty;
}

void Object::set_stream_data(Bytes data) {
    if (!stream_) stream_ = std::make_unique<Bytes>();
    *stream_ = std::move(data);
}

void Object::set(std::string key, Object value) {
    if (type_ == ObjType::Null) type_ = ObjType::Dict;
    dict().set(std::move(key), std::move(value));
}

const Object* Object::find(std::string_view key) const { return dict().find(key); }

Object* Object::find(std::string_view key) {
    return dict_ ? dict_->find(key) : nullptr;
}

bool Object::remove(std::string_view key) { return dict_ ? dict_->erase(key) : false; }

bool Object::equals(const Object& other) const {
    if (type_ != other.type_) return false;
    switch (type_) {
        case ObjType::Null: return true;
        case ObjType::Bool: return bool_ == other.bool_;
        case ObjType::Int: return int_ == other.int_;
        case ObjType::Real: return std::fabs(real_ - other.real_) < 1e-9;
        case ObjType::String:
        case ObjType::Name: return text_ == other.text_;
        case ObjType::Ref:
            return ref_number_ == other.ref_number_ && ref_generation_ == other.ref_generation_;
        case ObjType::Array:
            if (array_.size() != other.array_.size()) return false;
            for (std::size_t i = 0; i < array_.size(); ++i) {
                if (!array_[i].equals(other.array_[i])) return false;
            }
            return true;
        case ObjType::Dict:
        case ObjType::Stream:
            if (dict().size() != other.dict().size()) return false;
            for (const auto& [key, value] : dict().items) {
                const Object* theirs = other.dict().find(key);
                if (theirs == nullptr || !value.equals(*theirs)) return false;
            }
            return type_ != ObjType::Stream || stream_data() == other.stream_data();
    }
    return false;
}

std::string Object::debug_string(int depth) const {
    if (depth > 6) return "...";
    switch (type_) {
        case ObjType::Null: return "null";
        case ObjType::Bool: return bool_ ? "true" : "false";
        case ObjType::Int: return std::to_string(int_);
        case ObjType::Real: {
            char buffer[40];
            std::snprintf(buffer, sizeof(buffer), "%g", real_);
            return buffer;
        }
        case ObjType::String: {
            std::string out = "(";
            for (char c : text_) {
                if (c == '(' || c == ')' || c == '\\') out.push_back('\\');
                if (static_cast<unsigned char>(c) < 32) {
                    out += "\\x";
                    static constexpr char kHex[] = "0123456789abcdef";
                    out.push_back(kHex[(static_cast<unsigned char>(c) >> 4) & 0xF]);
                    out.push_back(kHex[static_cast<unsigned char>(c) & 0xF]);
                } else {
                    out.push_back(c);
                }
            }
            out.push_back(')');
            return out;
        }
        case ObjType::Name: return "/" + text_;
        case ObjType::Ref:
            return std::to_string(ref_number_) + " " + std::to_string(ref_generation_) + " R";
        case ObjType::Array: {
            std::string out = "[";
            for (std::size_t i = 0; i < array_.size(); ++i) {
                if (i != 0) out.push_back(' ');
                out += array_[i].debug_string(depth + 1);
            }
            out.push_back(']');
            return out;
        }
        case ObjType::Dict: return "<<" + dict().debug_string(depth + 1) + ">>";
        case ObjType::Stream:
            return "<<" + dict().debug_string(depth + 1) + ">> stream (" +
                   std::to_string(stream_data().size()) + " bytes)";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Dict
// ---------------------------------------------------------------------------
const Object* Dict::find(std::string_view key) const {
    for (const auto& [name, value] : items) {
        if (name == key) return &value;
    }
    return nullptr;
}

Object* Dict::find(std::string_view key) {
    for (auto& [name, value] : items) {
        if (name == key) return &value;
    }
    return nullptr;
}

Object& Dict::set(std::string key, Object value) {
    for (auto& [name, existing] : items) {
        if (name == key) {
            existing = std::move(value);
            return existing;
        }
    }
    items.emplace_back(std::move(key), std::move(value));
    return items.back().second;
}

bool Dict::erase(std::string_view key) {
    for (auto it = items.begin(); it != items.end(); ++it) {
        if (it->first == key) {
            items.erase(it);
            return true;
        }
    }
    return false;
}

std::int64_t Dict::get_int(std::string_view key, std::int64_t fallback) const {
    const Object* value = find(key);
    return value != nullptr ? value->as_int(fallback) : fallback;
}

double Dict::get_real(std::string_view key, double fallback) const {
    const Object* value = find(key);
    return value != nullptr ? value->as_real(fallback) : fallback;
}

bool Dict::get_bool(std::string_view key, bool fallback) const {
    const Object* value = find(key);
    return value != nullptr ? value->as_bool(fallback) : fallback;
}

std::string Dict::get_name(std::string_view key, std::string_view fallback) const {
    const Object* value = find(key);
    return value != nullptr && value->is_name() ? value->as_name() : std::string(fallback);
}

std::string Dict::get_string(std::string_view key, std::string_view fallback) const {
    const Object* value = find(key);
    return value != nullptr && value->is_string() ? value->as_string() : std::string(fallback);
}

std::uint32_t Dict::get_ref(std::string_view key) const {
    const Object* value = find(key);
    return value != nullptr && value->is_ref() ? value->ref_number() : 0;
}

Object* Dict::get_array(std::string_view key) {
    Object* value = find(key);
    return value != nullptr && value->is_array() ? value : nullptr;
}

Object* Dict::get_dict(std::string_view key) {
    Object* value = find(key);
    return value != nullptr && value->is_dict_like() ? value : nullptr;
}

std::string Dict::debug_string(int depth) const {
    std::string out;
    for (const auto& [key, value] : items) {
        if (!out.empty()) out.push_back(' ');
        out += "/" + key + " " + value.debug_string(depth);
    }
    return out;
}

}  // namespace scour

// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include "scour/object.hpp"

using namespace scour;

SCOUR_TEST(object, factories_and_types) {
    CHECK(Object::null().is_null());
    CHECK(Object::boolean(true).as_bool());
    CHECK_EQ(Object::integer(42).as_int(), std::int64_t{42});
    CHECK_EQ(Object::real(1.5).as_real(), 1.5);
    CHECK(Object::string("x").is_string());
    CHECK(Object::name("Page").is_name());
    CHECK(Object::array().is_array());
    CHECK(Object::dictionary({}).is_dict());
    CHECK(Object::reference(7, 2).is_ref());
    CHECK_EQ(Object::reference(7, 2).ref_generation(), std::uint16_t{2});
}

SCOUR_TEST(object, dictionary_preserves_insertion_order) {
    Object dict = Object::dictionary({});
    dict.set("Type", Object::name("Page"));
    dict.set("MediaBox", Object::array({Object::integer(0), Object::integer(0)}));
    dict.set("Rotate", Object::integer(90));

    const auto& items = dict.dict().items;
    CHECK_EQ(items.size(), std::size_t{3});
    CHECK_EQ(items[0].first, std::string("Type"));
    CHECK_EQ(items[2].first, std::string("Rotate"));

    // Setting an existing key replaces in place.
    dict.set("Type", Object::name("Pages"));
    CHECK_EQ(dict.dict().items[0].first, std::string("Type"));
    CHECK_EQ(dict.dict().items.size(), std::size_t{3});
    CHECK_EQ(dict.dict().get_name("Type"), std::string("Pages"));
}

SCOUR_TEST(object, copies_are_deep) {
    Object original = Object::dictionary({});
    original.set("Nested", Object::dictionary({}));
    original.find("Nested")->set("Value", Object::integer(1));

    Object copy = original;
    copy.find("Nested")->set("Value", Object::integer(2));
    CHECK_EQ(original.find("Nested")->find("Value")->as_int(), std::int64_t{1});
    CHECK_EQ(copy.find("Nested")->find("Value")->as_int(), std::int64_t{2});

    // Assignment into an existing object must not share storage either.
    Object third = Object::dictionary({});
    third = original;
    third.set("Extra", Object::integer(3));
    CHECK(original.find("Extra") == nullptr);
}

SCOUR_TEST(object, typed_getters) {
    Object dict = Object::dictionary({});
    dict.set("Int", Object::integer(9));
    dict.set("Name", Object::name("FlateDecode"));
    dict.set("String", Object::string("hello"));
    dict.set("Ref", Object::reference(12, 1));
    dict.set("Flag", Object::boolean(true));
    dict.set("Wrong", Object::string("not a name"));

    CHECK_EQ(dict.dict().get_int("Int"), std::int64_t{9});
    CHECK_EQ(dict.dict().get_int("Missing", 5), std::int64_t{5});
    CHECK_EQ(dict.dict().get_name("Name"), std::string("FlateDecode"));
    CHECK_EQ(dict.dict().get_name("Wrong", "fallback"), std::string("fallback"));
    CHECK_EQ(dict.dict().get_string("String"), std::string("hello"));
    CHECK_EQ(dict.dict().get_ref("Ref"), std::uint32_t{12});
    CHECK(dict.dict().get_bool("Flag"));
    CHECK(not dict.dict().contains("Absent"));
}

SCOUR_TEST(object, stream_keeps_encoded_bytes) {
    Bytes encoded = {0x78, 0x9C, 0x03, 0x00};
    Object stream = Object::stream({}, encoded);
    stream.set("Filter", Object::name("FlateDecode"));
    CHECK(stream.is_stream());
    CHECK_EQ(stream.stream_data().size(), std::size_t{4});
    CHECK_EQ(stream.dict().get_name("Filter"), std::string("FlateDecode"));

    Object copy = stream;
    copy.stream_data().push_back(0xFF);
    CHECK_EQ(stream.stream_data().size(), std::size_t{4});
}

SCOUR_TEST(object, equality_and_debug_string) {
    Object a = Object::array({Object::integer(1), Object::name("X")});
    Object b = Object::array({Object::integer(1), Object::name("X")});
    CHECK(a.equals(b));
    b.items().push_back(Object::null());
    CHECK(not a.equals(b));
    CHECK_EQ(a.debug_string(), std::string("[1 /X]"));

    Object dict = Object::dictionary({});
    dict.set("Type", Object::name("Catalog"));
    CHECK_EQ(dict.debug_string(), std::string("<</Type /Catalog>>"));
    CHECK_EQ(Object::string("a(b)").debug_string(), std::string("(a\\(b\\))"));
}

SCOUR_TEST(object, resolving_through_object_source) {
    struct MapSource : ObjectSource {
        std::vector<Object> objects;
        [[nodiscard]] const Object* resolve(const Object& object) const override {
            if (!object.is_ref()) return &object;
            const std::uint32_t number = object.ref_number();
            if (number == 0 || number > objects.size()) return nullptr;
            return &objects[number - 1];
        }
        [[nodiscard]] const Object* resolve_ref(std::uint32_t number) const override {
            if (number == 0 || number > objects.size()) return nullptr;
            return &objects[number - 1];
        }
    };
    MapSource source;
    source.objects.push_back(Object::dictionary({}));
    source.objects[0].set("Label", Object::string("resolved"));

    const Object ref = Object::reference(1);
    const Object* resolved = source.resolve(ref);
    CHECK(resolved != nullptr);
    CHECK_EQ(resolved->dict().get_string("Label"), std::string("resolved"));
}

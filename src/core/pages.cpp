// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "scour/pages.hpp"

#include <algorithm>
#include <string>
#include <unordered_set>

namespace scour {

namespace {

const char* const kInheritedKeys[] = {"Resources", "MediaBox", "CropBox", "Rotate"};

void collect_pages(Document& document, const Object& node, std::vector<std::uint32_t>& out,
                   std::unordered_set<std::uint32_t>& visited, Diagnostics& diagnostics, int depth) {
    if (depth > 64) return;
    std::uint32_t number = node.is_ref() ? node.ref_number() : 0;
    if (node.is_ref() && !visited.insert(number).second) {
        diagnostics.warn("pdf.pages.cycle", "the page tree contains a cycle");
        return;
    }
    const Object* resolved = document.resolve(node);
    if (resolved == nullptr || !resolved->is_dict_like()) return;
    const Dict& dict = resolved->dict();

    const bool is_page = dict.get_name("Type") == "Page";
    const Object* kids = dict.find("Kids");
    if (is_page || kids == nullptr) {
        if (number != 0) out.push_back(number);
        return;
    }
    const Object* resolved_kids = document.resolve(*kids);
    if (resolved_kids == nullptr || !resolved_kids->is_array()) return;
    for (const Object& kid : resolved_kids->items()) collect_pages(document, kid, out, visited, diagnostics, depth + 1);
}

}  // namespace

std::vector<std::uint32_t> collect_page_numbers(Document& document, Diagnostics& diagnostics) {
    std::vector<std::uint32_t> pages;
    const Object* catalog = document.catalog();
    if (catalog != nullptr) {
        const Object* root_pages = document.resolve_ref(catalog->dict().get_ref("Pages"));
        if (root_pages != nullptr) {
            std::unordered_set<std::uint32_t> visited;
            collect_pages(document, Object::reference(catalog->dict().get_ref("Pages")), pages, visited,
                         diagnostics, 0);
        }
    }
    if (pages.empty()) {
        // Broken page tree: fall back to every /Type /Page object, in object
        // number order, which is the order most viewers would use.
        std::vector<std::uint32_t> numbers;
        for (const auto& [number, entry] : document.xref()) numbers.push_back(number);
        std::sort(numbers.begin(), numbers.end());
        for (std::uint32_t number : numbers) {
            const Object* value = document.resolve_ref(number);
            if (value != nullptr && value->is_dict_like() &&
                value->dict().get_name("Type") == "Page")
                pages.push_back(number);
        }
        if (!pages.empty())
            diagnostics.warn("pdf.pages.recovered",
                             "the page tree was not usable; pages were recovered by scanning objects");
    }
    return pages;
}

namespace {

/// Walks /Parent until the key is found, as PDF inheritance requires.
const Object* inherited(const Document& document, std::uint32_t page_number, std::string_view key) {
    const Object* node = document.resolve_ref(page_number);
    for (int depth = 0; node != nullptr && node->is_dict_like() && depth < 64; ++depth) {
        if (const Object* value = node->find(key); value != nullptr) return value;
        const Object* parent = document.resolve_ref(node->dict().get_ref("Parent"));
        if (parent == nullptr || parent == node) break;
        node = parent;
    }
    return nullptr;
}

}  // namespace

Rect page_box(const Document& document, std::uint32_t page_number) {
    for (const char* key : {"CropBox", "MediaBox"}) {
        const Object* box = inherited(document, page_number, key);
        if (box == nullptr) continue;
        const Object* resolved = document.resolve(*box);
        if (resolved != nullptr && resolved->is_array() && resolved->items().size() >= 4) {
            const double a = resolved->items()[0].as_real();
            const double b = resolved->items()[1].as_real();
            const double c = resolved->items()[2].as_real();
            const double d = resolved->items()[3].as_real();
            Rect rect = Rect::from_corners(a, b, c, d);
            if (!rect.empty()) return rect;
        }
    }
    return Rect{0.0, 0.0, 612.0, 792.0};
}

int page_rotation(const Document& document, std::uint32_t page_number) {
    const Object* rotate = inherited(document, page_number, "Rotate");
    int value = rotate != nullptr ? static_cast<int>(rotate->as_int(0)) : 0;
    value %= 360;
    if (value < 0) value += 360;
    return (value / 90) * 90;
}

void set_page_rotation(Document& document, std::uint32_t page_number, int degrees) {
    Object* page = document.mutable_object(page_number);
    if (page == nullptr) return;
    int value = degrees % 360;
    if (value < 0) value += 360;
    value = (value / 90) * 90;
    page->set("Rotate", Object::integer(value));
}

// ---------------------------------------------------------------------------
// ObjectCopier
// ---------------------------------------------------------------------------
std::uint32_t ObjectCopier::copy_object(std::uint32_t number) {
    if (number == 0) return 0;
    if (const auto found = map_.find(number); found != map_.end()) return found->second;
    const Object* source = source_.resolve_ref(number);
    if (source == nullptr) return 0;
    const std::uint32_t target_number = target_.add_object(Object::null());
    map_[number] = target_number;
    Object copy = copy_value(*source);
    target_.set_object(target_number, std::move(copy));
    return target_number;
}

Object ObjectCopier::copy_value(const Object& value) {
    switch (value.type()) {
        case ObjType::Ref: {
            const std::uint32_t copied = copy_object(value.ref_number());
            return copied == 0 ? Object::null() : Object::reference(copied);
        }
        case ObjType::Array: {
            std::vector<Object> items;
            items.reserve(value.items().size());
            for (const Object& item : value.items()) items.push_back(copy_value(item));
            return Object::array(std::move(items));
        }
        case ObjType::Dict:
        case ObjType::Stream: {
            Dict dict;
            for (const auto& [key, item] : value.dict().items) dict.set(key, copy_value(item));
            if (value.is_stream()) return Object::stream(std::move(dict), value.stream_data());
            return Object::dictionary(std::move(dict));
        }
        default:
            return value;
    }
}

// ---------------------------------------------------------------------------
// PageAssembler
// ---------------------------------------------------------------------------
PageAssembler::PageAssembler(Document& target, Diagnostics& diagnostics)
    : target_(target), diagnostics_(diagnostics) {
    pages_number_ = target_.add_object(Object::dictionary({}));
    catalog_number_ = target_.add_object(Object::dictionary({}));
    target_.set_root_number(catalog_number_);
    target_.trailer().set("Size", Object::integer(static_cast<std::int64_t>(catalog_number_) + 1));
}

Object PageAssembler::inherited_value(Document& source, std::uint32_t page_number,
                                      std::string_view key) {
    const Object* value = inherited(source, page_number, key);
    if (value == nullptr) return Object::null();
    return *value;
}

std::uint32_t PageAssembler::add_page(Document& source, std::uint32_t page_number) {
    const Object* source_page = source.resolve_ref(page_number);
    if (source_page == nullptr || !source_page->is_dict_like()) {
        diagnostics_.warn("pdf.pages.missing", "page object " + std::to_string(page_number) +
                                                   " is missing and was skipped");
        return 0;
    }

    ObjectCopier copier(target_, source);
    Object page = Object::dictionary({});
    for (const auto& [key, value] : source_page->dict().items) {
        if (key == "Parent") continue;
        if (key == "Annots") {
            const Object* annots = source.resolve(value);
            if (annots == nullptr || !annots->is_array()) continue;
            std::vector<Object> copied_annots;
            for (const Object& item : annots->items()) {
                const Object* annotation = source.resolve(item);
                if (annotation == nullptr || !annotation->is_dict_like()) continue;
                Object shallow = Object::dictionary(annotation->dict());
                shallow.remove("P");   // would point back into the source document
                shallow.remove("Popup");  // geometry is recreated by viewers if omitted
                copied_annots.push_back(copier.copy_value(shallow));
            }
            page.set("Annots", Object::array(std::move(copied_annots)));
            continue;
        }
        page.set(key, copier.copy_value(value));
    }

    // Materialise inherited attributes so the new page is self-contained.
    for (const char* key : kInheritedKeys) {
        if (page.find(key) == nullptr) {
            Object value = inherited_value(source, page_number, key);
            if (!value.is_null()) page.set(key, copier.copy_value(value));
        }
    }
    if (page.find("MediaBox") == nullptr)
        page.set("MediaBox", Object::array({Object::integer(0), Object::integer(0), Object::integer(612),
                                            Object::integer(792)}));
    page.set("Type", Object::name("Page"));
    page.set("Parent", Object::reference(pages_number_));

    const std::uint32_t page_object_number = target_.add_object(std::move(page));
    kids_.push_back(Object::reference(page_object_number));
    return page_object_number;
}

std::uint32_t PageAssembler::finish() {
    Object pages = Object::dictionary({});
    pages.set("Type", Object::name("Pages"));
    pages.set("Kids", Object::array(kids_));
    pages.set("Count", Object::integer(static_cast<std::int64_t>(kids_.size())));
    target_.set_object(pages_number_, std::move(pages));

    Object catalog = Object::dictionary({});
    catalog.set("Type", Object::name("Catalog"));
    catalog.set("Pages", Object::reference(pages_number_));
    target_.set_object(catalog_number_, std::move(catalog));
    target_.set_root_number(catalog_number_);
    target_.trailer().set(
        "Size", Object::integer(static_cast<std::int64_t>(target_.cached_object_count()) + 1));
    return catalog_number_;
}

// ---------------------------------------------------------------------------
// Selection helpers
// ---------------------------------------------------------------------------
Document extract_pages(Document& source, const std::vector<int>& indices, Diagnostics& diagnostics) {
    Document target;
    target.trailer().set("Root", Object::null());
    PageAssembler assembler(target, diagnostics);
    const std::vector<std::uint32_t> pages = collect_page_numbers(source, diagnostics);
    for (int index : indices) {
        if (index < 0 || static_cast<std::size_t>(index) >= pages.size()) {
            diagnostics.warn("pdf.pages.out-of-range",
                             "page " + std::to_string(index + 1) + " does not exist and was skipped");
            continue;
        }
        assembler.add_page(source, pages[static_cast<std::size_t>(index)]);
    }
    assembler.finish();
    return target;
}

Document merge_documents(std::vector<Document*> sources, Diagnostics& diagnostics) {
    Document target;
    PageAssembler assembler(target, diagnostics);
    for (Document* source : sources) {
        if (source == nullptr) continue;
        const std::vector<std::uint32_t> pages = collect_page_numbers(*source, diagnostics);
        for (std::uint32_t page : pages) assembler.add_page(*source, page);
    }
    assembler.finish();
    return target;
}

}  // namespace scour

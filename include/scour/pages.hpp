// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_PAGES_HPP
#define SCOUR_PAGES_HPP

#include <cstdint>
#include <vector>

#include "scour/document.hpp"
#include "scour/error.hpp"
#include "scour/geometry.hpp"

namespace scour {

/// Flattens /Root/Pages into page object numbers, in reading order. Pages are
/// discovered by walking /Kids; a document with a broken tree falls back to
/// scanning every object for /Type /Page.
std::vector<std::uint32_t> collect_page_numbers(Document& document, Diagnostics& diagnostics);

/// Page geometry with inheritance resolved through the /Parent chain.
[[nodiscard]] Rect page_box(const Document& document, std::uint32_t page_number);
[[nodiscard]] int page_rotation(const Document& document, std::uint32_t page_number);
void set_page_rotation(Document& document, std::uint32_t page_number, int degrees);

/// Deep-copies objects between documents, remapping references and preserving
/// cycles (a page's /Parent, an annotation's /Popup, and so on).
class ObjectCopier {
public:
    ObjectCopier(Document& target, Document& source) : target_(target), source_(source) {}

    [[nodiscard]] std::uint32_t copy_object(std::uint32_t number);
    [[nodiscard]] Object copy_value(const Object& value);
    [[nodiscard]] Document& target() noexcept { return target_; }
    [[nodiscard]] Document& source() noexcept { return source_; }
    [[nodiscard]] const std::unordered_map<std::uint32_t, std::uint32_t>& mapping() const noexcept {
        return map_;
    }

private:
    Document& target_;
    Document& source_;
    std::unordered_map<std::uint32_t, std::uint32_t> map_;
};

/// Builds a new document page by page. The catalog and page tree are created as
/// pages are added, so every copied annotation already has a valid /Parent.
class PageAssembler {
public:
    PageAssembler(Document& target, Diagnostics& diagnostics);
    std::uint32_t add_page(Document& source, std::uint32_t page_number);
    std::uint32_t finish();
    [[nodiscard]] std::size_t count() const noexcept { return kids_.size(); }

private:
    Object inherited_value(Document& source, std::uint32_t page_number, std::string_view key);

    Document& target_;
    Diagnostics& diagnostics_;
    std::uint32_t pages_number_ = 0;
    std::uint32_t catalog_number_ = 0;
    std::vector<Object> kids_;
};

/// New document containing `indices` (0-based) of `source` in the given order.
Document extract_pages(Document& source, const std::vector<int>& indices, Diagnostics& diagnostics);

/// Concatenates every page of every source, in order.
Document merge_documents(std::vector<Document*> sources, Diagnostics& diagnostics);

}  // namespace scour

#endif  // SCOUR_PAGES_HPP

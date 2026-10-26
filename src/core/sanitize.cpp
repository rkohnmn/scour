// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// A scrub is a removal pass, not a paint pass. Each step deletes the data from
// the object graph; the writer then serialises only what is reachable from the
// catalog, so annotations and attachments do not merely become invisible, they
// are not written at all.
#include "scour/sanitize.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "scour/pages.hpp"
#include "scour/text.hpp"

namespace scour {

namespace {

std::vector<std::uint32_t> object_numbers(const Document& document) {
    std::vector<std::uint32_t> numbers;
    numbers.reserve(document.xref().size());
    for (const auto& [number, entry] : document.xref()) {
        if (entry.kind == XrefEntry::Kind::Free) continue;
        numbers.push_back(number);
    }
    std::sort(numbers.begin(), numbers.end());
    return numbers;
}

/// Removes an action dictionary entry if it is actually an action, so a benign
/// /OpenAction that only points at page 1 does not lose the reader's place...
/// except that it does: a scrubber that leaves an entry behind because it looks
/// harmless is a scrubber with a policy surface. The policy is: scripts go.
int strip_action_keys(Document& document) {
    int removed = 0;
    for (const std::uint32_t number : object_numbers(document)) {
        Object* object = document.mutable_object(number);
        if (object == nullptr || !object->is_dict_like()) continue;
        for (const char* key : {"JS", "JavaScript", "AA", "OpenAction"}) {
            if (object->remove(key)) ++removed;
        }
    }
    return removed;
}

int strip_javascript_names(Document& document) {
    Object* catalog = document.mutable_catalog();
    if (catalog == nullptr) return 0;
    Object* names = catalog->find("Names");
    if (names == nullptr) return 0;
    const Object* resolved = document.resolve(*names);
    Object* target = names;
    if (resolved != nullptr && resolved->is_dict_like()) {
        // /Names is usually an indirect dictionary; mutate the resolved copy in
        // place by writing it back through the reference.
        if (names->is_ref()) {
            target = document.mutable_object(names->ref_number());
        } else {
            target = names;
        }
    }
    if (target == nullptr || !target->is_dict_like()) return 0;
    int removed = 0;
    if (target->remove("JavaScript")) ++removed;
    if (target->dict().empty()) catalog->remove("Names");
    return removed;
}

int strip_metadata(Document& document) {
    int removed = 0;
    if (document.trailer().erase("Info")) ++removed;
    Object* catalog = document.mutable_catalog();
    if (catalog != nullptr) {
        if (catalog->remove("Metadata")) ++removed;
        if (catalog->remove("PieceInfo")) ++removed;
        if (catalog->remove("MarkInfo")) ++removed;
        if (catalog->remove("SpiderInfo")) ++removed;
    }
    // Page-level piece info carries application-private data.
    for (const std::uint32_t number : object_numbers(document)) {
        Object* object = document.mutable_object(number);
        if (object == nullptr || !object->is_dict_like()) continue;
        if (object->remove("PieceInfo")) ++removed;
        if (object->dict().get_name("Type") == "Page" && object->remove("LastModified")) ++removed;
    }
    return removed;
}

int strip_annotations(Document& document, int& forms_removed) {
    int removed = 0;
    Diagnostics scratch;
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, scratch);
    for (const std::uint32_t page_number : pages) {
        Object* page = document.mutable_object(page_number);
        if (page == nullptr || !page->is_dict_like()) continue;
        const Object* annots = page->find("Annots");
        if (annots == nullptr) continue;
        int count = 0;
        if (annots->is_array()) {
            count = static_cast<int>(annots->items().size());
        } else {
            const Object* resolved = document.resolve(*annots);
            if (resolved != nullptr && resolved->is_array())
                count = static_cast<int>(resolved->items().size());
        }
        page->remove("Annots");
        removed += count;
    }
    Object* catalog = document.mutable_catalog();
    if (catalog != nullptr) {
        const Object* acro = catalog->find("AcroForm");
        if (acro != nullptr) {
            catalog->remove("AcroForm");
            forms_removed = 1;
        }
    }
    return removed;
}

int strip_attachments(Document& document) {
    Object* catalog = document.mutable_catalog();
    if (catalog == nullptr) return 0;

    // A single attachment is normally referenced twice: from the EmbeddedFiles
    // name tree and from the catalog's /AF array. Report files, not references.
    std::unordered_set<std::uint32_t> specs;
    int files = 0;
    const auto account = [&](const Object& entry) {
        if (!entry.is_ref()) return;
        const std::uint32_t number = entry.ref_number();
        const Object* spec = document.resolve_ref(number);
        if (spec == nullptr || !spec->is_dict_like()) return;
        if (!specs.insert(number).second) return;
        ++files;
    };

    bool had_af = false;
    bool had_name_tree = false;
    if (const Object* af = catalog->find("AF"); af != nullptr) {
        const Object* entries = document.resolve(*af);
        if (entries != nullptr && entries->is_array()) {
            had_af = !entries->items().empty();
            for (const Object& item : entries->items()) account(item);
        }
    }

    Object* names = catalog->find("Names");
    if (names != nullptr) {
        Object* target = names;
        if (names->is_ref()) target = document.mutable_object(names->ref_number());
        if (target != nullptr && target->is_dict_like()) {
            if (const Object* embedded = target->find("EmbeddedFiles"); embedded != nullptr) {
                const Object* tree = document.resolve(*embedded);
                const Object* array = tree != nullptr && tree->is_dict_like()
                                          ? tree->dict().find("Names")
                                          : nullptr;
                const Object* items = array != nullptr ? document.resolve(*array) : nullptr;
                if (items != nullptr && items->is_array()) {
                    had_name_tree = !items->items().empty();
                    for (std::size_t i = 0; i + 1 < items->items().size(); i += 2)
                        account(items->items()[i + 1]);
                }
                target->remove("EmbeddedFiles");
            }
            if (target->dict().empty()) catalog->remove("Names");
        }
    }
    catalog->remove("AF");

    // A name tree entry may point at a direct dictionary rather than a
    // reference. There is still an attachment to count in that case.
    if (files == 0 && (had_af || had_name_tree)) files = 1;
    return files;
}

}  // namespace

ScrubReport scrub_document(Document& document, const ScrubOptions& options,
                           Diagnostics& diagnostics) {
    ScrubReport report;

    if (options.strip_scripts) {
        report.actions_removed = strip_action_keys(document);
        report.actions_removed += strip_javascript_names(document);
        if (report.actions_removed > 0)
            report.notes.push_back("removed " + std::to_string(report.actions_removed) +
                                   " action/script entries");
    }

    if (options.strip_attachments) {
        report.attachments_removed = strip_attachments(document);
        if (report.attachments_removed > 0)
            report.notes.push_back("removed " + std::to_string(report.attachments_removed) +
                                   " embedded file reference(s)");
    }

    if (options.strip_annotations) {
        report.annotations_removed = strip_annotations(document, report.form_fields_removed);
        if (report.annotations_removed > 0)
            report.notes.push_back("removed " + std::to_string(report.annotations_removed) +
                                   " annotation(s)");
        if (report.form_fields_removed > 0)
            report.notes.push_back("removed the interactive form dictionary");
    }

    if (options.strip_metadata) {
        report.metadata_removed = strip_metadata(document);
        if (report.metadata_removed > 0)
            report.notes.push_back("removed document information, XMP and application data");
    }

    const bool has_targets = !options.targets.terms.empty() || options.targets.pii ||
                             !options.targets.rects.empty();
    if (options.redact && has_targets) {
        report.redaction = redact_document(document, options.targets, diagnostics);
        report.redacted = true;
    } else if (options.redact) {
        report.notes.push_back("no redaction targets given; nothing was removed from the text");
    }

    return report;
}

}  // namespace scour

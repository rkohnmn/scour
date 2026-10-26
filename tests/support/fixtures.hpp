// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Test fixtures are written by hand, byte for byte, rather than by Scour's own
// writer. That is deliberate: a bug shared by the reader and the writer must not
// be able to hide behind a round-trip test.
#ifndef SCOUR_TEST_FIXTURES_HPP
#define SCOUR_TEST_FIXTURES_HPP

#include <string>

#include "scour/bytes.hpp"

namespace scour_test {

using scour::Bytes;

struct FixtureSpec {
    int pages = 3;
    bool metadata = true;          ///< /Info with author, producer, dates
    bool xmp = true;               ///< XMP metadata stream with a creator tool
    bool javascript = true;        ///< /OpenAction and document level JavaScript
    bool attachment = true;        ///< embedded file
    bool annotation = true;        ///< a comment carrying an author name
    bool form_field = true;        ///< AcroForm field with a value
    bool split_email = true;       ///< split one address across two Tj operators
    bool orphan_object = true;     ///< an unreferenced object holding a secret
};

/// A classic-xref PDF with realistic clutter: metadata, XMP, JavaScript,
/// attachments, annotations and PII.
Bytes make_fixture(const FixtureSpec& spec);

/// The fixture plus an appended incremental update that removes the visible
/// text on page 3 but leaves the original content stream in the file. This is
/// the exact failure mode Scour exists to find.
Bytes make_incremental_fixture();

/// Minimal one page document used for round-trip tests.
Bytes make_minimal_pdf(std::string text = "Hello, document.");

/// A PDF with a broken startxref and no usable cross-reference table.
Bytes make_broken_xref_pdf();

/// Same document, but with CRLF line endings and no EOL after `stream`.
Bytes make_quirky_pdf();

/// A one page document whose secrets are hidden four different ways: invisible
/// rendering mode, a black box painted over live text, white-on-white text and
/// text clipped outside the page box. Used by the inspector tests and by
/// `scour_fixtures`, so the demo file and the tests cannot drift apart.
Bytes make_hidden_text_fixture();

/// A single image on a page with no text layer at all.
Bytes make_scanned_fixture();

/// The known strings in the fixtures, so tests do not repeat literals.
inline constexpr const char* kEmail = "alice@example.com";
inline constexpr const char* kPhone = "+1 415 555 0132";
inline constexpr const char* kSsn = "123-45-6789";
inline constexpr const char* kCard = "4111 1111 1111 1111";
inline constexpr const char* kIban = "DE89370400440532013000";
inline constexpr const char* kNeedle = "PROJECT BLUEBIRD";
inline constexpr const char* kAuthor = "Alice Example";
inline constexpr const char* kProducer = "Acme ScanSuite 2.1";
inline constexpr const char* kOrphanSecret = "internal draft: do not distribute";
inline constexpr const char* kInvisibleSecret = "CONFIDENTIAL PROJECT BLUEBIRD";
inline constexpr const char* kCoveredSecret = "Secret settlement: 4200000";
inline constexpr const char* kWhiteSecret = "Internal note: do not share";
inline constexpr const char* kClippedSecret = "Clipped draft text";

}  // namespace scour_test

#endif  // SCOUR_TEST_FIXTURES_HPP

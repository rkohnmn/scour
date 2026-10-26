// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "framework.hpp"

#include <string>

#include "scour/patterns.hpp"

using namespace scour;

namespace {

bool has_kind(const std::vector<PatternMatch>& matches, std::string_view kind) {
    for (const PatternMatch& match : matches) {
        if (match.kind == kind) return true;
    }
    return false;
}

}  // namespace

SCOUR_TEST(patterns, checksums) {
    CHECK(passes_luhn("4111111111111111"));
    CHECK(passes_luhn("4242424242424242"));
    CHECK(not passes_luhn("4111111111111112"));
    CHECK(passes_luhn("79927398713"));
    CHECK(not passes_luhn(""));
    CHECK(passes_iban_checksum("DE89370400440532013000"));
    CHECK(passes_iban_checksum("GB82WEST12345698765432"));
    CHECK(not passes_iban_checksum("DE89370400440532013001"));
}

SCOUR_TEST(patterns, finds_common_pii) {
    const std::string text =
        "Contact alice@example.com or +1 415 555 0132. SSN 123-45-6789. "
        "Card 4111 1111 1111 1111. IBAN DE89370400440532013000. Host 10.0.0.42.";
    const auto matches = detect_pii(text);
    CHECK(has_kind(matches, "email"));
    CHECK(has_kind(matches, "phone"));
    CHECK(has_kind(matches, "ssn"));
    CHECK(has_kind(matches, "card"));
    CHECK(has_kind(matches, "iban"));
    CHECK(has_kind(matches, "ipv4"));
}

SCOUR_TEST(patterns, matches_have_valid_ranges) {
    const std::string text = "email: bob@example.org phone: 415 555 0100";
    const auto matches = detect_pii(text);
    CHECK(not matches.empty());
    for (const PatternMatch& match : matches) {
        CHECK(match.begin < match.end);
        CHECK(match.end <= text.size());
    }
}

SCOUR_TEST(patterns, does_not_flag_ordinary_numbers) {
    const std::string text = "Version 1.2.3 shipped in 2026 with 42 pages and 3.14159 precision.";
    const auto matches = detect_pii(text);
    CHECK(not has_kind(matches, "ssn"));
    CHECK(not has_kind(matches, "card"));
    CHECK(not has_kind(matches, "iban"));
}

SCOUR_TEST(patterns, finds_terms_case_insensitively_and_across_whitespace) {
    const std::string text = "The Project\n   Bluebird memo is attached.";
    const auto matches = detect_terms(text, {"project bluebird"});
    CHECK_EQ(matches.size(), std::size_t{1});
    CHECK_EQ(matches[0].begin, std::size_t{4});
    CHECK_EQ(matches[0].end, std::size_t{23});
    CHECK_EQ(matches[0].kind, std::string("term"));
}

SCOUR_TEST(patterns, finds_multiple_term_occurrences) {
    const auto matches = detect_terms("BLUEBIRD bluebird BLUEBIRD", {"bluebird"});
    CHECK_EQ(matches.size(), std::size_t{3});
}

SCOUR_TEST(patterns, detects_api_keys_and_private_keys) {
    const std::string text =
        "key AKIAIOSFODNN7EXAMPLE and -----BEGIN RSA PRIVATE KEY----- MIIEow -----END RSA PRIVATE KEY-----";
    const auto matches = detect_pii(text);
    CHECK(has_kind(matches, "api-key"));
    CHECK(has_kind(matches, "private-key"));
}

SCOUR_TEST(patterns, handles_utf8_text_without_crashing) {
    const std::string text = "Grüße aus München — Kontakt: jürgen@example.de — 49 30 123456";
    const auto matches = detect_pii(text);
    CHECK(not matches.empty());
    CHECK(has_kind(matches, "email"));
}

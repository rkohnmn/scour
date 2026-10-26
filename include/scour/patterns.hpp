// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#ifndef SCOUR_PATTERNS_HPP
#define SCOUR_PATTERNS_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace scour {

struct PatternMatch {
    std::size_t begin = 0;  ///< byte offset in the original text
    std::size_t end = 0;
    std::string kind;  ///< "email", "phone", "ssn", "card", "iban", "ipv4", "api-key", "term"
};

/// Finds personal and credential-shaped data in extracted text. Matching is
/// whitespace-insensitive (a phone number split across two lines still matches)
/// and, for terms, case-insensitive.
std::vector<PatternMatch> detect_pii(std::string_view text);

/// Literal, case-insensitive, whitespace-insensitive substring search.
std::vector<PatternMatch> detect_terms(std::string_view text, const std::vector<std::string>& terms);

/// Every detector name, in the order the inspector reports them.
const std::vector<std::string>& pii_kinds();

/// Luhn check for payment card numbers; exposed for tests.
bool passes_luhn(std::string_view digits);
bool passes_iban_checksum(std::string_view iban);

}  // namespace scour

#endif  // SCOUR_PATTERNS_HPP

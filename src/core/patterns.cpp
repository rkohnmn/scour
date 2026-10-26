// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// These detectors are deliberately conservative: they would rather flag one
// extra number than miss a card. A redaction tool's false positives cost a
// glance; its false negatives cost a leak.
#include "scour/patterns.hpp"

#include <algorithm>
#include <array>
#include <cctype>

namespace scour {

namespace {

struct Normalized {
    std::string text;
    std::vector<std::size_t> origin;  // origin[i] -> offset in the source string
};

Normalized normalize(std::string_view input) {
    Normalized out;
    out.text.reserve(input.size());
    out.origin.reserve(input.size());
    bool pending_space = false;
    for (std::size_t i = 0; i < input.size(); ++i) {
        const unsigned char byte = static_cast<unsigned char>(input[i]);
        if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n' || byte == '\f' ||
            byte == '\v') {
            pending_space = !out.text.empty();
            continue;
        }
        if (pending_space) {
            out.text.push_back(' ');
            out.origin.push_back(i);
            pending_space = false;
        }
        char c = static_cast<char>(byte);
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        out.text.push_back(c);
        out.origin.push_back(i);
    }
    return out;
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool is_alnum(char c) { return is_digit(c) || is_alpha(c); }
bool is_local(char c) { return is_alnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'; }
bool is_domain(char c) { return is_alnum(c) || c == '.' || c == '-'; }

void add_match(std::vector<PatternMatch>& matches, const Normalized& normalized, std::size_t begin,
               std::size_t end, std::string kind) {
    if (begin >= end || end > normalized.text.size()) return;
    const std::size_t original_begin = normalized.origin[begin];
    const std::size_t original_end = normalized.origin[end - 1] + 1;
    if (original_end <= original_begin) return;
    matches.push_back(PatternMatch{original_begin, original_end, std::move(kind)});
}


bool is_number_separator(char c) {
    return c == ' ' || c == '-' || c == '.' || c == '(' || c == ')' || c == '+' || c == '/';
}

void scan_emails(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (std::size_t at = 0; at < text.size(); ++at) {
        if (text[at] != '@') continue;
        std::size_t begin = at;
        while (begin > 0 && is_local(text[begin - 1])) --begin;
        std::size_t end = at + 1;
        while (end < text.size() && is_domain(text[end])) ++end;
        if (begin == at || end == at + 1) continue;
        const std::string_view domain(text.data() + at + 1, end - at - 1);
        const std::size_t dot = domain.rfind('.');
        if (dot == std::string_view::npos || dot == 0 || dot + 2 >= domain.size()) continue;
        std::size_t letters = 0;
        for (std::size_t i = dot + 1; i < domain.size(); ++i) {
            if (!is_alpha(domain[i])) {
                letters = 0;
                break;
            }
            ++letters;
        }
        if (letters < 2) continue;
        add_match(matches, normalized, begin, end, "email");
    }
}

void scan_ssn(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (std::size_t i = 0; i + 10 < text.size(); ++i) {
        if (!is_digit(text[i]) || !is_digit(text[i + 1]) || !is_digit(text[i + 2])) continue;
        const char sep = text[i + 3];
        if (sep != '-' && sep != ' ') continue;
        if (!is_digit(text[i + 4]) || !is_digit(text[i + 5])) continue;
        if (text[i + 6] != sep) continue;
        if (!is_digit(text[i + 7]) || !is_digit(text[i + 8]) || !is_digit(text[i + 9]) ||
            !is_digit(text[i + 10]))
            continue;
        if (i > 0 && is_digit(text[i - 1])) continue;
        add_match(matches, normalized, i, i + 11, "ssn");
    }
}

void scan_ipv4(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_digit(text[i])) continue;
        if (i > 0 && (is_digit(text[i - 1]) || text[i - 1] == '.')) continue;
        std::size_t position = i;
        int groups = 0;
        bool ok = true;
        while (groups < 4) {
            std::size_t start = position;
            int value = 0;
            while (position < text.size() && is_digit(text[position]) && position - start < 3) {
                value = value * 10 + (text[position] - '0');
                ++position;
            }
            if (position == start || value > 255) {
                ok = false;
                break;
            }
            ++groups;
            if (groups < 4) {
                if (position >= text.size() || text[position] != '.') {
                    ok = false;
                    break;
                }
                ++position;
            }
        }
        if (ok && groups == 4) {
            add_match(matches, normalized, i, position, "ipv4");
            i = position - 1;
        }
    }
}

void scan_ibans(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_alpha(text[i])) continue;
        if (i > 0 && is_alnum(text[i - 1])) continue;
        if (i + 4 > text.size() || !is_alpha(text[i + 1]) || !is_digit(text[i + 2]) ||
            !is_digit(text[i + 3]))
            continue;
        std::size_t end = i + 4;
        while (end < text.size() && is_alnum(text[end])) ++end;
        const std::string_view candidate(text.data() + i, end - i);
        if (candidate.size() < 15 || candidate.size() > 34) continue;
        if (passes_iban_checksum(candidate)) add_match(matches, normalized, i, end, "iban");
    }
}

void scan_cards(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_digit(text[i])) continue;
        if (i > 0 && is_digit(text[i - 1])) continue;
        std::size_t end = i;
        std::string digits;
        std::size_t last_digit = i;
        while (end < text.size() &&
               (is_digit(text[end]) || (is_number_separator(text[end]) && end + 1 < text.size() &&
                                        is_digit(text[end + 1])))) {
            if (is_digit(text[end])) {
                digits.push_back(text[end]);
                last_digit = end;
            }
            ++end;
        }
        if (digits.size() < 13 || digits.size() > 19) continue;
        if (!passes_luhn(digits)) continue;
        add_match(matches, normalized, i, last_digit + 1, "card");
        i = last_digit;
    }
}

void scan_phones(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const bool starts = is_digit(text[i]) || (text[i] == '+' && i + 1 < text.size() && is_digit(text[i + 1])) ||
                            (text[i] == '(' && i + 1 < text.size() && is_digit(text[i + 1]));
        if (!starts) continue;
        if (i > 0 && is_digit(text[i - 1])) continue;
        std::size_t end = i;
        std::size_t digits = 0;
        std::size_t last_digit = i;
        bool has_separator = false;
        while (end < text.size() &&
               (is_digit(text[end]) || (is_number_separator(text[end]) && end + 1 < text.size() &&
                                        (is_digit(text[end + 1]) || text[end + 1] == '(')))) {
            if (is_digit(text[end])) {
                ++digits;
                last_digit = end;
            } else {
                has_separator = true;
            }
            ++end;
        }
        end = last_digit + 1;
        if (digits < 9 || digits > 15) continue;
        const bool international = text[i] == '+';
        if (!international && digits < 10 && !has_separator) continue;
        add_match(matches, normalized, i, end, "phone");
        i = last_digit;
    }
}

void scan_keys(const Normalized& normalized, std::vector<PatternMatch>& matches) {
    const std::string& text = normalized.text;
    for (const std::string_view prefix : {"akia", "asia", "ghp_", "sk_live_", "xoxb-"}) {
        std::size_t position = 0;
        while ((position = text.find(prefix, position)) != std::string::npos) {
            std::size_t end = position + prefix.size();
            const std::size_t required = prefix == "ghp_" ? 24 : 16;
            std::size_t taken = 0;
            while (end < text.size() && is_alnum(text[end]) && taken < required) {
                ++end;
                ++taken;
            }
            if (taken >= required) add_match(matches, normalized, position, end, "api-key");
            position = end;
        }
    }
    std::size_t begin = 0;
    while ((begin = text.find("-----begin", begin)) != std::string::npos) {
        const std::size_t end = text.find("private key-----", begin);
        if (end == std::string::npos) break;
        std::size_t block_end = text.find("-----end", end);
        block_end = block_end == std::string::npos ? end + 16 : block_end + 12;
        add_match(matches, normalized, begin, std::min(block_end, text.size()), "private-key");
        begin = block_end;
    }
}

/// Removes matches that are contained in a higher priority match, so a card
/// number is not also reported as four phone numbers.
void deduplicate(std::vector<PatternMatch>& matches) {
    if (matches.empty()) return;
    std::sort(matches.begin(), matches.end(), [](const PatternMatch& a, const PatternMatch& b) {
        if (a.begin != b.begin) return a.begin < b.begin;
        return (a.end - a.begin) > (b.end - b.begin);
    });
    std::vector<PatternMatch> out;
    for (const PatternMatch& match : matches) {
        bool keep = true;
        for (PatternMatch& existing : out) {
            if (match.begin >= existing.begin && match.end <= existing.end) {
                keep = false;
                break;
            }
            if (match.begin < existing.end && existing.begin < match.end) {
                if (existing.end - existing.begin >= match.end - match.begin) {
                    keep = false;
                    break;
                }
                existing.end = match.end;
                keep = false;
                break;
            }
        }
        if (keep) out.push_back(match);
    }
    std::sort(out.begin(), out.end(),
              [](const PatternMatch& a, const PatternMatch& b) { return a.begin < b.begin; });
    matches = std::move(out);
}

}  // namespace

bool passes_luhn(std::string_view digits) {
    int sum = 0;
    bool double_digit = false;
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
        if (!is_digit(*it)) continue;
        int value = *it - '0';
        if (double_digit) {
            value *= 2;
            if (value > 9) value -= 9;
        }
        sum += value;
        double_digit = !double_digit;
    }
    return sum > 0 && sum % 10 == 0;
}

bool passes_iban_checksum(std::string_view iban) {
    std::string rearranged(iban.begin() + 4, iban.end());
    rearranged.append(iban.begin(), iban.begin() + 4);
    long long remainder = 0;
    for (char c : rearranged) {
        if (is_digit(c)) {
            remainder = (remainder * 10 + (c - '0')) % 97;
        } else if (is_alpha(c)) {
            const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            const int value = lower - 'a' + 10;
            remainder = (remainder * 100 + value) % 97;
        } else {
            return false;
        }
    }
    return remainder == 1;
}

const std::vector<std::string>& pii_kinds() {
    static const std::vector<std::string> kinds = {
        "email", "phone", "ssn", "card", "iban", "ipv4", "api-key", "private-key"};
    return kinds;
}

std::vector<PatternMatch> detect_pii(std::string_view text) {
    const Normalized normalized = normalize(text);
    std::vector<PatternMatch> matches;
    scan_emails(normalized, matches);
    scan_ssn(normalized, matches);
    scan_ibans(normalized, matches);
    scan_cards(normalized, matches);
    scan_ipv4(normalized, matches);
    scan_keys(normalized, matches);
    scan_phones(normalized, matches);
    deduplicate(matches);
    return matches;
}

std::vector<PatternMatch> detect_terms(std::string_view text, const std::vector<std::string>& terms) {
    std::vector<PatternMatch> matches;
    if (terms.empty()) return matches;
    const Normalized normalized = normalize(text);
    for (const std::string& raw : terms) {
        const Normalized term = normalize(raw);
        if (term.text.empty()) continue;
        std::size_t position = 0;
        while ((position = normalized.text.find(term.text, position)) != std::string::npos) {
            add_match(matches, normalized, position, position + term.text.size(), "term");
            position += term.text.size();
        }
    }
    std::sort(matches.begin(), matches.end(),
              [](const PatternMatch& a, const PatternMatch& b) { return a.begin < b.begin; });
    return matches;
}

}  // namespace scour

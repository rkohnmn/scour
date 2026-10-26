// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// A self-contained benchmark. It builds a synthetic document in memory with the
// same primitives the reader supports (Helvetica text, Flate streams, classic
// xref), then measures the operations a user waits for: open, extract, inspect
// and scrub+write. Nothing is read from disk and no fixture is special-cased, so
// the numbers reflect the library, not the benchmark's opinion of it.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <numeric>
#include <string>
#include <vector>

#include <sys/resource.h>

#include "scour/bytes.hpp"
#include "scour/deflate.hpp"
#include "scour/document.hpp"
#include "scour/inspector.hpp"
#include "scour/pages.hpp"
#include "scour/sanitize.hpp"
#include "scour/text.hpp"
#include "scour/writer.hpp"

namespace {

using scour::Bytes;
using scour::Diagnostics;
using scour::Document;
using scour::InspectOptions;
using scour::LoadOptions;
using scour::ScrubOptions;
using scour::WriteOptions;

struct DocumentSpec {
    int pages = 500;
    int lines_per_page = 30;
    bool compress = true;
};

struct BuiltDocument {
    Bytes bytes;
    int glyphs = 0;
};

std::string escape(std::string_view text) {
    std::string out;
    for (const char c : text) {
        if (c == '(' || c == ')' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

/// Builds a classic-xref PDF with `pages` pages of real text. The content is
/// deliberately repetitive so compression ratios resemble a generated report,
/// not a corpus of unique prose.
BuiltDocument build_document(const DocumentSpec& spec) {
    std::string out = "%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";
    std::vector<std::size_t> offsets(static_cast<std::size_t>(spec.pages) + 100, 0);
    int next_number = 10;
    const int first_page = next_number;
    next_number += spec.pages;
    const int first_content = next_number;
    next_number += spec.pages;
    const int info_number = next_number++;
    const int font_number = next_number++;

    const auto add_object = [&out, &offsets](int number, const std::string& body) {
        if (static_cast<std::size_t>(number) >= offsets.size())
            offsets.resize(static_cast<std::size_t>(number) + 1, 0);
        offsets[static_cast<std::size_t>(number)] = out.size();
        out += std::to_string(number) + " 0 obj\n" + body + "\nendobj\n";
    };
    const auto add_stream = [&out, &offsets](int number, const std::string& dict,
                                             const std::string& data) {
        if (static_cast<std::size_t>(number) >= offsets.size())
            offsets.resize(static_cast<std::size_t>(number) + 1, 0);
        offsets[static_cast<std::size_t>(number)] = out.size();
        out += std::to_string(number) + " 0 obj\n<< /Length " + std::to_string(data.size()) +
               " " + dict + " >>\nstream\n" + data + "\nendstream\nendobj\n";
    };

    add_object(1, "<< /Type /Catalog /Pages 2 0 R >>");
    std::string kids = "[";
    for (int i = 0; i < spec.pages; ++i) {
        kids += std::to_string(first_page + i) + " 0 R ";
    }
    kids += "]";
    add_object(2, "<< /Type /Pages /Kids " + kids + " /Count " + std::to_string(spec.pages) +
                      " /Resources << /Font << /F1 " + std::to_string(font_number) +
                      " 0 R >> >> >>");
    add_object(font_number,
               "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");

    int glyphs = 0;
    for (int page = 0; page < spec.pages; ++page) {
        add_object(first_page + page,
                   "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents " +
                       std::to_string(first_content + page) + " 0 R >>");

        std::string content = "BT\n/F1 9 Tf\n54 744 Td\n11 TL\n";
        for (int line = 0; line < spec.lines_per_page; ++line) {
            std::string text;
            switch (line % 6) {
                case 0:
                    text = "Case 2026-0042 review line " + std::to_string(page * spec.lines_per_page + line);
                    break;
                case 1:
                    text = "Client: Example Holdings International";
                    break;
                case 2:
                    text = "Contact: alice@example.com  +1 415 555 0132";
                    break;
                case 3:
                    text = "Reference 123-45-6789  IBAN DE89370400440532013000";
                    break;
                case 4:
                    text = "The parties agree to the schedule set out in Appendix B.";
                    break;
                default:
                    text = "Page " + std::to_string(page + 1) + " of " +
                           std::to_string(spec.pages) + " - internal working copy";
                    break;
            }
            glyphs += static_cast<int>(text.size());
            content += "(" + escape(text) + ") Tj\nT*\n";
        }
        content += "ET\n";

        std::string stored = content;
        std::string filter;
        if (spec.compress) {
            const Bytes compressed = scour::zlib_compress(content);
            if (compressed.size() + 32 < content.size()) {
                stored.assign(reinterpret_cast<const char*>(compressed.data()), compressed.size());
                filter = "/Filter /FlateDecode";
            }
        }
        add_stream(first_content + page, filter, stored);
    }

    add_object(info_number,
               "<< /Author (Benchmark Author) /Title (Synthetic 500 page report) "
               "/Producer (Scour benchmark generator) /Creator (Scour) "
               "/CreationDate (D:20260101120000Z) >>");
    const int size = next_number;
    const std::size_t xref = out.size();
    out += "xref\n0 " + std::to_string(size) + "\n0000000000 65535 f \n";
    for (int number = 1; number < size; ++number) {
        const std::size_t offset = static_cast<std::size_t>(number) < offsets.size()
                                       ? offsets[static_cast<std::size_t>(number)]
                                       : 0;
        if (offset == 0) {
            out += "0000000000 00000 f \n";
        } else {
            char buffer[32];
            std::snprintf(buffer, sizeof(buffer), "%010zu 00000 n \n", offset);
            out += buffer;
        }
    }
    out += "trailer\n<< /Size " + std::to_string(size) + " /Root 1 0 R /Info " +
           std::to_string(info_number) + " 0 R >>\nstartxref\n" + std::to_string(xref) +
           "\n%%EOF\n";
    return {scour::bytes_of(out), glyphs};
}

template <typename Function>
double median_ms(Function&& function, int iterations) {
    std::vector<double> samples;
    samples.reserve(static_cast<std::size_t>(iterations));
    for (int i = 0; i < iterations; ++i) {
        const auto start = std::chrono::steady_clock::now();
        function();
        const auto stop = std::chrono::steady_clock::now();
        samples.push_back(std::chrono::duration<double, std::milli>(stop - start).count());
    }
    std::sort(samples.begin(), samples.end());
    return samples[samples.size() / 2];
}

std::string human_size(std::size_t bytes) {
    char buffer[64];
    if (bytes >= 1024 * 1024)
        std::snprintf(buffer, sizeof(buffer), "%.2f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else
        std::snprintf(buffer, sizeof(buffer), "%.1f KB", static_cast<double>(bytes) / 1024.0);
    return buffer;
}

/// Throughput in the unit that keeps the number readable: a slow operation
/// measured in a fraction of a megabyte per second says "154 KB/s", not "0
/// MB/s". Reporting an integer zero would hide the measurement.
std::string throughput(std::size_t bytes, double milliseconds) {
    if (milliseconds <= 0.0) return {};
    const double megabytes_per_second =
        (static_cast<double>(bytes) / (1024.0 * 1024.0)) / (milliseconds / 1000.0);
    char buffer[64];
    if (megabytes_per_second >= 1.0)
        std::snprintf(buffer, sizeof(buffer), "%.1f MB/s", megabytes_per_second);
    else
        std::snprintf(buffer, sizeof(buffer), "%.0f KB/s", megabytes_per_second * 1024.0);
    return buffer;
}

void row(const char* name, double milliseconds, const std::string& unit) {
    std::printf("  %-22s %8.1f ms   %s\n", name, milliseconds, unit.c_str());
}

}  // namespace

int main(int argc, char** argv) {
    DocumentSpec spec;
    int iterations = 7;
    std::string dump_path;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--pages" && i + 1 < argc) {
            spec.pages = std::atoi(argv[++i]);
        } else if (argument == "--lines" && i + 1 < argc) {
            spec.lines_per_page = std::atoi(argv[++i]);
        } else if (argument == "--iterations" && i + 1 < argc) {
            iterations = std::atoi(argv[++i]);
        } else if (argument == "--write" && i + 1 < argc) {
            dump_path = argv[++i];
        } else if (argument == "--help") {
            std::printf(
                "usage: scour_bench [--pages N] [--lines N] [--iterations N] [--write FILE]\n"
                "\nBuilds a synthetic report in memory and times open, extract, inspect and\n"
                "scrub+write. --write also saves the input so an external tool can be timed\n"
                "on the identical bytes.\n");
            return 0;
        }
    }
    if (spec.pages < 1) spec.pages = 1;
    if (spec.lines_per_page < 1) spec.lines_per_page = 1;

    const BuiltDocument built = build_document(spec);
    std::printf("scour benchmark\n");
    std::printf("  document        %d pages, %d lines/page, %s, %d glyphs\n", spec.pages,
                spec.lines_per_page, human_size(built.bytes.size()).c_str(), built.glyphs);
    std::printf("  input           %zu bytes\n", built.bytes.size());
    std::printf("  iterations      %d (median)\n\n", iterations);

    if (!dump_path.empty()) {
        if (FILE* file = std::fopen(dump_path.c_str(), "wb")) {
            std::fwrite(built.bytes.data(), 1, built.bytes.size(), file);
            std::fclose(file);
            std::printf("  saved input     %s\n\n", dump_path.c_str());
        }
    }

    const auto fresh = [&]() {
        Diagnostics diagnostics;
        LoadOptions options;
        return Document::load(built.bytes, options, diagnostics);
    };

    const double open_ms = median_ms(
        [&]() {
            Diagnostics diagnostics;
            LoadOptions options;
            Document document = Document::load(built.bytes, options, diagnostics);
            const auto pages = scour::collect_page_numbers(document, diagnostics);
            if (pages.size() != static_cast<std::size_t>(spec.pages)) std::abort();
        },
        iterations);

    const double extract_ms = median_ms(
        [&]() {
            Document document = fresh();
            Diagnostics diagnostics;
            const scour::DocumentText text = scour::analyze_document(document, {}, diagnostics);
            if (text.pages.size() != static_cast<std::size_t>(spec.pages)) std::abort();
        },
        iterations);

    const double inspect_ms = median_ms(
        [&]() {
            Document document = fresh();
            Diagnostics diagnostics;
            InspectOptions options;
            const scour::InspectionReport report =
                scour::inspect_document(document, "benchmark.pdf", options, diagnostics);
            if (report.facts.pages != spec.pages) std::abort();
        },
        iterations);

    const double scrub_ms = median_ms(
        [&]() {
            Document document = fresh();
            Diagnostics diagnostics;
            ScrubOptions options;
            options.targets.pii = true;
            options.targets.terms = {"Example Holdings"};
            options.targets.paint = true;
            scour::scrub_document(document, options, diagnostics);
            const scour::WriteResult written =
                scour::write_document(document, WriteOptions{}, diagnostics);
            if (written.bytes.empty()) std::abort();
        },
        std::max(3, iterations / 2));

    const double write_ms = median_ms(
        [&]() {
            Document document = fresh();
            Diagnostics diagnostics;
            const scour::WriteResult written =
                scour::write_document(document, WriteOptions{}, diagnostics);
            if (written.bytes.empty()) std::abort();
        },
        std::max(3, iterations));

    std::printf("  operation              median     throughput\n");
    std::printf("  ------------------------------------------------------------\n");
    row("open + parse", open_ms, {});
    row("extract text", extract_ms, throughput(built.bytes.size(), extract_ms));
    row("inspect + PII scan", inspect_ms, throughput(built.bytes.size(), inspect_ms));
    row("rewrite only", write_ms, throughput(built.bytes.size(), write_ms));
    row("scrub + rewrite", scrub_ms, throughput(built.bytes.size(), scrub_ms));

    struct rusage usage {};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        std::printf("\n  peak RSS        %.1f MB\n",
                    static_cast<double>(usage.ru_maxrss) / 1024.0);
    }
    return 0;
}

// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Fuzz harness. `FuzzOne` sends one input through the same pipeline a user
// triggers — open, inspect, extract text, scrub, rewrite, re-open, verify, and
// page extraction — so a defect anywhere on that path is reachable from hostile
// bytes. Nothing here asserts; the sanitizers are the oracle.
//
// Two ways to run it:
//
//   ./scour_fuzz --corpus fixtures --iterations 20000 --seed 1
//       Standalone mutation driver. Deterministic: the same seed and iteration
//       count replay the same inputs, which is what makes a reported failure
//       reproducible. Build with -DSCOUR_SANITIZE=ON.
//
//   A coverage-guided campaign needs clang (the `-fsanitize=fuzzer` driver):
//   compile with -DSCOUR_LIBFUZZER, -fsanitize=fuzzer,address,undefined and
//   the core sources, and libFuzzer calls LLVMFuzzerTestOneInput instead.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <string>
#include <vector>

#include "scour/document.hpp"
#include "scour/inspector.hpp"
#include "scour/pages.hpp"
#include "scour/redact.hpp"
#include "scour/sanitize.hpp"
#include "scour/text.hpp"
#include "scour/writer.hpp"

namespace fs = std::filesystem;
using namespace scour;

namespace {

/// One input through every stage that parses untrusted bytes. Returns true when
/// the bytes were accepted as a document, which the driver reports as a crude
/// coverage proxy: garbage that is rejected immediately tests very little.
bool FuzzOne(const std::uint8_t* data, std::size_t size) {
    if (size == 0 || size > (16u << 20)) return false;

    Bytes bytes(data, data + size);
    LoadOptions load;
    load.repair = true;

    Diagnostics diagnostics;
    Document document;
    try {
        document = Document::load(std::move(bytes), load, diagnostics);
    } catch (const std::exception&) {
        return false;  // rejected input is a correct outcome
    }

    try {
        InspectOptions inspect_options;
        const InspectionReport report = inspect_document(document, "fuzz.pdf", inspect_options,
                                                         diagnostics);
        volatile int risk = report.risk;
        (void)risk;

        TextOptions text_options;
        const DocumentText text = analyze_document(document, text_options, diagnostics);
        if (!text.pages.empty()) {
            const PageAnalysis& page = text.pages.front();
            volatile std::size_t glyphs = page.runs.size();
            (void)glyphs;
        }

        const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
        for (std::uint32_t number : pages) {
            const Rect box = page_box(document, number);
            volatile int rotation = page_rotation(document, number);
            (void)box;
            (void)rotation;
        }

        // Page surgery: copy a page into a new document, then merge back.
        if (!pages.empty() && pages.size() <= 8) {
            Diagnostics surgery;
            Document extracted = extract_pages(document, {0}, surgery);
            std::vector<Document*> sources{&document, &extracted};
            Document merged = merge_documents(sources, surgery);
            (void)merged;
        }

        // Scrub: targets chosen so the redactor, the painters, the metadata
        // stripper and the action stripper all run.
        ScrubOptions scrub;
        scrub.targets.pii = true;
        scrub.targets.terms.emplace_back("statement");
        if (!pages.empty()) {
            scrub.targets.pages.push_back(1);
            scrub.targets.rects[1].push_back(Rect{60.0, 60.0, 200.0, 90.0});
        }
        Diagnostics scrub_diagnostics;
        const ScrubReport scrub_report = scrub_document(document, scrub, scrub_diagnostics);
        (void)scrub_report;

        WriteOptions write;
        write.compress_streams = size % 3 == 0;
        Diagnostics write_diagnostics;
        const WriteResult written = write_document(document, write, write_diagnostics);
        if (written.bytes.empty()) return true;

        // The writer's output must be readable by the reader: re-open it and
        // re-run detection, which is exactly what `scour verify` does.
        Diagnostics verify_diagnostics;
        Document reopened = Document::load(written.bytes, load, verify_diagnostics);
        const RedactionReport verdict = verify_document(reopened, scrub.targets,
                                                        verify_diagnostics);
        volatile bool clean = verdict.clean();
        (void)clean;
    } catch (const std::exception&) {
        // A malformed document may legitimately fail at any stage; only memory
        // errors and undefined behaviour are failures here.
    }
    return true;
}

// ---------------------------------------------------------------------------
// Standalone mutation driver
// ---------------------------------------------------------------------------

struct Rng {
    std::uint64_t state;
    explicit Rng(std::uint64_t seed) : state(seed ? seed : 0x9E3779B97F4A7C15ull) {}
    std::uint64_t next() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        return state;
    }
    std::size_t below(std::size_t limit) {
        return limit == 0 ? 0 : static_cast<std::size_t>(next() % limit);
    }
};

/// Vocabulary that reaches more parser branches than uniform noise does.
const char* const kTokens[] = {
    "obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref", "%%EOF",
    "<<", ">>", "[", "]", "/Type", "/Page", "/Pages", "/Kids", "/Root", "/Info",
    "/Encrypt", "/Filter", "/FlateDecode", "/LZWDecode", "/ASCII85Decode",
    "/ASCIIHexDecode", "/RunLengthDecode", "/Length", "/ObjStm", "/XRef", "/Prev",
    "0 R", "1 0 R", "true", "null", "(", ")", "<", ">"};

void Mutate(Bytes& buffer, Rng& rng, const std::vector<Bytes>& corpus) {
    const int operations = 1 + static_cast<int>(rng.below(6));
    for (int i = 0; i < operations; ++i) {
        switch (rng.below(8)) {
            case 0:  // flip a byte
                if (!buffer.empty()) buffer[rng.below(buffer.size())] ^= static_cast<Byte>(1u << rng.below(8));
                break;
            case 1:  // replace a byte
                if (!buffer.empty()) buffer[rng.below(buffer.size())] = static_cast<Byte>(rng.next());
                break;
            case 2: {  // duplicate a range
                if (buffer.empty()) break;
                const std::size_t at = rng.below(buffer.size());
                const std::size_t length = std::min<std::size_t>(rng.below(64) + 1, buffer.size() - at);
                const Bytes copy(buffer.begin() + static_cast<std::ptrdiff_t>(at),
                                 buffer.begin() + static_cast<std::ptrdiff_t>(at + length));
                buffer.insert(buffer.begin() + static_cast<std::ptrdiff_t>(at), copy.begin(), copy.end());
                break;
            }
            case 3: {  // delete a range
                if (buffer.size() < 2) break;
                const std::size_t at = rng.below(buffer.size());
                const std::size_t length = std::min<std::size_t>(rng.below(64) + 1, buffer.size() - at);
                buffer.erase(buffer.begin() + static_cast<std::ptrdiff_t>(at),
                             buffer.begin() + static_cast<std::ptrdiff_t>(at + length));
                break;
            }
            case 4: {  // insert a token from the PDF vocabulary
                const char* token = kTokens[rng.below(sizeof(kTokens) / sizeof(kTokens[0]))];
                const std::size_t at = buffer.empty() ? 0 : rng.below(buffer.size());
                buffer.insert(buffer.begin() + static_cast<std::ptrdiff_t>(at), token,
                              token + std::strlen(token));
                break;
            }
            case 5:  // truncate
                buffer.resize(1 + rng.below(buffer.size() + 1));
                break;
            case 6: {  // splice in bytes from another seed
                if (corpus.empty()) break;
                const Bytes& other = corpus[rng.below(corpus.size())];
                if (other.empty()) break;
                const std::size_t from = rng.below(other.size());
                const std::size_t length = std::min<std::size_t>(rng.below(512) + 1, other.size() - from);
                const std::size_t at = rng.below(buffer.size() + 1);
                buffer.insert(buffer.begin() + static_cast<std::ptrdiff_t>(at),
                              other.begin() + static_cast<std::ptrdiff_t>(from),
                              other.begin() + static_cast<std::ptrdiff_t>(from + length));
                break;
            }
            default: {  // overwrite a range with noise
                if (buffer.empty()) break;
                const std::size_t at = rng.below(buffer.size());
                const std::size_t length = std::min<std::size_t>(rng.below(32) + 1, buffer.size() - at);
                for (std::size_t k = 0; k < length; ++k) buffer[at + k] = static_cast<Byte>(rng.next());
                break;
            }
        }
        if (buffer.size() > (1u << 20)) buffer.resize(1u << 20);
    }
}

std::uint64_t fingerprint(const Bytes& buffer) {
    std::uint64_t hash = 1469598103934665603ull;
    for (Byte byte : buffer) {
        hash ^= byte;
        hash *= 1099511628211ull;
    }
    return hash;
}

std::vector<Bytes> read_corpus(const std::string& path) {
    std::vector<Bytes> seeds;
    std::error_code error;
    if (!fs::is_directory(path, error)) {
        std::fprintf(stderr, "scour_fuzz: not a directory: %s\n", path.c_str());
        return seeds;
    }
    // Sorted, because the order seeds are indexed in is part of the run: an
    // unsorted directory walk would make the same seed mutate different bytes
    // on a different machine, and a reported failure would not replay.
    std::vector<fs::path> files;
    for (const fs::directory_entry& entry : fs::recursive_directory_iterator(path, error)) {
        if (entry.is_regular_file(error)) files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end());
    for (const fs::path& file_path : files) {
        std::FILE* file = std::fopen(file_path.string().c_str(), "rb");
        if (file == nullptr) continue;
        Bytes buffer;
        std::uint8_t chunk[4096];
        std::size_t got = 0;
        while ((got = std::fread(chunk, 1, sizeof(chunk), file)) > 0) {
            buffer.insert(buffer.end(), chunk, chunk + got);
        }
        std::fclose(file);
        if (!buffer.empty()) seeds.push_back(std::move(buffer));
    }
    return seeds;
}

void usage() {
    std::printf(
        "usage: scour_fuzz [--corpus DIR]... [--iterations N] [--seed N] [--time SECONDS]\n"
        "\n"
        "Drives the parser, inspector, redactor, writer and verifier over mutated PDFs.\n"
        "The sanitizers built into the binary are the oracle: any memory error or\n"
        "undefined behaviour aborts the run. Runs are deterministic, so a suspected\n"
        "input is replayed with the seed and iteration printed before it.\n"
        "\n"
        "  --corpus DIR      seed PDFs, repeatable (default: fixtures)\n"
        "  --iterations N    inputs to try, 0 means until --time (default: 10000)\n"
        "  --seed N          mutation seed, printed on every input (default: 1)\n"
        "  --time SECONDS    wall-clock limit, 0 means no limit (default: 0)\n"
        "  --quiet           only print the summary\n");
}

}  // namespace

#if defined(SCOUR_LIBFUZZER)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    FuzzOne(data, size);
    return 0;
}
#else
int main(int argc, char** argv) {
    std::vector<std::string> corpora;
    std::uint64_t seed = 1;
    long long iterations = 10000;
    double time_limit = 0.0;
    bool quiet = false;
    bool seed_given = false;

    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--corpus" && i + 1 < argc) {
            corpora.push_back(argv[++i]);
        } else if (argument == "--iterations" && i + 1 < argc) {
            iterations = std::atoll(argv[++i]);
        } else if (argument == "--seed" && i + 1 < argc) {
            seed = std::strtoull(argv[++i], nullptr, 10);
            seed_given = true;
        } else if (argument == "--time" && i + 1 < argc) {
            time_limit = std::atof(argv[++i]);
        } else if (argument == "--quiet") {
            quiet = true;
        } else if (argument == "--help" || argument == "-h") {
            usage();
            return 0;
        } else {
            std::fprintf(stderr, "scour_fuzz: unknown argument %s\n", argument.c_str());
            usage();
            return 2;
        }
    }
    if (!seed_given) seed = 1;
    if (iterations < 0) iterations = 0;
    if (corpora.empty()) corpora.emplace_back("fixtures");

    std::vector<Bytes> corpus;
    for (const std::string& path : corpora) {
        std::vector<Bytes> loaded = read_corpus(path);
        if (loaded.empty()) {
            std::fprintf(stderr, "scour_fuzz: no seed files in %s\n", path.c_str());
        }
        for (Bytes& item : loaded) corpus.push_back(std::move(item));
    }
    if (corpus.empty()) {
        std::fprintf(stderr, "scour_fuzz: no seeds; pass --corpus DIR\n");
        return 2;
    }

    const std::clock_t started = std::clock();
    Rng rng(seed);
    std::size_t executions = 0;
    std::size_t accepted = 0;

    for (long long i = 0; iterations == 0 || i < iterations; ++i) {
        if (time_limit > 0.0) {
            const double elapsed = static_cast<double>(std::clock() - started) / CLOCKS_PER_SEC;
            if (elapsed > time_limit) break;
        }
        Bytes buffer = corpus[rng.below(corpus.size())];
        Mutate(buffer, rng, corpus);

        // Printed before the call and flushed: if the sanitizer aborts, this
        // line is the last thing on stderr and identifies the input exactly.
        if (!quiet) {
            std::fprintf(stderr, "input iteration=%lld seed=%llu bytes=%zu fnv=%016llx\n", i,
                         static_cast<unsigned long long>(seed), buffer.size(),
                         static_cast<unsigned long long>(fingerprint(buffer)));
            std::fflush(stderr);
        }
        if (FuzzOne(buffer.data(), buffer.size())) ++accepted;
        ++executions;
    }

    const double elapsed = static_cast<double>(std::clock() - started) / CLOCKS_PER_SEC;
    const double rate = elapsed > 0.0 ? static_cast<double>(executions) / elapsed : 0.0;
    const double reach = executions > 0 ? 100.0 * static_cast<double>(accepted) /
                                              static_cast<double>(executions)
                                        : 0.0;
    std::printf("scour_fuzz: %zu inputs in %.2f s (%.0f/s), seed %llu, %zu seeds\n", executions,
                elapsed, rate, static_cast<unsigned long long>(seed), corpus.size());
    std::printf("scour_fuzz: %zu parsed as documents (%.1f%%), %zu rejected early\n", accepted,
                reach, executions - accepted);
    std::printf("no crashes, no sanitizer reports\n");
    return 0;
}
#endif

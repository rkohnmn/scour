// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
//
// Exit codes are part of the contract, because the point of this tool is to be
// usable from CI and from other scripts:
//
//   0  success, and nothing was left to report
//   1  success, but findings remain (inspect: risk at or above the threshold,
//      scrub/verify: the verification pass still found the target)
//   2  usage error
//   3  the input could not be opened, decrypted or parsed
//   4  the output could not be written or failed verification
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include "scour/document.hpp"
#include "scour/error.hpp"
#include "scour/inspector.hpp"
#include "scour/pages.hpp"
#include "scour/redact.hpp"
#include "scour/sanitize.hpp"
#include "scour/text.hpp"
#include "scour/version.hpp"
#include "scour/writer.hpp"
#include "tui/app.hpp"

namespace {

using namespace scour;
namespace fs = std::filesystem;

constexpr int kExitClean = 0;
constexpr int kExitFindings = 1;
constexpr int kExitUsage = 2;
constexpr int kExitInput = 3;
constexpr int kExitOutput = 4;

std::string g_program = "scour";

// ---------------------------------------------------------------------------
// Terminal colour
// ---------------------------------------------------------------------------
bool g_color = false;

const char* kReset = "\x1b[0m";

std::string color(const char* code, std::string_view text) {
    if (!g_color) return std::string(text);
    return std::string(code) + std::string(text) + kReset;
}

std::string bold(std::string_view text) { return color("\x1b[1m", text); }
std::string red(std::string_view text) { return color("\x1b[31m", text); }
std::string green(std::string_view text) { return color("\x1b[32m", text); }
std::string yellow(std::string_view text) { return color("\x1b[33m", text); }
std::string cyan(std::string_view text) { return color("\x1b[36m", text); }

void detect_color(bool no_color_flag) {
    const bool tty = ::isatty(STDOUT_FILENO) != 0;
    const bool no_color_env = std::getenv("NO_COLOR") != nullptr;
    g_color = tty && !no_color_env && !no_color_flag;
}

std::string colorize_report(const std::string& text, int risk) {
    if (!g_color) return text;
    std::istringstream input(text);
    std::string line;
    std::string out;
    while (std::getline(input, line)) {
        const std::size_t bracket = line.find('[');
        if (bracket != std::string::npos && bracket <= 4) {
            const std::size_t end = line.find(']', bracket);
            if (end != std::string::npos) {
                const std::string tag = line.substr(bracket + 1, end - bracket - 1);
                if (tag == "error") {
                    line = line.substr(0, bracket) + red("[" + tag + "]") + line.substr(end + 1);
                } else if (tag == "warning") {
                    line = line.substr(0, bracket) + yellow("[" + tag + "]") + line.substr(end + 1);
                } else if (tag == "note") {
                    line = line.substr(0, bracket) + cyan("[" + tag + "]") + line.substr(end + 1);
                }
            }
        }
        if (line.find("RISK") != std::string::npos) {
            const std::string painted =
                risk >= 55 ? red(line) : risk >= 30 ? yellow(line) : green(line);
            line = painted;
        } else if (!line.empty() && line[0] != ' ' && line.find(':') == std::string::npos &&
                   line != "SCOUR REPORT" && line != "Scores" &&
                   (line == "METADATA" || line == "HIDDEN-TEXT" || line == "ANNOTATIONS" ||
                    line == "EMBEDDED" || line == "ACTIONS" || line == "STRUCTURE" ||
                    line == "PII" || line == "INTEGRITY")) {
            line = bold(line);
        }
        out += line;
        out.push_back('\n');
    }
    return out;
}

// ---------------------------------------------------------------------------
// Errors and usage
// ---------------------------------------------------------------------------
struct CliError {
    int code;
    std::string message;
};

[[noreturn]] void usage_error(const std::string& message) {
    throw CliError{kExitUsage, message};
}

std::string help_text();

void print_help() { std::cout << help_text(); }

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------
Bytes read_file(const fs::path& path) {
    std::error_code error;
    if (!fs::exists(path, error) || fs::is_directory(path, error))
        throw CliError{kExitInput, "no such file: " + path.string()};
    std::ifstream stream(path, std::ios::binary);
    if (!stream) throw CliError{kExitInput, "cannot open " + path.string()};
    stream.seekg(0, std::ios::end);
    const std::streamoff size = stream.tellg();
    if (size < 0) throw CliError{kExitInput, "cannot measure " + path.string()};
    stream.seekg(0, std::ios::beg);
    Bytes bytes(static_cast<std::size_t>(size));
    if (size > 0) stream.read(reinterpret_cast<char*>(bytes.data()), size);
    if (!stream) throw CliError{kExitInput, "cannot read " + path.string()};
    return bytes;
}

void write_file_atomic(const fs::path& path, const Bytes& bytes) {
    std::error_code error;
    if (path.has_parent_path()) fs::create_directories(path.parent_path(), error);
    const fs::path temporary = path.string() + ".scour-tmp";
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream) throw CliError{kExitOutput, "cannot write " + path.string()};
        if (!bytes.empty())
            stream.write(reinterpret_cast<const char*>(bytes.data()),
                         static_cast<std::streamsize>(bytes.size()));
        stream.flush();
        if (!stream) throw CliError{kExitOutput, "cannot write " + path.string()};
    }
    fs::rename(temporary, path, error);
    if (error) {
        fs::remove(temporary, error);
        throw CliError{kExitOutput, "cannot replace " + path.string()};
    }
}

std::string human_size(std::size_t bytes) {
    constexpr const char* kUnits[] = {"B", "KB", "MB", "GB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 3) {
        value /= 1024.0;
        ++unit;
    }
    char buffer[32];
    if (unit == 0)
        std::snprintf(buffer, sizeof(buffer), "%zu B", bytes);
    else
        std::snprintf(buffer, sizeof(buffer), "%.1f %s", value, kUnits[unit]);
    return buffer;
}

// ---------------------------------------------------------------------------
// Option parsing
// ---------------------------------------------------------------------------
struct Options {
    std::vector<std::string> positional;
    std::vector<std::pair<std::string, std::string>> flags;

    [[nodiscard]] bool has(std::string_view name) const {
        return std::any_of(flags.begin(), flags.end(),
                           [&](const auto& item) { return item.first == name; });
    }

    [[nodiscard]] std::optional<std::string> value(std::string_view name) const {
        for (auto it = flags.rbegin(); it != flags.rend(); ++it) {
            if (it->first == name) return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::string value_or(std::string_view name, std::string fallback) const {
        const std::optional<std::string> found = value(name);
        return found.has_value() ? *found : fallback;
    }

    [[nodiscard]] std::vector<std::string> all(std::string_view name) const {
        std::vector<std::string> values;
        for (const auto& [key, item] : flags) {
            if (key == name) values.push_back(item);
        }
        return values;
    }
};

const std::vector<std::string>& boolean_flags() {
    static const std::vector<std::string> kFlags = {
        "json",   "no-pii", "pii",         "no-boxes",  "in-place", "keep-metadata",
        "keep-annotations", "keep-attachments", "keep-scripts", "no-redact", "compress",
        "each",   "help",   "version",     "no-color",  "ansi",
    };
    return kFlags;
}

bool is_boolean_flag(const std::string& name) {
    const std::vector<std::string>& flags = boolean_flags();
    return std::find(flags.begin(), flags.end(), name) != flags.end();
}

bool is_value_flag(const std::string& name) {
    static const std::vector<std::string> kFlags = {
        "output", "password", "fail-on", "term", "page", "pages", "rect", "by", "dump",
        "keys", "theme",
    };
    return std::find(kFlags.begin(), kFlags.end(), name) != kFlags.end();
}

Options parse_options(const std::vector<std::string>& args) {
    Options options;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg = args[i];
        if (arg == "--") {
            for (++i; i < args.size(); ++i) options.positional.push_back(args[i]);
            break;
        }
        if (arg.size() > 2 && arg[0] == '-' && arg[1] == '-') {
            std::string name = arg.substr(2);
            std::string value;
            const std::size_t equals = name.find('=');
            if (equals != std::string::npos) {
                value = name.substr(equals + 1);
                name = name.substr(0, equals);
                options.flags.emplace_back(name, value);
                continue;
            }
            if (is_boolean_flag(name)) {
                options.flags.emplace_back(name, "");
                continue;
            }
            if (!is_value_flag(name)) usage_error("unknown option --" + name);
            if (i + 1 >= args.size())
                usage_error("option --" + name + " needs a value");
            options.flags.emplace_back(name, args[++i]);
            continue;
        }
        if (arg == "-o" || arg == "-p") {
            if (i + 1 >= args.size()) usage_error("option " + arg + " needs a value");
            options.flags.emplace_back(arg == "-o" ? "output" : "password", args[++i]);
            continue;
        }
        if (arg == "-h") {
            options.flags.emplace_back("help", "");
            continue;
        }
        if (arg.size() > 1 && arg[0] == '-' && arg != "-")
            usage_error("unknown option " + arg);
        options.positional.push_back(arg);
    }
    return options;
}

// ---------------------------------------------------------------------------
// Page lists
// ---------------------------------------------------------------------------
int page_count_of(Document& document, Diagnostics& diagnostics) {
    return static_cast<int>(collect_page_numbers(document, diagnostics).size());
}

/// Parses "1-3,7,9-" into 0-based page indices, clamped and de-duplicated while
/// preserving the order the user wrote.
std::vector<int> parse_pages(std::string_view spec, int count) {
    std::vector<int> pages;
    if (count <= 0) return pages;
    std::size_t position = 0;
    while (position < spec.size()) {
        const std::size_t comma = spec.find(',', position);
        std::string token(spec.substr(position, comma == std::string_view::npos
                                                   ? std::string_view::npos
                                                   : comma - position));
        position = comma == std::string_view::npos ? spec.size() : comma + 1;
        token.erase(std::remove_if(token.begin(), token.end(),
                                   [](unsigned char c) { return std::isspace(c) != 0; }),
                    token.end());
        if (token.empty()) continue;
        const std::size_t dash = token.find('-');
        int first = 0;
        int last = 0;
        if (dash == std::string::npos) {
            try {
                first = std::stoi(token);
            } catch (const std::exception&) {
                usage_error("bad page list: " + token);
            }
            last = first;
        } else {
            const std::string left = token.substr(0, dash);
            const std::string right = token.substr(dash + 1);
            try {
                first = left.empty() ? 1 : std::stoi(left);
                last = right.empty() ? count : std::stoi(right);
            } catch (const std::exception&) {
                usage_error("bad page list: " + token);
            }
        }
        if (first < 1) first = 1;
        if (last > count) last = count;
        for (int page = first; page <= last; ++page) {
            if (std::find(pages.begin(), pages.end(), page - 1) == pages.end())
                pages.push_back(page - 1);
        }
    }
    return pages;
}

std::string pages_to_string(const std::vector<int>& pages) {
    std::string out;
    for (std::size_t i = 0; i < pages.size(); ++i) {
        if (i != 0) out += ",";
        out += std::to_string(pages[i] + 1);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Document loading
// ---------------------------------------------------------------------------
Document open_document(const fs::path& path, const std::string& password, Diagnostics& diagnostics) {
    const Bytes bytes = read_file(path);
    LoadOptions options;
    options.password = password;
    try {
        Document document = Document::load(bytes, options, diagnostics);
        if (document.encrypted() && !document.security().valid()) {
            const std::string reason = document.security().info().failure;
            throw CliError{kExitInput,
                           path.string() + ": encrypted; " +
                               (options.password.empty()
                                    ? "a document password is required, pass -p PASSWORD"
                                    : "the password is wrong") +
                               (reason.empty() ? "" : " (" + reason + ")")};
        }
        return document;
    } catch (const ScourError& error) {
        throw CliError{kExitInput, path.string() + ": " + error.what() + " (" + error.code() + ")"};
    }
}

std::string default_output(const fs::path& input, const std::string& suffix) {
    const fs::path parent = input.parent_path();
    const std::string stem = input.stem().string();
    const std::string name = stem + suffix + ".pdf";
    return (parent / name).string();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
int command_inspect(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour inspect <file.pdf> [--json] [--no-pii] [--fail-on N]\n\n"
                     "Reports what the file still carries: metadata, hidden text, painted-over\n"
                     "text, annotations, attachments, scripts, dead objects and personal data.\n"
                     "Exits 1 when the risk score reaches the threshold (default 10).\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("inspect needs a file");
    if (options.positional.size() > 1) usage_error("inspect takes exactly one file");

    Diagnostics diagnostics;
    Document document = open_document(options.positional[0], options.value_or("password", ""), diagnostics);
    InspectOptions inspect_options;
    inspect_options.include_pii = !options.has("no-pii");
    const InspectionReport report =
        inspect_document(document, options.positional[0], inspect_options, diagnostics);

    if (options.has("json")) {
        std::cout << report.to_json();
    } else {
        std::cout << colorize_report(report.to_text(), report.risk);
    }

    int threshold = 10;
    if (const std::optional<std::string> value = options.value("fail-on")) {
        try {
            threshold = std::stoi(*value);
        } catch (const std::exception&) {
            usage_error("--fail-on needs a number between 0 and 100");
        }
        if (threshold < 0 || threshold > 100) usage_error("--fail-on must be 0..100");
    }
    return report.risk >= threshold ? kExitFindings : kExitClean;
}

RedactionTargets targets_from_options(const Options& options, int page_count) {
    RedactionTargets targets;
    targets.terms = options.all("term");
    targets.pii = options.has("pii");
    targets.paint = !options.has("no-boxes");
    if (const std::optional<std::string> pages = options.value("pages"))
        targets.pages = parse_pages(*pages, page_count);

    for (const std::string& spec : options.all("rect")) {
        const std::size_t colon = spec.find(':');
        if (colon == std::string::npos)
            usage_error("--rect wants PAGE:X0,Y0,X1,Y1, e.g. --rect 2:60,700,560,740");
        int page = 0;
        try {
            page = std::stoi(spec.substr(0, colon));
        } catch (const std::exception&) {
            usage_error("--rect wants a page number before the colon");
        }
        if (page < 1 || (page_count > 0 && page > page_count))
            usage_error("--rect page " + std::to_string(page) + " is outside the document");
        std::string body = spec.substr(colon + 1);
        std::vector<double> values;
        std::size_t position = 0;
        while (position <= body.size()) {
            const std::size_t comma = body.find(',', position);
            const std::string token =
                body.substr(position, comma == std::string::npos ? std::string::npos : comma - position);
            if (!token.empty()) {
                try {
                    values.push_back(std::stod(token));
                } catch (const std::exception&) {
                    usage_error("--rect has a non-numeric coordinate: " + token);
                }
            }
            if (comma == std::string::npos) break;
            position = comma + 1;
        }
        if (values.size() != 4) usage_error("--rect needs four coordinates: x0,y0,x1,y1");
        targets.rects[page].push_back(
            Rect::from_corners(values[0], values[1], values[2], values[3]));
    }
    return targets;
}

int command_scrub(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour scrub <file.pdf> -o <out.pdf> [options]\n\n"
                     "  --term TEXT            remove a literal term (repeatable, case-insensitive)\n"
                     "  --pii                  remove emails, phones, SSNs, cards, IBANs, keys\n"
                     "  --pages LIST           pages to redact, e.g. 1-3,7\n"
                     "  --rect PAGE:X0,Y0,X1,Y1   remove glyphs intersecting a box (repeatable)\n"
                     "  --no-boxes             do not paint black boxes over removed glyphs\n"
                     "  --keep-metadata        keep /Info and XMP\n"
                     "  --keep-annotations     keep comments and form fields\n"
                     "  --keep-attachments     keep embedded files\n"
                     "  --keep-scripts         keep JavaScript and launch actions\n"
                     "  --no-redact            only strip metadata, annotations and attachments\n"
                     "  --in-place             replace the input file (atomic write)\n"
                     "  --compress             deflate uncompressed streams when smaller\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("scrub needs a file");
    if (options.positional.size() > 1) usage_error("scrub takes exactly one file");

    const fs::path input = options.positional[0];
    fs::path output;
    if (options.has("in-place")) {
        output = input;
    } else if (const std::optional<std::string> value = options.value("output")) {
        output = *value;
    } else {
        output = default_output(input, ".scrubbed");
    }

    Diagnostics diagnostics;
    Document document = open_document(input, options.value_or("password", ""), diagnostics);
    const std::size_t before_bytes = document.file_size();
    ScrubOptions scrub_options;
    scrub_options.strip_metadata = !options.has("keep-metadata");
    scrub_options.strip_annotations = !options.has("keep-annotations");
    scrub_options.strip_attachments = !options.has("keep-attachments");
    scrub_options.strip_scripts = !options.has("keep-scripts");
    scrub_options.redact = !options.has("no-redact");
    const int pages = page_count_of(document, diagnostics);
    scrub_options.targets = targets_from_options(options, pages);

    const ScrubReport scrub = scrub_document(document, scrub_options, diagnostics);

    WriteOptions write_options;
    write_options.compress_streams = options.has("compress");
    write_options.deterministic_id = true;
    const WriteResult written = write_document(document, write_options, diagnostics);
    write_file_atomic(output, written.bytes);

    // Prove the result: reopen the file we just wrote and look again.
    Diagnostics verify_diagnostics;
    Document reopened = open_document(output, options.value_or("password", ""), verify_diagnostics);
    RedactionReport verification;
    verification.verified = true;
    verification.pages_scanned = pages;
    const bool has_targets = !scrub_options.targets.terms.empty() || scrub_options.targets.pii ||
                             !scrub_options.targets.rects.empty();
    if (scrub_options.redact && has_targets) {
        verification = verify_document(reopened, scrub_options.targets, verify_diagnostics);
    }

    std::ostringstream out;
    out << bold("SCRUBBED") << "  " << input.string() << " -> " << output.string() << "\n\n";
    out << "  size         " << human_size(before_bytes) << " -> "
        << human_size(written.bytes.size()) << "\n";
    out << "  objects      " << written.objects_written << " written, "
        << written.objects_dropped << " dropped\n";
    if (scrub.metadata_removed > 0) out << "  metadata     removed\n";
    if (scrub.annotations_removed > 0)
        out << "  annotations  " << scrub.annotations_removed << " removed\n";
    if (scrub.attachments_removed > 0)
        out << "  attachments  " << scrub.attachments_removed << " removed\n";
    if (scrub.actions_removed > 0)
        out << "  actions      " << scrub.actions_removed << " removed\n";
    if (scrub.redacted) {
        out << "  glyphs       " << scrub.redaction.glyphs_removed << " removed\n";
        out << "  boxes        " << scrub.redaction.boxes_painted << " painted\n";
    }
    for (const std::string& note : scrub.notes) out << "  note         " << note << "\n";
    for (const std::string& warning : scrub.redaction.warnings)
        out << "  " << yellow("warning") << "      " << warning << "\n";

    bool clean = true;
    if (scrub.redacted && has_targets) {
        if (verification.remaining.empty() && verification.verified) {
            out << "\n  " << green("verified") << "     re-opened the output; the targets are gone from "
                << "the text layer\n";
        } else {
            clean = false;
            out << "\n  " << red("not clean") << "    " << verification.remaining.size()
                << " target(s) survive in " << output.string() << "\n";
            for (const RedactionFinding& finding : verification.remaining) {
                out << "      page " << finding.page << "  " << finding.kind << "  "
                    << finding.text << "\n";
            }
        }
    }
    if (!verification.warnings.empty()) {
        std::size_t shown = 0;
        for (const std::string& warning : verification.warnings) {
            out << "  " << yellow("warning") << "      " << warning << "\n";
            if (++shown >= 6) break;
        }
    }
    std::cout << out.str();

    if (!clean) return kExitFindings;
    if (diagnostics.has_errors()) return kExitOutput;
    return kExitClean;
}

int command_verify(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour verify <file.pdf> [--term TEXT]... [--pii] [--json]\n\n"
                     "Re-extracts the document and reports whether any target still survives.\n"
                     "Exits 1 when something is left, 0 when the text layer is clean.\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("verify needs a file");
    if (options.positional.size() > 1) usage_error("verify takes exactly one file");

    Diagnostics diagnostics;
    Document document = open_document(options.positional[0], options.value_or("password", ""),
                                      diagnostics);
    const int pages = page_count_of(document, diagnostics);
    const RedactionTargets targets = targets_from_options(options, pages);
    RedactionReport report = verify_document(document, targets, diagnostics);

    if (options.has("json")) {
        std::ostringstream out;
        out << "{\"file\": " << json_quote(options.positional[0])
            << ", \"pages\": " << report.pages_scanned
            << ", \"verified\": " << (report.clean() ? "true" : "false")
            << ", \"remaining\": " << report.remaining.size() << ", \"items\": [";
        for (std::size_t i = 0; i < report.remaining.size(); ++i) {
            if (i != 0) out << ", ";
            out << "{\"page\": " << report.remaining[i].page << ", \"kind\": "
                << json_quote(report.remaining[i].kind) << ", \"text\": "
                << json_quote(report.remaining[i].text) << "}";
        }
        out << "]}\n";
        std::cout << out.str();
    } else {
        std::ostringstream out;
        out << (report.clean() ? green("CLEAN") : red("NOT CLEAN")) << "  "
            << options.positional[0] << "\n";
        out << "  pages scanned  " << report.pages_scanned << "\n";
        out << "  remaining      " << report.remaining.size() << "\n";
        for (const RedactionFinding& finding : report.remaining) {
            out << "    page " << finding.page << "  " << finding.kind << "  " << finding.text
                << "\n";
        }
        for (const std::string& warning : report.warnings) out << "  warning  " << warning << "\n";
        std::cout << out.str();
    }
    return report.clean() ? kExitClean : kExitFindings;
}

int command_text(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour text <file.pdf> [--page N]\n\n"
                     "Prints the extracted text layer, form-feed separated between pages.\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("text needs a file");
    if (options.positional.size() > 1) usage_error("text takes exactly one file");
    Diagnostics diagnostics;
    Document document = open_document(options.positional[0], options.value_or("password", ""),
                                      diagnostics);
    DocumentText text = analyze_document(document, TextOptions{}, diagnostics);
    int only = 0;
    if (const std::optional<std::string> value = options.value("page")) {
        try {
            only = std::stoi(*value);
        } catch (const std::exception&) {
            usage_error("--page needs a number");
        }
    }
    for (std::size_t i = 0; i < text.pages.size(); ++i) {
        if (only > 0 && static_cast<int>(i) + 1 != only) continue;
        if (only == 0 && i != 0) std::cout << '\f';
        std::cout << text.pages[i].text;
        if (!text.pages[i].text.empty() && text.pages[i].text.back() != '\n') std::cout << '\n';
    }
    return kExitClean;
}

int command_split(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour split <file.pdf> --pages LIST -o <out.pdf>\n"
                     "       scour split <file.pdf> --each -o <directory>\n\n"
                     "LIST is 1-based and accepts ranges: 1-3,7,10-\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("split needs a file");
    Diagnostics diagnostics;
    Document document = open_document(options.positional[0], options.value_or("password", ""),
                                      diagnostics);
    const int pages = page_count_of(document, diagnostics);
    const fs::path input = options.positional[0];

    if (options.has("each")) {
        const fs::path directory = options.value_or("output", (input.parent_path() / "pages").string());
        std::error_code error;
        fs::create_directories(directory, error);
        if (error) throw CliError{kExitOutput, "cannot create " + directory.string()};
        const std::string stem = input.stem().string();
        for (int page = 0; page < pages; ++page) {
            Document part = extract_pages(document, {page}, diagnostics);
            const WriteResult written = write_document(part, WriteOptions{}, diagnostics);
            char number[32];
            std::snprintf(number, sizeof(number), "%03d", page + 1);
            const fs::path target = directory / (stem + "-page-" + number + ".pdf");
            write_file_atomic(target, written.bytes);
        }
        std::cout << "wrote " << pages << " files to " << directory.string() << "\n";
        return kExitClean;
    }

    if (!options.has("pages")) usage_error("split needs --pages or --each");
    const std::vector<int> selected = parse_pages(options.value_or("pages", ""), pages);
    if (selected.empty()) usage_error("the page list selected no pages");
    Document part = extract_pages(document, selected, diagnostics);
    const WriteResult written = write_document(part, WriteOptions{}, diagnostics);
    const fs::path output = options.value_or("output", default_output(input, ".pages"));
    write_file_atomic(output, written.bytes);
    std::cout << "wrote pages " << pages_to_string(selected) << " to " << output.string() << "\n";
    return kExitClean;
}

int command_merge(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour merge -o <out.pdf> <a.pdf> <b.pdf> [...]\n\n"
                     "Concatenates documents in the order given, remapping annotations and links.\n";
        return kExitClean;
    }
    if (options.positional.size() < 2) usage_error("merge needs at least two input files");
    Diagnostics diagnostics;
    std::vector<Document> documents;
    documents.reserve(options.positional.size());
    for (const std::string& path : options.positional) {
        documents.push_back(open_document(path, options.value_or("password", ""), diagnostics));
    }
    std::vector<Document*> pointers;
    pointers.reserve(documents.size());
    for (Document& document : documents) pointers.push_back(&document);
    Document merged = merge_documents(std::move(pointers), diagnostics);
    const WriteResult written = write_document(merged, WriteOptions{}, diagnostics);
    const fs::path output = options.value_or("output", "merged.pdf");
    write_file_atomic(output, written.bytes);
    std::cout << "wrote " << written.objects_written << " objects to " << output.string()
              << "\n";
    return kExitClean;
}

int command_rotate(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour rotate <file.pdf> --by 90 -o <out.pdf> [--pages LIST]\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("rotate needs a file");
    int degrees = 90;
    if (const std::optional<std::string> value = options.value("by")) {
        try {
            degrees = std::stoi(*value);
        } catch (const std::exception&) {
            usage_error("--by needs 90, 180 or 270");
        }
    }
    if (degrees % 90 != 0) usage_error("--by must be a multiple of 90");
    Diagnostics diagnostics;
    Document document = open_document(options.positional[0], options.value_or("password", ""),
                                      diagnostics);
    const std::vector<std::uint32_t> pages = collect_page_numbers(document, diagnostics);
    std::vector<int> selected;
    if (const std::optional<std::string> value = options.value("pages"))
        selected = parse_pages(*value, static_cast<int>(pages.size()));
    else {
        for (std::size_t i = 0; i < pages.size(); ++i) selected.push_back(static_cast<int>(i));
    }
    for (const int index : selected) {
        const int current = page_rotation(document, pages[static_cast<std::size_t>(index)]);
        set_page_rotation(document, pages[static_cast<std::size_t>(index)],
                          ((current + degrees) % 360 + 360) % 360);
    }
    const WriteResult written = write_document(document, WriteOptions{}, diagnostics);
    const fs::path input = options.positional[0];
    const fs::path output = options.value_or("output",
                                             default_output(input, ".rotated"));
    write_file_atomic(output, written.bytes);
    std::cout << "rotated " << selected.size() << " page(s) by " << degrees << " degrees -> "
              << output.string() << "\n";
    return kExitClean;
}

int command_tui(const std::vector<std::string>& args) {
    const Options options = parse_options(args);
    if (options.has("help")) {
        std::cout << "usage: scour tui <file.pdf> [--dump WxH] [--keys STR] [--theme midnight|paper]\n"
                     "                  [--no-color]\n\n"
                     "Interactive dashboard. --dump renders one frame to stdout and exits, which\n"
                     "is how the snapshots in docs/ are generated. --no-color (or NO_COLOR in\n"
                     "the environment) drops colour; press m to toggle it inside the dashboard.\n"
                     "The dashboard needs a 64x18 terminal; below that it asks you to resize.\n";
        return kExitClean;
    }
    if (options.positional.empty()) usage_error("tui needs a file");
    tui::TuiOptions tui_options;
    tui_options.path = options.positional[0];
    tui_options.password = options.value_or("password", "");
    if (const std::optional<std::string> dump = options.value("dump")) {
        const std::size_t x = dump->find('x');
        if (x == std::string::npos) usage_error("--dump wants WIDTHxHEIGHT, e.g. 100x32");
        try {
            tui_options.dump_width = std::stoi(dump->substr(0, x));
            tui_options.dump_height = std::stoi(dump->substr(x + 1));
        } catch (const std::exception&) {
            usage_error("--dump wants WIDTHxHEIGHT, e.g. 100x32");
        }
        tui_options.dump = true;
    }
    tui_options.ansi = options.has("ansi");
    // The same rule as the line-oriented commands: an explicit flag or NO_COLOR,
    // so a terminal without colour still gets a readable dashboard.
    tui_options.mono = options.has("no-color") || std::getenv("NO_COLOR") != nullptr;
    if (const std::optional<std::string> keys = options.value("keys")) tui_options.keys = *keys;
    if (const std::optional<std::string> theme = options.value("theme")) tui_options.theme = *theme;
    return tui::run(tui_options);
}

// ---------------------------------------------------------------------------
// Help
// ---------------------------------------------------------------------------
std::string help_text() {
    std::ostringstream out;
    out << bold("scour " + std::string(kVersion)) << "  offline document inspector and scrubber\n\n";
    out << "  scour inspect <file>              what the file still says about you\n";
    out << "  scour scrub <file> -o <out>       remove text, metadata and hidden data\n";
    out << "  scour verify <file>               prove a target no longer survives\n";
    out << "  scour tui <file>                  find, inspect and scrub in a terminal\n";
    out << "  scour text <file>                 print the extracted text layer\n";
    out << "  scour split <file> --pages 1-3    write a subset of pages\n";
    out << "  scour merge -o <out> a.pdf b.pdf  concatenate documents\n";
    out << "  scour rotate <file> --by 90       rotate pages\n\n";
    out << "Run `scour <command> --help` for the options of a command.\n\n";
    out << "Exit codes: 0 clean, 1 findings remain, 2 usage, 3 unreadable input,\n";
    out << "            4 unwritable output or failed verification.\n\n";
    out << "Every byte stays on this machine. Scour has no network code, no telemetry and\n";
    out << "no upload path: the binary links only against the C++ runtime and libc.\n";
    return out.str();
}

}  // namespace

int main(int argc, char** argv) {
    if (argc > 0 && argv[0] != nullptr) {
        g_program = fs::path(argv[0]).filename().string();
        if (g_program.empty()) g_program = "scour";
    }
    std::vector<std::string> args(argv + (argc > 0 ? 1 : 0), argv + argc);
    bool no_color = false;
    for (const std::string& arg : args) {
        if (arg == "--no-color") no_color = true;
    }
    detect_color(no_color);

    try {
        if (args.empty()) {
            print_help();
            return kExitClean;
        }
        std::string command = args.front();
        args.erase(args.begin());
        if (command == "--version" || command == "version") {
            std::cout << "scour " << kVersion << "\n";
            return kExitClean;
        }
        if (command == "--help" || command == "-h" || command == "help") {
            print_help();
            return kExitClean;
        }
        if (command == "inspect") return command_inspect(args);
        if (command == "scrub") return command_scrub(args);
        if (command == "verify") return command_verify(args);
        if (command == "text") return command_text(args);
        if (command == "split") return command_split(args);
        if (command == "merge") return command_merge(args);
        if (command == "rotate") return command_rotate(args);
        if (command == "tui") return command_tui(args);
        throw CliError{kExitUsage, "unknown command: " + command};
    } catch (const CliError& error) {
        std::cerr << g_program << ": " << error.message << "\n";
        if (error.code == kExitUsage) std::cerr << "run `" << g_program << " help` for usage\n";
        return error.code;
    } catch (const ScourError& error) {
        std::cerr << g_program << ": " << error.what() << " (" << error.code() << ")\n";
        return kExitInput;
    } catch (const std::exception& error) {
        std::cerr << g_program << ": unexpected failure: " << error.what() << "\n";
        return kExitOutput;
    }
}

// Scour — offline document inspector and scrubber.
// Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#include "fixtures.hpp"

#include <algorithm>
#include <cstdlib>

#include "scour/deflate.hpp"
#include <cstdio>
#include <string>
#include <vector>

namespace scour_test {

using scour::Bytes;
using scour::zlib_compress;

namespace {

std::string escape_text(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (c == '(' || c == ')' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

std::string content_stream(const std::vector<std::string>& lines) {
    std::string out = "BT\n/F1 11 Tf\n72 720 Td\n";
    bool first = true;
    for (const std::string& line : lines) {
        if (!first) out += "0 -18 Td\n";
        first = false;
        out += "(" + escape_text(line) + ") Tj\n";
    }
    out += "ET\n";
    return out;
}

class Builder {
public:
    void header(int minor = 7) {
        out_ = "%PDF-1." + std::to_string(minor) + "\n%\xE2\xE3\xCF\xD3\n";
        offsets_.assign(1, 0);
    }

    void object(int number, const std::string& body) {
        if (number >= static_cast<int>(offsets_.size())) offsets_.resize(static_cast<std::size_t>(number) + 1, 0);
        offsets_[static_cast<std::size_t>(number)] = out_.size();
        out_ += std::to_string(number) + " 0 obj\n" + body + "\nendobj\n";
    }

    void stream(int number, const std::string& dict_extra, const std::string& data) {
        if (number >= static_cast<int>(offsets_.size())) offsets_.resize(static_cast<std::size_t>(number) + 1, 0);
        offsets_[static_cast<std::size_t>(number)] = out_.size();
        out_ += std::to_string(number) + " 0 obj\n<<" + dict_extra + " /Length " +
                std::to_string(data.size()) + ">>\nstream\n" + data + "\nendstream\nendobj\n";
    }

    void write_xref(int root, int info, bool with_info) {
        const std::size_t xref = out_.size();
        const std::size_t size = offsets_.size();
        out_ += "xref\n0 " + std::to_string(size) + "\n0000000000 65535 f \n";
        for (std::size_t i = 1; i < size; ++i) {
            char buffer[32];
            if (offsets_[i] == 0) {
                out_ += "0000000000 00000 f \n";
                continue;
            }
            std::snprintf(buffer, sizeof(buffer), "%010zu 00000 n \n", offsets_[i]);
            out_ += buffer;
        }
        out_ += "trailer\n<< /Size " + std::to_string(size) + " /Root " + std::to_string(root) +
                " 0 R";
        if (with_info && info > 0) out_ += " /Info " + std::to_string(info) + " 0 R";
        out_ += " /ID [<" + std::string(32, 'a') + "> <" + std::string(32, 'a') + ">] >>\n";
        out_ += "startxref\n" + std::to_string(xref) + "\n%%EOF\n";
        last_xref_ = xref;
        last_size_ = size;
    }

    [[nodiscard]] const std::string& data() const { return out_; }
    [[nodiscard]] std::size_t last_xref() const { return last_xref_; }
    [[nodiscard]] std::size_t last_size() const { return last_size_; }
    [[nodiscard]] std::size_t object_offset(int number) const {
        return offsets_.at(static_cast<std::size_t>(number));
    }

    void append(const std::string& text) { out_ += text; }

private:
    std::string out_;
    std::vector<std::size_t> offsets_;
    std::size_t last_xref_ = 0;
    std::size_t last_size_ = 0;
};

const char* kXmpMetadata =
    "<?xpacket begin=\"\xEF\xBB\xBF\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n"
    "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n"
    " <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
    "  <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"\n"
    "    xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">\n"
    "   <dc:creator><rdf:Seq><rdf:li>Alice Example</rdf:li></rdf:Seq></dc:creator>\n"
    "   <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Merger Brief</rdf:li></rdf:Alt></dc:title>\n"
    "   <xmp:CreatorTool>Acme Word 2019</xmp:CreatorTool>\n"
    "   <xmp:CreateDate>2026-03-04T09:12:00Z</xmp:CreateDate>\n"
    "   <pdf:Producer>Acme ScanSuite 2.1</pdf:Producer>\n"
    "  </rdf:Description>\n"
    " </rdf:RDF>\n"
    "</x:xmpmeta>\n"
    "<?xpacket end=\"w\"?>";

}  // namespace

Bytes make_fixture(const FixtureSpec& spec) {
    Builder builder;
    builder.header();

    builder.object(1,
                   "<< /Type /Catalog /Pages 2 0 R"
                   " /Names << /JavaScript 11 0 R /EmbeddedFiles 12 0 R >>"
                   " /OpenAction 13 0 R"
                   " /AcroForm << /Fields [14 0 R] /NeedAppearances true >>"
                   " /Metadata 10 0 R >>");
    // Page tree.
    std::string kids = "[";
    for (int i = 0; i < spec.pages; ++i) kids += std::to_string(3 + i) + " 0 R ";
    kids += "]";
    builder.object(2, "<< /Type /Pages /Kids " + kids + " /Count " + std::to_string(spec.pages) +
                          " /Resources << /Font << /F1 40 0 R >> >> >>");

    const std::vector<std::vector<std::string>> page_texts = {
        {"Scour fixture - page 1",
         std::string("Prepared for: ") + kAuthor,
         std::string("Project: ") + kNeedle,
         std::string("Contact: ") + kEmail,
         std::string("Phone: ") + kPhone},
        {"Scour fixture - page 2",
         std::string("SSN: ") + kSsn,
         std::string("Card: ") + kCard,
         std::string("IBAN: ") + kIban,
         "This page is intentionally noisy."},
        {"Scour fixture - page 3",
         std::string("Approved by ") + kAuthor,
         std::string("Escalate to ") + kEmail,
         "Draft - internal use only."}};

    for (int i = 0; i < spec.pages; ++i) {
        std::string annots;
        if (spec.annotation) annots = " /Annots [15 0 R]";
        builder.object(3 + i, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]" + annots +
                                  " /Contents " + std::to_string(7 + i) + " 0 R >>");
    }

    for (int i = 0; i < spec.pages; ++i) {
        const std::vector<std::string>& lines =
            page_texts[static_cast<std::size_t>(std::min<int>(i, 2))];
        std::string content = content_stream(lines);
        if (spec.split_email && i == 0) {
            // Replace the whole-line Tj for the email with two adjacent Tj
            // operators, so text extraction and redaction must join runs.
            const std::string whole = "(" + escape_text(std::string("Contact: ") + kEmail) + ") Tj";
            const std::string halved = "(Contact: alice@exam) Tj (ple.com) Tj";
            const std::size_t position = content.find(whole);
            if (position != std::string::npos) content.replace(position, whole.size(), halved);
        }
        if (i == 0) {
            // Exercise the Flate path on one page while keeping the rest of the
            // fixture readable for debugging.
            const Bytes compressed = scour::zlib_compress(content);
            builder.stream(7 + i, "/Filter /FlateDecode",
                           std::string(reinterpret_cast<const char*>(compressed.data()),
                                       compressed.size()));
        } else {
            builder.stream(7 + i, "", content);
        }
    }

    builder.object(10,
                   "<< /Type /Metadata /Subtype /XML /Length " +
                       std::to_string(std::string(kXmpMetadata).size()) + " >>\nstream\n" +
                       std::string(kXmpMetadata) + "\nendstream");
    builder.object(11, "<< /S /JavaScript /JS (app.alert('scour fixture');) >>");
    builder.object(12,
                   "<< /Names [(secret.txt) 20 0 R] >>");
    builder.object(13, "<< /S /JavaScript /JS (this.print\\(\\); ) >>");
    builder.object(14, "<< /FT /Tx /T (FullName) /V (" + std::string(kAuthor) + ") /DV () >>");
    builder.object(15, "<< /Type /Annot /Subtype /Text /Rect [72 600 96 624] /Contents (Call " +
                           std::string(kPhone) + " before filing) /T (" + std::string(kAuthor) +
                           ") >>");
    builder.object(16, "<< /Author (" + std::string(kAuthor) + ") /Producer (" +
                           std::string(kProducer) + ") /Creator (Acme Word 2019) /Title (Merger Brief) /CreationDate (D:20260304091200Z) >>");
    builder.object(20, "<< /Type /Filespec /F (secret.txt) /EF << /F 21 0 R >> >>");
    builder.stream(21, "/Type /EmbeddedFile",
                   "Note: PROJECT BLUEBIRD valuation floor is 42 million. This file was "
                   "attached to the email and should never have shipped.");
    builder.object(40, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");

    if (spec.orphan_object) {
        builder.stream(30, "", kOrphanSecret);
    }

    if (!spec.metadata) {
        builder.write_xref(1, 0, false);
    } else {
        builder.write_xref(1, 16, true);
    }
    return scour::bytes_of(builder.data());
}

Bytes make_minimal_pdf(std::string text) {
    // Built directly so the caller's text is used verbatim.
    Builder builder;
    builder.header();
    builder.object(1, "<< /Type /Catalog /Pages 2 0 R >>");
    builder.object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> >> >>");
    builder.object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>");
    const std::string content = content_stream({text});
    builder.stream(4, "", content);
    builder.object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
    builder.write_xref(1, 0, false);
    return scour::bytes_of(builder.data());
}

Bytes make_incremental_fixture() {
    const Bytes base = make_fixture(FixtureSpec{});
    std::string out(reinterpret_cast<const char*>(base.data()), base.size());

    // Locate the original xref offset from the last startxref.
    const std::size_t marker = out.rfind("startxref");
    const std::size_t previous_xref =
        static_cast<std::size_t>(std::stoull(out.substr(marker + 9)));

    // Appended update: page 3 (object 5) now points at a scrubbed content
    // stream. The original content stream (object 9) stays in the file, which is
    // exactly the leak the inspector has to find.
    const std::string new_content = content_stream({"Scour fixture - page 3", "Redacted.", ""});
    const std::size_t object_17_offset = out.size();
    out += "17 0 obj\n<< /Length " + std::to_string(new_content.size()) + " >>\nstream\n" +
           new_content + "\nendstream\nendobj\n";
    const std::size_t object_5_offset = out.size();
    out += "5 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 17 0 R >>\nendobj\n";

    const std::size_t xref_offset = out.size();
    out += "xref\n0 1\n0000000000 65535 f \n5 1\n";
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%010zu 00000 n \n", object_5_offset);
    out += buffer;
    out += "17 1\n";
    std::snprintf(buffer, sizeof(buffer), "%010zu 00000 n \n", object_17_offset);
    out += buffer;
    out += "trailer\n<< /Size 18 /Root 1 0 R /Info 16 0 R /Prev " +
           std::to_string(previous_xref) + " /ID [<" + std::string(32, 'a') + "> <" +
           std::string(32, 'a') + ">] >>\nstartxref\n" + std::to_string(xref_offset) + "\n%%EOF\n";
    return scour::bytes_of(out);
}

Bytes make_broken_xref_pdf() {
    const Bytes base = make_minimal_pdf("Broken cross reference, intact contents.");
    std::string out(reinterpret_cast<const char*>(base.data()), base.size());
    // Point startxref at a plausible but wrong offset; readers must rebuild.
    const std::size_t marker = out.rfind("startxref");
    out.replace(marker + 10, 10, "0000000000");
    return scour::bytes_of(out);
}

Bytes make_quirky_pdf() {
    Builder builder;
    builder.header(4);
    builder.object(1, "<< /Type /Catalog /Pages 2 0 R >>");
    builder.object(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> >> >>");
    builder.object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>");
    // CR-only line endings: old Mac writers emitted these, and the lexer has to
    // treat a bare carriage return as whitespace everywhere.
    const std::string content = content_stream({"Quirky but valid."});
    builder.stream(4, "", content);
    builder.object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
    builder.write_xref(1, 0, false);
    std::string out = builder.data();
    std::replace(out.begin(), out.end(), '\n', '\r');
    return scour::bytes_of(out);
}

Bytes make_hidden_text_fixture() {
    Builder builder;
    builder.header();
    builder.object(1, "<< /Type /Catalog /Pages 2 0 R >>");
    builder.object(2,
                   "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> >> >>");
    builder.object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>");
    std::string content = "BT\n/F1 11 Tf\n72 740 Td\n(Public summary of the agreement.) Tj\nET\n";
    // Invisible text: present in the text layer, never painted.
    content += "BT\n/F1 11 Tf\n3 Tr\n72 720 Td\n(" + std::string(kInvisibleSecret) +
               ") Tj\n0 Tr\nET\n";
    // Live text, then a filled rectangle painted over it: a fake redaction.
    content += "BT\n/F1 11 Tf\n72 700 Td\n(" + std::string(kCoveredSecret) + ") Tj\nET\n";
    content += "q\n0 g\n60 692 320 18 re f\nQ\n";
    // White text on unpainted paper.
    content += "BT\n/F1 11 Tf\n1 g\n72 670 Td\n(" + std::string(kWhiteSecret) + ") Tj\nET\n";
    // Text entirely outside the media box.
    content += "BT\n/F1 11 Tf\n0 g\n72 -120 Td\n(" + std::string(kClippedSecret) + ") Tj\nET\n";
    builder.stream(4, "", content);
    builder.object(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
    builder.write_xref(1, 0, false);
    return scour::bytes_of(builder.data());
}

Bytes make_scanned_fixture() {
    Builder builder;
    builder.header();
    builder.object(1, "<< /Type /Catalog /Pages 2 0 R >>");
    builder.object(2,
                   "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /XObject << /Im1 5 0 R >> >> >>");
    builder.object(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>");
    builder.stream(4, "", "q\n480 0 0 620 66 86 cm\n/Im1 Do\nQ\n");
    std::string pixels;
    pixels.reserve(24 * 24 * 3);
    for (int y = 0; y < 24; ++y) {
        for (int x = 0; x < 24; ++x) {
            pixels.push_back(static_cast<char>((x * 7 + y * 3) & 0xFF));
            pixels.push_back(static_cast<char>((x * 11) & 0xFF));
            pixels.push_back(static_cast<char>((y * 13) & 0xFF));
        }
    }
    builder.stream(5,
                   "/Type /XObject /Subtype /Image /Width 24 /Height 24 /ColorSpace /DeviceRGB "
                   "/BitsPerComponent 8",
                   pixels);
    builder.write_xref(1, 0, false);
    return scour::bytes_of(builder.data());
}

}  // namespace scour_test

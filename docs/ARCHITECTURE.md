# Architecture

Scour is a PDF engine, an inspector and a redactor in one repository, with a terminal dashboard on top. This document explains how the pieces fit together and why the important choices were made.

---

## 1. Goals and non-goals

**Goals**

- Read real-world PDFs without a third-party PDF library.
- Answer "what is in this file?" with evidence, not a boolean.
- Remove content structurally, not cosmetically.
- Prove the removal against the bytes on disk.
- Run as one binary, offline, with no runtime dependencies.
- Be fast enough that verification is not skipped.
- Be testable without a rendering stack or a network.

**Non-goals**

- A general page-layout or rendering engine.
- A PDF editor for changing visible content, fonts or graphics.
- OCR for scanned documents (reported, not performed).
- A malware sandbox.
- Byte-for-byte preservation of the input file. A scrub is a rewrite by design.
- Digital-signature preservation over modified content.

Keeping these boundaries is what makes the code small enough to audit. A tool that claims to do everything becomes another opaque suite.

---

## 2. Layers

```text
include/scour/          public headers; no terminal or CLI types
src/core/               PDF engine, inspector, redactor, sanitizer, writer
src/cli/main.cpp        argument parsing, reports, exit codes, commands
src/tui/screen.*        cell buffer, styles, wide glyphs, diffed ANSI output
src/tui/app.*           document dashboard, navigation, overlays, scrub flow
tests/                  hand-written fixtures and the test harness
tools/                  fixture generator, external verification, snapshot renderer
bench/                  synthetic-document benchmark
```

`scour_core` is a static library. The `scour` executable is the only place that knows about a terminal, a file path or an exit code. This boundary is deliberate: the engine can be embedded in a service, a test harness or another front end without dragging in `termios` or `isatty`.

### Core modules

| Module | Responsibility |
|---|---|
| `bytes`, `hash` | byte buffers, SHA-256/SHA-512 for the security handler and deterministic `/ID` |
| `lexer`, `parser` | PDF tokens, objects, streams, indirect objects |
| `document` | xref chains, repair scan, object cache, trailers, encryption setup |
| `filters` | Flate, LZW, ASCII85, ASCIIHex, RunLength, predictors |
| `crypt` | RC4, AES-128/256, standard security handler R2–R6 |
| `pages` | page tree traversal, inheritance, extraction, merge, rotation |
| `text` | decoding, font encodings, ToUnicode, glyph geometry, content-stream walking |
| `inspector` | eight finding categories, severity, evidence, risk, text/JSON reports |
| `patterns` | email, phone, SSN, card (Luhn), IBAN (mod-97), IPv4, API keys, private keys |
| `redact` | target matching, glyph replacement, rectangle intersection, verification |
| `sanitize` | metadata, XMP, annotations, forms, attachments, actions, name trees |
| `writer` | reachable-object collection, fresh xref, deterministic serialization |

---

## 3. Reading a PDF

### 3.1 The object model

A PDF object is a null, boolean, integer, real, string, name, array, dictionary, stream or indirect reference. `Object` stores the small values inline and the large ones behind `std::shared_ptr`-style ownership. `Dict` preserves insertion order, which matters for deterministic output and for readable diffs.

`Document` owns the file bytes and a map from object number to `XrefEntry`. Objects are parsed lazily and cached. The cache is `mutable` so a `const Document&` can still hand out stable pointers; that keeps the inspector and extractor signatures honest without a second ownership layer.

### 3.2 Cross-reference chains

Reading starts at the last `startxref`. Scour follows `/Prev` through every section, merging entries newest-first. This is what makes earlier revisions visible: the newest xref says object 5 points at the scrubbed content, while the older section still points at the original stream. The file contains both; a viewer shows the newest. A scrubber must know about both.

Supported forms:

- classic `xref` tables;
- xref streams (`/Type /XRef`) with `/W` and `/Index`;
- object streams (`/Type /ObjStm`) with compressed entries;
- hybrid files that combine a classic table with an xref stream;
- missing or broken tables, rebuilt by scanning the file for `N G obj` headers.

The repair scan is deliberately conservative. It records a diagnostic and marks the document as repaired; the inspector reports this as an integrity finding. A repaired file is usable, but it is not silently treated as pristine.

### 3.3 Streams and filters

`Document::decode_stream` applies the filter chain in order. Flate uses a self-contained inflater (with stored, fixed-Huffman and dynamic-Huffman blocks), because linking zlib would violate the no-dependency rule and because a PDF-specific inflater is small enough to test exhaustively. LZW, ASCII85, ASCIIHex, RunLength and the PNG/TIFF predictors cover the filters that appear in office documents and scans.

The inflater is hardened against truncated input, invalid distances, oversized windows and output bombs: a stream cannot expand beyond a configured limit without an error, and every read is bounds-checked. A malformed PDF is input, not a trusted program.

### 3.4 Encryption

The security handler implements revisions 2–6:

- RC4 (40–128 bit) for R2–R4;
- AES-128 (R4) with the object-key derivation;
- AES-256 (R5/R6) with the hardened hash (Algorithm 2.B), `/UE`/`/OE` and `/Perms` validation.

Authentication tries the empty user password first (the common "protected but opens" case), then the owner password, then the password supplied by the caller. If none works, the core leaves the handler invalid and records a failure. The CLI turns that into exit code `3` instead of producing a report about ciphertext. This distinction matters: a clean-looking report on an unreadable encrypted file is worse than an error.

Encrypted strings and streams are decrypted per object, using the object number and generation. Metadata can be unencrypted even when the rest of the file is, if `/EncryptMetadata` is false; the inspector reports that separately.

---

## 4. Text extraction

Text is where a PDF stops being a container and becomes a puzzle.

### 4.1 Fonts and encodings

A content stream says `(Hello) Tj`, but the bytes in `Hello` are not Unicode. They index a font encoding:

- **Simple fonts** (Type1, TrueType): a single-byte code maps through the font's `/Encoding` (standard, WinAnsi, MacRoman or a difference array) to a glyph name or Unicode.
- **Composite fonts** (Type0): the string is a sequence of character codes whose width is `/W`; the mapping to Unicode comes from `/ToUnicode`, an identity CMap, or a predefined CMap.
- **ToUnicode CMaps** are parsed for `bfchar` and `bfrange`, including multi-byte destinations and array destinations.

If a font has no reliable mapping, Scour does not invent characters. It marks the page as unreliable, reports the limitation and keeps the glyph geometry where it can. A redactor that guesses is more dangerous than one that says "I cannot read this".

### 4.2 Glyph geometry

For each shown string, the extractor tracks:

- the text matrix and the line matrix (`Tm`, `Td`, `TD`, `T*`, `TL`);
- the graphics state (`q`/`Q`, `cm`, `Tc`, `Tw`, `Tz`, `TL`, `Ts`, `Tr`, fill colour);
- the font size and horizontal scaling;
- each glyph's displacement from `/Widths` or `/W`, plus `/FontMatrix` for Type3.

It computes a page-space rectangle for every glyph. That rectangle is what lets the inspector find text outside the media box or underneath a painted rectangle, and what lets a rectangle redaction select glyphs precisely.

The extractor also records the byte span of every decoded character in the **encoded** string. A redaction is a rewrite of those bytes, not a rewrite of the rendered page.

### 4.3 Reading order and run joining

Text is grouped into runs by the stream and the text object. Runs are sorted by page position with a tolerance for the baseline, then joined with separators. Each character in the extracted string maps back to a run and a byte offset (`run_of_byte`, `run_text_start`), so a match can be translated back to the operands that produced it.

This is what makes split runs work:

```text
(Contact: alice@exam) Tj (ple.com) Tj
```

The extracted text is one string; the matcher sees one email; the redactor rewrites both operands and preserves the space advance. The unit tests include this case because it is the canonical failure of naive tools.

### 4.4 Forms and paint order

Form XObjects are followed with a depth limit and a visited set. Their text is included in the page analysis and flagged as `from_form`, so a redaction can edit the form's stream. Paint operators (`re` + `f`) are recorded with their fill luminance and their order in the content stream. The inspector uses that order to distinguish "text under a black box" from "text that happens to be near a black box".

Images are recorded, not decoded into text. A page with an image and no text layer is reported as scanned; Scour does not claim it is clean.

---

## 5. Inspection

### 5.1 Findings

A `Finding` has a stable id, a category, a severity, a title, a detail, evidence, an optional page and an optional location. Findings are aggregated: one detector per document or page, with up to three samples. A page with two thousand invisible glyphs produces one finding, not two thousand, because a report a human cannot read is not a report.

Categories and caps:

| Category | Cap | Examples |
|---|---:|---|
| metadata | 28 | author, title, producer, timestamps, custom keys, XMP |
| hidden-text | 42 | invisible render mode, white-on-white, clipped, painted over |
| annotations | 24 | comments, authors, form values, attachment annotations |
| embedded | 30 | embedded files, name trees, `/AF` |
| actions | 40 | JavaScript, launch, submit, remote go-to, import data |
| structure | 26 | unreachable objects, earlier revisions, repair |
| pii | 36 | email, phone, SSN, card, IBAN, IPv4, API/private keys |
| integrity | 22 | unreadable encryption, weak crypto, unencrypted metadata |

### 5.2 Risk

Risk is **not** the sum of category percentages. One recoverable secret is dangerous even if every other category is clean. Each finding contributes a severity weight — error 34, warning 14, note 4, debug 1 — and the weights are sorted descending and decayed geometrically:

```text
risk = min(100, Σ weight[i] * 0.82^i)
```

The first serious problem dominates; a long tail of notes cannot drown it. A file with no findings is `0`; a file with only a note is at least `1`. Grades are `clean` (<10), `low` (10–29), `elevated` (30–54), `high` (55–79) and `critical` (80+). The default `--fail-on` threshold is 10, so a file with any meaningful finding fails a CI check unless the caller raises the threshold.

The score is a triage aid, not a compliance certification. The report says so, and the threat model repeats it.

### 5.3 Hidden text detection

The inspector compares each glyph's box and style with the page box and the paint list:

- **Invisible**: rendering mode 3 or 7.
- **White on white**: fill luminance near 1.0 and no dark paint behind the glyph.
- **Painted over**: a later opaque rectangle intersects the glyph box and is darker than the glyph.
- **Clipped**: the glyph box lies outside the media box.

Each hit is aggregated per page and method, with evidence. The report does not claim that a glyph is "invisible" if the analysis cannot trust the font; it reports the limitation instead.

### 5.4 PII detectors

The detectors are conservative and explainable:

- **Email**: RFC-shaped local/domain with a valid TLD, de-duplicated.
- **Phone**: international and North American patterns with digit-count validation, avoiding dates and invoice numbers.
- **SSN**: US format with invalid-area rejection.
- **Card**: 13–19 digits with Luhn validation.
- **IBAN**: country length plus mod-97 check.
- **IPv4**: dotted quad with octet validation.
- **API keys**: common prefixes and high-entropy token shapes.
- **Private keys**: PEM blocks.

They are filters, not classifiers. A missed identifier is possible; a false positive is possible. The workflow is inspect, review, scrub, verify — not "press a button and trust a model".

---

## 6. Redaction

`redact_document` works in four steps.

1. **Analyze** every selected page (or all pages). Analysis produces runs, glyphs, byte spans, boxes and paint order.
2. **Match** the requested terms (case-insensitive literal) and detectors against the extracted text. Matches are mapped back to glyphs through `run_of_byte`; a match that spans runs is split into per-run ranges.
3. **Rewrite** each affected content stream. For each run, the encoded string is rebuilt: matched glyphs become the font's space bytes (the same advance) and unmatched glyphs are copied. If a font has no space glyph, a TJ adjustment preserves the advance. The stream is re-encoded with the original filter (or Flate when recompression is requested).
4. **Paint** an opaque box over each removed range when `paint` is true. The box is cosmetic; the text is already gone. Glyph boxes are merged into one block per line before painting, so a redacted paragraph costs a handful of `re f` operators instead of one rectangle per character.

Rectangles requested by the user intersect glyph boxes directly. A rectangle redaction does not need the text to be recognized, which makes it useful for a region on a scanned page — but Scour still cannot remove pixels inside an image, and it says so.

The operation is idempotent in the useful sense: running it again finds no targets. It is also deterministic: the same input and targets produce the same output bytes, because the `/ID` is derived from the body and the object order is stable.

### Verification

`verify_document` runs the same analysis and matching against the **output** document. It returns the remaining findings, not a boolean. `scour scrub` calls it automatically after writing; `scour verify` exposes it as a standalone command. Both exit `1` if anything survives.

This closes the loop that most tools leave open. The scrubber's in-memory state is not evidence; the file on disk is.

---

## 7. Sanitization

`sanitize.cpp` removes data from the object graph:

- `/Info` and the trailer reference;
- the catalog's `/Metadata` XMP stream;
- `/PieceInfo` and application data;
- every page's `/Annots`, and the catalog's `/AcroForm`;
- `/Names/EmbeddedFiles` and the catalog's `/AF`;
- `/OpenAction`, `/AA`, `/JS`, the JavaScript name tree and launch/submit/remote actions;
- unreachable objects, via the writer's reachability pass.

Counting is file-oriented, not reference-oriented: one attachment reachable from both `/Names` and `/AF` is one attachment, not two. This sounds small until a report says "3 attachments removed" for a single file and the user stops trusting the numbers.

The scrubber does not attempt to preserve the visual appearance of removed annotations or form fields. Removing a comment removes its icon; removing a form field removes its widget. That is the correct trade for a sanitization tool, and the user asked for it.

---

## 8. Writing

The writer serializes a **fresh** document:

- Collect reachable objects from the trailer keys (default `/Root` and `/Info`; a metadata scrub removes `/Info` from the trailer first, so it is a deletion, not a flag).
- Assign numbers in a stable traversal order.
- Write a classic xref table with correct offsets.
- Derive `/ID` from a hash of the body unless the caller asks for random IDs.
- Optionally re-deflate uncompressed streams when that makes them smaller.
- Write atomically: a temporary file in the destination directory, flush, then rename.

A rewrite is the only way to guarantee that an earlier revision, an orphaned object or a stale metadata reference is gone. It is also what makes the output smaller: a 4 KB leaky fixture becomes a 1.9 KB clean file because eleven unreachable objects are not written.

The writer does not preserve incremental updates, object streams or encryption. The output is a clean classic-xref PDF. That is a deliberate trade: maximum reader compatibility and a structure that is easy to verify, at the cost of a slightly larger file for some inputs. Recompression is available when size matters.

---

## 9. The terminal UI

The TUI is not a wrapper around `less`. It is a small immediate-mode UI with a cell buffer.

- `Screen` stores a grid of `Cell { glyph, style, continuation }`. Styles are truecolor foreground/background plus bold/dim.
- `put`, `text`, `text_padded`, `panel`, `hline`, `shadow` and `dim` are the primitives.
- Wide glyphs occupy two cells; the second is marked as a continuation and skipped during output.
- `to_ansi` emits cursor-positioned runs and only changes SGR when the style changes. `to_plain` exists for tests and snapshots.
- The terminal layer puts the tty in raw mode, queries the window size, reads keys with a timeout and restores the terminal on every exit path, including errors.
- The dashboard keeps a `category` and `selected` index, a filter, an overlay state (`Help`, `Palette`, `Prompt`, `Detail`) and a notification line. Rendering is a pure function of that state, which makes `--dump` a real screenshot of the shipping UI.

`--dump WxH` and `--keys STR` exist so documentation images and end-to-end tests can drive the actual rendering code without a pty. The images in this repository are generated that way, not mocked up.

---

## 10. Testing strategy

The suite has 118 unit tests plus shell-level end-to-end tests. The important choices:

- **Fixtures are hand-written.** `make_fixture` builds bytes directly, including xref offsets, rather than calling Scour's writer. A shared bug cannot hide behind a round trip.
- **The malicious cases are explicit.** Broken xref, CR-only line endings, object streams, split runs, invisible text, white text, clipped text, painted-over text, an orphan object holding a secret, an incremental update that leaves the old page in the file.
- **Encryption is tested with known vectors.** RC4, AES and the R6 hash have unit tests independent of the document layer.
- **The CLI is tested as a user touches it.** Exit codes, atomic replacement, in-place scrubbing, split/merge/rotate and TUI dumps.
- **External readers are the judge.** `tools/verify_external.py` builds documents with pikepdf/pypdf and validates Scour's output with both. See [VERIFICATION.md](VERIFICATION.md).
- **Sanitizers are a build mode.** ASan/UBSan runs in CI; a parser that reads untrusted bytes should be tested under them.
- **The parser is fuzzed, not merely sampled.** `fuzz/pdf_fuzz.cpp` sends mutated documents through open, inspect, extract, scrub, rewrite, re-open and verify with ASan/UBSan as the oracle; the first campaign found an integer overflow in number parsing. See [FUZZING.md](FUZZING.md).

The test harness is intentionally tiny (a registry, assertion macros and a filter). A test framework dependency would be another thing to audit.

---

## 11. Performance notes

The hot paths are text extraction and glyph replacement, not file I/O.

- Objects are parsed lazily and cached; opening a 1,000-page file does not parse 1,000 content streams.
- The extractor allocates one `PageAnalysis` per page and reuses glyph storage where possible.
- Redaction builds a new encoded string per affected run, not per glyph.
- The writer's reachability walk is iterative with an explicit stack, so deep page trees do not blow the C++ stack.
- The inflater is allocation-light and bounds-checked; decompression dominates on image-heavy files.

Measured numbers and methodology are in the [README](../README.md#performance). The benchmark is reproducible with `scour_bench`.

The main memory cost is glyph geometry: roughly 150 bytes per glyph in the current representation. A 1,000-page text report peaks around 200 MB. That is acceptable for a desktop tool and is the next optimization target for very large batches.

---

## 12. Why C++

The requirement was a fast, dependency-free binary that can be dropped onto an air-gapped machine and audited.

- **C++20** gives deterministic resource management, zero-cost abstractions, `std::string_view`, `std::filesystem` and concepts without a runtime.
- A Rust implementation would also fit; it would add a toolchain and a crate graph for compression, hashing and terminal handling, or require reimplementing them. Since the hard parts here are parsing and byte-level rewriting, the language advantage is small and the dependency cost is real.
- The code avoids exceptions for control flow, uses `ScourError` for recoverable failures, and keeps the parser's allocations bounded. It compiles cleanly with `-Wall -Wextra -Wpedantic -Wconversion` (conversion warnings are reported but not fatal).
- The binary links only `libstdc++`, `libm`, `libgcc_s` and `libc`. There is no network code, no plugin loader and no dynamic PDF library.

The TUI is POSIX (`termios`, `poll`, `ioctl`). A native Windows console backend is a contained addition, not a rewrite of the engine.

---

## 13. Known weaknesses

- Exotic CMaps and malformed font descriptors are handled conservatively; some text may be flagged as unreliable rather than extracted.
- The repair scan can recover a usable document from a badly broken file, but it may not recover the same page tree a lenient viewer would.
- Redaction preserves advance widths, so copied text contains spaces where the removed characters were. That is intentional, but it is visible.
- Rectangle redaction removes glyphs that intersect the box; it does not remove vector artwork or image pixels underneath.
- The writer does not preserve object streams or encryption. It produces a clean classic-xref file.
- PII detection is heuristic. It is a review aid, not a guarantee.
- Memory scales with the number of glyphs retained for inspection.

These are documented in [THREAT-MODEL.md](THREAT-MODEL.md) rather than hidden in a FAQ.

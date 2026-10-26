# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-22

The first release. One binary, no runtime dependencies, no network code.

### Added

- **Inspection** of PDF 1.0–2.0 documents: metadata, XMP, hidden text, covered text, white text, clipped text, annotations, form values, embedded files, JavaScript/launch actions, unreachable objects, incremental revisions, encryption weaknesses and PII.
- **Risk report** with eight category scores, severity, evidence and a stable JSON format (`format: 1`).
- **PII detectors** for email, phone, US SSN, payment cards (Luhn), IBANs (mod-97), IPv4, API keys and PEM private keys.
- **True redaction**: glyph-level removal from content streams with width preservation, split-run matching, rectangle selection, optional painted boxes.
- **Sanitization**: `/Info`, XMP, `/PieceInfo`, annotations, form dictionaries, embedded files, `/AF`, JavaScript, launch/submit/remote actions and JavaScript name trees.
- **Full rewrite**: fresh classic xref, reachable objects only, deterministic `/ID`, optional recompression, atomic replacement.
- **Verification**: the scrubber reopens its own output and re-extracts the text; `scour verify` exposes the same check as a standalone command.
- **Terminal dashboard**: category navigation, findings list, detail pane, filter, command palette, keyboard help, midnight/paper themes, in-place scrub, JSON export, resumable screen state and `--dump` snapshots.
- **Dashboard edge states**: a 64×18 minimum-size panel that explains the requirement instead of drawing a collapsed frame, and a monochrome mode (`--no-color`, `NO_COLOR`, or `m`) that keeps severity, selection and structure legible without colour.
- **Commands**: `inspect`, `scrub`, `verify`, `tui`, `text`, `split`, `merge`, `rotate`.
- **PDF support**: classic xref, xref streams, object streams, hybrid files, broken-xref repair, Flate/LZW/ASCII85/ASCIIHex/RunLength filters, RC4/AES-128/AES-256 (R2–R6), forms, Type0/CID fonts, ToUnicode CMaps, page extraction/merge/rotation.
- **Tests**: 118 unit tests and a shell end-to-end suite; hand-written fixtures including hidden text, split runs, incremental updates, encryption and malformed xrefs.
- **External verification**: a pikepdf/pypdf interoperability harness with 43 checks.
- **Fuzzing**: a mutation harness over the whole pipeline, with a standalone deterministic driver and a libFuzzer entry point.
- **Benchmark**: a self-contained synthetic-document benchmark.
- **Documentation**: market thesis, architecture, threat model, CLI reference, design system, verification report and screenshot pipeline.
- **Packaging**: CMake install, man page, a source archive script, and `tools/release.sh` — one command that builds, tests, strips and verifies a static single-file binary for Linux (x86-64, arm64) and macOS (arm64, x86-64). Tag-triggered releases build all four in CI and attach them with a `SHA256SUMS.txt`.
- **Windows CI**: the MSVC build and test run is a CI job, so the Windows boundary and the UTF-8 handling are checked on every push instead of by hand.

### Fixed

- **Integer overflow in number parsing**: the lexer accumulated digits with a guard that permitted one multiplication past `INT64_MAX`. A hostile file could wrap a `/Length`, object number or offset into a plausible value. Digits now saturate, every consumer range-checks, and `tests/test_lexer.cpp` pins it with a 4,000-digit input. Found by the mutation fuzzer on its first campaign.
- **Dashboard contrast**: tertiary text and the paper-theme warning chip were below the 4.5:1 target (3.0–3.6:1). `text_dim`, `text_faint` and the paper `warn` role were retuned; every text pair is now measured at 4.5:1 or better in both themes, and the measurements are published in `docs/DESIGN.md`.
- **UTF-8 literals under MSVC**: the MSVC branch never passed `/utf-8`, so narrow literals were encoded in the local code page. On a CP1252 machine that mangled every box-drawing glyph in the dashboard and broke the ellipsis assertion in `tests/test_bytes.cpp`. Found by an external MSVC 19.44 build, which passed 117 of 118 assertions before the fix. The Windows build also no longer tries to compile the POSIX-only CLI and dashboard: it reports that it is building the engine and tests instead of failing on `unistd.h`.

### Security

- No network code, no telemetry, no plugin loading and no external processes.
- The TUI filters C0/C1 control characters from document text before writing a cell, preventing terminal escape injection.
- ASan and UBSan builds are part of CI.
- A sanitizer-instrumented fuzzer runs in CI; its first campaign found an integer overflow in number parsing, fixed above.

### Known limitations

- Text inside images is not OCR'd; image-only pages are reported rather than certified.
- Optional content layers are not modeled as hidden.
- Native Windows console support is not included; use WSL2.
- Redaction preserves advance widths, so copied text contains spaces where characters were removed.
- Rewriting invalidates digital signatures.
- PII detection is heuristic; verification is scoped to the text layer and the requested targets.

[1.0.0]: https://github.com/scour-pdf/scour/releases/tag/v1.0.0

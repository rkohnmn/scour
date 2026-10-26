# Verification report

**Release:** Scour 1.0.0 · **Date:** 23 October 2026 · **Status:** all checks listed below pass.

This report records what was actually run, on which versions, and what it does not cover. It is meant to be reproducible: every command is in the repository.

---

## 1. Environment

| Item | Value |
|---|---|
| OS | Linux (Ubuntu 24.04 base), x86_64 |
| CPU | 2 vCPU, shared cloud runner |
| Compiler | GCC 13.3.0 |
| CMake | 4.4.4 |
| Build | `Release` (`-O3 -DNDEBUG`), warnings-as-errors |
| Python | 3.12.3 |
| pikepdf | 10.17.0 |
| pypdf | 6.21.2 |

Timings on a shared 2-vCPU runner are noisy. They are reported as medians of three to five runs and should be read as orders of magnitude, not lab measurements.

---

## 2. Unit tests

```bash
./build-werror/tests/scour_tests
```

```text
118/118 tests passed
```

Suites cover:

| Area | What is asserted |
|---|---|
| bytes/hash | hex, byte views, CRC-32, MD5/SHA-256 vectors |
| inflate/deflate | independent zlib fixture, stored blocks, raw deflate, corrupt input, output limits, round trips |
| crypt | RC4, AES-128/256, R6 hash, password validation, object-key derivation |
| object/lexer/parser | names, strings, streams, malformed input, recursion limits |
| document | classic xref, xref streams, object streams, repair, revisions, encryption |
| writer | reachable-object collection, escaping, deterministic IDs, round trips |
| pages | inheritance, extraction, merge, rotation, malformed trees |
| text | encodings, ToUnicode, widths, form XObjects, split runs, hidden-text geometry |
| patterns | every detector, Luhn/mod-97 checks, near-miss negatives |
| redact | term and PII removal, split runs, rectangles, width preservation, verification |
| inspector | metadata, hidden text, annotations, attachments, actions, PII, risk, JSON escaping |
| sanitize | metadata/XMP, annotations, forms, attachments, actions, counts |

---

## 3. End-to-end tests

```bash
bash tests/cli_e2e.sh ./build/scour ./build/scour_fixtures /tmp/scour-e2e
```

```text
cli e2e: all checks passed
```

The suite drives the real binary and checks:

- `inspect` on a leaky fixture exits `1`; on a clean fixture exits `0`.
- JSON output parses and contains the expected findings, pages and risk.
- `scrub` writes a file whose text no longer contains the target, whose metadata is gone and whose risk is `0`.
- `verify` exits `0` on the scrubbed output and `1` on a file that only paints over its text.
- Two scrubs of the same input are byte-identical (`cmp`).
- `split`, `merge` and `rotate` preserve the expected page counts.
- Usage errors exit `2`; a missing file exits `3`.
- TUI frames contain the header, sidebar, findings and detail panes; help and palette overlays render; moving the selection changes the frame; an in-dashboard scrub writes a file that re-inspects clean.
- A 40×10 frame reports `WINDOW TOO SMALL`, the current size and the `scour inspect` fallback, and does **not** draw the dashboard panes.
- `--no-color`, `NO_COLOR` and the `m` key remove every `38;2;` truecolor sequence while the frame keeps its panes; the default frame still has them.

### Dashboard states

The monitor-facing states are checked by the same suite and by direct frames:

| State | Check |
|---|---|
| 64×18 minimum | renders the dashboard; 40×10 renders the resize panel instead |
| monochrome | no truecolor SGR; selection marker, severity words and bold survive |
| empty list | clean file and filtered-to-nothing copy |
| empty palette query | `No action matches that query.` |
| help overflow | longest binding `p / ctrl-p` keeps its label column |

The palette contrast values in [DESIGN.md](DESIGN.md) are computed from the
shipped RGB constants, not estimated; every text pair measures at least 4.5:1 in
both themes. Borders are deliberately excluded and labelled decorative.

---

## 4. External interoperability

Scour has no PDF dependency, so Scour's own round trip cannot prove that other readers accept its output. `tools/verify_external.py` builds documents with two independent implementations, runs the real binary, and re-opens the results with both.

```bash
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements-external.txt
.venv/bin/python tools/verify_external.py --scour build/scour
```

```text
pikepdf 10.17.0, pypdf pypdf
scour   .../build/scour

[1] foreign writer -> inspect -> scrub -> foreign readers
  ok    inspect finds three pages
  ok    inspect reads the author
  ok    inspect identifies PII
  ok    inspect exits 1 above the risk threshold
  ok    text extraction reads a foreign content stream
  ...
[2] AES-256 source with a user password
  ...
[3] pypdf writer
  ...

43/43 external checks passed
```

### Test 1 — pikepdf source, object streams

pikepdf writes a three-page document with `/Info`, an XMP-free catalog, JavaScript in `/OpenAction`, a text annotation, an embedded file and PII in the content streams, using **object streams and Flate compression**.

Scour is required to:

- parse the file and report three pages;
- read the author and identify PII;
- extract the text (including the foreign content stream encoding);
- scrub PII, the author and a term;
- produce a file that **pikepdf** parses with `check_pdf_syntax() == []`;
- preserve the page count;
- have no `/Info`, `/Metadata`, `/Names`, `/OpenAction` or `/AcroForm`;
- have no attachments and no annotations;
- produce text that **pypdf** extracts without any target;
- pass `scour verify`;
- be byte-identical when scrubbed again (determinism).

All checks pass.

### Test 2 — AES-256 source, revision 6

pikepdf saves the same document with AES-256 (R6), owner password `owner-pw`, user password `user-pw`.

- `scour inspect` without a password exits **3** and does not print a clean report.
- `scour inspect -p user-pw` reads three pages and reports the encryption.
- `scour scrub -p user-pw` produces an output that opens **without a password** and has no `/Encrypt`.
- The output passes the same syntax, metadata, annotation, attachment and text checks.

All checks pass.

### Test 3 — pypdf source

pypdf writes a two-page document with `/Info` metadata. Scour reads it, scrubs it and produces a two-page file that pikepdf parses with valid syntax and empty document info.

All checks pass.

### What this proves

- Scour reads xref streams, object streams and compressed streams produced by another engine.
- Scour's output is accepted by two independent readers (pikepdf/qpdf and pypdf).
- The removal is visible to a different text extractor, not just to Scour.
- Encryption handling works on a real R6 file, including the no-password error path.
- The writer's output is structurally valid.

It does **not** prove that every PDF viewer renders the output identically, that every font is decoded, or that PII detection is complete.

---

## 5. Sanitizers

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSCOUR_SANITIZE=ON
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=0 ./build-asan/tests/scour_tests
ASAN_OPTIONS=detect_leaks=0 bash tests/cli_e2e.sh \
  ./build-asan/scour ./build-asan/scour_fixtures /tmp/scour-e2e-asan
```

```text
118/118 tests passed
cli e2e: all checks passed
```

The sanitizer run found a test-only lifetime bug (a `string_view` into a temporary `Bytes` in `test_inflate.cpp`). It was fixed by keeping the buffer alive; the library itself was not implicated. This is recorded because a verification report that only lists successes is less useful than one that shows the process.

ASan/UBSan also runs in CI on the unit and end-to-end suites.

---

## 6. Mutation fuzzing

Scour opens files it did not write. The fuzzer sends mutated documents through
the whole pipeline — open, inspect, extract text, page surgery, scrub, rewrite,
re-open, verify — with ASan and UBSan as the only oracle. There are no
assertions in the harness: a memory error or an integer overflow aborts it.

```bash
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
      -DSCOUR_SANITIZE=ON -DSCOUR_BUILD_FUZZ=ON -DSCOUR_BUILD_TESTS=OFF
cmake --build build-fuzz -j
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
# build/e2e is written by the end-to-end suite (§3) and adds the generated
# fixtures — encryption, revisions, object streams — to the seed set.
  ./build-fuzz/scour_fuzz --corpus fixtures --corpus build/e2e \
                          --iterations 25000 --seed N
```

Seeds are sorted before indexing, so a seed number selects the same bytes on
another machine and a reported failure replays exactly.

| Campaign | Inputs | Accepted as documents | Result |
|---|---:|---:|---|
| Seeds 21–30, 25,000 each | 250,000 | 81,167 (32.5%) | 0 crashes, 0 sanitizer reports |

The campaign ran for 810 seconds in total, about 309 inputs per second, from 59
seed files (ten hand-written fixtures plus the forty-nine files the end-to-end
suite generates). A third of the mutated inputs still parsed, which is what
makes the numbers meaningful: the mutations stay close enough to valid PDF to
reach the parser, the font decoder, the redactor and the writer rather than
bouncing off the header.

### What the campaign found

The first run, 3,000 inputs in, aborted in `Lexer::next`: digits accumulated
into an `int64` with a guard that allowed one multiplication past the limit, so
a number long enough to overflow wrapped around. In a parser that turns numbers
into object numbers, stream lengths and byte offsets, a wrapped value can point
somewhere plausible instead of failing visibly.

```text
src/core/lexer.cpp:240:70: runtime error: signed integer overflow:
  937040044053201300 * 10 cannot be represented in type 'long int'
    #0 scour::Lexer::next()
    #1 scour::Document::rebuild_from_scan()
    #2 scour::Document::load()
```

The lexer now saturates at `INT64_MAX`; every consumer range-checks the value,
and `tests/test_lexer.cpp::absurd_integers_saturate` pins it with a 4,000-digit
input. No further findings appeared in the campaign above.

### What this does not establish

- **Coverage is blind.** The standalone driver mutates without feedback. A
  libFuzzer target is included for a coverage-guided campaign on clang, but the
  numbers in this report came from blind mutation.
- **The corpus is synthetic.** Five hand-written fixtures plus the end-to-end
generated files. Real documents contain font programs, colour spaces and
compressed constructs these do not, and mutation cannot invent a construct it
has never seen.
- **No hang detection.** The driver has no per-input timeout; a pathological
  input would look like a stalled campaign rather than a failure. Wall-clock
  rate is printed for this reason.
- **Correctness is not fuzzing's job.** It proves Scour does not fall over on
  hostile bytes, not that the redacted output is faithful.

Full guide: [FUZZING.md](FUZZING.md).

---

## 7. Warnings-as-errors build

```bash
cmake -S . -B build-werror -DCMAKE_BUILD_TYPE=Release -DSCOUR_WARNINGS_AS_ERRORS=ON
cmake --build build-werror -j
```

```text
build exit 0
118/118 tests passed
cli e2e: all checks passed
```

The flags include `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor -Wcast-align -Wnull-dereference -Wdouble-promotion -Wformat=2 -Wimplicit-fallthrough`. Conversion warnings are normally reported but not fatal; this build treats them as errors and is clean.

---

## 8. Performance

### Scour benchmark

```bash
./build/scour_bench --pages 1000 --lines 30 --iterations 5
```

1,000 pages, 30 text lines per page, 1,292,612 glyphs, 533 KB compressed:

| Operation | Median | Notes |
|---|---:|---|
| open + parse | 1.9 ms | lazy object parsing; xref + page tree |
| extract text | 169 ms | ~7.6 M glyphs/s |
| inspect + PII | 175 ms | all eight categories |
| rewrite only | 7.4 ms | fresh xref, reachable objects only |
| scrub + rewrite (PII + term) | 0.45 s | text analysis, matching, glyph replacement, paint boxes, write |
| peak RSS | 202 MB | glyph geometry is the dominant allocation |

### CLI end to end

Same 1,000-page file, five runs, median:

| Command | Median |
|---|---:|
| `scour scrub --pii --term "Example Holdings"` (incl. re-open + verify) | 680 ms |
| `scour scrub --pii` (incl. verify) | 625 ms |
| `scour inspect --pii` | 179 ms |
| `scour text` (writes 1,000 pages to stdout) | 296 ms |

### Independent comparison

On a separate 300-page, 385k-glyph synthetic report (5 runs, process start included):

| Tool | Operation | Median |
|---|---|---:|
| Scour | `scour text` (extract all pages) | 89.6 ms |
| pypdf 6.21.2 | `extract_text()` on all pages | 825.7 ms |
| Scour | `scour inspect` (extract + 8 categories + PII) | 55.3 ms |
| pikepdf 10.17.0 | open + read every page content stream | 4.0 ms |

The comparison is deliberately narrow. pypdf is pure Python and does no PII scanning; pikepdf is a C++ library doing a different job (it does not extract text here). It establishes that Scour is in the same performance class as native libraries for structure, and roughly an order of magnitude faster than a pure-Python extractor for text. It is not a claim that Scour is faster than qpdf at qpdf's job.

---

## 9. Release artefacts

`tools/release.sh <triple>` is the only way a shippable binary is produced. It configures a `Release` build with warnings as errors and `SCOUR_NATIVE=OFF`, runs the unit and end-to-end suites, packages `dist/scour-<version>-<triple>.tar.gz`, and then unpacks that archive into a temporary directory and drives the binary inside it: `--version` must report the packaged version, `inspect` must produce a report, `scrub --pii` must rewrite a fixture, `verify --pii` must exit 0, and on Linux `ldd` must report no dynamic dependencies.

Verifying the extracted copy matters because it is stripped, statically linked and in a directory the test suite never touched. A binary that only works from its build tree fails here instead of on someone's laptop.

| Target | Runner | Linkage | Exercised locally |
|---|---|---|---|
| `linux-x86_64` | `ubuntu-24.04` | fully static | yes — build, tests, archive |
| `linux-aarch64` | `ubuntu-24.04-arm` | fully static | no — CI only |
| `macos-arm64` | `macos-15` | libSystem, macOS 13+ | no — CI only |
| `macos-x86_64` | `macos-15-intel` | libSystem, macOS 13+ | no — CI only |

Linux binaries are linked with `-static` in full, not `-static-libstdc++`: the latter still pins the build host's glibc, which is why a binary built on a current distro refuses to start on an older one. A fully static binary leaves only the kernel as a compatibility requirement.

What was measured locally, on x86-64 Linux with GCC 13.3 and glibc 2.39:

```text
$ bash tools/release.sh linux-x86_64
100% tests passed out of 18

packaged  dist/scour-1.0.0-linux-x86_64.tar.gz
  version  1.0.0
  size     1.4M
  members  12
  verified extracted binary: --version, inspect, scrub --pii, verify --pii
```

The digest in the sidecar was checked with `sha256sum -c`, and `SHA256SUMS.txt` was assembled from the artefact the way the `publish` job assembles it.

The archive holds `scour`, `scour.1`, `README.md`, `LICENSE`, `CHANGELOG.md` and the five sample fixtures under a single `scour-<version>-<triple>/` directory, with a `.sha256` sidecar beside it. The `publish` job in `.github/workflows/release.yml` concatenates every target into one `SHA256SUMS.txt` and attaches it to the release.

Both workflow files pass `actionlint` 1.7.12 with its `shellcheck` 0.11.0 integration, and `tools/release.sh` is clean under `shellcheck -x`. What that does not establish is that the workflow executes: no job in this repository has run on GitHub's runners yet, so the first tag is the first real run of the YAML.

---

## 10. What was not verified

- **Native Windows.** The engine builds and tests on MSVC; the terminal layer is POSIX, so the CLI and dashboard are not part of a Windows build at all. An external check (Windows 10 19045, MSVC 19.44.35226, CMake 4.4.4) compiled `scour_core`, `scour_fixtures` and `scour_tests` and registered 118 tests: 117 passed. The single failure, `bytes.truncate_cells_adds_ellipsis`, was a real build defect rather than a test defect — the MSVC branch never passed `/utf-8`, so `std::string("abc\u2026")` was encoded in code page 1252 and no longer equalled the UTF-8 bytes `truncate_cells` appends; the same omission produced 20 `C4566` warnings for the dashboard's box-drawing glyphs. `/utf-8` is now set for MSVC, and on Windows the build reports that it is skipping the POSIX-only CLI instead of failing on `unistd.h`, `sys/ioctl.h` and `SIGWINCH`. What this does not establish: the fix has not been re-run on an MSVC toolchain, because none was reachable while it was made. Windows use means the static Linux binary under WSL2. The MSVC build and test run is now automated on `windows-latest` in CI, though as of this commit the workflow has still never executed on GitHub.
- **macOS hardware.** CI builds `macos-15` and `macos-15-intel`; this report was produced on Linux. The code uses POSIX APIs available on macOS, but the macOS binaries were not manually exercised on a Mac.
- **A large real-world corpus.** Fixtures are synthetic and targeted, and the fuzzer mutates them (§6). No crawl of millions of real documents was run, so font programs, colour spaces and constructs absent from the fixtures are untested.
- **OCR / scanned documents.** Verification explicitly does not claim to see text in images.
- **All PDF viewers.** Pikepdf and pypdf are strong independent readers, not every viewer. A high-stakes release should also be opened in the recipient's viewer and searched manually.
- **Formal verification.** The parser is hardened, sanitizer-tested and fuzzed over a synthetic corpus, not proven correct.
- **Independent security audit.** None has been performed. Do not represent Scour as audited.
- **PII completeness.** Detectors cover common formats; names, addresses, national ID formats and context-dependent identifiers are not exhaustive.

---

## 11. Reproduce everything

```bash
# release build, warnings as errors
cmake -S . -B build-werror -DCMAKE_BUILD_TYPE=Release -DSCOUR_WARNINGS_AS_ERRORS=ON
cmake --build build-werror -j
./build-werror/tests/scour_tests
bash tests/cli_e2e.sh ./build-werror/scour ./build-werror/scour_fixtures /tmp/scour-e2e

# sanitizers
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSCOUR_SANITIZE=ON
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=0 ./build-asan/tests/scour_tests

# external readers
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements-external.txt
.venv/bin/python tools/verify_external.py --scour build-werror/scour

# benchmark
cmake -S . -B build-bench -DCMAKE_BUILD_TYPE=Release -DSCOUR_BUILD_BENCH=ON
cmake --build build-bench -j
./build-bench/scour_bench --pages 1000 --lines 30 --iterations 5

# release binary and archive, verified from the extracted copy
bash tools/release.sh linux-x86_64
```

If a check fails on your machine, include the output, the compiler and the platform in an issue. A failing verification is a bug report, not a support request to hide.

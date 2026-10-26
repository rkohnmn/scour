# Contributing

Scour is a privacy tool. A change that makes it faster but less predictable, or that adds a dependency without a very good reason, is not automatically an improvement. The bar is: **does this make the result easier to trust?**

---

## Set up

```bash
git clone <your-fork>
cd scour
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
./build/tests/scour_tests
bash tests/cli_e2e.sh ./build/scour ./build/scour_fixtures /tmp/scour-e2e
```

A release build with warnings as errors is the integration gate:

```bash
cmake -S . -B build-werror -DCMAKE_BUILD_TYPE=Release -DSCOUR_WARNINGS_AS_ERRORS=ON
cmake --build build-werror -j
./build-werror/tests/scour_tests
```

Sanitizers:

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSCOUR_SANITIZE=ON
cmake --build build-asan -j
ASAN_OPTIONS=detect_leaks=0 ./build-asan/tests/scour_tests
```

External interoperability (optional, needs Python):

```bash
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements-external.txt
.venv/bin/python tools/verify_external.py --scour build/scour
```

---

## What to work on

Good first contributions:

- a PDF that Scour misreads, with a minimal reproducer;
- a detector that misses a common identifier format (with tests and a sample);
- a documentation fix where the behavior and the text disagree;
- a performance improvement with a benchmark before and after;
- a regression test for a bug you found.

Please open an issue before a large feature. Scour is deliberately small; a general PDF renderer, an OCR engine or a plugin system is a different project.

---

## Fixture policy

**Fixtures are written by hand, byte for byte.** Do not generate a test fixture with Scour's writer. A bug shared by the reader and the writer would then pass a round-trip test.

- `tests/support/fixtures.cpp` builds the sample documents directly.
- `tests/support/fixtures.hpp` exposes the known strings so tests do not repeat literals.
- `tools/fixtures.cpp` writes the same bytes to `fixtures/` for manual testing and screenshots.

When adding a case:

1. Add a builder function to `fixtures.cpp` and a declaration to `fixtures.hpp`.
2. Add it to the generator in `tools/fixtures.cpp` if it belongs in the sample set.
3. Write a unit test that asserts the behavior, not the implementation.
4. If the case is a security-relevant bypass, add an end-to-end check as well.

Fixtures must contain **synthetic data only**. Never commit a real person's document, even with the name changed. Use `alice@example.com`, `123-45-6789`, `4111 1111 1111 1111`, `DE89370400440532013000` and `PROJECT BLUEBIRD` as the canonical values.

---

## Coding style

- C++20, four spaces, no tabs, braces on the same line.
- `snake_case` for functions and variables, `PascalCase` for types, `kConstant` for constants.
- Prefer `std::string_view` for read-only text and `const std::string&` for ownership.
- Errors use `ScourError(code, message)`; do not throw across the C API boundary (there is none) and do not use exceptions for normal control flow.
- No `using namespace` in headers. No raw `new`/`delete`; use values and `std::make_unique`.
- Every public function gets a comment explaining the contract, not the implementation.
- No new dependency without an issue and a clear argument about attack surface, licensing and build cost.
- Warnings are not acceptable. The build uses `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`; conversion warnings are reported but not fatal in default builds, and everything else is expected to be clean under `-Werror`.

### Comments

Comment the *why*, not the *what*. A comment that repeats the code is noise; a comment that explains a PDF quirk, a security decision or a performance trade-off is valuable. If a block needs a paragraph to explain what it does, it probably needs a smaller function.

### Commits

- One logical change per commit.
- Subject in the imperative mood, under 72 characters.
- Body explains the motivation and the user-visible effect.
- Reference the issue or the failing fixture.
- Do not commit build output, `.venv`, `dist/` or generated files.

Example:

```text
Fix glyph advance when a font has no space

A Type1 font without a space glyph caused the redactor to collapse the
removed range to zero width, shifting the rest of the line. Fall back to a
TJ adjustment instead. Adds a fixture and a regression test.
```

---

## Pull request checklist

- [ ] The change is scoped to one problem.
- [ ] `cmake --build` is clean with warnings as errors.
- [ ] `./build/tests/scour_tests` passes.
- [ ] `tests/cli_e2e.sh` passes.
- [ ] A regression test covers the bug or the new behavior.
- [ ] For a parser, lexer, filter or writer change: a fuzz campaign ran clean (see below).
- [ ] Documentation is updated if the CLI, JSON, exit codes or limits changed.
- [ ] No real personal data, secrets or customer documents are included.
- [ ] No new dependency, network call or telemetry.
- [ ] For a performance change: before/after numbers from `scour_bench`.
- [ ] For a UI change: a `--dump` frame or a screenshot generated from the shipping binary (`tools/screenshots.py` renders one from a real frame).

---

## Fuzzing

Anything that parses hostile bytes — the lexer, the parser, xref repair, the
stream filters, the crypt handlers, the redactor and the writer — is reachable
from `fuzz/pdf_fuzz.cpp`. It runs the full open → inspect → extract → scrub →
rewrite → re-open pipeline over mutated documents, with ASan and UBSan as the
oracle. No assertions: a report is a crash.

```bash
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
      -DSCOUR_SANITIZE=ON -DSCOUR_BUILD_FUZZ=ON -DSCOUR_BUILD_TESTS=OFF
cmake --build build-fuzz -j
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ./build-fuzz/scour_fuzz --corpus fixtures --iterations 25000 --seed 1
```

Run at least one seed before sending a parser change; CI runs one per build.
Runs are deterministic and print the seed and iteration of every input, so a
failure replays by rerunning with that seed and one more iteration. Turn a
finding into a unit test with the same bytes — that is the artifact, not the
mutated blob. Details, options and limitations are in
[docs/FUZZING.md](docs/FUZZING.md).

---

## Adding a detector

A detector lives in `src/core/patterns.cpp` and must:

1. Have a precise shape (prefix, checksum, length) rather than a loose regex.
2. Validate where possible (Luhn for cards, mod-97 for IBAN, octet ranges for IPv4).
3. Avoid matching inside longer tokens (use boundaries, not just `find`).
4. Return the original span so the redactor can rewrite the source bytes.
5. Have positive and negative tests, including a near-miss that must not match.
6. Be described in the report with a title that says what was found, not just the pattern name.

False positives are costly in a redaction tool: they remove legitimate text and train users to ignore warnings. Prefer precision.

---

## Adding a command

- Register it in `main.cpp` and add it to `help_text`.
- Decide its exit-code contract before writing the implementation.
- Add a `--help` block with examples.
- Add an end-to-end test for the happy path and at least one failure path.
- Update `docs/CLI.md`.
- Keep the command composable: read a file, write a file, print a result, return a code.

---

## Cutting a release

1. Bump `VERSION` in `CMakeLists.txt`, add the dated section to `CHANGELOG.md` and update the version numbers in `README.md`.
2. `bash tools/release.sh <triple>` on your machine. It builds with warnings as errors, runs the tests, packages the archive and then verifies the extracted binary; `.github/workflows/release.yml` runs the same script for all four targets.
3. Commit, then `git tag -a vX.Y.Z -m "Scour X.Y.Z" && git push origin vX.Y.Z`.
4. The tag builds the four targets in parallel. `publish` writes `SHA256SUMS.txt` and attaches the archives to the release. A manual `workflow_dispatch` run builds the artefacts without publishing, which is the cheap way to check the pipeline.

Tag the commit that bumps the version, and do not move a tag once it is public: the version is embedded in every file name.

---

## Screenshots

Documentation images are generated from the real binary, not mocked up:

```bash
python3 tools/screenshots.py \
  --font /path/to/JetBrainsMono-Regular.ttf \
  --bold-font /path/to/JetBrainsMono-Bold.ttf
```

That renders `dashboard.png`, `help.png` and `palette.png` from real 108x34
frames of `fixtures/contract-leak.pdf`. The script needs Pillow. The font is
JetBrains Mono (OFL) and is not vendored. Do not add HTML; documentation is
Markdown and PNG.

---

## Security reports

Do not open a public issue for a memory-safety bug, a verification bypass or a privacy leak. See [SECURITY.md](SECURITY.md).

---

## License

By contributing, you agree that your contribution is licensed under the MIT license in [LICENSE](LICENSE).

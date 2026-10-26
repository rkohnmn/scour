# Fuzzing

Scour opens files it did not write, from people it does not trust. Unit tests
prove the cases we thought of. Fuzzing looks for the ones we did not.

`fuzz/pdf_fuzz.cpp` feeds mutated documents through the whole pipeline a user
triggers, with AddressSanitizer and UndefinedBehaviorSanitizer as the oracle.
There are no assertions in the harness: a memory error, an integer overflow or
an unhandled state is the failure, and it aborts the run with a stack trace.

## What one input goes through

1. `Document::load` — header, xref chain, xref streams, object streams, broken
   xref repair, encryption setup.
2. `inspect_document` — all eight categories, including PII detection.
3. `analyze_document` — content-stream lexing, font decoding, glyph geometry.
4. `collect_page_numbers`, `page_box`, `page_rotation` — page tree walking.
5. `extract_pages` and `merge_documents` — object copying, page-tree rebuilding.
6. `scrub_document` — term and PII targets, painted boxes, metadata, annotation,
   attachment and action removal.
7. `write_document` — serialisation, optional recompression, xref emission.
8. Re-open the written bytes and run `verify_document` on them, which is exactly
   what `scour scrub` does before it reports success.

A rejected input is a correct outcome and counts as a pass. The driver reports
how many inputs still parsed, because garbage that fails at the header tests
very little.

## Running a campaign

Build with the sanitizers and the fuzzer, then mutate the sample corpus:

```bash
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug \
      -DSCOUR_SANITIZE=ON -DSCOUR_BUILD_FUZZ=ON -DSCOUR_BUILD_TESTS=OFF
cmake --build build-fuzz -j

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
./build-fuzz/scour_fuzz --corpus fixtures --iterations 25000 --seed 21
```

| Option | Meaning |
|---|---|
| `--corpus DIR` | Directory of seed files, recursive. Repeatable; default `fixtures`. |
| `--iterations N` | Inputs to try. `0` runs until `--time` expires. |
| `--seed N` | Mutation seed. Printed on every input. |
| `--time SECONDS` | Wall-clock limit. |
| `--quiet` | Only the summary. |

A single seed of 25,000 inputs takes about 80 seconds in a debug sanitizer
build on the 2-vCPU runner used for the verification report. CI runs one seed
per build; a longer campaign is a local exercise, not a CI cost.

## Replaying a failure

Runs are deterministic: the seed selects a seed file, the mutations are drawn
from a fixed sequence, and corpus files are sorted before indexing so a seed
number means the same bytes on another machine. Every input is announced
before it is executed:

```text
input iteration=8137 seed=21 bytes=2314 fnv=8f4a0c1d9e2b7755
```

If the sanitizer aborts, that line is the last thing on stderr. Replaying is
`--seed 21 --iterations 8138`; the failing input is the last one. Reduce it to a
unit test with the same bytes — for a parser, a hand-written fixture is usually
shorter than the mutated blob.

Artifacts are not written per iteration; a deterministic replay is cheaper than
a directory of half-reduced inputs, and it is the state that matters.

## What it has found

The first campaign (3,000 inputs against the sample corpus) found undefined
behaviour in number parsing: `Lexer::next` accumulated digits into an `int64`
with a guard that allowed one more multiplication past the limit, so a number
like `9370400440532013000` overflowed. In a parser that turns numbers into
object numbers, lengths and byte offsets, a wrapped value can point somewhere
plausible instead of failing.

The lexer now saturates at `INT64_MAX` (`src/core/lexer.cpp`), every consumer
range-checks the value, and `tests/test_lexer.cpp` pins the behaviour with a
4,000-digit input. Everything after that is recorded in
[docs/VERIFICATION.md](VERIFICATION.md).

## Coverage-guided campaigns

The standalone driver mutates blindly. With clang, the same harness is a
libFuzzer target, which keeps inputs that reach new code:

```bash
clang++ -std=c++20 -g -O1 -fsanitize=fuzzer,address,undefined \
        -DSCOUR_LIBFUZZER -Iinclude \
        fuzz/pdf_fuzz.cpp src/core/*.cpp -o scour_fuzz_libfuzzer

mkdir -p corpus && cp fixtures/*.pdf corpus/
./scour_fuzz_libfuzzer -max_total_time=300 -timeout=10 corpus/
```

`FuzzOne` does not allocate anything static, so the target is safe to call
repeatedly. Keep `-timeout` set: a pathological file that makes the redactor
quadratic in page size should be caught as a hang, not left to run.

## What this does not cover

- **The terminal layer.** `src/tui` is exercised by the end-to-end suite and its
  own escape-injection checks; the fuzzer only speaks the library.
- **A broad real-world corpus.** Seeds are the synthetic fixtures. Real
  documents contain font programs, colour spaces and structures these fixtures
  do not, and mutation cannot invent a construct it has never seen.
- **Semantic correctness.** Fuzzing proves Scour does not fall over. It cannot
  prove the output is faithful, which is what the pikepdf/pypdf harness and the
  end-to-end tests are for.
- **Thread safety.** There is no threading in the engine, and none is fuzzed.

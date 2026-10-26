# CLI reference

`scour` is a single executable with eight commands. This page documents every option and the exact behavior that scripts can rely on.

```text
scour <command> [arguments] [options]
```

Global options accepted by every command:

| Option | Meaning |
|---|---|
| `--help`, `-h` | print help for the command and exit `0` |
| `--version` | print `scour <version>` and exit `0` (only as the first argument) |
| `--no-color` | disable ANSI color; `NO_COLOR` has the same effect |
| `-p`, `--password PASSWORD` | open a password-protected PDF |

Colors are only emitted when stdout is a terminal and `NO_COLOR` is unset.

---

## Exit codes

| Code | Name | When |
|---|---|---|
| `0` | clean | success; nothing remained to report |
| `1` | findings | `inspect`: risk at or above `--fail-on`; `scrub`: verification found a surviving target; `verify`: a target survived |
| `2` | usage | unknown command/option, missing value, malformed page list, bad rectangle |
| `3` | input | missing/unreadable file, header/parse failure, encrypted without a usable password |
| `4` | output | cannot write/replace the output, or a writer/verification failure |

A non-zero code is always meaningful. In a pipeline, do not swallow it:

```bash
set -o pipefail
scour verify "$file" --pii | tee verify.log
```

---

## `scour inspect`

```text
scour inspect <file.pdf> [--json] [--no-pii] [--fail-on N] [-p PASSWORD]
```

Reads the document end to end and reports what a recipient could recover that the page does not show. It never modifies the input.

| Option | Default | Meaning |
|---|---|---|
| `--json` | off | emit the stable JSON report instead of text |
| `--no-pii` | off | skip email/phone/SSN/card/IBAN/IP/key detection |
| `--fail-on N` | `10` | exit `1` when the risk score is at or above `N` (0–100) |
| `-p`, `--password` | empty | document password |

Text output sections: `METADATA`, `HIDDEN-TEXT`, `ANNOTATIONS`, `EMBEDDED`, `ACTIONS`, `STRUCTURE`, `PII`, `INTEGRITY`, followed by category scores. Findings carry a severity (`error`, `warning`, `note`), a page when relevant, an explanation and evidence.

```bash
scour inspect brief.pdf
scour inspect brief.pdf --json > brief.json
scour inspect brief.pdf --fail-on 0       # any finding fails
scour inspect brief.pdf --fail-on 100     # only a perfect 100 fails
```

JSON shape is documented in the [README](../README.md#json). `format` is `1`; consumers should ignore unknown fields.

---

## `scour scrub`

```text
scour scrub <file.pdf> -o <out.pdf> [options]
```

Removes targets and sanitizes the object graph, then rewrites the file and verifies the output.

| Option | Default | Meaning |
|---|---|---|
| `-o`, `--output PATH` | `<input>.scrubbed.pdf` | output path |
| `--term TEXT` | none | remove a literal, case-insensitive term; repeatable |
| `--pii` | off | remove every PII detector match |
| `--pages LIST` | all | pages to redact; accepts `1-3,7,10-` |
| `--rect PAGE:X0,Y0,X1,Y1` | none | remove glyphs intersecting a user-space box; repeatable |
| `--no-boxes` | off | do not paint an opaque box over removed glyphs |
| `--keep-metadata` | off | keep `/Info` and XMP |
| `--keep-annotations` | off | keep comments and form fields |
| `--keep-attachments` | off | keep embedded files |
| `--keep-scripts` | off | keep JavaScript and action dictionaries |
| `--no-redact` | off | skip the redaction pass (metadata/annotation scrub only) |
| `--in-place` | off | replace the input atomically |
| `--compress` | off | re-deflate uncompressed streams when smaller |
| `-p`, `--password` | empty | password for the input |

Behavior:

- Targets are removed from the content streams; removed glyphs are replaced with spaces of the same advance width.
- Metadata, XMP, annotations, form fields, attachments, JavaScript and launch actions are removed unless a `--keep-*` flag says otherwise.
- The output is a **full rewrite**: no incremental updates, no unreachable objects, fresh xref, deterministic `/ID`.
- The output is reopened and re-extracted. If a target survives, the command exits `1` and lists the page and text.
- The write is atomic: a temporary file in the destination directory is renamed into place.

```bash
# PII and a codename, boxes painted
scour scrub brief.pdf -o brief.safe.pdf --pii --term "Project Bluebird"

# A rectangle on page 2, no painted boxes
scour scrub brief.pdf -o brief.safe.pdf --rect 2:60,700,560,740 --no-boxes

# Metadata/comments/attachments only
scour scrub brief.pdf -o brief.safe.pdf --no-redact

# Replace the original, keeping a compressed result
scour scrub brief.pdf --in-place --pii --compress
```

### Page lists

`--pages` accepts comma-separated page numbers and ranges:

```text
1           page 1
1-3         pages 1, 2, 3
7,9-11      pages 7, 9, 10, 11
5-          page 5 to the end
-3          pages 1 to 3
```

Pages are 1-based. Values are clamped to the document and de-duplicated in the order written. An empty selection is a usage error.

### Rectangles

`--rect PAGE:X0,Y0,X1,Y1` uses PDF user-space coordinates in points, with the origin at the bottom-left of the page, before page rotation. A rectangle removes every glyph whose box intersects it. It is useful when the text cannot be decoded reliably; it does not remove vector art or image pixels.

```bash
scour scrub scan.pdf -o scan.safe.pdf --rect 1:72,600,540,720
```

### After a scrub

`scrub` prints what it removed: size before/after, objects written/dropped, metadata, annotations, attachments, actions, glyphs, boxes, and notes. Read the notes. A warning about an undecodable font or an image-only page means the verification is incomplete.

---

## `scour verify`

```text
scour verify <file.pdf> [--term TEXT]... [--pii] [--pages LIST] [--json] [-p PASSWORD]
```

Re-extracts the document and reports whether any target survives. This is the same check that `scrub` runs automatically, exposed as a standalone command so you can verify a file produced elsewhere.

| Option | Meaning |
|---|---|
| `--term TEXT` | literal, case-insensitive target; repeatable |
| `--pii` | every detector |
| `--pages LIST` | restrict verification to pages |
| `--json` | machine-readable result |
| `-p`, `--password` | password |

Exit `0` when clean, `1` when anything survives. A warning about unreliable fonts or image-only pages is printed; treat it as incomplete rather than clean.

```bash
scour verify brief.safe.pdf --pii --term "Project Bluebird"
scour verify brief.safe.pdf --pii --json
```

JSON:

```json
{
  "file": "brief.safe.pdf",
  "pages": 3,
  "verified": true,
  "remaining": 0,
  "items": []
}
```

---

## `scour text`

```text
scour text <file.pdf> [--page N] [-p PASSWORD]
```

Prints the extracted text layer. Pages are separated by a form feed (`\f`). `--page N` prints one page (1-based).

```bash
scour text brief.pdf
scour text brief.pdf --page 2
```

Exit `3` if the document cannot be opened or decrypted. Text extraction is the same engine used by `inspect`; a font with no reliable Unicode mapping is flagged, and the page is treated as unreliable.

---

## `scour split`

```text
scour split <file.pdf> --pages LIST -o <out.pdf>
scour split <file.pdf> --each -o <directory>
```

| Option | Meaning |
|---|---|
| `--pages LIST` | 1-based page list; ranges allowed |
| `--each` | write one file per page into a directory |
| `-o`, `--output` | output file or directory |
| `-p`, `--password` | password |

With `--each`, files are named `<stem>-page-001.pdf`, `<stem>-page-002.pdf`, and so on. Without `-o`, the default output is `<stem>.pages.pdf` for a subset and `<parent>/pages/` for `--each`.

```bash
scour split report.pdf --pages 1-3 -o intro.pdf
scour split report.pdf --each -o pages/
```

---

## `scour merge`

```text
scour merge -o <out.pdf> <a.pdf> <b.pdf> [...]
```

Concatenates documents in argument order. Pages are copied into a new document; annotations and link destinations are remapped. The output is a fresh PDF (not an incremental append).

```bash
scour merge -o combined.pdf a.pdf b.pdf c.pdf
```

At least two inputs are required. A single password applies to every input.

---

## `scour rotate`

```text
scour rotate <file.pdf> --by DEGREES -o <out.pdf> [--pages LIST] [-p PASSWORD]
```

`--by` must be a multiple of 90; negative values are normalized. The rotation is added to the page's existing `/Rotate`, and the page content is not re-rendered.

```bash
scour rotate scan.pdf --by 90 -o scan-upright.pdf
scour rotate report.pdf --by 180 --pages 2-4 -o report-fixed.pdf
```

---

## `scour tui`

```text
scour tui <file.pdf> [--theme midnight|paper] [--no-color] [-p PASSWORD]
scour tui <file.pdf> --dump WIDTHxHEIGHT [--ansi] [--keys STR] [--theme ...]
```

The interactive dashboard. It needs a terminal of at least 64×18 cells; below that it prints a `WINDOW TOO SMALL` panel with the current size and the `scour inspect` fallback rather than drawing a collapsed frame. `--dump` renders one frame to stdout and exits, which is how the documentation images and end-to-end tests are generated.

| Option | Meaning |
|---|---|
| `--theme midnight` | dark theme (default) |
| `--theme paper` | light theme |
| `--dump WxH` | render one frame of `W` columns by `H` rows and exit |
| `--ansi` | with `--dump`, include truecolor SGR sequences |
| `--keys STR` | with `--dump`, apply keys first (`?` help, `p` palette, `/` filter, `s` scrub, `t` theme, `m` monochrome, `q` quit) |
| `--no-color` | drop colour; `NO_COLOR` has the same effect, and `m` toggles it live |
| `-p`, `--password` | password |

```bash
scour tui brief.pdf
scour tui brief.pdf --theme paper
scour tui brief.pdf --no-color
scour tui brief.pdf --dump 110x34 --ansi --keys '?'
```

The TUI writes files only on explicit action:

- `s` scrubs and writes `<stem>.scrubbed.pdf` next to the input;
- `e` writes `<stem>.report.json` next to the input.

It never phones home. The dashboard uses the same engine as the CLI, so a finding shown there is the finding `inspect` reports.

---

## Common patterns

### Pre-flight in CI

```bash
#!/usr/bin/env bash
set -euo pipefail
file="$1"
report="$(mktemp)"
scour inspect "$file" --json --fail-on 10 > "$report" || {
  echo "inspection failed; report:"
  cat "$report"
  exit 1
}
scour scrub "$file" -o "${file%.pdf}.safe.pdf" --pii
scour verify "${file%.pdf}.safe.pdf" --pii
```

### A folder of documents

```bash
find ./outbox -name '*.pdf' -print0 |
  while IFS= read -r -d '' file; do
    scour scrub "$file" -o "${file%.pdf}.safe.pdf" --pii --term "ACME-INTERNAL"
  done
```

There is no batch command yet; the CLI is designed so a shell loop is enough. Preserve the exit status of each invocation.

### Password-protected input

```bash
scour inspect locked.pdf -p "$PDF_PASSWORD"
scour scrub locked.pdf -p "$PDF_PASSWORD" -o unlocked.pdf --pii
```

The output of `scrub` is not encrypted. If you need encryption at rest, use a separate tool; Scour does not implement encryption of output.

### Reproducible checks

```bash
scour scrub input.pdf -o a.pdf --pii --term "X"
scour scrub input.pdf -o b.pdf --pii --term "X"
cmp a.pdf b.pdf     # byte-identical
```

---

## Environment

| Variable | Effect |
|---|---|
| `NO_COLOR` | disable ANSI color in CLI output |
| `TERM` | used by the TUI to decide whether it can enter raw mode; `dumb` or a non-tty fails cleanly |
| `COLUMNS`, `LINES` | fallback when the terminal size cannot be queried |

There is no configuration file, no environment-based upload path, no proxy variable and no licensing endpoint. The binary does not read a config directory.

---

## Help

Every command accepts `--help`:

```bash
scour help
scour inspect --help
scour scrub --help
scour verify --help
scour tui --help
```

If a command is given a file it cannot read, the error names the file and the reason, and the exit code is `3`. Usage errors print a one-line reminder to run `scour help` and exit `2`.

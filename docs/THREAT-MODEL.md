# Threat model

This document describes what Scour protects against, what it does not, and what "verified" means. It is deliberately specific. A security tool that is vague about its guarantees is a liability.

---

## 1. Assets

- The **content** of a document that the sender does not intend to share: text, names, identifiers, comments, tracked changes, earlier revisions.
- The **existence and identity** of the document: filename, author, client, project codename.
- The **recipient's trust**: a document that looks clean but is not.
- The **sender's machine and network**: the document must not be uploaded, logged or retained by a third party.

## 2. Adversaries

| Adversary | Capability | In scope? |
|---|---|---|
| A recipient with a normal PDF viewer | Select text, copy, search, open attachments, inspect properties, view comments, extract images | **Yes** |
| A recipient with a PDF editor or script | Recover hidden text, earlier revisions, XMP, form values, JavaScript, embedded files | **Yes** |
| A public web upload / cloud redaction service | Retains, logs or processes the document | **Out of scope by construction** — Scour never uploads |
| A network observer | Sees traffic | **Out of scope** — there is no traffic |
| A compromised local machine | Reads memory, disk, clipboard or the output file | **Out of scope** |
| A malicious PDF author | Exploits the parser, exhausts memory, triggers code execution | **Partially in scope** — hardened parser, no execution, fuzzing/ASan; not a formal proof |
| A determined forensic analyst with the original file | Recovers data from the original medium, temporary files, backups, SSD wear levelling | **Out of scope** — Scour removes data from the output file, not from history |
| A legal adversary who subpoenas the source document | — | **Out of scope** |

The core assumption: **the attacker gets the file, not the machine**. That is the realistic threat for a contract, a board pack, a source document or a medical letter.

---

## 3. What Scour is designed to prevent

### 3.1 Accidental disclosure through structure

- **Text under a black box.** A rectangle is a drawing operator. The text is still in the content stream. Scour detects the overlap and removes the glyphs.
- **Invisible text.** Rendering mode 3/7, white-on-white, or text placed outside the page box. Scour finds it and can remove it.
- **Metadata and XMP.** Author, title, producer, timestamps, custom properties, XMP packets. Removed from `/Info`, the catalog and the trailer.
- **Annotations and comments.** The icon may be collapsed; the contents are in the file. Removed with the page's `/Annots`.
- **Form values.** A flattened form can still carry `/V` values in the field dictionary. The form dictionary is removed.
- **Attachments.** The editable source, a spreadsheet, a key or a certificate chain. Removed from `/Names/EmbeddedFiles` and `/AF`.
- **Active content.** JavaScript, launch actions, submit/import actions, remote go-to. Removed from the catalog, page actions and name trees.
- **Earlier revisions.** An incremental update appends; it does not replace. The earlier page, its text and its metadata remain in the file. A full rewrite drops them.
- **Unreachable objects.** Objects no longer in the page tree but still in the file. The writer collects only reachable objects.
- **PII in the text layer.** Common identifiers are detected and can be removed with `--pii`.

### 3.2 Disclosure through a false sense of safety

- **No "clean" on an unreadable file.** If the document is encrypted and the password is wrong or missing, Scour exits `3` instead of reporting a clean container.
- **Image-only pages are not called clean.** The inspector reports pages with images and no text layer. It cannot see the words in the pixels, and it says so.
- **Fonts with unreliable encodings are flagged.** Scour does not invent Unicode.
- **Verification is against the output.** The scrubber does not trust its in-memory state. It reopens the bytes and re-extracts.
- **The report separates facts from inference.** "The author field contains Alice Example" is a fact; "this is Alice's document" is not stated.

---

## 4. What Scour cannot do

### 4.1 Text in images

If a page is a scan, a screenshot or a flattened image, the words are pixels. Scour can report that the page has no text layer and that an image covers the page. It does not OCR. A redaction box on such a page can cover pixels, but the original pixels may remain elsewhere in the image, in an earlier revision, or in the scanner's file.

**Do not treat an image-only document as verified.** Re-scan or re-export from the source if the content matters.

### 4.2 Optional content (layers)

PDF optional content groups can hide layers. Scour's extractor reads text in the content streams it walks; it does not currently model layer visibility or report a hidden layer as a distinct finding. Treat a layered PDF with suspicion, flatten it in a trusted tool, and re-inspect.

### 4.3 Encryption without a password

Scour implements RC4, AES-128 and AES-256 (R2–R6). Without the correct password, it cannot decrypt the content. It will not guess, brute-force or pretend. The CLI exits `3`; the TUI shows a clear error. An owner password does not grant access if the user password is required and unknown, unless the owner password itself authenticates.

### 4.4 Digital signatures

Rewriting a signed document invalidates the signature. Scour does not preserve a signature over modified bytes, because that would be a lie. If a signature is required after redaction, the document must be re-signed by the appropriate party.

### 4.5 Malware and exploits

Scour removes JavaScript and launch actions, but it is not an antivirus. It does not execute PDF content, and it rejects malformed structures, but a determined exploit against a different viewer is out of scope. Use a sandbox and a malware scanner for untrusted files.

### 4.6 Data remanence on the sender's machine

`scour scrub` reads the input and writes a new file. The input remains untouched unless `--in-place` is used. The output is written atomically via a temporary file, then renamed. On a modern SSD, "deleted" blocks may persist due to wear levelling; on a network filesystem, snapshots and backups may retain the original. Scour cannot erase storage history. If the source must be destroyed, use full-disk encryption, secure erase or a trusted data-destruction process — and remember backups.

### 4.7 Legal compliance

Scour produces evidence, not a legal opinion. A clean report does not establish GDPR, HIPAA, CCPA, FOIA or court-rule compliance. The detectors are heuristics. A human must review the findings and the context.

### 4.8 Every reader, every font, every file

PDF is a large, permissive format. Scour's parser covers the constructs found in real documents and the test corpus, but no implementation can promise to understand every producer's output. The inspector reports parser diagnostics and repairs instead of hiding them. If a file does not parse cleanly, treat the report as provisional and test with another reader.

---

## 5. What "verified" means

`scour verify` and the automatic verification in `scour scrub` mean:

1. The output file was reopened from disk.
2. The page tree was traversed.
3. The text layer was extracted with the same engine used for inspection.
4. The requested terms and detectors were matched again.
5. No match was found in the extracted text.

It does **not** mean:

- that no pixels contain the text (images are not OCR'd);
- that a different PDF reader with a different font map would extract the same text;
- that metadata, attachments or annotations are gone — verification is scoped to the redaction targets; `scrub` removes those classes separately and reports what it removed;
- that the document is compliant, anonymous or safe in every context;
- that the output is byte-identical to the input minus the target (a rewrite changes the structure).

For a full post-scrub check, run `scour inspect` on the output as well. The scrub report says what was removed; the inspection report says what remains.

### Verification and fonts

If the font's encoding cannot be trusted, the extractor marks the page unreliable. A target may not be found because it was never decoded, not because it was removed. Scour reports the unreliable page. Treat a verification with warnings as incomplete, not as a pass.

### Verification and the `remaining` list

`verify` returns findings, not a boolean. A target that survives is listed with its page, kind and text. This is intentionally actionable: you can see whether the miss is a real leak, a detection artifact or a font issue.

---

## 6. Security of the tool itself

### 6.1 Attack surface

- **No network code.** The binary does not include a socket API, an HTTP client or a telemetry endpoint. This is verifiable by inspecting the source and the linked libraries.
- **No plugin loading.** No shared objects, no scripts, no eval.
- **No external processes.** Scour does not shell out to Ghostscript, ImageMagick, a browser or a renderer.
- **Untrusted input.** Every file is treated as hostile: bounds-checked lexer/parser, allocation limits, recursion depth limits for forms and page trees, no unbounded loops on malformed xrefs.
- **Terminal output.** The TUI sanitizes control characters in extracted text before writing it to the terminal, so a malicious document cannot inject escape sequences. (This is a real attack class; the cell buffer stores glyphs, not raw escape streams.)

### 6.2 Memory safety

The code is C++20 with `std::string`, `std::vector` and bounds-checked accessors. It is built with ASan and UBSan in CI and tested against malformed fixtures. It is not formally verified. A parser bug is possible; the response is coordinated disclosure, a fix and a regression test.

### 6.3 Supply chain

- Build: CMake + a C++20 compiler. No package manager dependencies.
- Runtime: the C++ standard library and libc.
- Release: source zip, checksums, reproducible build instructions. A future release will publish signed binaries and an SBOM.
- Tests: no network access required.

### 6.4 Privacy of the tool

- No telemetry, analytics, crash reporting or update check.
- No account, licence server or activation.
- The TUI writes only the files the user asks for: the scrubbed PDF and, on `e`, a `.report.json` next to the input.
- The CLI writes the output path and, with `--in-place`, atomically replaces the input.
- Temporary files are created in the destination directory and renamed; they are not left behind on success.

### 6.5 Build reproducibility

The writer uses a deterministic `/ID` by default, and the tests check that two scrubs of the same input are byte-identical. This is about verifiable behavior, not bit-reproducible compiler output; the latter depends on the toolchain and build path. A reproducible-build setup (fixed paths, `-ffile-prefix-map`) is planned.

---

## 7. Operational guidance

### Before sending a sensitive PDF

1. Run `scour inspect file.pdf`. Read the findings, not just the score.
2. If the file is image-only, do not assume it is clean; re-export from the source.
3. Run `scour scrub` with the terms and PII classes you need.
4. Read the scrub report: what was removed, what was not.
5. Run `scour inspect` on the output. A clean inspection plus a clean verification is the strongest signal this tool can give.
6. Open the output in a different viewer and search for the target. Defense in depth.

### In CI

```bash
scour inspect board-pack.pdf --fail-on 10 --json > report.json
scour scrub board-pack.pdf -o safe.pdf --pii --term "Project Bluebird"
scour verify safe.pdf --pii --term "Project Bluebird"
```

`inspect` exits `1` when the risk is at or above the threshold. `scrub` and `verify` exit `1` when a target survives. Any non-zero code should fail the job; do not pipe the command into `tail` without preserving the status.

### If you find a leak in a released file

1. Stop distribution; withdraw the file.
2. Treat it as a disclosure: assess the data, the recipients and the legal notification duties (GDPR 72 hours where applicable; HIPAA 60 days; contractual notice).
3. Recover the source, redact from the source, not from the already-redacted PDF.
4. Verify with Scour and a second reader.
5. Preserve logs and the original for the incident record.
6. Fix the process that produced the file; a tool cannot compensate for a bad workflow.

---

## 8. Residual risks

| Risk | Residual? | Mitigation |
|---|---|---|
| Text in scanned images | Yes | report image-only pages; re-export from source; OCR review on roadmap |
| Optional content layers | Yes | documented limitation; flatten and re-inspect |
| Exotic font encodings | Yes | warnings; verification may be incomplete; test corpus expansion |
| PII false negatives | Yes | custom terms, review, multiple detectors |
| PII false positives | Yes | evidence shown; user decides |
| A different reader extracts differently | Yes | verify with a second reader for high-stakes files |
| Parser memory-safety bug | Low, not zero | ASan/UBSan, fuzzing, bounds checks, disclosure process |
| Compromised host | Yes | out of scope; use full-disk encryption and a trusted machine |
| Storage remanence | Yes | out of scope; secure erase/backups |
| Signature invalidation | Certain | re-sign after redaction |
| Legal/compliance | Yes | tool is evidence, not advice; human review |

---

## 9. Reporting a vulnerability

Do not open a public issue for a memory-safety or bypass vulnerability. Email the maintainers (see [SECURITY.md](../SECURITY.md)) with:

- a description and the affected version;
- a minimal PDF or a generator;
- the command that triggers it;
- the observed and expected behavior;
- whether you intend to publish, and a disclosure timeline.

We aim to acknowledge within 72 hours, provide a fix or mitigation within 30 days for high-severity issues, and credit reporters who want credit. Please do not include real personal data in a report; use synthetic values.

---

## 10. Summary card

| Question | Answer |
|---|---|
| Does it upload my file? | No. There is no network code. |
| Does it remove the text or just cover it? | It removes the encoded glyphs and rewrites the content stream. The box is cosmetic. |
| Does it remove metadata? | Yes, by default: `/Info`, XMP, `/PieceInfo`, application data. |
| Does it remove comments, forms, attachments, scripts? | Yes, by default. Each can be kept with a flag. |
| Does it remove earlier revisions? | Yes, by rewriting the file. |
| Can it prove the result? | It reopens the output and re-extracts the text. That is strong evidence, not a mathematical proof. |
| Can it see text in a scan? | No. It reports the page as image-only. |
| Does it work without a password? | No. It exits with an input error. |
| Is it a compliance certification? | No. It is a review and removal tool. |
| Is it safe on hostile files? | It is hardened and sanitizer-tested, but not formally verified. Use a sandbox for unknown files. |

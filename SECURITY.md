# Security policy

Scour reads untrusted files and makes claims about removing data. Both properties deserve a security process.

---

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 | no |

Security fixes are released on the latest minor line. There are no long-term support branches yet.

---

## Reporting a vulnerability

**Do not open a public issue** for:

- a memory-safety bug (out-of-bounds read/write, use-after-free, integer overflow);
- a parser crash or denial of service on a crafted PDF;
- a verification bypass: a document where `scour verify` or the automatic scrub verification reports clean but a requested target survives;
- a metadata or attachment class that `scrub` claims to remove but does not;
- a terminal escape injection or any path from document content to code execution;
- a supply-chain issue in the build or release process.

Use GitHub's **private vulnerability reporting** for this repository (Security → Report a vulnerability). If that is unavailable, open a minimal public issue that says only "security report — please contact me" and wait for a private channel; do not include the details or the file.

Include:

- affected version and platform;
- a minimal PDF or a generator that reproduces the issue;
- the exact command and the observed vs. expected result;
- whether the issue is already public and your intended disclosure timeline;
- a way to credit you, if you want credit.

**Never include real personal data** in a report. Replace names, numbers and documents with synthetic values.

## What to expect

| Stage | Target |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix or mitigation for high severity | within 30 days |
| Coordinated disclosure | by agreement, usually after a release |

We will tell you what we found, whether we consider it in scope, and when a fix is planned. We will credit reporters who want credit. We will not pursue legal action against good-faith research that respects this policy and does not access other people's data.

---

## Scope

**In scope**

- The Scour binary and library in this repository.
- The parser, filters, encryption handler, text extractor, redactor, sanitizer and writer.
- The CLI and TUI.
- The release and packaging scripts, where they could ship something unintended.

**Out of scope**

- Vulnerabilities in a PDF viewer, office suite or operating system.
- A document that is malicious in a way Scour does not execute (Scour does not run JavaScript or render pages).
- Denial of service caused solely by a file larger than available memory, without a parsing bug.
- Issues that require an already-compromised host, debugger or modified binary.
- Social-engineering a user into ignoring the report.
- Missing a PII format that is not claimed in the documentation; report it as a feature request with a sample.

---

## Threat model

The guarantees and non-guarantees are documented in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). Read it before reporting a "bypass": a scan with text in the pixels is a documented limitation, not a vulnerability. A bypass is when Scour's own verification says a target is gone and it is still recoverable from the text layer, or when a class of data that the scrub report says it removed is still present.

---

## Hardening practices

- No network code, no telemetry and no external process execution.
- The parser treats every file as hostile: bounds checks, allocation limits, recursion limits.
- ASan and UBSan run in CI on the unit and end-to-end suites.
- Fuzzing coverage is a roadmap item; reports of parser crashes are welcome and treated as security issues.
- Release artifacts are built from the tagged source; checksums are published. Signed binaries and reproducible-build attestations are planned.

---

## If you find a leak in a released document

That is an incident, not a vulnerability in Scour. See the operational guidance in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md#7-operational-guidance): withdraw the file, assess notification duties, recover the source, re-redact from the source, verify, and preserve the record.

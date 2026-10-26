# Market thesis

*Desk research and product strategy for Scour 1.0 — October 2026. This document separates sourced facts from hypotheses. Figures marked "estimate" are planning assumptions, not measurements.*

---

## 1. The one-sentence thesis

**Every organisation now has a "send it externally" moment, and the tools for that moment are either expensive suites, cloud uploads, or low-level components that require a PDF engineer. Scour is the fast, local, verifiable default — a single binary that inspects, removes and proves.**

The wedge is not "another PDF editor". It is the specific, recurring, high-anxiety task of making a document safe to share. That task is currently underserved in the middle of the market: too important for a free viewer, too small for an enterprise DMS, too sensitive for a random upload site.

---

## 2. Demand evidence

### 2.1 The format is the distribution channel

Adobe estimated in 2023 that more than **3 trillion PDF documents** exist and that customers opened more than **400 billion PDFs in Acrobat products in 2022**. ([Adobe, 30 years of Acrobat](https://blog.adobe.com/en/publish/2023/06/15/celebrating-30-years-of-digital-transformation-with-adobe-acrobat)) These are vendor estimates, not an independent census, but they establish the order of magnitude: PDF is not a niche format, it is the default container for final-form documents.

The consequence is structural. Every contract, offer letter, invoice, medical letter, court filing, insurance claim and government release is likely to be a PDF. Every one of those has a sender who must decide what to remove before it leaves the building.

### 2.2 Failures are common, public and expensive

| Case | What happened | Why it matters |
|---|---|---|
| **TSA screening manual, 2009** | A 93-page manual posted with black-box redactions; readers removed the boxes and recovered screening procedures. ([CBS](https://www.cbsnews.com/news/unredacted-tsa-manual-leaked-online/)) | The oldest and clearest demonstration that a box is not a removal. |
| **Citigroup bankruptcy filings, 2013** | Personal information, including SSNs and birth dates, was exposed in proofs of claim; nearly **150,000 consumers in 85 jurisdictions** affected; ~50,000 additional filings had issues. Remediation: replacement filings, notification, credit monitoring, independent audit. ([DOJ](https://www.justice.gov/archive/ust/press/docs/2013/pr20130715.htm)) | A redaction defect became a multi-month remediation programme. |
| **Paul Manafort filing, 2019** | Text beneath black bars remained selectable and copyable. ([BBC](https://www.bbc.com/news/world-us-canada-46804127)) | Even a high-stakes legal filing by sophisticated counsel can get this wrong. |
| **Security-agency PDFs, 2021 study** | 39,664 PDFs from 75 agencies in 47 countries; sensitive information found in **65% of the PDFs that had been sanitized**; only seven agencies sanitized some files. ([arXiv:2103.02707](https://arxiv.org/abs/2103.02707)) | Sanitization is attempted, and frequently fails, even in security-conscious organisations. |
| **Redaction-tool study, 2022** | 11 popular tools tested; two left text beneath redactions copyable; more than **6,000 vulnerable non-excising redactions** and **300 vulnerable excising redactions** in public documents. ([arXiv:2206.02285](https://arxiv.org/html/2206.02285v3)) | The failure is in the tools, not only in user error. |
| **Epstein-related releases, 2025–26** | Reports of text redactions that could be overridden and victim information exposed; DOJ withdrew and reworked documents. ([Guardian](https://www.theguardian.com/us-news/2025/dec/23/epstein-unredacted-files-social-media), [AP/PBS](https://www.pbs.org/newshour/politics/government-says-its-fixing-thousands-of-documents-in-epstein-related-files-that-may-have-had-victim-information)) | The problem is current, not historical. |

Two independent studies are the strongest evidence for a product: the failure rate is high, it occurs in organisations that believe they have a process, and it is caused by tools that do not verify their own output. A product that makes verification automatic is not a nicer UI; it changes the failure mode.

### 2.3 Legal pressure is broad, not niche

- **GDPR**: data minimisation and integrity/confidentiality principles; Article 32 requires risk-appropriate technical measures; breach notification within 72 hours where required; fines up to **€20 million or 4% of worldwide turnover** (with a lower tier for some security obligations). ([European Commission](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr_en), [Art. 32](https://gdpr-info.eu/art-32-gdpr/), [Art. 83](https://gdpr-info.eu/art-83-gdpr/))
- **CCPA/CPRA**: consumer rights and a private right of action for breaches of nonencrypted, nonredacted personal information; CPPA's inflation-adjusted thresholds include **$26,625,000** revenue and statutory damages of **$107–$799 per consumer per incident**. ([California AG](https://oag.ca.gov/privacy/ccpa), [CPPA](https://cppa.ca.gov/regulations/cpi_adjustment.html))
- **HIPAA**: minimum-necessary standard; Safe Harbor requires removal of **18 identifier categories**; breach notice within **60 days**. ([45 CFR §164.514](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514), [§164.404](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-D/section-164.404))
- **FOIA**: release with segregable non-exempt portions; Exemption 6 for personal privacy. ([FOIA.gov](https://www.foia.gov/faq.html))
- **FRCP 5.2**: filings limited to last four digits of SSNs/account numbers, birth year, minor's initials; responsibility is on the filing party. ([Rule 5.2](https://www.law.cornell.edu/rules/frcp/rule_5.2))

None of these laws prescribes a "remove metadata" button. That is the opening: the obligation is outcome-based, so a tool that can demonstrate the outcome has a defensible place in the workflow.

---

## 3. Who is underserved

### Persona 1 — Maya, employment lawyer (primary)

- **Context**: 12-person firm, 15–30 redactions a week, matters under NDA, clients increasingly ask for documents by email.
- **Current stack**: Acrobat Pro, a checklist, and a junior associate who manually searches the output.
- **Pain**: Acrobat's redaction is buried in a suite; metadata and attachments are a separate mental model; she cannot hand a client a machine-checkable proof; cloud tools are a non-starter for client material.
- **Willingness to pay**: already pays ~$20/month for Acrobat; would pay for a tool that reduces review time and produces a defensible artifact.
- **What wins**: a clear report, a verify command, no upload, a Windows/macOS binary, and language she can put in a memo.

### Persona 2 — Devon, security engineer (secondary, high-leverage)

- **Context**: builds release and due-diligence pipelines; asked to "make sure the board pack has no PII" at 6 p.m. before a raise.
- **Current stack**: Python scripts, `qpdf`, `pdftotext`, regex, manual spot checks.
- **Pain**: existing tools are interactive; `qpdf` is not a redactor; scripts do not verify; no stable JSON; no deterministic output to diff.
- **Willingness to pay**: team tooling budget; cares more about exit codes and CI integration than about a GUI.
- **What wins**: single binary, JSON, deterministic output, `--fail-on`, no network, fast on 1,000-page documents.

### Persona 3 — Priya, investigative journalist (influencer segment)

- **Context**: receives leaked documents, publishes excerpts, works against a deadline, often on a laptop in a co-working space.
- **Pain**: cannot upload a source document to a web service; needs to see what is hidden *before* publishing; needs to explain the result to an editor.
- **What wins**: offline by construction, terminal UI, screenshots for the editor, plain-language findings.

### Persona 4 — Sam, HR / people ops (volume segment)

- **Context**: offer letters, accommodation letters, investigations; no PDF expertise; uses a Mac.
- **Pain**: "remove metadata" in office software is inconsistent; does not know what XMP is; fears a mistake.
- **What wins**: one command or one TUI flow, a green "verified" line, and a report that says what was removed.

### Persona 5 — Government / FOIA officers (institutional segment)

- **Context**: large release batches, legal review, procurement constraints, air-gapped networks.
- **Pain**: cloud tools are prohibited; commercial suites are expensive per seat; auditability is weak.
- **What wins**: offline, deterministic, scriptable, per-file JSON, reproducible builds, support contract.

### Jobs to be done

1. *Before sharing*: "Tell me what is in this file that I cannot see."
2. *While removing*: "Remove these things without changing the layout or leaving a copy behind."
3. *After removing*: "Prove it, in a form I can attach to the matter file or a CI log."
4. *At scale*: "Do that for a folder, deterministically, without a server."

---

## 4. Competitive landscape

| Product | Price (public, U.S., 2025–26) | Strength | Gap Scour exploits |
|---|---|---|---|
| **Adobe Acrobat Pro** | ~$19.99/month annual billing; Pro 2024 three-year term option | Ubiquity, polished redaction, OCR, support | Subscription; desktop suite; verification is a manual review; metadata is a separate concept; no CI surface |
| **Foxit PDF Editor / Editor+** | $129.99 / $159.99 per year (PCWorld, Apr 2025) | Lower price than Acrobat; manual redaction + sanitization | Smart Redact is cloud-based; suite weight; limited automation |
| **Nitro PDF Pro** | ~$15/user/month annual (indexed) | Manual redaction, Smart Redact add-on | Nitro's own guide notes redaction does not strip metadata; no local verification story |
| **PDF Expert** | $79.99/year | Excellent Mac/iOS UX | Apple-only; redaction is a feature, not a workflow; no CLI |
| **Redactable** | $19/month for 15 docs; $79/month for 150 | Legal/insurance workflow, audit logs, OCR | Cloud service; per-document pricing; not for air-gapped work |
| **Stirling PDF** | Self-hosted free tier (5 users), paid team/enterprise | Broad PDF toolbox, self-hosted, active community | Server/Docker deployment; not a single binary; redaction is one tool among dozens |
| **qpdf** | Free, open source | Excellent structural engine, reliable | Not a redactor; no text extraction or UI; metadata cleanup is a known request |
| **pdf-redact-tools** | Free, open source | Simple rasterize-and-rebuild model | Unmaintained; external ImageMagick dependency; destroys searchable text; security warning |
| **JoshData/pdf-redactor** | Free, open source | Programmatic text/annotation/metadata rewriting | Explicitly incomplete: no images, attachments, scripts, forms; not a product |
| **`redact-pdf` (gaborcsapo)** | Free, open source | Two-phase scan/review/verify CLI, close in spirit | Young project; no independent audit or adoption signal |

**Pricing signal**: the market has established that redaction is worth **$80–$240 per seat per year**, and that automated detection commands a premium. At the same time, the most popular local PDF tools are free and have enormous reach (Stirling PDF: 94,744 GitHub stars and 10M+ Docker pulls; OCRmyPDF: 1.08M PyPI downloads in a month and 35,127 stars; qpdf: 5,510 stars; PDF Arranger: 5,991 stars — all fetched in 2026). ([Stirling](https://github.com/Stirling-Tools/Stirling-PDF), [OCRmyPDF stats](https://pypistats.org/packages/ocrmypdf), [qpdf](https://github.com/qpdf/qpdf), [PDF Arranger](https://github.com/pdfarranger/pdfarranger))

**The gap is the middle**: a free/inexpensive local tool with the *workflow* of a commercial redactor — find, review, remove, verify — and the *distribution* of a CLI. Scour does not need to beat Acrobat at editing. It needs to be the thing a professional reaches for when the job is "make this safe and prove it".

### What users complain about

1. "I drew a black box — is it really gone?" The distinction between annotation and removal is still not obvious. ([Stirling discussion](https://github.com/Stirling-Tools/Stirling-PDF/discussions/637))
2. Metadata is a separate, confusing step. Nitro's own documentation says its redaction does not strip metadata; qpdf users have requested a one-step cleanup. ([Nitro guide](https://www.gonitro.com/user-guide/pro/article/redaction-in-a-pdf-file), [qpdf issue](https://github.com/qpdf/qpdf/issues/1145))
3. Applying redactions can hang or fail, with little feedback. ([Adobe community report](https://community.adobe.com/questions-9/acrobat-hangs-on-applying-redaction-1281151) — anecdote, not prevalence)
4. Automation still needs review. OCR and auto-detection miss things; vendors tell users to verify manually. ([Nitro Smart Redact guide](https://www.gonitro.com/user-guide/workspace/smart-redact))
5. Rasterization costs searchability and file size. ([CoverUP](https://github.com/digidigital/CoverUP), [Stirling issue](https://github.com/Stirling-Tools/Stirling-PDF/issues/4462))
6. Subscription fatigue. A three-year Acrobat licence and lower-priced alternatives are explicit purchase contrasts. ([Adobe compare](https://www.adobe.com/acrobat/pricing/compare-versions.html))

Scour's answers map one-to-one: structural removal, metadata included by default, fast deterministic runs, verification built in, text stays text, MIT licence.

---

## 5. Positioning

> **For anyone about to send a PDF outside their organisation, Scour is the offline inspector and scrubber that removes what the page does not show — and proves it. Unlike Acrobat, Foxit or cloud redaction services, Scour is a single dependency-free binary with no account, no upload and a verification command you can put in CI.**

Supporting messages:

- **Proof, not promises.** "Verified" means the output was reopened and re-extracted.
- **Local by construction.** No network code exists in the binary; it is not a setting.
- **Fast enough to use twice.** Inspect before, verify after; a 1,000-page document takes about two seconds.
- **A report a non-expert can read.** Findings explain *why* the thing matters, not just that a regex matched.
- **Free and auditable.** MIT, no telemetry, reproducible test fixtures.

Category: **document privacy / redaction**. Do not position as a general PDF editor; that is a crowded, feature-driven comparison Scour would lose. Position as the **pre-flight check for documents**, adjacent to security scanners and DLP, not adjacent to Canva.

---

## 6. Market sizing (scenario model, not a forecast)

There is no reliable public estimate for "PDF redaction" as a category. The honest approach is a transparent scenario model with explicit assumptions.

**Demand base**: 400 billion Acrobat PDF opens/year (Adobe, 2022). This is a usage figure, not unique documents or unique users.

| Assumption | Conservative | Base | Aggressive |
|---|---:|---:|---:|
| Opens that involve preparing a document for external sharing | 0.1% | 0.5% | 2% |
| Share where redaction/sanitization is considered | 5% | 10% | 20% |
| Implied redaction events per year | 2M | 20M | 160M |
| Share willing to use a dedicated tool (vs. suite/manual) | 2% | 5% | 10% |
| Tool sessions per year | 40k | 1M | 16M |
| Revenue per session (support/licence equivalent) | $5 | $5 | $10 |
| **Implied annual value** | **$0.2M** | **$5M** | **$160M** |

The model is intentionally rough. It says the category is plausibly a **$5M–$50M** niche today, with upside if verification becomes a procurement requirement. That is large enough for a focused open-source product with commercial support, and too small to justify another full PDF editor. That asymmetry is the strategic point.

**Bottom-up sanity check**: a 12-person law firm doing 20 redactions/week is ~10,000/year. At $200/seat/year for two seats, that is $400/year per firm. Ten thousand such firms would be $4M/year. The base scenario is consistent with reaching a few thousand paying teams, not with a venture-scale standalone company. Plan accordingly: lean, open source, support-led.

**Adjacent expansion**: the same engine powers metadata cleanup, attachment stripping, batch pre-flight, page extraction and merge. The buyer is the same; the budget line is "document hygiene", not "redaction".

---

## 7. Business model and sustainability

The repository is MIT and the core stays free. A privacy tool that gates verification behind a paywall would undermine its own thesis.

Plausible revenue, in order of fit:

1. **Support and SLAs** for legal, government and healthcare teams: $2k–$10k/year, including a named contact and response targets.
2. **Signed, reproducible release binaries** and an SBOM/attestation package for procurement. Free source remains; the convenience and compliance artifacts are paid.
3. **Policy packs and training**: detector configuration for a jurisdiction, a review checklist, a workshop for a legal ops team.
4. **Custom detectors / integrations**: a DMS connector, a batch pre-flight service, a CI plugin.
5. **Grants and sponsorship**: NLnet, Sovereign Tech Fund, Open Technology Fund, GitHub Sponsors. Document privacy is a plausible public-interest fit.
6. **Hosted verification (later, optional)**: never upload the document; upload only hashes and a signed verification receipt. Only if customers ask.

Explicitly rejected: advertising, telemetry, selling anonymised document statistics, a mandatory cloud account, or an "AI redaction" tier that uploads pages.

---

## 8. Go-to-market

### Launch sequence (first 30 days)

**Week 0 — make it installable**

- Tag `v1.0.0`; publish source zip and checksums.
- Homebrew formula, AUR package, Nix flake, static Linux/macOS binaries.
- A 60-second demo: inspect a leaky PDF, scrub, verify; no narration needed.
- `docs/VERIFICATION.md` with reproducible external checks.

**Week 1 — developer launch**

- Show HN: *"Show HN: Scour – an offline PDF redactor that proves the text is gone"*.
- r/commandline, r/coolgithubprojects, r/privacy, r/cybersecurity (follow each community's self-promotion rules).
- Lobsters, Hacker News, `awesome-privacy`, `awesome-cpp`, `awesome-cli-apps` PRs.
- Post the benchmark methodology, not just the number.

**Week 2 — professional launch**

- LinkedIn article for legal ops, HR and compliance: "Your redaction is a suggestion. Here is how to verify it."
- Law-firm knowledge-management newsletters; ILTA community; privacy officers' groups.
- Pitch to privacy/security press with the 2021 and 2022 studies as the news hook, not the product.

**Week 3 — trust**

- Publish a threat model and a "what Scour cannot do" page.
- Offer a public sample report for a known leaky file.
- Invite independent review; publish a security contact and a 90-day disclosure policy.

**Week 4 — iterate**

- Ship the top three requests from issues.
- Publish a short "what we learned" post with adoption numbers and failure cases.

### Channels and message fit

| Channel | Audience | Message |
|---|---|---|
| Hacker News / Lobsters | engineers, founders | single binary, no deps, benchmark, deterministic output |
| r/privacy, Privacy Guides | privacy advocates | no network code, no telemetry, local by construction |
| LinkedIn | legal, HR, compliance | "verify before you send"; remediation cost; audit artifact |
| X / Bluesky / Mastodon | infosec, journalism | visual before/after; "the black box is not the redaction" |
| YouTube / short video | general professionals | 45-second screen recording of inspect → scrub → verify |
| Law-firm newsletters | partners, KM | matter-file proof, no client data leaves the machine |
| Package managers | developers | one-command install; `brew install scour` |

### Publicity angles

1. **"The redaction is a suggestion."** Lead with the TSA/Manafort pattern and the 65% study. Demonstrate a black box being lifted in a viewer, then show Scour finding the text.
2. **"We tested the tools."** A reproducible harness (pikepdf/pypdf + Scour) that checks whether a redaction survived. Invite journalists to run it on their own files. This is a story with a built-in demo.
3. **"A privacy tool with no network code."** Show `ldd`, show the absence of sockets, publish the dependency list (the C++ runtime). Privacy editors love a verifiable claim.
4. **"1,000 pages in two seconds."** Performance is a trust signal: people skip verification when it is slow. Show the benchmark and the methodology.
5. **"The PDF is a database."** Explainer on hidden text, XMP, incremental updates and attachments; useful, shareable, and it makes the product obvious.

### Social calendar (two weeks, copy-ready)

| Day | Platform | Post |
|---|---|---|
| 1 | X / LinkedIn | "A black box is a drawing. The text underneath is still there. Scour finds it, removes it, and reopens the file to prove it's gone. MIT, single binary, no upload." + dashboard image |
| 2 | Mastodon / Bluesky | Short thread: four ways PDFs hide text (invisible render mode, white on white, clipped, painted over) with a screenshot of each finding. |
| 3 | LinkedIn | "What a redaction failure costs": Citi 150k consumers, 85 jurisdictions, credit monitoring and an audit. Link to the DOJ release, then the tool. |
| 4 | X | 20-second video: `scour inspect` → `scour scrub` → `scour verify`, terminal only. Caption: "No account. No upload. No network code." |
| 5 | Reddit / HN | Launch post with benchmark table and a link to the threat model. Respond to criticism with measurements, not adjectives. |
| 6 | LinkedIn | Carousel (images, not HTML): "Before you send the PDF" — 5 checks: metadata, comments, attachments, previous revisions, hidden text. |
| 7 | X | "We ran Scour on a 1,000-page report: 1.9 ms to open, 169 ms to extract, 0.68 s to scrub and verify. Verification is fast enough to do every time." |
| 8 | Mastodon | "The tool is MIT. The fixtures are hand-written. The test suite has 118 cases. Here's how to run it." Link to CONTRIBUTING. |
| 9 | LinkedIn | Persona story: an HR team, an offer letter, a comment thread that should not have shipped. No product screenshot until the end. |
| 10 | X / Bluesky | "Your PDF has a revision history. Scour drops it." Side-by-side `scour text` before/after on `revisions.pdf`. |
| 11 | Reddit r/commandline | "Scour: a PDF inspector/scrubber in one C++ binary (no deps)" — focus on the TUI and exit codes. |
| 12 | LinkedIn | "What Scour does not do": scans, OCR, signatures, malware. Trust is built by limits. Link to THREAT-MODEL. |
| 13 | X | User quote / issue highlight: a real workflow improved. Ask permission first. |
| 14 | All | "v1.0.1: fixes from launch week" — show responsiveness. |

Hashtags: use sparingly and only where native (`#PDF`, `#privacy`, `#infosec`, `#opensource`, `#legaltech`). Avoid hashtag soup on LinkedIn.

### Success metrics

- **Activation**: install → first `inspect` within 10 minutes (measured by docs feedback, not telemetry).
- **Proof usage**: ratio of `scrub` runs followed by `verify` or built-in verification (CLI output is local; measure via survey and issue reports, not tracking).
- **Distribution**: package-manager inclusion, release downloads, GitHub stars (vanity, but useful for social proof).
- **Quality**: escaped-defect rate, external verification pass rate, time to fix a false negative.
- **Commercial**: support conversations, pilot teams, renewal.

Do not add telemetry to measure these. Ask users, read issues, and publish what you learn.

---

## 9. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| False sense of security: a user treats "no findings" as a guarantee | Medium | High | Verification language, explicit limits, image-only warnings, "not a compliance certification" in the report footer |
| Missed PII (context-dependent identifiers, non-Latin scripts) | Medium | High | Detector coverage roadmap, custom terms, review workflow, external verification, never claim completeness |
| Font/encoding edge cases leave text | Medium | High | Conservative encoding handling, warnings, verification, fixture expansion, fuzzing |
| Incumbent bundles a "verify" button | Medium | Medium | Speed, offline guarantee, CLI/CI, open source, trust; stay focused on the workflow |
| Clone with a slicker UI | Medium | Medium | Community, test corpus, reproducible verification, integrations; MIT makes cloning legal but execution is the moat |
| Security vulnerability in the parser | Medium | High | ASan/UBSan, fuzzing, minimal attack surface, no network, coordinated disclosure, signed releases |
| Legal exposure from overclaiming | Low | Medium | Precise language, disclaimers, no "legally compliant" claim, publish methodology |
| Platform gap (Windows) | High | Medium | WSL2 documented now; native console backend on the roadmap; prioritize if enterprise pilots demand it |
| Maintainer burnout | Medium | High | Narrow scope, good docs, contributor guide, funded support only for what can be sustained |

---

## 10. Roadmap

**1.0 (this release)** — inspect, scrub, verify, TUI, text/split/merge/rotate, encryption, JSON, deterministic output, external verification.

**1.1** — native Windows console backend; batch input (`scour inspect folder/`); SARIF output for code scanning; a `--report` HTML-free PDF/Markdown summary; faster glyph removal.

**1.2** — optional OCR-assisted review (local Tesseract, never uploaded) that *flags* image regions rather than claiming to redact them; detector plugins; policy files.

**1.3** — signed verification receipts (hash + timestamp + tool version) for audit trails; reproducible-build attestations; package-manager presence.

**Later** — PDF/A-aware output, accessibility checks, DMS/CLI integrations, a hosted receipt verifier that never sees the document.

---

## 11. What would falsify this thesis

A senior team should write down what would change its mind.

- Professionals do not actually verify redactions, even when verification is free and fast — the purchase is driven by liability transfer, not tooling, and they buy the suite's audit log instead.
- Most redaction work happens inside a DMS or e-discovery platform where a CLI cannot enter, and buyers will not add a second tool.
- Acrobat/Foxit make verification automatic and trustworthy at no extra cost, collapsing the differentiation.
- The failure rate in the 2021/2022 studies is driven by a handful of pathological files, and ordinary office PDFs are mostly safe — in which case the wedge is narrower (regulated/high-stakes documents only).
- Windows support is non-negotiable for the buyer, and a POSIX-first tool cannot get piloted.

The response to each is measurable: run pilots, track whether `verify` is used, instrument nothing, and ask. The product should stay small enough to change direction.

---

## 12. Sources

- Adobe, *Celebrating 30 years of digital transformation with Adobe Acrobat* (2023). https://blog.adobe.com/en/publish/2023/06/15/celebrating-30-years-of-digital-transformation-with-adobe-acrobat
- Adhatarao & Lauradoux, *Leaky Files: Sanitization of PDFs in the Wild* (arXiv:2103.02707, 2021). https://arxiv.org/abs/2103.02707
- Bland, Iyer & Levchenko, *Story Beyond the Eye: Glyph Positions Break PDF Text Redaction* (arXiv:2206.02285, 2022). https://arxiv.org/html/2206.02285v3
- U.S. Department of Justice, *Citigroup settlement* (2013). https://www.justice.gov/archive/ust/press/docs/2013/pr20130715.htm
- BBC News, *Manafort court filing redaction failure* (2019). https://www.bbc.com/news/world-us-canada-46804127
- CBS News, *Unredacted TSA manual leaked online* (2009). https://www.cbsnews.com/news/unredacted-tsa-manual-leaked-online/
- European Commission, *GDPR principles*. https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/principles-gdpr_en
- GDPR Article 32. https://gdpr-info.eu/art-32-gdpr/ · Article 83. https://gdpr-info.eu/art-83-gdpr/
- California Attorney General, *CCPA*. https://oag.ca.gov/privacy/ccpa
- CPPA, *Inflation-adjusted thresholds*. https://cppa.ca.gov/regulations/cpi_adjustment.html
- 45 CFR §164.514. https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514
- FOIA.gov FAQ. https://www.foia.gov/faq.html
- FRCP 5.2. https://www.law.cornell.edu/rules/frcp/rule_5.2
- Adobe Acrobat plans. https://www.adobe.com/acrobat/plans.html
- Foxit PDF Editor review and pricing (PCWorld, 2025). https://www.pcworld.com/article/2163281/foxit-pdf-editor-review.html
- PDF Expert pricing. https://pdfexpert.com/pricing
- Redactable pricing. https://www.redactable.com/pricing
- Nitro redaction guide. https://www.gonitro.com/user-guide/pro/article/redaction-in-a-pdf-file
- Stirling PDF. https://github.com/Stirling-Tools/Stirling-PDF
- OCRmyPDF download statistics. https://pypistats.org/packages/ocrmypdf
- qpdf. https://github.com/qpdf/qpdf
- pdf-redact-tools. https://github.com/firstlookmedia/pdf-redact-tools
- JoshData/pdf-redactor limitations. https://github.com/JoshData/pdf-redactor
- `redact-pdf` (gaborcsapo). https://github.com/gaborcsapo/redact-pdf

*All web sources were accessed in October 2026. Prices change; verify at checkout.*

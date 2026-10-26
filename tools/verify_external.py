#!/usr/bin/env python3
"""Independent interoperability checks for Scour.

Scour has no PDF dependency: the reader and writer are its own. That is the
point, but it also means a round-trip through Scour's own code cannot prove that
other readers will accept the result. This script builds documents with
pikepdf and pypdf, runs the real `scour` binary against them, and then re-opens
Scour's output with both libraries.

Requirements: pikepdf, pypdf (see tools/requirements-external.txt).

    python3 tools/verify_external.py --scour build/scour

Every check is printed; the process exits non-zero if one fails.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pikepdf
from pypdf import PdfReader

PII = ["alice@example.com", "123-45-6789", "+1 415 555 0132"]
TERM = "PROJECT BLUEBIRD"


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"  ok    {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}" + (f"  ({detail})" if detail else ""))

    def summary(self) -> int:
        total = self.passed + self.failed
        print(f"\n{self.passed}/{total} external checks passed")
        return 1 if self.failed else 0


def run(scour: Path, *args: str, expect: int = 0) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [str(scour), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != expect:
        raise AssertionError(
            f"scour {' '.join(args)} exited {result.returncode}, expected {expect}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def make_pikepdf_source(path: Path, pages: int = 3) -> None:
    """A small but realistic document written by a different PDF engine."""
    pdf = pikepdf.new()
    for _ in range(pages):
        pdf.add_blank_page(page_size=(612, 792))
    font = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Font,
            Subtype=pikepdf.Name.Type1,
            BaseFont=pikepdf.Name.Helvetica,
            Encoding=pikepdf.Name.WinAnsiEncoding,
        )
    )
    for index, page in enumerate(pdf.pages):
        page.Resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font))
        text = (
            f"Page {index + 1}: Alice Example  alice@example.com  "
            "123-45-6789  +1 415 555 0132"
        )
        page.Contents = pdf.make_stream(
            f"BT /F1 14 Tf 72 720 Td ({text}) Tj ET".encode("ascii")
        )
    pdf.docinfo["/Author"] = "Alice Example"
    pdf.docinfo["/Title"] = "Pikepdf Brief"
    pdf.docinfo["/Creator"] = "pikepdf fixture"
    pdf.Root["/OpenAction"] = pdf.make_indirect(
        pikepdf.Dictionary(
            S=pikepdf.Name.JavaScript, JS=pikepdf.String("app.alert('scour');")
        )
    )
    annotation = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name.Annot,
            Subtype=pikepdf.Name.Text,
            Rect=[72, 600, 96, 624],
            Contents=pikepdf.String(f"Call +1 415 555 0132 ({TERM})"),
            T=pikepdf.String("Alice Example"),
        )
    )
    pdf.pages[0].Annots = pdf.make_indirect([annotation])
    spec = pikepdf.AttachedFileSpec(
        pdf,
        f"internal: {TERM}".encode("ascii"),
        filename="secret.txt",
        mime_type="text/plain",
    )
    pdf.attachments["secret.txt"] = spec
    # Object streams and Flate compression exercise paths that a hand-written
    # classic-xref fixture never reaches.
    pdf.save(
        path,
        object_stream_mode=pikepdf.ObjectStreamMode.generate,
        compress_streams=True,
    )


def make_pypdf_source(path: Path) -> None:
    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(2):
        writer.add_blank_page(width=612, height=792)
    writer.add_metadata(
        {
            "/Author": "Bob Example",
            "/Title": "Pypdf Memo",
            "/Producer": "pypdf fixture",
        }
    )
    with path.open("wb") as stream:
        writer.write(stream)


def pdf_text(path: Path) -> str:
    reader = PdfReader(str(path))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def check_output(checks: Checks, path: Path, targets: list[str]) -> None:
    with pikepdf.open(path) as pdf:
        checks.check("pikepdf parses Scour output", True)
        problems = pdf.check_pdf_syntax()
        checks.check("pikepdf sees no syntax problems", problems == [], repr(problems))
        checks.check("page count is preserved", len(pdf.pages) == 3, str(len(pdf.pages)))
        checks.check("document info is empty", len(dict(pdf.docinfo)) == 0, repr(dict(pdf.docinfo)))
        checks.check("XMP metadata is gone", "/Metadata" not in pdf.Root)
        checks.check("name trees are gone", "/Names" not in pdf.Root)
        checks.check("open actions are gone", "/OpenAction" not in pdf.Root)
        checks.check("form dictionary is gone", "/AcroForm" not in pdf.Root)
        checks.check("attachments are gone", len(pdf.attachments) == 0, repr(list(pdf.attachments)))
        checks.check(
            "annotations are gone",
            all("/Annots" not in page for page in pdf.pages),
        )
    text = pdf_text(path)
    for target in targets:
        checks.check(f"pypdf text no longer contains {target!r}", target not in text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scour", default="build/scour", type=Path)
    parser.add_argument("--keep", type=Path, help="write generated files here")
    args = parser.parse_args()

    scour = args.scour.resolve()
    if not scour.is_file():
        print(f"scour binary not found: {scour}", file=sys.stderr)
        return 2

    checks = Checks()
    print(f"pikepdf {pikepdf.__version__}, pypdf {PdfReader.__module__.split('.')[0]}")
    print(f"scour   {scour}")

    with tempfile.TemporaryDirectory(prefix="scour-ext-") as temporary:
        root = args.keep if args.keep else Path(temporary)
        root.mkdir(parents=True, exist_ok=True)

        # ------------------------------------------------------------------
        # 1. Read a document generated by pikepdf (xref + object streams).
        # ------------------------------------------------------------------
        print("\n[1] foreign writer -> inspect -> scrub -> foreign readers")
        source = root / "pikepdf-source.pdf"
        make_pikepdf_source(source)

        report = json.loads(
            run(scour, "inspect", str(source), "--json", expect=1).stdout
        )
        checks.check("inspect finds three pages", report["facts"]["pages"] == 3, str(report["facts"]["pages"]))
        checks.check("inspect reads the author", report["facts"]["author"] == "Alice Example")
        pii_score = next(
            (score for score in report["scores"] if score["category"] == "pii"), None
        )
        checks.check("inspect identifies PII", pii_score is not None and pii_score["points"] > 0)
        checks.check("inspect exits 1 above the risk threshold",
                     run(scour, "inspect", str(source), expect=1).returncode == 1)

        text = run(scour, "text", str(source)).stdout
        checks.check("text extraction reads a foreign content stream",
                     "alice@example.com" in text)

        cleaned = root / "pikepdf-clean.pdf"
        run(scour, "scrub", str(source), "-o", str(cleaned),
            "--pii", "--term", "Alice Example", "--term", TERM)
        check_output(checks, cleaned, PII + ["Alice Example", TERM])
        run(scour, "verify", str(cleaned), "--pii", "--term", "Alice Example",
            "--term", TERM)
        checks.check("scrub reports success and verifies", True)

        # Byte-identical output for the same input is what makes scrubbing
        # testable in CI.
        again = root / "pikepdf-clean-again.pdf"
        run(scour, "scrub", str(source), "-o", str(again),
            "--pii", "--term", "Alice Example", "--term", TERM)
        checks.check("scrubbing is deterministic",
                     cleaned.read_bytes() == again.read_bytes())

        # ------------------------------------------------------------------
        # 2. Password-protected source (AES-256, revision 6).
        # ------------------------------------------------------------------
        print("\n[2] AES-256 source with a user password")
        encrypted = root / "pikepdf-encrypted.pdf"
        with pikepdf.open(source) as pdf:
            pdf.save(
                encrypted,
                encryption=pikepdf.Encryption(owner="owner-pw", user="user-pw", R=6),
                object_stream_mode=pikepdf.ObjectStreamMode.generate,
            )
        blocked = run(scour, "inspect", str(encrypted), expect=3)
        checks.check("inspect without a password is an input error, not a clean report",
                     "password" in blocked.stderr.lower(), blocked.stderr.strip())
        report = json.loads(
            run(scour, "inspect", str(encrypted), "-p", "user-pw", "--json", expect=1).stdout
        )
        checks.check("AES-256 document opens with the user password",
                     report["facts"]["encrypted"] and report["facts"]["pages"] == 3)
        decrypted = root / "pikepdf-decrypted.pdf"
        run(scour, "scrub", str(encrypted), "-p", "user-pw", "-o", str(decrypted),
            "--pii", "--term", "Alice Example")
        with pikepdf.open(decrypted) as pdf:
            checks.check("scrubbed output no longer needs a password", True)
            checks.check("scrubbed output has no /Encrypt", "/Encrypt" not in pdf.trailer)
        check_output(checks, decrypted, PII + ["Alice Example"])

        # ------------------------------------------------------------------
        # 3. A document written by pypdf.
        # ------------------------------------------------------------------
        print("\n[3] pypdf writer")
        pypdf_source = root / "pypdf-source.pdf"
        make_pypdf_source(pypdf_source)
        report = json.loads(
            run(scour, "inspect", str(pypdf_source), "--json", expect=1).stdout
        )
        checks.check("inspect reads pypdf metadata", report["facts"]["author"] == "Bob Example")
        pypdf_clean = root / "pypdf-clean.pdf"
        run(scour, "scrub", str(pypdf_source), "-o", str(pypdf_clean))
        with pikepdf.open(pypdf_clean) as pdf:
            checks.check("pypdf document round-trips through Scour",
                         len(pdf.pages) == 2 and len(dict(pdf.docinfo)) == 0)
            checks.check("pypdf output has a valid syntax", pdf.check_pdf_syntax() == [])

    return checks.summary()


if __name__ == "__main__":
    raise SystemExit(main())

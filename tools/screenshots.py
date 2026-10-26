#!/usr/bin/env python3
# Scour — offline document inspector and scrubber.
# Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
"""Render the documentation screenshots from the shipping dashboard.

`scour tui --dump` prints a real frame: the same cell grid the live TUI draws,
already clipped, wrapped and truncated by the product code. This script only
turns that frame into a PNG, so a screenshot can never disagree with the binary.

It needs Pillow and a monospaced TrueType font. The font is not part of the
repository: pass --font, or set SCOUR_SCREENSHOT_FONT, or install one of the
common system paths checked below.

    python3 tools/screenshots.py --font /path/to/JetBrainsMono-Regular.ttf
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - dependency hint, not a code path
    sys.exit("scour: screenshots.py needs Pillow (pip install pillow)")

CSI = re.compile("\x1b\\[([0-9;?]*)([A-Za-z])")
FRAMES = [
    ("dashboard.png", ""),
    ("help.png", "?"),
    ("palette.png", "p"),
]
COMMON_FONTS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/jetbrains-mono/JetBrainsMono-Regular.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/Library/Fonts/JetBrainsMono-Regular.ttf",
    "C:/Windows/Fonts/consola.ttf",
]


def find_font(explicit: str | None) -> Path:
    candidate = explicit or os.environ.get("SCOUR_SCREENSHOT_FONT")
    if candidate:
        path = Path(candidate)
        if not path.is_file():
            sys.exit(f"scour: no font at {path}")
        return path
    for name in COMMON_FONTS:
        if Path(name).is_file():
            return Path(name)
    sys.exit(
        "scour: screenshots need a monospaced TTF; pass --font or set "
        "SCOUR_SCREENSHOT_FONT"
    )


def parse_frame(frame: str) -> tuple[dict[tuple[int, int], tuple[str, str, str, bool]], int, int, str]:
    """Turns an ANSI frame into {(row, col): (glyph, fg, bg, bold)}."""
    cells: dict[tuple[int, int], tuple[str, str, str, bool]] = {}
    fg = "#D6DEEB"
    bg = "#0D1017"
    bold = False
    row = 0
    col = 0
    rows = 1
    cols = 1
    index = 0
    while index < len(frame):
        if frame[index] == "\x1b":
            match = CSI.match(frame, index)
            if not match:
                index += 1
                continue
            params, final = match.group(1), match.group(2)
            index = match.end()
            values = [int(value) if value else 0 for value in params.split(";")] if params else [0]
            if final == "H":
                row = max(0, values[0] - 1)
                col = max(0, (values[1] if len(values) > 1 else 1) - 1)
            elif final == "m":
                position = 0
                while position < len(values):
                    code = values[position]
                    if code == 0:
                        bold = False
                        fg, bg = "#D6DEEB", "#0D1017"
                    elif code == 1:
                        bold = True
                    elif code == 22:
                        bold = False
                    elif code == 38 and values[position + 1 : position + 2] == [2]:
                        fg = "#%02X%02X%02X" % tuple(values[position + 2 : position + 5])
                        position += 4
                    elif code == 48 and values[position + 1 : position + 2] == [2]:
                        bg = "#%02X%02X%02X" % tuple(values[position + 2 : position + 5])
                        position += 4
                    position += 1
            continue
        glyph = frame[index]
        index += 1
        if glyph in "\n\r":
            continue
        width = 2 if unicodedata.east_asian_width(glyph) in ("W", "F") else 1
        if unicodedata.combining(glyph):
            continue
        cells[(row, col)] = (glyph, fg, bg, bold)
        rows = max(rows, row + 1)
        cols = max(cols, col + width)
        col += width
    return cells, rows, cols, bg_of(cells)


def bg_of(cells: dict[tuple[int, int], tuple[str, str, str, bool]]) -> str:
    return cells.get((0, 0), (" ", "#D6DEEB", "#0D1017", False))[2]


def render(
    cells: dict[tuple[int, int], tuple[str, str, str, bool]],
    rows: int,
    cols: int,
    background: str,
    regular: Path,
    bold_path: Path | None,
    size: int,
    padding: int,
) -> Image.Image:
    font = ImageFont.truetype(str(regular), size)
    bold_font = ImageFont.truetype(str(bold_path), size) if bold_path and bold_path.is_file() else font
    cell_w = round(font.getlength("M"))
    cell_h = round(size * 1.6)
    baseline = round(size * 1.22)
    image = Image.new(
        "RGB",
        (cols * cell_w + padding * 2, rows * cell_h + padding * 2),
        background,
    )
    draw = ImageDraw.Draw(image)
    for (row, col), (glyph, fg, bg, bold) in cells.items():
        x = padding + col * cell_w
        y = padding + row * cell_h
        draw.rectangle([x, y, x + cell_w - 1, y + cell_h - 1], fill=bg)
        if glyph != " ":
            draw.text(
                (x, y + baseline),
                glyph,
                font=bold_font if bold else font,
                fill=fg,
                anchor="ls",
            )
    return image


def dump(binary: Path, document: Path, keys: str, width: int, height: int) -> str:
    command = [
        str(binary),
        "tui",
        str(document),
        "--dump",
        f"{width}x{height}",
        "--ansi",
    ]
    if keys:
        command += ["--keys", keys]
    result = subprocess.run(command, capture_output=True, check=False)
    if result.returncode != 0:
        sys.exit(
            f"scour: {' '.join(command)} failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout.decode("utf-8", "replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="build/scour", help="path to the scour executable")
    parser.add_argument(
        "--document",
        default="fixtures/contract-leak.pdf",
        help="PDF to render; the default is the sample leaky contract",
    )
    parser.add_argument("--font", help="monospaced TTF to draw with")
    parser.add_argument("--bold-font", help="bold TTF; defaults to Regular")
    parser.add_argument("--size", type=int, default=20, help="font size in pixels")
    parser.add_argument("--padding", type=int, default=16, help="image padding in pixels")
    parser.add_argument("--width", type=int, default=108, help="frame width in cells")
    parser.add_argument("--height", type=int, default=34, help="frame height in cells")
    parser.add_argument("--out", default="docs/assets", help="output directory")
    args = parser.parse_args()

    binary = Path(args.binary)
    document = Path(args.document)
    if not binary.is_file():
        sys.exit(f"scour: no executable at {binary}; build first")
    if not document.is_file():
        sys.exit(f"scour: no document at {document}; run build/scour_fixtures fixtures")
    regular = find_font(args.font)
    bold = Path(args.bold_font) if args.bold_font else regular.with_name(
        regular.name.replace("Regular", "Bold")
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    for name, keys in FRAMES:
        frame = dump(binary, document, keys, args.width, args.height)
        cells, rows, cols, background = parse_frame(frame)
        image = render(cells, rows, cols, background, regular, bold, args.size, args.padding)
        target = out / name
        image.save(target)
        print(f"wrote {target} ({image.width}x{image.height})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

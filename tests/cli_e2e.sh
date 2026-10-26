#!/usr/bin/env bash
# Scour — end-to-end tests.
# Copyright (c) 2026 The Scour Authors. MIT licensed; see LICENSE.
#
# These tests drive the shipped binary the way a user does: files on disk, exit
# codes, a terminal frame. The unit suite proves the algorithms; this proves the
# product.
set -uo pipefail

SCOUR="${1:-build/scour}"
FIXTURES="${2:-build/scour_fixtures}"
WORK="${3:-build/e2e}"

mkdir -p "$WORK"
"$FIXTURES" "$WORK" >/dev/null || {
    echo "FAIL: could not generate fixtures" >&2
    exit 1
}

failures=0
check() {
    if ! "$@"; then
        echo "FAIL: $*" >&2
        failures=$((failures + 1))
    fi
}

contains() {
    local file="$1" needle="$2" label="$3"
    if ! grep -qF -- "$needle" "$file"; then
        echo "FAIL: $label: expected to find '$needle'" >&2
        failures=$((failures + 1))
    fi
}

missing() {
    local file="$1" needle="$2" label="$3"
    if grep -qF -- "$needle" "$file"; then
        echo "FAIL: $label: did not expect '$needle'" >&2
        failures=$((failures + 1))
    fi
}

expect_status() {
    local want="$1" label="$2" output="$3"
    shift 3
    "$@" >"$output" 2>&1
    local got=$?
    if [ "$got" -ne "$want" ]; then
        echo "FAIL: $label: expected exit $want, got $got" >&2
        sed -n '1,20p' "$output" >&2
        failures=$((failures + 1))
    fi
}

# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------
expect_status 1 "inspect finds leaks" "$WORK/inspect.txt" \
    "$SCOUR" inspect "$WORK/contract-leak.pdf"
contains "$WORK/inspect.txt" "RISK" "inspect report"
contains "$WORK/inspect.txt" "EMBEDDED" "inspect report"
contains "$WORK/inspect.txt" "Alice Example" "inspect report"

expect_status 0 "inspect clean file" "$WORK/inspect-clean.txt" \
    "$SCOUR" inspect "$WORK/clean-memo.pdf"
contains "$WORK/inspect-clean.txt" "clean" "clean report"

expect_status 1 "inspect json" "$WORK/report.json" \
    "$SCOUR" inspect "$WORK/contract-leak.pdf" --json
contains "$WORK/report.json" '"tool": "scour"' "json report"
contains "$WORK/report.json" '"findings"' "json report"
python3 - "$WORK/report.json" <<'EOF'
import json, sys
with open(sys.argv[1]) as handle:
    data = json.load(handle)
assert data["risk"] >= 55, data["risk"]
assert data["facts"]["pages"] == 3
assert any(item["id"] == "actions.javascript" for item in data["findings"])
EOF
if [ $? -ne 0 ]; then
    echo "FAIL: json report is not valid JSON" >&2
    failures=$((failures + 1))
fi

# ---------------------------------------------------------------------------
# scrub + verify
# ---------------------------------------------------------------------------
expect_status 0 "scrub" "$WORK/scrub.txt" \
    "$SCOUR" scrub "$WORK/contract-leak.pdf" -o "$WORK/scrubbed.pdf" \
    --term "PROJECT BLUEBIRD" --pii
contains "$WORK/scrub.txt" "verified" "scrub report"

expect_status 0 "verify scrubbed" "$WORK/verify.txt" \
    "$SCOUR" verify "$WORK/scrubbed.pdf" --term "PROJECT BLUEBIRD" --pii
contains "$WORK/verify.txt" "CLEAN" "verify report"

expect_status 0 "inspect scrubbed" "$WORK/inspect-scrubbed.txt" \
    "$SCOUR" inspect "$WORK/scrubbed.pdf"
contains "$WORK/inspect-scrubbed.txt" "0/100" "scrubbed risk"
missing "$WORK/inspect-scrubbed.txt" "EMBEDDED" "scrubbed metadata"

"$SCOUR" text "$WORK/scrubbed.pdf" >"$WORK/scrubbed.txt" 2>&1
missing "$WORK/scrubbed.txt" "PROJECT BLUEBIRD" "scrubbed text"
contains "$WORK/scrubbed.txt" "Scour fixture - page 1" "scrubbed text"

# Deterministic output: the same input and options produce the same bytes.
"$SCOUR" scrub "$WORK/contract-leak.pdf" -o "$WORK/again.pdf" \
    --term "PROJECT BLUEBIRD" --pii >/dev/null 2>&1
if ! cmp -s "$WORK/scrubbed.pdf" "$WORK/again.pdf"; then
    echo "FAIL: scrubbing the same document twice produced different bytes" >&2
    failures=$((failures + 1))
fi

# A painted cover is not a redaction: verify must fail on a file that only hides
# its text under a rectangle.
expect_status 1 "verify catches painted-over text" "$WORK/verify-hidden.txt" \
    "$SCOUR" verify "$WORK/contract-leak.pdf" --term "PROJECT BLUEBIRD"
contains "$WORK/verify-hidden.txt" "NOT CLEAN" "verify catches leaks"

# ---------------------------------------------------------------------------
# page operations
# ---------------------------------------------------------------------------
expect_status 0 "split" "$WORK/split.txt" \
    "$SCOUR" split "$WORK/contract-leak.pdf" --pages 1 -o "$WORK/page1.pdf"
expect_status 0 "inspect split" "$WORK/split-inspect.txt" \
    "$SCOUR" inspect "$WORK/page1.pdf" --fail-on 100
contains "$WORK/split-inspect.txt" "Pages       1" "split page count"

expect_status 0 "merge" "$WORK/merge.txt" \
    "$SCOUR" merge -o "$WORK/merged.pdf" "$WORK/page1.pdf" "$WORK/clean-memo.pdf"
expect_status 0 "inspect merged" "$WORK/merge-inspect.txt" \
    "$SCOUR" inspect "$WORK/merged.pdf" --fail-on 100
contains "$WORK/merge-inspect.txt" "Pages       2" "merged page count"

expect_status 0 "rotate" "$WORK/rotate.txt" \
    "$SCOUR" rotate "$WORK/merged.pdf" --by 90 -o "$WORK/rotated.pdf"
expect_status 0 "inspect rotated" "$WORK/rotate-inspect.txt" \
    "$SCOUR" inspect "$WORK/rotated.pdf" --fail-on 100
contains "$WORK/rotate-inspect.txt" "Pages       2" "rotated page count"

# ---------------------------------------------------------------------------
# text
# ---------------------------------------------------------------------------
"$SCOUR" text "$WORK/clean-memo.pdf" >"$WORK/text.txt" 2>&1
contains "$WORK/text.txt" "Logistics memo" "text extraction"

expect_status 0 "text single page" "$WORK/text-page.txt" \
    "$SCOUR" text "$WORK/contract-leak.pdf" --page 2
contains "$WORK/text-page.txt" "SSN:" "text page selection"

expect_status 0 "no-color is accepted globally" "$WORK/no-color.txt" \
    "$SCOUR" inspect "$WORK/clean-memo.pdf" --no-color

# ---------------------------------------------------------------------------
# exit codes
# ---------------------------------------------------------------------------
expect_status 2 "unknown command" "$WORK/usage.txt" "$SCOUR" nonsense
expect_status 2 "missing argument" "$WORK/usage2.txt" "$SCOUR" inspect
expect_status 3 "missing file" "$WORK/missing.txt" "$SCOUR" inspect "$WORK/nope.pdf"

# ---------------------------------------------------------------------------
# TUI frames
# ---------------------------------------------------------------------------
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 >"$WORK/frame.txt" 2>&1
contains "$WORK/frame.txt" "SCOUR" "tui header"
contains "$WORK/frame.txt" "FINDINGS" "tui list"
contains "$WORK/frame.txt" "NAVIGATE" "tui sidebar"
contains "$WORK/frame.txt" "DETAIL" "tui detail"

"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --keys '?' >"$WORK/help.txt" 2>&1
contains "$WORK/help.txt" "KEYBOARD" "tui help"

"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --keys 'p' >"$WORK/palette.txt" 2>&1
contains "$WORK/palette.txt" "ACTIONS" "tui palette"
contains "$WORK/palette.txt" "Scrub hidden data" "tui palette entries"

"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --keys '/zzznotfound' >"$WORK/filter.txt" 2>&1
contains "$WORK/filter.txt" "FILTER" "tui filter"

"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --keys 'jjj' >"$WORK/moved.txt" 2>&1
if cmp -s "$WORK/frame.txt" "$WORK/moved.txt"; then
    echo "FAIL: moving the selection did not change the frame" >&2
    failures=$((failures + 1))
fi

# Below the minimum the dashboard explains itself instead of drawing a frame
# whose panels have collapsed into each other.
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 40x10 >"$WORK/tiny.txt" 2>&1
contains "$WORK/tiny.txt" "WINDOW TOO SMALL" "tui minimum size message"
contains "$WORK/tiny.txt" "terminal is 40" "tui reports its terminal size"
missing "$WORK/tiny.txt" "FINDINGS" "tui does not draw a broken frame"

# --no-color and NO_COLOR drop SGR colour but keep the frame, and `m` toggles
# the same mode at runtime. The default frame is still coloured.
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --ansi --no-color >"$WORK/mono.txt" 2>&1
missing "$WORK/mono.txt" "38;2;" "--no-color drops colour"
contains "$WORK/mono.txt" "FINDINGS" "monochrome frame is complete"
NO_COLOR=1 "$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --ansi >"$WORK/mono-env.txt" 2>&1
missing "$WORK/mono-env.txt" "38;2;" "NO_COLOR drops colour"
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --ansi --keys 'm' >"$WORK/mono-key.txt" 2>&1
missing "$WORK/mono-key.txt" "38;2;" "m toggles monochrome"
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 108x34 --ansi >"$WORK/colour.txt" 2>&1
contains "$WORK/colour.txt" "38;2;" "colour is the default"

# The full-screen finding scrolls: a long body is reachable, and the footer
# says so instead of hiding the remainder.
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 64x18 --keys $'jj\n' >"$WORK/detail.txt" 2>&1
contains "$WORK/detail.txt" "FINDING" "tui detail overlay"
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 64x18 --keys $'jj\njjjjjj' >"$WORK/detail-scrolled.txt" 2>&1
if cmp -s "$WORK/detail.txt" "$WORK/detail-scrolled.txt"; then
    echo "FAIL: scrolling the detail overlay did not change the frame" >&2
    failures=$((failures + 1))
fi

# On a narrow terminal the key map is one scrollable column, not two truncated
# ones: the last binding must be reachable and the footer must show position.
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 64x18 --keys '?' >"$WORK/help-narrow.txt" 2>&1
contains "$WORK/help-narrow.txt" "1/8" "narrow help position"
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 64x18 --keys '?jjjjjjjj' >"$WORK/help-scrolled.txt" 2>&1
contains "$WORK/help-scrolled.txt" "quit" "narrow help reaches the last binding"

# At the minimum width the header keeps both ends of the file name rather than
# cutting the extension off.
"$SCOUR" tui "$WORK/contract-leak.pdf" --dump 64x18 >"$WORK/narrow.txt" 2>&1
contains "$WORK/narrow.txt" "…" "tui middle-truncated file name"

# A scrub from inside the dashboard writes a new file and re-inspects it.
cp "$WORK/contract-leak.pdf" "$WORK/dashboard.pdf"
"$SCOUR" tui "$WORK/dashboard.pdf" --dump 108x34 --keys 's' >"$WORK/scrub-frame.txt" 2>&1
if [ ! -f "$WORK/dashboard.scrubbed.pdf" ]; then
    echo "FAIL: dashboard scrub did not write an output file" >&2
    failures=$((failures + 1))
fi
expect_status 0 "inspect dashboard output" "$WORK/dashboard-inspect.txt" \
    "$SCOUR" inspect "$WORK/dashboard.scrubbed.pdf" --fail-on 100
missing "$WORK/dashboard-inspect.txt" "Alice Example" "dashboard scrub metadata"

if [ "$failures" -ne 0 ]; then
    echo "$failures end-to-end check(s) failed" >&2
    exit 1
fi
echo "cli e2e: all checks passed"

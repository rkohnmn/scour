---
design.version: 1
appearance: "terminal, truecolor, two themes (midnight default, paper)"

color.midnight.background: "#0D1017"
color.midnight.panel: "#141924"
color.midnight.panel_alt: "#1A202D"
color.midnight.border: "#2D3748"
color.midnight.border_strong: "#465670"
color.midnight.text: "#D6DEEB"
color.midnight.text_dim: "#96A2B8"
color.midnight.text_faint: "#788399"
color.midnight.accent: "#7AA2F7"
color.midnight.accent_soft: "#384C76"
color.midnight.ok: "#68D391"
color.midnight.warn: "#E5C07B"
color.midnight.danger: "#F58B7A"
color.midnight.critical: "#FF6384"
color.midnight.selection: "#2A364E"
color.midnight.selection_text: "#ECF2FF"

color.paper.background: "#F6F4EF"
color.paper.panel: "#FFFFFC"
color.paper.panel_alt: "#EEEBE3"
color.paper.border: "#D0CABE"
color.paper.border_strong: "#AAA294"
color.paper.text: "#282826"
color.paper.text_dim: "#545048"
color.paper.text_faint: "#746E62"
color.paper.accent: "#2458A8"
color.paper.accent_soft: "#BECDE6"
color.paper.ok: "#267A4A"
color.paper.warn: "#8C6004"
color.paper.danger: "#B23A2E"
color.paper.critical: "#A01E3C"
color.paper.selection: "#DEE6F4"
color.paper.selection_text: "#141E30"

type.body.family: "the terminal's monospace face"
type.body.size: "1 cell"
type.body.weight: 400
type.label.weight: 700
type.meta.weight: 400

spacing.unit: "1 cell"
spacing.gap: "2 cells"
spacing.panel_padding: "2–3 cells"

size.min_width: 64
size.min_height: 18
size.header_height: 3
size.footer_height: 2
size.sidebar_min: 26
size.sidebar_max: 30
size.detail_min: 38
size.detail_max: 52

radius.panel: "1 cell (rounded corner glyphs)"
radius.control: "0 cells (square keycaps)"

border.subtle: "panel outlines, inactive edges"
border.strong: "focused panels and modals"
elevation.shadow: "1 cell offset behind modals"
elevation.scrim: 0.24

motion.policy: "none — no animation, no spinners, no transitions"
motion.timing: "0 ms"

accessibility.text_contrast: "4.5:1 minimum, measured below"
accessibility.focus_marker: "▌ marker, bold weight, selection fill"
accessibility.color_independence: "words, glyphs and weight carry meaning; hue never does alone"
accessibility.color_off: "--no-color, NO_COLOR, or m inside the dashboard"
---

## Overview

Scour is a document instrument, not a dashboard product. The dashboard exists so
a person can see what a PDF still says about them and remove it without leaving
the terminal; it should read like a well-made analyser: quiet surfaces, one
accent, dense rows, exact numbers, no decoration that competes with evidence.

The visual direction is a **reading-room terminal**: the black-and-ink calm of a
long `less` session, the typographic discipline of a technical report, and the
one-glance score of a laboratory instrument. It is deliberately not a web
dashboard: there are no cards floating on a gradient, no drop shadows pretending
to be depth, and no icon set. Structure is drawn with box rules and alignment;
hierarchy is carried by weight and value, not by boxes within boxes.

Design consequences:

- Neutral, low-chroma surfaces for the workspace; the risk score is the only
  element allowed to shout, and it shouts in words as well as colour.
- Findings are rows, not cards. A row is two lines: severity, title, page; then
  the quoted evidence in a dimmer value.
- Every screen explains itself in a footer: keys first, prose second.
- The document is never hidden behind chrome. The findings list is the largest
  region at every supported size.

## Colors

Colour has roles, not names. Both themes define the same sixteen roles; a
component asks for `text_dim` or `critical`, never for "grey" or "red".

| Role | Use |
| --- | --- |
| `background` | workspace behind panels |
| `panel` | panel interiors, modal surfaces, footer strip |
| `panel_alt` | keycaps and inset controls |
| `border` | panel outlines and separators |
| `border_strong` | the panel that owns focus, modal outlines |
| `text` | primary content: finding titles, values, headings |
| `text_dim` | evidence lines, descriptions, secondary labels |
| `text_faint` | page numbers, counts, hints, footer prose |
| `accent` | the one interactive colour: keybinding keys, selection marker, panel titles |
| `accent_soft` | low-emphasis accent fills |
| `ok` | clean state, low risk |
| `warn` | warnings, medium risk |
| `danger` | errors, high risk |
| `critical` | the risk score at its worst, error chips |
| `selection` | selected row fill |
| `selection_text` | text on the selected row |

Measured contrast (WCAG 2.1 relative luminance, computed from the values above):

| Pair | midnight | paper | Target |
| --- | --- | --- | --- |
| `text` on `background` | 14.05:1 | 13.44:1 | ≥ 4.5 |
| `text` on `panel` | 12.98:1 | 14.74:1 | ≥ 4.5 |
| `text_dim` on `background` | 7.39:1 | 7.30:1 | ≥ 4.5 |
| `text_dim` on `panel` | 6.83:1 | 8.01:1 | ≥ 4.5 |
| `text_faint` on `background` | 4.99:1 | 4.60:1 | ≥ 4.5 |
| `text_faint` on `panel` | 4.61:1 | 5.05:1 | ≥ 4.5 |
| `accent` on `background` | 7.56:1 | 6.29:1 | ≥ 4.5 |
| chip `ok` (background text on fill) | 10.25:1 | 4.82:1 | ≥ 4.5 |
| chip `warn` | 11.02:1 | 5.04:1 | ≥ 4.5 |
| chip `danger` | 8.03:1 | 5.40:1 | ≥ 4.5 |
| chip `critical` | 6.68:1 | 6.96:1 | ≥ 4.5 |
| `selection_text` on `selection` | 10.78:1 | 13.30:1 | ≥ 4.5 |
| `border` on `background` | 1.59:1 | 1.48:1 | decorative |
| `border_strong` on `background` | 2.56:1 | 2.30:1 | decorative |

Borders are decorative: regions are identified by position, panel titles and
spacing, so the panel outline is not the only way to perceive a boundary. That is
why the border roles are exempt from the 3:1 non-text target rather than being
silently claimed as compliant.

Rules:

- Never encode state in hue alone. Severity is spelled `ERROR`, `WARN`, `NOTE`,
  `TRACE`; the selected row carries a `▌` marker and bold weight; the risk score
  is a number followed by a word.
- One accent per screen. The accent marks interactive keys and the current
  selection, nothing else.
- `critical` is reserved for the score at its worst and for error chips. Using it
  for ordinary headings would make the one urgent thing look ordinary.
- In monochrome (`--no-color`, `NO_COLOR`, or `m`) all colour is dropped and the
  same information survives through words, glyphs and bold weight. No layout
  depends on a coloured fill to be legible.

## Typography

The grid is monospace by construction; there is no font family to choose and no
font size to set. Typography therefore means hierarchy inside fixed cells.

- **Body** — regular weight, `text` or `text_dim`, sentence case. Finding titles
  and values.
- **Label** — bold, uppercase, `accent`, used only for panel titles
  (`FINDINGS`, `DETAIL`, `KEYBOARD`, `ACTIONS`). Uppercase is a signal, so it is
  not used for sentences.
- **Meta** — regular, `text_faint`, used for page numbers, counts, hints and the
  footer prose. It must remain readable at 4.5:1, which is why `text_faint` was
  lightened in midnight and darkened in paper.
- **Keycap** — bold key name on `panel_alt`, one space of padding either side,
  followed by a regular-weight verb (`↑↓ move`).

Rules:

- One idea per line. The second line of a finding is always the evidence.
- Truncate with `…`, never with a bare cut; the full value is available in the
  detail pane and in the JSON report.
- Wrap at word boundaries; break long words only when a single word exceeds the
  panel.
- No proportional-font assumptions: a glyph is one or two cells, combining marks
  are zero, and the renderer measures with `display_width` rather than bytes.
- East Asian wide glyphs, emoji and combining marks are measured and drawn as
  their true width; a document cannot misalign the frame.

## Layout

The dashboard is three columns over a fixed header and footer, drawn on a cell
grid at every size:

```
┌ header (3 rows): mark, version, file, risk score ─────────────┐
│ NAVIGATE       │ FINDINGS                    │ DETAIL          │
│ categories     │ severity · title · page     │ evidence,       │
│ with counts    │ quoted evidence             │ location, id    │
├ footer (2 rows): keycaps, then state and provenance ──────────┤
```

- Header: 3 rows. The file name truncates from the middle; the risk score is
  right-aligned and never truncated.
- Sidebar: `clamp(width / 4, 26, 30)` cells, categories with counts, a dot per
  category coloured by worst severity (the count carries the same information).
- Findings: all remaining width. Two rows per finding. A scroll thumb appears
  only when the list overflows, plus an `n/total` counter in the title.
- Detail: shown at `width ≥ 104`, `clamp(width / 3, 38, 52)` cells. Below that the
  detail moves into a full-screen overlay opened with `enter`.
- Footer: 2 rows. The upper row is a rule; the lower row is keycaps followed by
  status (toast, source note). Hints are dropped from the right as width shrinks,
  never wrapped into a second line.
- Modals: help 94×16 max, palette 64×18, prompt 66×7, detail 90×30. Each is
  centred, dims the page to 0.24, and casts a one-cell shadow.
- **Minimum size: 64×18.** Below that the dashboard is replaced by a single
  `WINDOW TOO SMALL` panel that states the requirement, the current size, and how
  to get a report at any width. It never draws a collapsed frame, and a resize
  recovers without restarting.
- At 64×18 all keys remain available; the footer sheds hints but the help panel
  still lists every binding.

## Elevation & Depth

Depth is one bit, expressed in cells, not blur:

- **Shadow** — a single cell offset down and right behind modals, in
  `background`. It reads as a lifted sheet without pretending to be light.
- **Scrim** — the whole page behind a modal is multiplied by 0.24, not blurred and
  not hidden. Context stays visible; focus is unmistakable.
- **Border weight** — the focused panel or modal uses `border_strong`; everything
  else uses `border`. There are no drop shadows on panels, no stacked cards and no
  z-order beyond "page, then modal".

## Shapes

- Panels are rectangles with rounded corner glyphs (`╭ ╮ ╰ ╯`) and a one-cell
  radius. The title sits in the top border, prefixed by a one-cell rule.
- Rules are `─`; vertical separators are `│`; the scroll thumb is a `│` in
  `border_strong`; the selection marker is `▌`.
- Keycaps are square, filled with `panel_alt`, no radius. Chips are square,
  filled with the severity colour, with the severity word in bold.
- One shape family only: no circles, no pill buttons, no nested rounded boxes.
  A finding is a row, not a card inside a panel inside a panel.

## Components

Each component defines purpose, states, keyboard behaviour and sizing. All
components share the tokens above; none carries its own palette.

**Header / risk token.** Purpose: identify the file and its score. State: clean
(`ok`), elevated (`warn`), high (`danger`), critical (`critical`). Always shows
`RISK n /100` plus a word. Never colour-only. Height 3 rows.

**Category sidebar.** Purpose: filter by category. States: normal, hover-less
selection (`selection` fill, `▌` marker, bold), empty category (faint dot, count
absent). Keys: `↑↓` move within list, `←→`/`tab` change category, `g`/`G`/home/end
jump. Sizing: 26–30 cells. Empty categories remain visible so the shape of the
report is stable.

**Finding row.** Purpose: one finding, scannable in two lines. States: normal,
selected (`selection` fill, `▌`, bold, `selection_text`), filtered out (absent).
Line 1: severity chip, truncated title, page number. Line 2: evidence in quotes
or the detail. Height 2 rows. Keyboard: `enter` opens detail.

**Detail column.** Purpose: the finding at a glance: severity, category, title,
detail, evidence, location and id. It is abbreviated to the column height rather
than wrapped indefinitely. States: populated, empty ("Select a finding to see the
evidence."). `enter` opens the full-screen version; below 104 columns that is the
only way to see the evidence.

**Finding overlay.** Purpose: the full finding without losing the end of a long
body. Size 90×30 max, scrolls the whole block with `↑↓`, `j`/`k`, `pgup`/`pgdn`,
`home`/`end`; the footer shows `↑↓ scroll n/m` only when content exceeds the
panel, so a short finding has no dead hint. Dismissed with `esc`, `enter`, `?` or
`q`; no scroll position is kept between findings.

**Footer.** Purpose: teach the keys, then report state. States: idle, toast
(message for 6 s), busy. Shows at most the keycaps that fit; never wraps. Contains
no actions of its own; it is a legend, not a toolbar.

**Command palette.** Purpose: every action without memorising a key. Hints are
short by design (≤ 18 cells) and right-aligned, so the list reads as label plus
consequence. States: query empty (all actions), filtered (`No action matches`),
selected (`▌` + fill).
Keys: `↑↓` select, `enter` run, `esc` close, typing filters on label and hint.
Size: 64×18 max.

**Prompt.** Purpose: one line of text for a filter or a redaction term. Shows the
label, the input with a block cursor, and a hint. Keys: `enter` accept, `esc`
cancel, backspace edits. Height 7 rows.

**Help panel.** Purpose: the complete key map, never a half-written label. The key
column reserves 14 cells for the longest binding (`p  /  ctrl-p`). At 86 or more
cells of panel width it splits into two columns with a one-cell gutter; below
that it becomes a single column that scrolls (`↑↓`, `pgup`/`pgdn`, `home`/`end`)
with a `n/m` position in the footer. Clears the dashboard rather than covering
half of it, because a reference is read, not glanced at. Dismissed with `esc`,
`?`, `enter` or `q`.

**Toast.** Purpose: confirm an action ("monochrome on", "scrubbed 14 findings") or
report a failure. Lives in the footer for 6 seconds; the same information is
always also visible in the frame or in the JSON report, so a missed toast never
loses state.

**Empty states.** Each one states why the region is empty and what to do next:
clean file ("Nothing to report. This file is clean."), filtered-to-nothing ("No
finding matches this filter."), palette with no match ("No action matches that
query."), nothing selected ("Select a finding to see the evidence."), and the
too-small terminal (requirement, current size, fallback command). No empty state
is a blank panel.

**Error screen.** Purpose: a document that cannot be opened. Shows the path, the
error in plain words, and `q or enter quits`. Exit code 3. Never a stack trace and
never a silent failure.

**Accessibility contract.** Every component above is operable with the keyboard
alone; focus is always visible as `▌` plus a fill and bold weight, not colour
alone; nothing auto-advances or times out (the toast expires but no state depends
on it); `--no-color`, `NO_COLOR` and `m` remove colour without removing
information; there is no animation to disable; and the line-oriented commands
(`inspect`, `scrub`, `verify`, `text`) exist as the screen-reader-friendly path,
since a cell-addressed TUI cannot expose a meaningful accessibility tree.

## Do's and Don'ts

Do:

- Do keep the findings list the largest region at every supported size.
- Do state severity in words next to the colour.
- Do preserve the `▌` focus marker, keycaps and quoted evidence; they are the
  interface's grammar.
- Do measure contrast and width instead of trusting a screenshot.
- Do treat the 64×18 floor and the monochrome mode as first-class states with
  their own copy.
- Do keep the risk score, the finding count and the file name visible at once.
- Do prefer one accent and neutral surfaces; the document is the colour.

Don't:

- Don't add gradients, glows, blur or texture. The terminal has none of these and
  should not pretend to.
- Don't wrap findings in cards inside panels; a row is already a unit.
- Don't animate state changes, add spinners, or schedule automatic refreshes.
- Don't encode a state only in hue, and don't use `critical` decoratively.
- Don't truncate without `…`, and don't wrap footer hints onto a second line.
- Don't crop a panel until controls disappear; collapse the detail column first.
- Don't add a third theme: two themes with measured contrast beat four unverified
  ones.
- Don't invent numbers in the interface. A count, a score and a page number must
  come from the document, not from an empty-state placeholder.

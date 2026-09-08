#!/usr/bin/env python3
"""
Builds charra_attestation_walkthrough.pptx -- a focused 9-slide deck:

    1. Title
    2. System architecture
    3. The five steps -- who sends what (sequence diagram)
    4. What the Relying Party does with what it receives
    5. Redaction, before and after -- one real IMA log entry
    6. The three trust modes: qualify, tee, zk
    7. The /qualify action flow
    8. Measurements I -- where the time goes
    9. Measurements II -- what each mode costs, and ZK scaling

A third deck alongside the exhaustive 31-slide walkthrough
(build_privacy_slides.py) and the 6-slide talk deck
(build_privacy_aware_slides.py) -- this one exists to cover exactly the
sections asked for, no more: architecture, the RP's own actions and the
wire traffic around it, one redaction example, the three trust modes, the
/qualify flow, and measurements.

    pip install python-pptx
    python3 charra-ressources/build_attestation_walkthrough_slides.py

Every value is real output from a run or from charra_measurements_v2.md.
Diagram arrows are filled autoshapes, not line connectors: python-pptx has
no API for a connector's arrowhead, and one appended by hand to the XML
never reached the file in an earlier attempt, so every "arrow" rendered as
a bare line. Filled block-arrow shapes have no such gap.
"""

import math
import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

W, H = 13.333, 7.5
MARGIN = 0.60
BODY_W = W - 2 * MARGIN
TITLE_TOP, TITLE_H = 0.34, 0.70
BODY_BOTTOM = 7.00

INK    = RGBColor(0x16, 0x20, 0x2C)
ACCENT = RGBColor(0x1F, 0x5C, 0x8B)
RED    = RGBColor(0xA8, 0x35, 0x2A)
GREEN  = RGBColor(0x1B, 0x63, 0x40)
MUTED  = RGBColor(0x5A, 0x66, 0x72)
LIGHT  = RGBColor(0xF2, 0xF5, 0xF8)
RULE   = RGBColor(0xD5, 0xDD, 0xE4)
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)

SANS, MONO = "Calibri", "Consolas"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(W), Inches(H)
BLANK = prs.slide_layouts[6]
B = {"bold": True}


def fit(text, width_in, ideal, mono=False, floor=8):
    cw = 0.550 if mono else 0.480
    if not text:
        return ideal
    return max(floor, min(ideal, math.floor((width_in * 72.0) / (len(text) * cw) * 2) / 2))


def box(s, l, t, w, h):
    return s.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))


def para(tf, runs, size, first=False, align=PP_ALIGN.LEFT, space_after=6,
         line=1.16, font=SANS):
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.alignment = align
    p.space_after = Pt(space_after)
    p.line_spacing = line
    if isinstance(runs, str):
        runs = [(runs, {})]
    for text, o in runs:
        r = p.add_run()
        r.text = text
        r.font.size = Pt(o.get("size", size))
        r.font.bold = o.get("bold", False)
        r.font.name = o.get("font", font)
        r.font.color.rgb = o.get("color", INK)
    return p


def slide(title, kicker=None):
    s = prs.slides.add_slide(BLANK)
    tb = box(s, MARGIN, TITLE_TOP, BODY_W, TITLE_H)
    tf = tb.text_frame
    tf.word_wrap = True
    for m in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(tf, m, 0)
    para(tf, [(title, {"bold": True})], fit(title, BODY_W, 29), first=True, space_after=0)
    ln = s.shapes.add_shape(1, Inches(MARGIN), Inches(TITLE_TOP + TITLE_H + 0.04),
                            Inches(1.5), Inches(0.045))
    ln.fill.solid(); ln.fill.fore_color.rgb = ACCENT
    ln.line.fill.background(); ln.shadow.inherit = False
    if kicker:
        kb = box(s, MARGIN, TITLE_TOP + TITLE_H + 0.14, BODY_W, 0.32)
        kb.text_frame.word_wrap = True
        para(kb.text_frame, [(kicker, {"color": MUTED})], 13.5, first=True, space_after=0)
    return s


def bullets(s, items, top=1.42, size=17, width=BODY_W, left=MARGIN, gap=9):
    tb = box(s, left, top, width, BODY_BOTTOM - top)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = 0
    first = True
    for it in items:
        if it == "":
            para(tf, [(" ", {})], 6, first=first, space_after=0); first = False
            continue
        p = para(tf, [("▪   ", {"color": ACCENT, "bold": True})] +
                 (it if isinstance(it, list) else [(it, {})]),
                 size, first=first, space_after=gap)
        first = False
    return tb


def table(s, rows, col_w, top, size=13, head_size=13, row_h=0.40, head_h=0.40,
          aligns=None, mono_cols=(), left=MARGIN):
    n_r, n_c = len(rows), len(rows[0])
    total_h = head_h + row_h * (n_r - 1)
    shape = s.shapes.add_table(n_r, n_c, Inches(left), Inches(top),
                               Inches(sum(col_w)), Inches(total_h))
    tbl = shape.table
    tbl.first_row = True
    tbl.horz_banding = False
    for i, cw in enumerate(col_w):
        tbl.columns[i].width = Inches(cw)
    tbl.rows[0].height = Inches(head_h)
    for r in range(1, n_r):
        tbl.rows[r].height = Inches(row_h)
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            cell = tbl.cell(r, c)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.margin_left = cell.margin_right = Inches(0.08)
            cell.margin_top = cell.margin_bottom = Inches(0.02)
            cell.fill.solid()
            cell.fill.fore_color.rgb = ACCENT if r == 0 else (WHITE if r % 2 else LIGHT)
            tf = cell.text_frame
            tf.word_wrap = True
            runs = val if isinstance(val, list) else [(str(val), {})]
            fnt = MONO if c in mono_cols and r > 0 else SANS
            p = para(tf, runs, head_size if r == 0 else size, first=True,
                     space_after=0, line=1.05, font=fnt)
            p.alignment = (PP_ALIGN.LEFT if aligns is None else
                           {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER,
                            "r": PP_ALIGN.RIGHT}[aligns[c]])
            if r == 0:
                for run in p.runs:
                    run.font.bold = True
                    run.font.color.rgb = WHITE
    assert top + total_h <= H - 0.15, f"table overflows: {top + total_h:.2f}"
    return shape


def rawline(s, segments, top, height=0.60, ideal=17, left=MARGIN, width=BODY_W):
    bg = s.shapes.add_shape(1, Inches(left), Inches(top), Inches(width), Inches(height))
    bg.fill.solid(); bg.fill.fore_color.rgb = LIGHT
    bg.line.color.rgb = RULE; bg.line.width = Pt(0.75)
    bg.shadow.inherit = False
    text = "".join(t for t, _ in segments)
    size = fit(text, width - 0.36, ideal, mono=True)
    tb = box(s, left + 0.14, top + 0.03, width - 0.28, height - 0.06)
    tf = tb.text_frame
    tf.word_wrap = False
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(tf, m, 0)
    para(tf, [(t, {"color": c, "font": MONO, "bold": c is not INK}) for t, c in segments],
         size, first=True, space_after=0)


def note(s, runs, top, size=13.5, h=0.5):
    tb = box(s, MARGIN, top, BODY_W, h)
    tb.text_frame.word_wrap = True
    para(tb.text_frame, runs, size, first=True, space_after=0)


def node(s, l, t, w, h, title, sub=None, fill=WHITE, edge=ACCENT, tsize=15):
    shp = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(l), Inches(t), Inches(w), Inches(h))
    shp.fill.solid(); shp.fill.fore_color.rgb = fill
    shp.line.color.rgb = edge; shp.line.width = Pt(1.75)
    shp.shadow.inherit = False
    tf = shp.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    para(tf, [(title, {"bold": True, "color": INK})], tsize, first=True,
         align=PP_ALIGN.CENTER, space_after=0)
    if sub:
        para(tf, [(sub, {"color": MUTED})], 10.5, align=PP_ALIGN.CENTER, space_after=0)
    return shp


def blockarrow(s, y, x_from, x_to, colour=ACCENT, thick=True, both=False):
    lo, hi = min(x_from, x_to), max(x_from, x_to)
    h = 0.28 if thick else 0.20
    shape_type = MSO_SHAPE.LEFT_RIGHT_ARROW if both else (
        MSO_SHAPE.RIGHT_ARROW if x_to > x_from else MSO_SHAPE.LEFT_ARROW)
    shp = s.shapes.add_shape(shape_type, Inches(lo), Inches(y - h / 2.0),
                             Inches(hi - lo), Inches(h))
    shp.fill.solid(); shp.fill.fore_color.rgb = colour
    shp.line.fill.background()
    shp.shadow.inherit = False
    try:
        shp.adjustments[0] = 0.42
        shp.adjustments[1] = 1.0 if not both else 0.5
    except (IndexError, ValueError):
        pass
    return shp


def vblockarrow(s, x, y_from, y_to, colour=ACCENT, thick=True, both=True):
    lo, hi = min(y_from, y_to), max(y_from, y_to)
    w = 0.26 if thick else 0.18
    shape_type = MSO_SHAPE.UP_DOWN_ARROW if both else (
        MSO_SHAPE.DOWN_ARROW if y_to > y_from else MSO_SHAPE.UP_ARROW)
    shp = s.shapes.add_shape(shape_type, Inches(x - w / 2.0), Inches(lo),
                             Inches(w), Inches(hi - lo))
    shp.fill.solid(); shp.fill.fore_color.rgb = colour
    shp.line.fill.background()
    shp.shadow.inherit = False
    try:
        shp.adjustments[0] = 0.42
        shp.adjustments[1] = 1.0 if not both else 0.5
    except (IndexError, ValueError):
        pass
    return shp


def alabel(s, l, t, w, runs, size=12.5, align=PP_ALIGN.CENTER, h=0.5):
    tb = box(s, l, t, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_top", "margin_bottom", "margin_left", "margin_right"):
        setattr(tf, m, 0)
    para(tf, runs, size, first=True, align=align, space_after=0)
    return tb


def hexchange(s, y_c, x_from, x_to, top_runs=None, bot_runs=None, colour=ACCENT):
    """A horizontal exchange: an arrow with a label above and below it, each
    in its own fixed-height box with a real geometric gap to the arrow --
    not an estimate of rendered text height, so nothing can end up touching."""
    lo, hi = min(x_from, x_to), max(x_from, x_to)
    arrow_h, lab_h, gap = 0.28, 0.22, 0.09
    if top_runs:
        alabel(s, lo, y_c - arrow_h / 2.0 - gap - lab_h, hi - lo, top_runs, size=11.5, h=lab_h)
    blockarrow(s, y_c, x_from, x_to, colour=colour, thick=True)
    if bot_runs:
        alabel(s, lo, y_c + arrow_h / 2.0 + gap, hi - lo, bot_runs, size=10, h=lab_h)


def selfbox(s, x_c, y, w, lines, edge=ACCENT, size=11):
    n = len(lines)
    h = 0.30 if n == 1 else 0.18 + 0.26 * n
    bx = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x_c - w / 2.0),
                            Inches(y), Inches(w), Inches(h))
    bx.fill.solid(); bx.fill.fore_color.rgb = WHITE
    bx.line.color.rgb = edge; bx.line.width = Pt(1.25)
    bx.shadow.inherit = False
    tf = bx.text_frame; tf.word_wrap = True; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_top", "margin_bottom", "margin_left", "margin_right"):
        setattr(tf, m, Inches(0.05))
    for i, line in enumerate(lines):
        para(tf, line, size, first=(i == 0), align=PP_ALIGN.CENTER, space_after=1, line=1.05)
    return y + h


def msg(s, y, x_from, x_to, runs, colour=ACCENT, dashed=False, size=11):
    """One arrow with ONE label placed above it, real geometric clearance."""
    lo, hi = min(x_from, x_to), max(x_from, x_to)
    lab_h, gap = 0.22, 0.08
    alabel(s, lo, y, hi - lo, runs, size=size, h=lab_h)
    arrow_h = 0.20 if dashed else 0.28
    arrow_cy = y + lab_h + gap + arrow_h / 2.0
    blockarrow(s, arrow_cy, x_from, x_to, colour=colour, thick=not dashed)
    return arrow_cy + arrow_h / 2.0


def wire(s, sender, receiver, endpoint, fields, left, top, width, accent=ACCENT, fsize=12.5):
    head_h = 0.34
    row_h = 0.255
    h = head_h + row_h * len(fields) + 0.14
    bg = s.shapes.add_shape(1, Inches(left), Inches(top), Inches(width), Inches(h))
    bg.fill.solid(); bg.fill.fore_color.rgb = LIGHT
    bg.line.color.rgb = RULE; bg.line.width = Pt(0.75)
    bg.shadow.inherit = False
    hd = s.shapes.add_shape(1, Inches(left), Inches(top), Inches(width), Inches(head_h))
    hd.fill.solid(); hd.fill.fore_color.rgb = accent
    hd.line.fill.background(); hd.shadow.inherit = False
    tf = hd.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = Inches(0.10); tf.margin_top = tf.margin_bottom = 0
    label = f"{sender}  →  {receiver}"
    para(tf, [(label, {"bold": True, "color": WHITE}),
              (f"    {endpoint}" if endpoint else "",
               {"color": WHITE, "font": MONO, "size": fsize})],
         fsize + 0.5, first=True, space_after=0)
    tb = box(s, left + 0.10, top + head_h + 0.05, width - 0.20, h - head_h - 0.10)
    tf = tb.text_frame; tf.word_wrap = False
    for m in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(tf, m, 0)
    widest = max(len(n) for n, _ in fields)
    for i, (name, desc) in enumerate(fields):
        pad = name.ljust(widest + 2)
        line = pad + desc
        sz = min(fsize, fit(line, width - 0.30, fsize, mono=True))
        para(tf, [(pad, {"font": MONO, "bold": True, "color": INK}),
                  (desc, {"font": MONO, "color": MUTED})],
             sz, first=(i == 0), space_after=2.5, line=1.0)
    return h


ELIDE = "…"

# ============================================================ 1. title
s = prs.slides.add_slide(BLANK)
bar = s.shapes.add_shape(1, Inches(0), Inches(0), Inches(0.34), Inches(H))
bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
bar.line.fill.background(); bar.shadow.inherit = False
tb = box(s, 1.15, 2.45, 11.2, 2.9)
tf = tb.text_frame; tf.word_wrap = True
para(tf, [("Privacy-Aware Remote Attestation", B)], 40, first=True, space_after=14)
para(tf, [("Architecture, protocol, redaction, trust modes, and what it costs",
           {"color": ACCENT})], 19, space_after=22)
para(tf, [("CHARRA-v2   ·   proof of concept", {"color": MUTED})], 14)


# ============================================================ 2. architecture
s = slide("System architecture",
          "Four independent binaries, one per role, talking CoAP over UDP.")
node(s, 5.17, 1.70, 3.0, 0.68, "Trust Manager", "resolves Verifier IDs -> {ip, port}")
node(s, 0.60, 3.55, 2.85, 1.05, "Attester", "own TPM -- measures every file")
node(s, 4.92, 3.42, 3.50, 1.32, "Relying Party", "own TPM -- redacts, then vouches",
     fill=LIGHT, edge=RED, tsize=16)
node(s, 9.88, 3.55, 2.85, 1.05, "Verifier  x N", "appraises log_r, votes YES/NO")
vblockarrow(s, 6.67, 2.38, 3.42, colour=ACCENT)
alabel(s, 6.90, 2.62, 3.6, [("discoverVerifiers", B)], size=12.5, align=PP_ALIGN.LEFT)
hexchange(s, 4.07, 3.45, 4.92, [("getEvidence", B)],
          [("Quote_a + log_a", {"font": MONO, "size": 9.5, "color": RED})], colour=RED)
hexchange(s, 4.07, 8.42, 9.88, [("submitAndCollect", B)],
          [("Quote_r + log_r", {"font": MONO, "size": 9.5, "color": GREEN})], colour=GREEN)
note(s, [("log_a", {"font": MONO, "bold": True, "color": RED}),
         (" stops at the Relying Party -- the privacy boundary. ", {"bold": True}),
         ("log_r", {"font": MONO, "bold": True, "color": GREEN}),
         (" replaces it going out.", {})], top=5.15, size=15)
note(s, [("Transport: ", B), ("CoAP over UDP", {"font": MONO}),
         (" between every pair. DTLS is optional and off by default -- ", {}),
         ("DTLS_MODE=psk", {"font": MONO}), (" or ", {}), ("DTLS_MODE=rpk", {"font": MONO}),
         (" turns it on for all four roles at once.", {})], top=5.75, size=13.5)
note(s, [("Trust in the redaction itself is separate from transport trust: ", {}),
         ("TRUST_MODE=qualify | tee | zk", {"font": MONO, "bold": True}),
         (" picks how the RP proves it, covered later.", {})], top=6.30, size=13.5)

# ============================================================ 3a. info flow
s = slide("What travels between the roles",
          "Every payload, from the Attester through the RP to a Verifier.")
wire(s, "RP", "Attester", "/attest", [
    ("nonce", "20 B, the RP's challenge"),
    ("pcr_selections", "which PCRs to quote — 0-7, 10"),
    ("sig_key_id", "which AK to sign with"),
], left=MARGIN, top=1.85, width=5.85)
wire(s, "Attester", "RP", "", [
    ("attestation_data", "Quote_a — TPMS_ATTEST, 133 B"),
    ("tpm2_signature", "AK_a's signature over it"),
    ("tpm2_public_key", "AK_a — 616 B TPM2B_PUBLIC"),
    ("event_log", "log_a — 4728 B, REAL PATHS"),
], left=6.85, top=1.85, width=5.88, accent=RED)
note(s, [("log_a", {"font": MONO, "bold": True, "color": RED}),
         (" arrives at the RP. It goes no further.", {"bold": True})], top=3.42, size=15)
wire(s, "RP", "Verifier", "/appraise", [
    ("rp_attestation_data", "Quote_r — PCR 23, 145 B"),
    ("rp_signature", "AK_r's signature over it"),
    ("log_r", "the redacted log — paths hashed"),
    ("attestation_data", "Quote_a, forwarded verbatim"),
    ("tpm2_signature", "AK_a's signature over it, forwarded"),
    ("tpm2_public_key", "AK_a, forwarded — so the Verifier can check it"),
    ("trust_mode", "qualify | tee | zk"),
    ("tee_* / zk_proof", "only the fields that mode needs"),
], left=MARGIN, top=3.75, width=8.6, accent=GREEN)
note(s, [("Quote_a", {"font": MONO, "bold": True}), (" travels ", {}), ("verbatim", B),
         (" to the Verifier — signature and key included — so it checks the Attester's evidence itself, rather than taking the RP's word for it.", {})],
     top=6.40, size=13)

# ============================================================ 3b. RP actions
s = slide("What the Relying Party does",
          "Before redacting anything, six checks on what the Attester sent.")
table(s, [
    ["The RP checks", "Against"],
    [[("1.  AK_a is an identity we trust", {})], [("keys/trusted_keys.txt", {"font": MONO})]],
    [[("2.  ", {}), ("Quote_a", {"font": MONO}), ("'s signature", {})], "AK_a, RSA-PSS / SHA-256"],
    [[("3.  the nonce inside ", {}), ("extraData", {"font": MONO})], "the 20 bytes it just sent"],
    [[("4.  every entry's ", {}), ("template_digest", {"font": MONO})],
     [("SHA256(template_data)", {"font": MONO}), (" — each entry is self-consistent", {})]],
    [[("5.  ", {}), ("log_a", {"font": MONO}), (" replays to the sealed ", {}), ("pcrDigest", {"font": MONO})],
     "its own replay of the log"],
    [[("6.  every file content digest", {})], "the whitelist and the blacklist"],
], col_w=[6.0, 6.13], top=1.90, size=13.5, head_size=13.5, row_h=0.44, head_h=0.40)
wire(s, "RP", "Attester", "/attestation_result", [
    ("accepted", "1 = evidence accepted, 0 = rejected"),
    ("reason", "human-readable, for the Attester's log"),
], left=MARGIN, top=5.25, width=6.5)
bullets(s, [
    [("Only then", B), (" does it redact and replay ", {}), ("log_r", {"font": MONO}),
     (" into its own TPM — the RP's own action, on the next slide.", {})],
], top=5.30, size=12.5, width=5.35, left=7.4, gap=6)

# ============================================================ 4. redaction example
s = slide("One IMA log entry, before and after",
          f"Real output from a run. Long hex fields are elided in the middle ({ELIDE}) so each entry fits on one line.")
alabel(s, MARGIN, 1.62, 4.0, [("log_a", {"font": MONO, "bold": True, "color": RED}),
                              ("  — Attester → RP", {})], size=13, align=PP_ALIGN.LEFT, h=0.24)
rawline(s, [("10  ", INK), (f"b82f9269{ELIDE}ad8bc104", INK), ("  ima-ng  ", INK),
            (f"sha256:61cee375{ELIDE}becfd541", INK), ("  ", INK),
            ("/usr/lib/systemd/systemd", RED)],
        top=1.90, height=0.58, ideal=17)
alabel(s, MARGIN, 2.58, 4.0, [("log_r", {"font": MONO, "bold": True, "color": GREEN}),
                              ("  — RP → Verifier", {})], size=13, align=PP_ALIGN.LEFT, h=0.24)
rawline(s, [("10  ", INK), (f"b0c30a6d{ELIDE}32fa7e6f", ACCENT), ("  ima-ng  ", INK),
            (f"sha256:61cee375{ELIDE}becfd541", INK), ("  ", INK),
            (f"4c28124b{ELIDE}0616dea8", GREEN)],
        top=2.86, height=0.58, ideal=17)
table(s, [
    ["Field", "log_a", "log_r", ""],
    ["PCR", "10", "10", "unchanged"],
    ["template_digest", f"b82f9269{ELIDE}ad8bc104", f"b0c30a6d{ELIDE}32fa7e6f",
     [("recomputed", {"bold": True, "color": ACCENT})]],
    ["file digest", f"sha256:61cee375{ELIDE}…", f"sha256:61cee375{ELIDE}…",
     [("byte-identical", B), (" — kept on purpose", {})]],
    [[("pathname", {"bold": True, "color": RED})],
     [("/usr/lib/systemd/systemd", {"bold": True, "color": RED})],
     [(f"4c28124b{ELIDE}0616dea8", {"bold": True, "color": GREEN})],
     [("replaced", {"bold": True, "color": GREEN}), (" — SHA256(path ‖ salt), always 32 B", {})]],
], col_w=[2.35, 3.35, 2.90, 3.53], top=3.68, size=13, head_size=13, row_h=0.46,
   head_h=0.40, mono_cols=(1, 2))
note(s, [("A fresh 32-byte salt per entry, never transmitted", B),
         (" — so the same path redacts differently every time, and a Verifier can neither reverse it nor link repeated paths.", {})],
     top=6.05, size=14)

# ============================================================ 5. trust modes
s = slide("The three trust modes: qualify, tee, zk",
          "The Verifier cannot see log_a, so it cannot check the redaction directly. Three mechanisms answer that, chosen with one flag.")
table(s, [
    ["Mode", "What it proves", "Over how much log", "Cost"],
    [[("qualify", {"font": MONO, "bold": True})], "the redaction output",
     "40-entry synthetic log", "238 ms per grant window"],
    [[("tee", {"font": MONO, "bold": True})], "the code doing the redaction",
     [("3 source files — ", {}), ("log-independent", B)], "≈ 24 ms per Verifier"],
    [[("zk", {"font": MONO, "bold": True})], "the redaction itself, in zero knowledge",
     [("33-entry circuit ceiling", B)], "≈ 4.1 s per cycle"],
], col_w=[1.5, 4.4, 3.3, 2.93], top=2.10, size=13, head_size=13, row_h=0.60)
note(s, [("The attestation log here is ", {}), ("33 entries", B), (". ", {}),
         ("qualify", {"font": MONO}), (" is priced over a 40-entry log the Verifier invents, not the real one; ", {}),
         ("tee", {"font": MONO}), (" hashes source files, so its cost does not move with log size; ", {}),
         ("zk", {"font": MONO}), (" pays for its circuit's compiled ceiling whatever the fill — about ", {}),
         ("82 ms and 35 MiB per entry", B), (".", {})], top=4.35, size=12.5)
note(s, [("One flag sets both roles: ", {}), ("TRUST_MODE=qualify | tee | zk", {"font": MONO, "bold": True}),
         (". A mismatch is reported, not guessed at — the Verifier votes NO and logs ", {}),
         ("MODE MISMATCH", {"font": MONO}), (".", {})], top=5.20, size=13.5)
note(s, [("A malicious RP could hide a blacklisted file rather than merely hiding its path — this is what closes that gap.", {"color": MUTED})],
     top=5.85, size=13)

# ------------------------------------------ 21a. the /qualify action flow
s = slide("The /qualify action flow",
          "A redaction competence test. Time runs downward; the Verifier always moves first.")

V_X, RP_X2 = 2.55, 10.15
TOPQ, BOTQ = 2.02, 7.00
for x, name, sub, edge in ((V_X, "Verifier", "sets the exam", ACCENT),
                            (RP_X2, "Relying Party", "sits the exam", RED)):
    node(s, x - 1.55, 1.44, 3.10, 0.50, name, sub, edge=edge, tsize=13)
    vblockarrow(s, x, TOPQ, BOTQ, colour=RULE, thick=False, both=False)


def qact(cursor_y, x, lines, edge=ACCENT, max_w=3.9, size=10.5):
    """A self-action box, sized to however many explicit lines it is given.

    Lines are authored short enough to fit rather than left to auto-wrap --
    predictable height beats a clever fit() call here, since the box has to
    be placed precisely against the arrows above and below it.
    """
    n = len(lines)
    h = 0.34 if n == 1 else 0.20 + 0.30 * n
    half_w = min(max_w / 2.0, x - MARGIN - 0.08, (MARGIN + BODY_W) - x - 0.08)
    w = half_w * 2.0
    bx = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x - half_w),
                            Inches(cursor_y), Inches(w), Inches(h))
    bx.fill.solid(); bx.fill.fore_color.rgb = WHITE
    bx.line.color.rgb = edge; bx.line.width = Pt(1.25)
    bx.shadow.inherit = False
    tf = bx.text_frame; tf.word_wrap = True; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_top", "margin_bottom", "margin_left", "margin_right"):
        setattr(tf, m, Inches(0.04))
    for i, line in enumerate(lines):
        para(tf, line, size, first=(i == 0), align=PP_ALIGN.CENTER, space_after=1,
             line=1.05)
    return cursor_y + h


def qmsg(cursor_y, x_from, x_to, runs, colour=ACCENT, dashed=False, size=10.5):
    """Label, a real gap, then the arrow -- geometry is exact, not estimated:
    the label sits in its own 0.24in box and the arrow starts a full 0.14in
    below that box's bottom edge, so no line-height guess can make them
    touch."""
    lo, hi = min(x_from, x_to), max(x_from, x_to)
    label_h, gap = 0.24, 0.14
    alabel(s, lo, cursor_y, hi - lo, runs, size=size, h=label_h)
    arrow_h = 0.24 if dashed else 0.30
    arrow_cy = cursor_y + label_h + gap + arrow_h / 2.0
    blockarrow(s, arrow_cy, x_from, x_to, colour=colour, thick=not dashed)
    return arrow_cy + arrow_h / 2.0


y = TOPQ
y = qact(y, V_X, [[("generate a 40-entry synthetic log", {})],
                  [("+  redact it — the golden answer", {"color": MUTED})]])
y += 0.12
y = qmsg(y, V_X, RP_X2, [("/qualify", B),
                        ("   challenge_log (5210 B) + salt", {"font": MONO, "size": 9.5})])
y += 0.10
y = qact(y, RP_X2, [[("redact the same log, same salt", {})]], edge=RED)
y += 0.12
y = qact(y, RP_X2, [[("sign (redacted log ‖ salt) with AK_r", {})],
                    [("— 210 ms, almost the whole cost", {"color": MUTED})]], edge=RED)
y += 0.12
y = qmsg(y, RP_X2, V_X, [("/qualify_submit", B),
                        ("  redaction + rp_signature + rp_public_key",
                         {"font": MONO, "size": 9.5})])
y += 0.10
y = qact(y, V_X, [[("verify the signature, then compare byte for byte", {})]])
y += 0.12
y = qmsg(y, V_X, RP_X2, [("qualified = 1", {"font": MONO}),
                        ("   +   expires_at (+180 s)", {"color": MUTED})],
        colour=GREEN, dashed=True)

note(s, [("238 ms total", B), (" the first time; ", {}),
         ("0.023 ms", B), (" to re-check a grant that still holds — three to four orders of magnitude cheaper.", {})],
     top=y + 0.14, size=13, h=0.28)

# ------------------------------------------------- 18. where the time goes
s = slide("Where the time goes", "One attestation cycle, steady state. Each operation has its own timer.")
table(s, [
    ["Operation", "Who does the work", "Time", "% of cycle"],
    [[("discoverVerifiers", {"font": MONO})], "RP ↔ Trust Manager", "0.40 ms", "0.01 %"],
    [[("getEvidence", {"font": MONO})], "RP ↔ Attester", "212.3 ms", "6.5 %"],
    [[("appraiseEvidence_a", {"font": MONO})], "RP, locally", "1.02 ms", "0.03 %"],
    [[("prepareEvidence_r", {"font": MONO, "bold": True, "color": RED})],
     [("RP + its own TPM", {"bold": True, "color": RED})],
     [("2820.8 ms", {"bold": True, "color": RED})], [("86.8 %", {"bold": True, "color": RED})]],
    [[("submitAndCollect", {"font": MONO})], "RP ↔ N Verifiers", "216.6 ms", "6.7 %"],
    [[("Total cycle", B)], "", [("3251.2 ms", B)], [("100 %", B)]],
], col_w=[3.5, 4.3, 2.3, 2.03], top=1.85, size=13, head_size=12.5, row_h=0.40,
   head_h=0.36, aligns=["l", "l", "r", "r"])
note(s, [("The five sum to within ", {}), ("0.004 %", B), (" of the measured total — the bottleneck is the RP replaying ", {}),
         ("log_r", {"font": MONO}), (" into its own TPM.", {})],
     top=4.72, size=12.5, h=0.24)

alabel(s, MARGIN, 5.16, BODY_W, [
    ("For ", {}), ("qualify", {"font": MONO, "bold": True}),
    (" mode, adding Verifiers increases the total ", {}),
    ("linearly", {"bold": True, "color": ACCENT}), (":", {})],
    size=14, align=PP_ALIGN.LEFT, h=0.26)
table(s, [
    ["Verifiers", "1", "2", "3", "4", "5"],
    [[("Total cycle", B)], "3251 ms", "3484 ms", "3671 ms", "3894 ms", "4097 ms"],
], col_w=[2.2, 1.986, 1.986, 1.986, 1.986, 1.986], top=5.54, size=13, head_size=13,
   row_h=0.40, head_h=0.36, aligns=["l", "c", "c", "c", "c", "c"])
note(s, [("Fixed:  ", B), ("3049 ms", {"font": MONO, "bold": True}),
         (" once per cycle.   Marginal:  ", {}), ("210 ms per Verifier", {"font": MONO, "bold": True}),
         (" — entirely ", {}), ("submitAndCollect", {"font": MONO}),
         (", the only per-Verifier operation.", {})], top=6.42, size=12.5, h=0.24)

# --------------------------------------------------------- 21. zk scaling
s = slide("The ZK proof: what grows, and what does not",
          "Nine circuits, each proved five times. Entries is the circuit's compiled ceiling.")
table(s, [
    ["Entries", "Gates", "bb prove only", "Peak RAM", "Proof size", "Verify"],
    ["4", "123 K", "0.65 s", "212 MiB", "14,656 B", "0.01 s"],
    ["33", "839 K", "3.10 s", "1,249 MiB", "14,656 B", "0.01 s"],
    ["128", "3.18 M", "10.46 s", "4,547 MiB", "14,656 B", "0.02 s"],
    ["192", "4.77 M", "16.47 s", "6,839 MiB", "14,656 B", "0.02 s"],
    [[("256", {"bold": True, "color": RED})], [("6.3 M", {"color": RED})], [("—", {"color": RED})],
     [("≈ 9 GB — OOM", {"bold": True, "color": RED})], [("—", {"color": RED})], [("—", {"color": RED})]],
], col_w=[1.5, 2.0, 2.0, 2.63, 2.2, 1.8], top=2.05, size=13.5, head_size=13,
   row_h=0.45, aligns=["r", "r", "r", "r", "r", "r"])
bullets(s, [
    [("Linear in the entry count:  ", B), ("81.5 ms", {"font": MONO, "bold": True}), (" and ", {}),
     ("34.9 MiB", {"font": MONO, "bold": True}), (" per entry", {}),
     ("   (R² = 0.998 and 0.9998)", {"color": MUTED})],
    [("The proof is ", {}), ("14,656 bytes at every size", B),
     (" — the gigabytes are transient prover RAM, never written and never sent.", {})],
], top=4.85, size=13.5, gap=8)


out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "charra_attestation_walkthrough.pptx")
prs.save(out)
print(f"{len(prs.slides._sldIdLst)} slides -> {out}")

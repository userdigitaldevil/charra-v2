#!/usr/bin/env python3
"""
Builds privacy_aware_remote_attestation.pptx -- the six-slide version.

The long deck (build_privacy_slides.py, 30 slides) walks every hop. This one
is for a talk where the speaker narrates: slide 2 is a diagram of the four
roles with the five steps on the arrows, and the rest is evidence -- the
functions behind each step, one real redaction, and the measurements.

    pip install python-pptx
    python3 charra-ressources/build_privacy_aware_slides.py

Every value is real output from a run: the log lines come from
ima_test_logs.txt through charra_sdk_redact_ima_log(), the timings from
charra_measurements_v2.md.
"""

import math
import os
from lxml import etree
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
from pptx.enum.dml import MSO_LINE_DASH_STYLE
from pptx.oxml.ns import qn

W, H = 13.333, 7.5
MARGIN = 0.60
BODY_W = W - 2 * MARGIN
TITLE_TOP, TITLE_H = 0.34, 0.70

INK    = RGBColor(0x16, 0x20, 0x2C)
ACCENT = RGBColor(0x1F, 0x5C, 0x8B)
RED    = RGBColor(0xA8, 0x35, 0x2A)
GREEN  = RGBColor(0x1B, 0x63, 0x40)
MUTED  = RGBColor(0x5A, 0x66, 0x72)
LIGHT  = RGBColor(0xF2, 0xF5, 0xF8)
RULE   = RGBColor(0xD5, 0xDD, 0xE4)
WHITE  = RGBColor(0xFF, 0xFF, 0xFF)

SANS, MONO = "Calibri", "Consolas"
CW_MONO, CW_SANS = 0.550, 0.480

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(W), Inches(H)
BLANK = prs.slide_layouts[6]
B = {"bold": True}


def fit(text, width_in, ideal, mono=False, floor=8):
    cw = CW_MONO if mono else CW_SANS
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
    tb.text_frame.word_wrap = True
    for m in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(tb.text_frame, m, 0)
    para(tb.text_frame, [(title, {"bold": True})], fit(title, BODY_W, 29),
         first=True, space_after=0)
    ln = s.shapes.add_shape(1, Inches(MARGIN), Inches(TITLE_TOP + TITLE_H + 0.04),
                            Inches(1.5), Inches(0.045))
    ln.fill.solid(); ln.fill.fore_color.rgb = ACCENT
    ln.line.fill.background(); ln.shadow.inherit = False
    if kicker:
        kb = box(s, MARGIN, TITLE_TOP + TITLE_H + 0.14, BODY_W, 0.32)
        kb.text_frame.word_wrap = True
        para(kb.text_frame, [(kicker, {"color": MUTED})], 13.5, first=True,
             space_after=0)
    return s


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
                     space_after=0, line=1.04, font=fnt)
            p.alignment = (PP_ALIGN.LEFT if aligns is None else
                           {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER,
                            "r": PP_ALIGN.RIGHT}[aligns[c]])
            if r == 0:
                for run in p.runs:
                    run.font.bold = True
                    run.font.color.rgb = WHITE
    assert top + total_h <= H - 0.2, f"table overflows: {top + total_h:.2f}"
    return shape


def rawline(s, segments, top, height=0.62, ideal=16, left=MARGIN, width=BODY_W):
    bg = s.shapes.add_shape(1, Inches(left), Inches(top), Inches(width), Inches(height))
    bg.fill.solid(); bg.fill.fore_color.rgb = LIGHT
    bg.line.color.rgb = RULE; bg.line.width = Pt(0.75)
    bg.shadow.inherit = False
    text = "".join(t for t, _ in segments)
    size = fit(text, width - 0.40, ideal, mono=True)
    tb = box(s, left + 0.14, top + 0.03, width - 0.28, height - 0.06)
    tf = tb.text_frame
    tf.word_wrap = False
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(tf, m, 0)
    para(tf, [(t, {"color": c, "font": MONO, "bold": c is not INK})
              for t, c in segments], size, first=True, space_after=0)
    return size


# --- diagram primitives ---------------------------------------------------

def node(s, l, t, w, h, title, sub=None, fill=WHITE, edge=ACCENT, tsize=16):
    """A labelled role box."""
    shp = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                             Inches(l), Inches(t), Inches(w), Inches(h))
    shp.fill.solid(); shp.fill.fore_color.rgb = fill
    shp.line.color.rgb = edge; shp.line.width = Pt(1.75)
    shp.shadow.inherit = False
    tf = shp.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    para(tf, [(title, {"bold": True, "color": INK})], tsize, first=True,
         align=PP_ALIGN.CENTER, space_after=0)
    if sub:
        para(tf, [(sub, {"color": MUTED})], 11, align=PP_ALIGN.CENTER,
             space_after=0)
    return shp


def blockarrow(s, y, x_from, x_to, colour=ACCENT, thick=True):
    """A filled block arrow between two lifelines.

    Line connectors were tried first and did not survive: python-pptx has no
    arrowhead API, and the <a:tailEnd> appended by hand never reached the
    file, so every message rendered as a plain rule. A filled autoshape has
    no such problem and carries much better to a projector.
    """
    lo, hi = min(x_from, x_to), max(x_from, x_to)
    h = 0.30 if thick else 0.24
    shp = s.shapes.add_shape(
        MSO_SHAPE.RIGHT_ARROW if x_to > x_from else MSO_SHAPE.LEFT_ARROW,
        Inches(lo), Inches(y - h / 2.0), Inches(hi - lo), Inches(h))
    shp.fill.solid(); shp.fill.fore_color.rgb = colour
    shp.line.fill.background()
    shp.shadow.inherit = False
    # Defaults give a stubby head on a shape this wide: adj1 is shaft
    # thickness, adj2 head length, both as a fraction of the height.
    try:
        shp.adjustments[0] = 0.42
        shp.adjustments[1] = 1.0
    except (IndexError, ValueError):
        pass
    return shp


def alabel(s, l, t, w, runs, size=12.5, align=PP_ALIGN.CENTER, h=0.5):
    tb = box(s, l, t, w, h)
    tb.text_frame.word_wrap = True
    para(tb.text_frame, runs, size, first=True, align=align, space_after=0)
    return tb


# ============================================================ 1. title
s = prs.slides.add_slide(BLANK)
bar = s.shapes.add_shape(1, Inches(0), Inches(0), Inches(0.34), Inches(H))
bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT
bar.line.fill.background(); bar.shadow.inherit = False
tb = box(s, 1.15, 2.45, 11.2, 2.9)
tf = tb.text_frame; tf.word_wrap = True
para(tf, [("Privacy-Aware Remote Attestation", B)], 42, first=True, space_after=14)
para(tf, [("Proving a machine is trustworthy without disclosing what it runs",
           {"color": ACCENT})], 20, space_after=24)
para(tf, [("CHARRA-v2   ·   proof of concept", {"color": MUTED})], 15)

# ============================================================ 2. the diagram
s = slide("One attestation cycle, step by step",
          "Time runs downward. Every exchange is started by the Relying Party.")

# --- lifelines. RP sits third so only one arrow ever crosses another line.
LANES = [(1.85, "Trust Manager", "which Verifiers to use"),
         (5.15, "Attester", "has a TPM, measures files"),
         (8.45, "Relying Party", "redacts, then vouches"),
         (11.65, "Verifier  x N", "appraises, votes")]
TOP, BOT = 2.12, 6.45
for x, name, sub in LANES:
    is_rp = name.startswith("Relying")
    hd = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                            Inches(x - 1.25), Inches(1.52), Inches(2.50), Inches(0.56))
    hd.fill.solid(); hd.fill.fore_color.rgb = LIGHT if is_rp else WHITE
    hd.line.color.rgb = RED if is_rp else ACCENT
    hd.line.width = Pt(1.75 if is_rp else 1.25)
    hd.shadow.inherit = False
    tf = hd.text_frame; tf.word_wrap = True; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_top", "margin_bottom"): setattr(tf, m, 0)
    para(tf, [(name, {"bold": True})], 13, first=True, align=PP_ALIGN.CENTER, space_after=0)
    para(tf, [(sub, {"color": MUTED})], 9, align=PP_ALIGN.CENTER, space_after=0)
    ll = s.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x), Inches(TOP),
                                Inches(x), Inches(BOT))
    ll.line.color.rgb = RULE
    ll.line.width = Pt(1.25)
    ll.line.dash_style = MSO_LINE_DASH_STYLE.DASH

RP_X, TM_X, AT_X, VF_X = 8.45, 1.85, 5.15, 11.65


def msg(y, x_from, x_to, runs, colour=ACCENT, dashed=False, size=11.5):
    """One message: a block arrow with its label directly above it."""
    blockarrow(s, y, x_from, x_to, colour=colour, thick=not dashed)
    lo, hi = min(x_from, x_to), max(x_from, x_to)
    alabel(s, lo, y - 0.40, hi - lo, runs, size=size, h=0.22)


def selfact(y, runs, h=0.40, w=3.30):
    """Work the RP does without talking to anyone."""
    bx = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(RP_X - w / 2.0),
                            Inches(y), Inches(w), Inches(h))
    bx.fill.solid(); bx.fill.fore_color.rgb = WHITE
    bx.line.color.rgb = RED; bx.line.width = Pt(1.25)
    bx.shadow.inherit = False
    tf = bx.text_frame; tf.word_wrap = True; tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    for m in ("margin_top", "margin_bottom"): setattr(tf, m, 0)
    para(tf, runs, 11.5, first=True, align=PP_ALIGN.CENTER, space_after=0)

N = lambda n: (f"{n}  ", {"bold": True, "color": ACCENT})

# Vertical rhythm: a message needs 0.53in (label 0.18 + gap + arrow 0.30),
# so messages sit 0.56in apart and never collide.
msg(2.50, RP_X, TM_X, [N(1), ("discoverVerifiers", B)])
msg(3.06, TM_X, RP_X, [("{ ip, port } x N", {"font": MONO, "size": 10, "color": MUTED})],
    colour=MUTED, dashed=True)

msg(3.62, RP_X, AT_X, [N(2), ("getEvidence", B), ("   — 20-byte nonce", {})])
msg(4.18, AT_X, RP_X, [("Quote_a  +  log_a   — real paths",
                        {"font": MONO, "size": 10, "color": RED})],
    colour=RED, dashed=True)

selfact(4.42, [N(3), ("appraiseEvidence_a", B), ("   — 6 checks", {"color": MUTED})], h=0.34)
selfact(4.84, [N(4), ("prepareEvidence_r", B),
               ("   — redact, replay into its own TPM", {"color": MUTED})], h=0.34)

msg(5.64, RP_X, VF_X, [N(5), ("submitAndCollect", B), ("  ", {}),
                       ("Quote_r + log_r", {"font": MONO, "size": 10, "color": GREEN})],
    size=10.5)
msg(6.20, VF_X, RP_X, [("signed verdict:  YES / NO",
                        {"font": MONO, "size": 10, "color": MUTED})],
    colour=MUTED, dashed=True)

alabel(s, MARGIN, 6.62, BODY_W, [
    ("log_a", {"font": MONO, "bold": True, "color": RED}),
    (" stops at the Relying Party. ", {"bold": True}),
    ("log_r", {"font": MONO, "bold": True, "color": GREEN}),
    (" — the same log with every path hashed — goes to the Verifiers in its place. The RP then takes a majority vote over all N verdicts.", {})],
    size=13, align=PP_ALIGN.LEFT)

# ============================================================ 3. the functions
s = slide("What each step actually calls",
          "Timed at the Relying Party, steady state, one Verifier. n = 10.")
table(s, [
    ["#", "Step", "Function", "File", "Time"],
    ["1", "discoverVerifiers", "get_verifiers()", "rp_attestation.c", "0.40 ms"],
    ["2", "getEvidence", "get_evidence()", "rp_attestation.c", "212.3 ms"],
    ["3", "appraiseEvidence_a", "charra_rp_appraise_evidence()", "rp_evidence.c", "1.02 ms"],
    ["4", [("prepareEvidence_r", {"bold": True, "color": RED})],
     [("charra_rp_prepare_evidence()", {"bold": True, "color": RED})],
     [("rp_evidence.c", {"color": RED})],
     [("2820.8 ms", {"bold": True, "color": RED})]],
    ["5", "submitAndCollect", "get_attestation_results()", "rp_attestation.c",
     [("216.6 ms", {}), (" /verifier", {"color": MUTED, "size": 10})]],
], col_w=[0.5, 2.85, 4.35, 2.5, 1.93], top=1.72, size=12.5, head_size=12.5,
   row_h=0.52, mono_cols=(2, 3), aligns=["c", "l", "l", "l", "r"])
alabel(s, MARGIN, 4.95, BODY_W, [
    ("Step 4 is 87 % of the cycle", {"bold": True, "color": RED}),
    (" — and almost all of that is the RP replaying the redacted log into its own TPM to rebuild PCR 23. The bottleneck is TPM I/O, not cryptography.", {})],
    size=14.5, align=PP_ALIGN.LEFT)
alabel(s, MARGIN, 5.75, BODY_W, [
    ("The redaction itself is ", {}), ("charra_sdk_redact_ima_log()", {"font": MONO, "bold": True}),
    (", called from step 4, and it costs ", {}), ("0.1 ms", B),
    (". Privacy is the cheap part; vouching for the result is what costs.", {})],
    size=14.5, align=PP_ALIGN.LEFT)

# ============================================================ 3b. the functions to show
s = slide("The functions worth opening",
          "One per thing the system actually does, grouped by the role that runs it.")
table(s, [
    ["Role", "Function", "File", "What it does"],
    [[("Attester", {"bold": True, "color": ACCENT})], "coap_attest_handler()",
     "attester_attest.c", "answers /attest: TPM2_Quote over PCRs 0-7,10 + the IMA log"],
    ["", "charra_get_ima_log()", "attester_ima_log.c", "reads the measurement log the quote covers"],

    [[("Relying Party", {"bold": True, "color": RED})], "charra_rp_appraise_evidence()",
     "rp_evidence.c", "the six checks on Quote_a before anything is forwarded"],
    ["", [("charra_sdk_redact_ima_log()", {"bold": True, "color": RED})],
     [("charra_sdk.c", {"color": RED})],
     [("the redaction itself", {"bold": True, "color": RED}), (" — every path becomes SHA256(path ‖ salt)", {})]],
    ["", "charra_replay_ima_log()", "charra_event_log.c", "replays log_r into PCR 23 so Quote_r can vouch for it"],
    ["", "get_attestation_results()", "rp_attestation.c", "fans out to N Verifiers, then the majority vote"],

    [[("Verifier", {"bold": True, "color": GREEN})],
     [("coap_appraise_handler()", {"bold": True, "color": GREEN})],
     [("verifier_appraise.c", {"color": GREEN})],
     [("Step 3a and 3b", {"bold": True, "color": GREEN}), (" — both quotes, the replay, self-consistency, the hash policy", {})]],
    ["", "charra_verdict_sign()", "charra_verdict.c", "signs the vote, bound to this nonce and this evidence"],
], col_w=[1.65, 3.45, 2.35, 4.68], top=1.72, size=11, head_size=11.5,
   row_h=0.44, head_h=0.38, mono_cols=(1, 2))

alabel(s, MARGIN, 6.28, BODY_W, [
    ("Mode-specific entry points: ", {"color": MUTED}),
    ("charra_rp_qualification_generate()", {"font": MONO, "size": 11.5}),
    ("  ·  ", {"color": MUTED}), ("tee_attestation()", {"font": MONO, "size": 11.5}),
    ("  ·  ", {"color": MUTED}), ("charra_zk_prove()", {"font": MONO, "size": 11.5})],
    size=12, align=PP_ALIGN.LEFT)

# ============================================================ 4. the example
E = "…"
s = slide("One IMA log entry, before and after",
          f"Real output from a run. Long hex fields are elided in the middle ({E}) so each entry fits on one line.")
alabel(s, MARGIN, 1.72, 3.0, [("log_a", {"font": MONO, "bold": True, "color": RED}),
                              ("  — Attester → RP", {})], size=14, align=PP_ALIGN.LEFT)
rawline(s, [("10  ", INK), (f"b82f9269{E}ad8bc104", INK), ("  ima-ng  ", INK),
            (f"sha256:61cee375{E}becfd541", INK), ("  ", INK),
            ("/usr/lib/systemd/systemd", RED)], top=2.10, height=0.62, ideal=17)
alabel(s, MARGIN, 2.92, 3.0, [("log_r", {"font": MONO, "bold": True, "color": GREEN}),
                              ("  — RP → Verifier", {})], size=14, align=PP_ALIGN.LEFT)
rawline(s, [("10  ", INK), (f"b0c30a6d{E}32fa7e6f", ACCENT), ("  ima-ng  ", INK),
            (f"sha256:61cee375{E}becfd541", INK), ("  ", INK),
            (f"4c28124b{E}0616dea8", GREEN)], top=3.30, height=0.62, ideal=17)
table(s, [
    ["Field", "log_a", "log_r", ""],
    ["PCR", "10", "10", "unchanged"],
    ["template_digest", f"b82f9269{E}ad8bc104", f"b0c30a6d{E}32fa7e6f",
     [("recomputed", {"bold": True, "color": ACCENT})]],
    ["file digest", f"sha256:61cee375{E}…", f"sha256:61cee375{E}…",
     [("byte-identical", B), (" — kept on purpose", {})]],
    [[("pathname", {"bold": True, "color": RED})],
     [("/usr/lib/systemd/systemd", {"bold": True, "color": RED})],
     [(f"4c28124b{E}0616dea8", {"bold": True, "color": GREEN})],
     [("replaced", {"bold": True, "color": GREEN}), (" — SHA256(path ‖ salt), always 32 B", {})]],
], col_w=[2.05, 3.0, 2.6, 4.48], top=4.20, size=12, head_size=12, row_h=0.46,
   mono_cols=(1, 2))
alabel(s, MARGIN, 6.55, BODY_W, [
    ("A fresh 32-byte salt per entry, never transmitted", B),
    (" — so the same path redacts differently every time, and a Verifier can neither reverse it nor link repeated paths.", {})],
    size=13.5, align=PP_ALIGN.LEFT)

# ============================================================ 5. measurements
s = slide("What it costs",
          "Every figure measured on the same host, over the 33-entry attestation log.")
alabel(s, MARGIN, 1.66, 5.9, [("Scaling with Verifiers", {"bold": True, "color": ACCENT})],
       size=15, align=PP_ALIGN.LEFT, h=0.28)
table(s, [
    ["Verifiers", "1", "2", "3", "4", "5"],
    ["Total cycle", "3251", "3484", "3671", "3894", "4097 ms"],
], col_w=[1.55, 0.92, 0.92, 0.92, 0.92, 1.02], top=2.02, size=12, head_size=12,
   row_h=0.42, head_h=0.38, aligns=["l", "r", "r", "r", "r", "r"])
alabel(s, MARGIN, 2.90, 6.4, [
    ("3049 ms fixed + 210 ms per Verifier.", B),
    ("  The fixed part is one TPM replay; only ", {}), ("submitAndCollect", {"font": MONO}),
    (" grows.", {})], size=12.5, align=PP_ALIGN.LEFT)

alabel(s, 7.15, 1.66, 5.58, [("The three trust modes", {"bold": True, "color": ACCENT})],
       size=15, align=PP_ALIGN.LEFT, h=0.28)
table(s, [
    ["Mode", "Extra per cycle", "Extra per Verifier"],
    ["qualify", "— (baseline)", "—"],
    ["tee", "—", [("+ 24 ms", B)]],
    ["zk", [("+ 4.5 s", {"bold": True, "color": RED})], "—"],
], col_w=[1.5, 2.15, 1.93], top=2.02, size=12, head_size=12, row_h=0.42,
   head_h=0.38, left=7.15, mono_cols=(0,))
alabel(s, 7.15, 3.72, 5.58, [
    ("tee", {"font": MONO, "bold": True}), (" pays per Verifier, ", {}),
    ("zk", {"font": MONO, "bold": True}), (" pays per cycle.", {})],
    size=12.5, align=PP_ALIGN.LEFT)

alabel(s, MARGIN, 4.35, BODY_W, [("How the ZK proof scales", {"bold": True, "color": ACCENT})],
       size=15, align=PP_ALIGN.LEFT, h=0.28)
table(s, [
    ["Entries", "Gates", "bb prove", "Peak RAM", "Proof size", "Verify"],
    ["4", "123 K", "0.65 s", "212 MiB", "14,656 B", "0.01 s"],
    ["33", "839 K", "3.10 s", "1,249 MiB", "14,656 B", "0.01 s"],
    ["128", "3.18 M", "10.46 s", "4,547 MiB", "14,656 B", "0.02 s"],
    ["192", "4.77 M", "16.47 s", "6,839 MiB", "14,656 B", "0.02 s"],
    [[("256", {"bold": True, "color": RED})], [("6.3 M", {"color": RED})],
     [("—", {"color": RED})], [("≈ 9 GB — OOM", {"bold": True, "color": RED})],
     [("—", {"color": RED})], [("—", {"color": RED})]],
], col_w=[1.5, 2.0, 2.1, 2.5, 2.2, 1.83], top=4.70, size=11.5, head_size=11.5,
   row_h=0.36, head_h=0.34, aligns=["r", "r", "r", "r", "r", "r"])
alabel(s, MARGIN, 6.90, BODY_W, [
    ("Linear: 81.5 ms and 34.9 MiB per entry (R² 0.998).", B),
    ("  The proof is 14,656 bytes at every size — the gigabytes are transient prover RAM, never stored or sent.", {})],
    size=13, align=PP_ALIGN.LEFT)

# ============================================================ 6. trust modes
s = slide("How the Verifier knows the redaction was honest",
          "The Verifier cannot see log_a, so it cannot check the redaction directly. Three mechanisms answer that, chosen with one flag.")
table(s, [
    ["Mode", "What it proves", "How", "Blind spot"],
    [[("qualify", {"font": MONO, "bold": True})], "the redaction output",
     "the Verifier invents a 40-entry log and compares the RP's cleaning to its own, byte for byte",
     "says nothing about which code produced it"],
    [[("tee", {"font": MONO, "bold": True})], "the code doing the redaction",
     "a measurement of 3 source files, signed under a key AK_r certified",
     "hashes source on disk, not the running binary"],
    [[("zk", {"font": MONO, "bold": True})], "the redaction itself",
     "a Noir/UltraHonk proof that every cleaned path commits to one that replays to pcrdigest_a",
     "trusts the circuit is the right circuit"],
], col_w=[1.5, 2.7, 5.0, 2.93], top=2.05, size=12, head_size=12.5, row_h=0.95)
alabel(s, MARGIN, 5.35, BODY_W, [
    ("Set with one variable, for the RP and every Verifier at once: ", {}),
    ("TRUST_MODE=qualify | tee | zk", {"font": MONO, "bold": True}),
    (". A mismatch is reported, not guessed at — the Verifier votes NO and logs ", {}),
    ("MODE MISMATCH", {"font": MONO}), (".", {})], size=13.5, align=PP_ALIGN.LEFT)
alabel(s, MARGIN, 6.20, BODY_W, [
    ("What the Verifier never learns, in any mode:", B),
    ("  any file path or filename, which entries share a directory, or whether the same path appears twice.", {})],
    size=13.5, align=PP_ALIGN.LEFT)

out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "privacy_aware_remote_attestation.pptx")
prs.save(out)
print(f"{len(prs.slides._sldIdLst)} slides -> {out}")

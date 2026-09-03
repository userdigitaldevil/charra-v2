#!/usr/bin/env python3
"""
Builds charra_privacy_attestation_slides_v2.pptx.

Written against python-pptx rather than pandoc because pandoc places text in
the template's placeholders and cannot size them: long lines simply ran past
the slide edge. Here every box is positioned explicitly and every font size is
checked against the width it has to fit in (see `fit`), so nothing overflows.

    pip install python-pptx
    python3 charra-ressources/build_privacy_slides.py

Every value in the deck is real output from a run -- the log lines come from
ima_test_logs.txt through charra_sdk_redact_ima_log(), the timings from
charra_measurements_v2.md. Long hex fields are elided in the middle (ELIDE)
purely so a whole log entry fits on one line at a readable size.
"""

import math
import os
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

# ---------------------------------------------------------------- design system

W, H = 13.333, 7.5          # inches, 16:9
MARGIN = 0.60
BODY_W = W - 2 * MARGIN     # 12.13"
TITLE_TOP, TITLE_H = 0.34, 0.72
BODY_TOP = 1.42
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
CW_MONO, CW_SANS = 0.550, 0.480   # mean char width as a fraction of the em

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(W), Inches(H)
BLANK = prs.slide_layouts[6]


def fit(text, width_in, ideal, mono=False, floor=8):
    """Largest size <= ideal at which `text` fits on one line in width_in."""
    cw = CW_MONO if mono else CW_SANS
    if not text:
        return ideal
    cap = (width_in * 72.0) / (len(text) * cw)
    return max(floor, min(ideal, math.floor(cap * 2) / 2))


def box(slide, l, t, w, h):
    return slide.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))


def para(tf, runs, size, first=False, align=PP_ALIGN.LEFT, space_after=6,
         line=1.18, font=SANS):
    """runs: str, or list of (text, {bold,color,font,size}) tuples."""
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
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    para(tf, [(title, {"bold": True, "color": INK})],
         fit(title, BODY_W, 30), first=True, space_after=0)
    # accent rule under the title
    ln = s.shapes.add_shape(1, Inches(MARGIN), Inches(TITLE_TOP + TITLE_H + 0.06),
                            Inches(1.5), Inches(0.045))
    ln.fill.solid(); ln.fill.fore_color.rgb = ACCENT; ln.line.fill.background()
    ln.shadow.inherit = False
    if kicker:
        kb = box(s, MARGIN, TITLE_TOP + TITLE_H + 0.16, BODY_W, 0.34)
        kb.text_frame.word_wrap = True
        para(kb.text_frame, [(kicker, {"color": MUTED})], 14, first=True,
             space_after=0)
    return s


def bullets(s, items, top=BODY_TOP, size=17, width=BODY_W, left=MARGIN, gap=9):
    """items: str (bullet) | ('', ...) blank | ('#', text) sub-note."""
    tb = box(s, left, top, width, BODY_BOTTOM - top)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = 0
    first = True
    for it in items:
        if it == "":
            para(tf, [(" ", {})], 6, first=first, space_after=0); first = False
            continue
        sub = isinstance(it, tuple) and it[0] == "#"
        content = it[1] if isinstance(it, tuple) else it
        runs = [("▪   ", {"color": ACCENT, "bold": True})] if not sub else [("      ", {})]
        runs += content if isinstance(content, list) else [(content, {})]
        p = para(tf, runs, size - (2 if sub else 0), first=first, space_after=gap)
        if sub:
            for r in p.runs:
                r.font.color.rgb = MUTED
        first = False
    return tb


def table(s, rows, col_w, top, size=13, head_size=13, row_h=0.40, head_h=0.42,
          aligns=None, mono_cols=(), left=MARGIN):
    """rows[0] is the header. col_w in inches, summing to <= BODY_W."""
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
            cell.margin_left = cell.margin_right = Inches(0.09)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            cell.fill.solid()
            cell.fill.fore_color.rgb = (ACCENT if r == 0
                                        else (WHITE if r % 2 else LIGHT))
            tf = cell.text_frame
            tf.word_wrap = True
            runs = val if isinstance(val, list) else [(str(val), {})]
            fnt = MONO if c in mono_cols and r > 0 else SANS
            sz = head_size if r == 0 else size
            p = para(tf, runs, sz, first=True, space_after=0, line=1.05, font=fnt)
            p.alignment = (PP_ALIGN.LEFT if aligns is None
                           else {"l": PP_ALIGN.LEFT, "c": PP_ALIGN.CENTER,
                                 "r": PP_ALIGN.RIGHT}[aligns[c]])
            if r == 0:
                for run in p.runs:
                    run.font.bold = True
                    run.font.color.rgb = WHITE
    assert top + total_h <= H - 0.25, f"table overflows: {top + total_h:.2f}in"
    return shape


def rawline(s, segments, top, height=0.78, ideal=17, label=None, tint=LIGHT):
    """One unbroken monospace line in a tinted band. segments: [(text, color)]."""
    bg = s.shapes.add_shape(1, Inches(MARGIN), Inches(top), Inches(BODY_W), Inches(height))
    bg.fill.solid(); bg.fill.fore_color.rgb = tint
    bg.line.color.rgb = RULE; bg.line.width = Pt(0.75)
    bg.shadow.inherit = False

    text = "".join(t for t, _ in segments)
    size = fit(text, BODY_W - 0.45, ideal, mono=True)
    tb = box(s, MARGIN + 0.16, top + 0.04, BODY_W - 0.32, height - 0.08)
    tf = tb.text_frame
    tf.word_wrap = False
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    para(tf, [(t, {"color": c, "font": MONO, "bold": c is not INK})
              for t, c in segments], size, first=True, space_after=0)
    if label:
        lb = box(s, MARGIN, top - 0.30, BODY_W, 0.28)
        para(lb.text_frame, label, 13, first=True, space_after=0)
    return size


def note(s, runs, top=None, size=13.5):
    top = top if top is not None else BODY_BOTTOM - 0.05
    tb = box(s, MARGIN, top, BODY_W, 0.5)
    tb.text_frame.word_wrap = True
    para(tb.text_frame, runs, size, first=True, space_after=0)


def wire(s, sender, receiver, endpoint, fields, left, top, width,
         accent=ACCENT, fsize=12.5):
    """A labelled panel showing exactly what travels on one hop.

    fields: list of (name, description). Rendered name-then-description so
    the payload reads as a field list, not prose.
    """
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
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    widest = max(len(n) for n, _ in fields)
    for i, (name, desc) in enumerate(fields):
        pad = name.ljust(widest + 2)
        line = pad + desc
        sz = min(fsize, fit(line, width - 0.30, fsize, mono=True))
        para(tf, [(pad, {"font": MONO, "bold": True, "color": INK}),
                  (desc, {"font": MONO, "color": MUTED})],
             sz, first=(i == 0), space_after=2.5, line=1.0)
    return h


def notes(s, text):
    s.notes_slide.notes_text_frame.text = text


B = {"bold": True}
def M(c=INK):  return {"font": MONO, "color": c, "size": 15}


# ------------------------------------------------------------------- 1. title
s = prs.slides.add_slide(BLANK)
bar = s.shapes.add_shape(1, Inches(0), Inches(0), Inches(0.34), Inches(H))
bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT; bar.line.fill.background()
bar.shadow.inherit = False
tb = box(s, 1.15, 2.35, 11.2, 3.0)
tf = tb.text_frame; tf.word_wrap = True
para(tf, [("Privacy-Preserving Remote Attestation", B)], 42, first=True, space_after=14)
para(tf, [("How a Verifier can trust a machine it is never allowed to see",
           {"color": ACCENT})], 21, space_after=26)
para(tf, [("CHARRA-v2   ·   proof of concept", {"color": MUTED})], 15)
notes(s, "Every value in this deck is real output from one run. Nothing is illustrative.")

# ------------------------------------------------------------------- 2. roles
s = slide("The four roles", "Four processes, four binaries. The Attester and the RP each hold their own TPM.")
table(s, [
    ["Role", "What it does"],
    [[("Attester", B)], "Holds a TPM. Measures every file it loads into an IMA log."],
    [[("Relying Party (RP)", B)], "Collects the Attester's evidence, redacts it, vouches for the result with its own TPM."],
    [[("Verifier", B)], "Appraises the redacted evidence and votes YES / NO."],
    [[("Trust Manager", B)], "Tells the RP which Verifiers to use this cycle."],
], col_w=[3.1, 9.03], top=2.25, size=15, head_size=14, row_h=0.66, head_h=0.44)
note(s, [("The RP is the privacy boundary. ", B), ("Everything sensitive stops there.", {})], top=5.55)

# --------------------------------------------------------------- 3. problem
s = slide("Classical remote attestation leaks")
bullets(s, [
    "To prove a machine booted correctly, the Verifier needs two things:",
    "",
    [("A TPM quote", B), (" — signed PCR values, unforgeable. A few hundred bytes, and it reveals nothing.", {})],
    [("The event log", B), (" — the list of measurements that produced those PCR values.", {})],
    "",
    [("The log is the problem.", {"bold": True, "color": RED}),
     ("  The Verifier has to replay it to check the quote, so classically it must be sent in full — every file path the machine loaded.", {})],
], top=1.55, size=18)

# ------------------------------------------------------- 4. what a log leaks
s = slide("What one log actually discloses", "The first paths from a real Attester log")
tb = box(s, MARGIN, 1.95, BODY_W, 2.5)
tf = tb.text_frame; tf.word_wrap = False
for i, p in enumerate([
        "/usr/lib/systemd/systemd",
        "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        "/usr/lib/aarch64-linux-gnu/systemd/libsystemd-core-259.so",
        "/etc/ld.so.cache",
        "/usr/lib/aarch64-linux-gnu/libcrypto.so.3"]):
    para(tf, [(p, {"font": MONO, "color": RED})], 16, first=(i == 0), space_after=5)
note(s, [("Ten lines give away the CPU architecture (", {}), ("aarch64", {"font": MONO}),
         ("), the init system, the exact library set and ", {}), ("systemd 259", {"font": MONO}),
         (" — enough to look up known vulnerabilities against that build.", {})], top=4.75, size=16)
note(s, [("This is what must never reach a third-party Verifier.", {"bold": True, "color": RED})], top=5.65, size=17)

# ------------------------------------------------------------ 5. five steps
s = slide("The protocol, in five steps")
table(s, [
    ["#", "Step", "Between", "Share of cycle"],
    ["1", [("discoverVerifiers", {"font": MONO})], "RP ↔ Trust Manager", "0.01 %"],
    ["2", [("getEvidence", {"font": MONO})], "RP ↔ Attester", "6.5 %"],
    ["3", [("appraiseEvidence_a", {"font": MONO})], "RP, locally", "0.03 %"],
    ["4", [("prepareEvidence_r", {"font": MONO, "bold": True, "color": RED})], "RP + its own TPM",
     [("86.8 %", {"bold": True, "color": RED})]],
    ["5", [("submitAndCollect", {"font": MONO})], "RP ↔ N Verifiers", "6.7 %"],
], col_w=[0.7, 4.0, 4.4, 3.03], top=1.75, size=15, head_size=14, row_h=0.55,
   aligns=["c", "l", "l", "c"])
note(s, [("Step 4 is where privacy is created", {"bold": True, "color": RED}),
         (" — and it is 87 % of the time an attestation cycle takes.", {})], top=5.45, size=17)

# ------------------------------------------------ 6. step 1 discoverVerifiers
s = slide("Step 1 — discoverVerifiers", "The RP asks the Trust Manager which Verifiers to use this cycle.")
wire(s, "RP", "Trust Manager", "/get_verifiers", [
    ("verifier_ids[]", "which Verifier IDs to resolve"),
], left=MARGIN, top=2.10, width=5.85)
wire(s, "Trust Manager", "RP", "", [
    ("verifiers[]", "one entry per ID that was found:"),
    ("  ip_address", "IPv4 string"),
    ("  port_number", "the port it listens on"),
], left=6.85, top=2.10, width=5.88)
note(s, [("The response may carry ", {}), ("fewer", B),
         (" entries than were requested — an ID missing from the Trust Manager's ", {}),
         ("verifiers_config.txt", {"font": MONO}), (" simply does not come back, so the RP must never assume it got them all.", {})],
     top=4.25, size=14)

# ------------------------------------------------------- 7. step 2 getEvidence
s = slide("Step 2 — getEvidence", "The RP challenges the Attester. Its TPM answers.")
wire(s, "RP", "Attester", "/attest", [
    ("nonce", "20 B, the RP's challenge"),
    ("pcr_selections", "which PCRs to quote — 0-7, 10"),
    ("sig_key_id", "which AK to sign with"),
], left=MARGIN, top=1.95, width=5.85)
wire(s, "Attester", "RP", "", [
    ("attestation_data", "Quote_a — TPMS_ATTEST, 133 B"),
    ("tpm2_signature", "AK_a's signature over it"),
    ("tpm2_public_key", "AK_a — 616 B TPM2B_PUBLIC"),
    ("event_log", "log_a — 4728 B, REAL PATHS"),
], left=6.85, top=1.95, width=5.88, accent=RED)
note(s, [("The nonce is not a field of Quote_a — the TPM seals it ", {}), ("inside", B),
         (" the structure it signs, as ", {}), ("extraData", {"font": MONO}), (".", {})], top=4.05, size=14)
note(s, [("log_a", {"font": MONO, "bold": True, "size": 18, "color": RED}),
         (" arrives at the RP. It goes no further.", {"bold": True, "color": RED})], top=4.60, size=18)

# ----------------------------------------- 7. step 3: what the RP does with Quote_a
s = slide("Step 3 — what the RP does with Quote_a", "Before redacting anything, the RP runs six checks on what it received.")
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
], col_w=[6.0, 6.13], top=2.02, size=13.5, head_size=13.5, row_h=0.44, head_h=0.40)
wire(s, "RP", "Attester", "/attestation_result", [
    ("accepted", "1 = evidence accepted, 0 = rejected"),
    ("reason", "human-readable, for the Attester's log"),
], left=MARGIN, top=5.35, width=6.5)

# --------------------------------------------------------- 8. step 4 redact
s = slide("Step 4 — redaction: the privacy step")
bullets(s, [[("An ", {}), ("ima-ng", {"font": MONO}), (" entry has five fields. Exactly ", {}), ("one", B), (" of them is sensitive.", {})]],
        top=1.55, size=18)
rawline(s, [("PCR  |  template_digest  |  template_name  |  file digest  |  ", INK),
            ("pathname", RED)], top=2.25, height=0.72, ideal=19)
bullets(s, [[("The RP replaces the pathname with", {})]], top=3.30, size=18)
rawline(s, [("SHA256( pathname ‖ salt )", ACCENT)], top=3.90, height=0.75, ideal=22)
note(s, [("a fresh 32-byte random salt ", {}), ("per entry", B), (", never transmitted.", {})],
     top=4.95, size=17)

# ------------------------------------------------- 9. log_a raw + breakdown
ELIDE = "…"
s = slide("Example — one IMA log entry, as the Attester wrote it",
          f"The whole line, unbroken. Long hex fields are elided in the middle ({ELIDE}) so it fits at this size.")
rawline(s, [("10  ", INK), (f"b82f9269{ELIDE}ad8bc104", INK), ("  ima-ng  ", INK),
            (f"sha256:61cee375{ELIDE}becfd541", INK), ("  ", INK),
            ("/usr/lib/systemd/systemd", RED)],
        top=2.05, height=0.80, ideal=18)
table(s, [
    ["Field", "Value", "What it is"],
    ["PCR", "10", "the register this entry extends"],
    ["template_digest", f"b82f9269{ELIDE}ad8bc104", "SHA256 of the two fields below"],
    ["template_name", "ima-ng", "the log format"],
    ["file digest", f"sha256:61cee375{ELIDE}becfd541", "hash of the file's contents"],
    [[("pathname", {"bold": True, "color": RED})],
     [(f"/usr/lib/systemd/systemd", {"bold": True, "color": RED})],
     [("where the file lives — sensitive", {"bold": True, "color": RED})]],
], col_w=[2.7, 5.2, 4.23], top=3.25, size=13, head_size=13, row_h=0.52, mono_cols=(0, 1))

# ------------------------------------------------- 10. log_r raw + breakdown
s = slide("The same entry, after redaction",
          "One field changed on purpose; one changed as a consequence.")
rawline(s, [("10  ", INK), (f"b0c30a6d{ELIDE}32fa7e6f", ACCENT), ("  ima-ng  ", INK),
            (f"sha256:61cee375{ELIDE}becfd541", INK), ("  ", INK),
            (f"4c28124b{ELIDE}0616dea8", GREEN)],
        top=2.05, height=0.80, ideal=18)
table(s, [
    ["Field", "Value", "Versus log_a"],
    ["PCR", "10", "identical"],
    ["template_digest", f"b0c30a6d{ELIDE}32fa7e6f",
     [("recomputed", {"bold": True, "color": ACCENT}), (" — it must equal SHA256(template_data)", {})]],
    ["template_name", "ima-ng", "identical"],
    ["file digest", f"sha256:61cee375{ELIDE}becfd541",
     [("byte-identical", {"bold": True}), (" — kept on purpose", {})]],
    [[("pathname", {"bold": True, "color": GREEN})],
     [(f"4c28124b{ELIDE}0616dea8", {"bold": True, "color": GREEN})],
     [("replaced", {"bold": True, "color": GREEN}), (" — always 32 bytes, whatever the path", {})]],
], col_w=[2.7, 5.2, 4.23], top=3.25, size=13, head_size=13, row_h=0.52, mono_cols=(0, 1))

# ------------------------------------------------------ 11. why file digest
s = slide("Why the file digest is kept")
bullets(s, [
    [("The content hash stays so the ", {}), ("Verifier's whitelist / blacklist check", B),
     (" remains possible at all.", {})],
    "",
    [("It says ", {}), ("some", B), (" file hashed to this value.", {})],
    [("It never says ", {}), ("where", B), (" that file lives.", {})],
    "",
    [("So the Verifier can reject a known-bad binary without ever learning a single path — and it checks for itself, rather than trusting that the RP already did.", {})],
    "",
    [("Redacting the digest too would throw away the appraisal without buying any privacy.", {"color": MUTED})],
], top=1.70, size=17)

# --------------------------------------------------------------- 12. salt
s = slide("Why there is a salt", "Redacting the same log twice gives different output")
rawline(s, [("run 1    98a07f3a897b44ce30501d26322aa41e…", INK)], top=2.05, height=0.62, ideal=17)
rawline(s, [("run 2    e9c9ca904fc9a0c66ee4e9082db6e275…", INK)], top=2.75, height=0.62, ideal=17)
bullets(s, [
    [("Irreversible.", B), ("  An unsalted SHA256(path) is precomputable — the whole log would reverse in seconds against a dictionary.", {})],
    [("Not correlatable.", B), ("  Two entries with the same path redact differently, so a Verifier cannot count or link repeated paths.", {})],
], top=3.75, size=16, gap=12)

# ------------------------------------------------------- 13. the consequence
s = slide("The consequence that shapes everything")
bullets(s, [
    [("Because ", {}), ("template_digest", {"font": MONO}), (" is recomputed, ", {}),
     ("log_r can never replay to the Attester's sealed pcrDigest", {"bold": True, "color": RED}),
     (" — mathematically, not by policy.", {})],
    "",
    [("So the Attester's TPM cannot vouch for the redacted log. Something else must.", {})],
    "",
    [("The RP replays ", {}), ("log_r", {"font": MONO, "bold": True}),
     (" into PCR 23 of its own TPM and quotes it.", B)],
], top=1.60, size=18)
note(s, [("The guarantee becomes:  ", {}),
         ("“the RP vouches for this, anchored by the RP's own TPM.”", {"bold": True, "color": ACCENT})],
     top=5.30, size=18)

# ------------------------------------------------------------- 14. step 5
s = slide("Step 5 — the Verifier challenges first", "Every round starts with the Verifier drawing its own freshness challenge.")
wire(s, "RP", "Verifier", "/nonce", [
    ("(empty request)", "just: give me a challenge"),
], left=MARGIN, top=2.05, width=5.85)
wire(s, "Verifier", "RP", "", [
    ("challenge_nonce", "32 B, drawn by THIS Verifier"),
], left=6.85, top=2.05, width=5.88)
bullets(s, [
    [("The RP must sign ", {}), ("this", B), (" value, not one it chose itself — otherwise it could replay an old signature over a nonce it already knew would match.", {})],
    [("Every Verifier draws its own, which is what keeps one Verifier's vote from being counted in another's slot.", {})],
    [("/nonce is also the first request of every round, so it is what marks a new round in the Verifier's log.", {"color": MUTED})],
], top=3.55, size=15, gap=11)

# ------------------------------------------- 14b. what the RP submits
s = slide("What the RP submits", "The whole /appraise payload. This is every byte the Verifier ever sees.")
wire(s, "RP", "Verifier", "/appraise", [
    ("rp_attestation_data", "Quote_r — PCR 23, 145 B"),
    ("rp_signature", "AK_r's signature over it"),
    ("rp_public_key", "AK_r — 616 B TPM2B_PUBLIC"),
    ("log_r", "the redacted log — paths hashed"),
    ("attester_nonce", "the 20 B the RP sent the Attester"),
    ("attestation_data", "Quote_a, forwarded verbatim"),
    ("tpm2_signature", "AK_a's signature over it"),
    ("tpm2_public_key", "AK_a — so the Verifier can check it"),
    ("trust_mode", "qualify | tee | zk"),
    ("tee_* / zk_proof", "only the fields that mode needs"),
], left=MARGIN, top=1.90, width=8.6)
bullets(s, [
    [("log_a", {"font": MONO, "bold": True, "color": RED}), (" is absent.", B),
     (" Forwarding it would defeat the redaction entirely.", {})],
    "",
    [("Quote_a", {"font": MONO, "bold": True}), (" travels ", {}), ("verbatim", B),
     (" — the Verifier checks the Attester's signature itself rather than taking the RP's word for it.", {})],
], top=1.95, size=12.5, width=3.6, left=9.4, gap=6)

# --------------------------------------------------------- 15. two bundles
s = slide("The two evidence bundles, side by side")
table(s, [
    ["", "Attester → RP", "RP → Verifier"],
    ["Quote", [("Quote_a", {"font": MONO}), (" — 133 B", {})], [("Quote_r", {"font": MONO}), (" — 145 B", {})]],
    ["signed by", "AK_a — the Attester's TPM", [("AK_r — the RP's own TPM", B)]],
    ["PCRs quoted", "0–7, 10 — the boot chain", "23 — the RP's replay register"],
    ["nonce inside", "20 B, chosen by the RP", "32 B, chosen by that Verifier"],
    [[("Event log", B)],
     [("log_a", {"font": MONO, "bold": True, "color": RED}), (" — real paths", {"bold": True, "color": RED})],
     [("log_r", {"font": MONO, "bold": True, "color": GREEN}), (" — paths hashed", {"bold": True, "color": GREEN})]],
    ["also carried", "—", [("Quote_a", {"font": MONO}), (", forwarded verbatim", {})]],
], col_w=[2.5, 4.85, 4.78], top=1.55, size=13.5, head_size=13.5, row_h=0.50)
note(s, [("The Verifier receives ", {}), ("both", B), (" quotes and checks both. Only the log is substituted — ", {}),
         ("log_a", {"font": MONO}), (" → ", {}), ("log_r", {"font": MONO}),
         (" — and that substitution is the entire privacy mechanism.", {})], top=5.15, size=15.5)

# ------------------------------------------- 15b. what the Verifier checks
s = slide("What the Verifier checks", "It verifies both quotes — the RP's, and the Attester's, forwarded through the RP.")
tbx = box(s, MARGIN, 1.60, 6.0, 0.4)
para(tbx.text_frame, [("Step 3a — Quote_r", {"bold": True, "color": ACCENT})], 18, first=True, space_after=0)
bullets(s, [
    "1.  AK_r is in the trust anchor",
    "1b.  the RP is qualified — or its TEE / ZK proof holds",
    [("2.  ", {}), ("Quote_r", {"font": MONO}), ("'s signature, under AK_r", {})],
    "3.  the nonce is the one this Verifier issued",
    [("4.  replaying ", {}), ("log_r", {"font": MONO}), (" reproduces the quote's ", {}), ("pcrDigest", {"font": MONO})],
    [("5.  every entry's ", {}), ("template_digest", {"font": MONO}), (" hashes its own ", {}),
     ("template_data", {"font": MONO})],
    [("6.  every file digest in ", {}), ("log_r", {"font": MONO}),
     (", against its own whitelist / blacklist", {})],
], top=2.10, size=13, width=6.0, left=MARGIN, gap=6)

tbx = box(s, 6.95, 1.60, 5.75, 0.4)
para(tbx.text_frame, [("Step 3b — Quote_a", {"bold": True, "color": ACCENT})], 18, first=True, space_after=0)
bullets(s, [
    "1.  AK_a is in the trust anchor",
    [("2.  ", {}), ("Quote_a", {"font": MONO}), ("'s signature, under AK_a", {})],
    "3.  the nonce the RP says it sent",
], top=2.12, size=13.5, width=5.75, left=6.95, gap=8)

# ------------------------------------------------- 15c. the signed verdict
s = slide("The verdict comes back signed", "Not a string — a vote bound to this round and this evidence.")
wire(s, "Verifier", "RP", "/appraise response", [
    ("accepted", "the vote itself"),
    ("challenge_nonce", "the 32 B THIS Verifier issued"),
    ("evidence_digest", "SHA-256 of the submission appraised"),
    ("signed_at", "wall clock — an assertion, not proof"),
    ("signature", "over the payload bytes as received"),
], left=MARGIN, top=1.85, width=6.6)
bullets(s, [
    [("challenge_nonce", {"font": MONO, "bold": True}), ("  — the 32 bytes ", {}), ("this", B),
     (" Verifier issued this round. Stops replay across rounds, and stops a vote landing in another Verifier's slot.", {})],
    [("evidence_digest", {"font": MONO, "bold": True}), ("  — SHA-256 over the submission appraised, so a YES cast over one submission cannot be pasted onto another.", {})],
    [("signature", {"font": MONO, "bold": True}), ("  — under ", {}), ("keys/verifier.der", {"font": MONO}), (". The RP checks all three before counting the vote.", {})],
], top=1.90, size=12.5, width=5.3, left=7.45, gap=8)
note(s, [("Before this, the answer was the ASCII string ", {}), ("\"Attestation successful!\"", {"font": MONO}),
         (" over plain UDP — anything that could reach the RP's socket could vote. Signing raises that bar to ", {}),
         ("holds keys/verifier.der", {"font": MONO}), (".", {})], top=4.55, size=13.5)

# ------------------------------------------------------- 15d. majority vote
s = slide("The majority vote", "The RP tallies every Verifier it was configured to use.")
rawline(s, [("if (2 * num_true > num_verifiers)   →   attestation successful", ACCENT)],
        top=1.95, height=0.70, ideal=18)
bullets(s, [[("Strict majority, and ", {}), ("fail-closed", {"bold": True, "color": RED}),
             (": every vote starts as NO. A Verifier counts as a pass only if it appraised the evidence ", {}),
             ("and", B), (" accepted it. Everything else is a NO:", {})]], top=2.95, size=15)
table(s, [
    ["Counts as NO", "Why"],
    ["any failed check in Step 3a or 3b", "the evidence did not hold up"],
    ["an unreachable Verifier, or a timeout", "no vote was cast"],
    ["evidence we never managed to send", "the exchange did not happen"],
    ["a verdict whose signature or nonce fails", "we have no vote we can count"],
], col_w=[6.0, 6.13], top=3.95, size=13.5, head_size=13.5, row_h=0.45)
note(s, [("Not completing the exchange is never a reason to accept.", {"bold": True})], top=6.15, size=15)

# ---------------------------------------------------- 16. remaining question
s = slide("The question that remains", "The Verifier trusts that the RP vouched for this log. It still cannot see whether the RP redacted honestly.")
bullets(s, [
    [("A malicious RP could hide a blacklisted file rather than merely hiding its path.", {})],
    [("This PoC implements ", {}), ("all three answers", B), (", and you choose one at launch — ", {}),
     ("TRUST_MODE=qualify | tee | zk", {"font": MONO, "bold": True}),
     (" — which sets the RP and every Verifier together.", {})],
], top=2.02, size=15, gap=7)
table(s, [
    ["Mode", "What it proves", "Over how much log", "Cost"],
    [[("qualify", {"font": MONO, "bold": True})], "the redaction output",
     "40-entry synthetic log", "238 ms per grant window"],
    [[("tee", {"font": MONO, "bold": True})], "the code doing the redaction",
     [("3 source files — ", {}), ("log-independent", B)], "≈ 24 ms per Verifier"],
    [[("zk", {"font": MONO, "bold": True})], "the redaction itself, in zero knowledge",
     [("33-entry circuit ceiling", B)], "≈ 4.1 s per cycle"],
], col_w=[1.5, 4.4, 3.3, 2.93], top=3.00, size=13, head_size=13, row_h=0.58)
note(s, [("The attestation log here is ", {}), ("33 entries", B), (". ", {}),
         ("qualify", {"font": MONO}), (" is priced over a 40-entry log the Verifier invents, not the real one; ", {}),
         ("tee", {"font": MONO}), (" hashes source files, so its cost does not move with log size; ", {}),
         ("zk", {"font": MONO}), (" pays for its circuit's compiled ceiling whatever the fill — about ", {}),
         ("82 ms and 35 MiB per entry", B), (".", {})], top=5.28, size=12.5)
note(s, [("Both roles must be set the same way. A mismatch is reported: the Verifier votes NO and logs ", {}),
         ("MODE MISMATCH", {"font": MONO}), (".", {})], top=6.20, size=13)

# ---------------------------------------------- 17. learns / never learns
s = slide("What the Verifier learns — and never learns")
tbx = box(s, MARGIN, 1.55, 5.9, 0.4)
para(tbx.text_frame, [("Learns", {"bold": True, "color": ACCENT})], 19, first=True, space_after=0)
bullets(s, [
    "the machine's PCR values are as expected",
    "every measured file's content digest is on the whitelist, none blacklisted",
    "how many events were measured",
    "the RP vouches for all of it, under its own TPM key",
], top=2.10, size=15, width=5.9, left=MARGIN, gap=10)

tbx = box(s, 7.0, 1.55, 5.7, 0.4)
para(tbx.text_frame, [("Never learns", {"bold": True, "color": GREEN})], 19, first=True, space_after=0)
bullets(s, [
    "any file path or filename",
    "which entries live in the same directory",
    "whether the same path appears twice",
    "anything about the Attester's identity beyond AK_a",
], top=2.10, size=15, width=5.7, left=7.0, gap=10)

# =================================================== MEASUREMENTS ===========

s = prs.slides.add_slide(BLANK)
bar = s.shapes.add_shape(1, Inches(0), Inches(0), Inches(0.34), Inches(H))
bar.fill.solid(); bar.fill.fore_color.rgb = ACCENT; bar.line.fill.background()
bar.shadow.inherit = False
tb = box(s, 1.15, 3.0, 11.0, 1.6)
para(tb.text_frame, [("What it costs", {"bold": True})], 40, first=True, space_after=12)
para(tb.text_frame, [("Measured, not estimated", {"color": MUTED})], 20)

# ------------------------------------------------- 18. where the time goes
s = slide("Where the time goes", "One attestation cycle, steady state, a single Verifier. Each operation has its own timer.")
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
], col_w=[3.5, 4.3, 2.3, 2.03], top=2.15, size=14, head_size=13, row_h=0.48,
   aligns=["l", "l", "r", "r"])
note(s, [("The five sum to within ", {}), ("0.004 %", B), (" of the measured total — nothing of consequence falls outside them. The bottleneck is the RP replaying ", {}),
         ("log_r", {"font": MONO}), (" into its TPM.", {})], top=5.90, size=14)

# ------------------------------------------------------- 19. verifier scaling
s = slide("Scaling with the number of Verifiers", "Least-squares fit over a 1..5 sweep, 10 runs at each step")
table(s, [
    ["Verifiers", "1", "2", "3", "4", "5"],
    ["Total cycle", "3251 ms", "3484 ms", "3671 ms", "3894 ms", "4097 ms"],
], col_w=[2.6, 1.906, 1.906, 1.906, 1.906, 1.906], top=1.95, size=14, head_size=14,
   row_h=0.46, aligns=["l", "c", "c", "c", "c", "c"])
bullets(s, [
    [("Fixed cost:  ", B), ("3048.9 ms", {"font": MONO, "bold": True}),
     ("  — the four operations that happen once per cycle, whatever the Verifier count.", {})],
    [("Marginal cost:  ", B), ("210.2 ms per Verifier", {"font": MONO, "bold": True}),
     ("  — entirely ", {}), ("submitAndCollect", {"font": MONO}), (", the only per-Verifier operation.", {})],
], top=3.15, size=16, gap=13)
note(s, [("Within that marginal cost, the growth is overwhelmingly the extra ", {}),
         ("Quote_r", {"font": MONO}), (" the RP must produce for each Verifier's nonce — TPM queueing, not appraisal work. A Verifier's own appraisal costs about 1 ms.", {})],
     top=4.95, size=14)

# ------------------------------------------------------ 20. three modes cost
s = slide("What each trust mode costs",
          "Total time for one attestation cycle. Five measured cycles at each Verifier count, over the 33-entry log.")
table(s, [
    ["Verifiers", "1", "2", "3", "4", "5"],
    [[("qualify", {"font": MONO, "bold": True})], "3225 ms", "3411 ms", "3609 ms", "3791 ms", "3988 ms"],
    [[("tee", {"font": MONO, "bold": True})], "3283 ms", "3456 ms", "3686 ms", "3918 ms", "4124 ms"],
    [[("zk", {"font": MONO, "bold": True, "color": RED})],
     [("7759 ms", {"color": RED})], [("7938 ms", {"color": RED})], [("8053 ms", {"color": RED})],
     [("8340 ms", {"color": RED})], [("8549 ms", {"color": RED})]],
], col_w=[1.83, 2.06, 2.06, 2.06, 2.06, 2.06], top=1.92, size=13.5, head_size=13,
   row_h=0.44, head_h=0.40, aligns=["l", "r", "r", "r", "r", "r"])

hb = box(s, MARGIN, 3.88, BODY_W, 0.34)
para(hb.text_frame, [("Where the extra cost lands", {"bold": True, "color": ACCENT}),
                     ("   — and it is the opposite place for each", {"color": MUTED})],
     16, first=True, space_after=0)

table(s, [
    ["Mode", "Extra, once per cycle", "Extra, per Verifier"],
    [[("qualify", {"font": MONO, "bold": True})],
     [("— the baseline. The handshake is a no-op while the grant holds.", {})], "—"],
    [[("tee", {"font": MONO, "bold": True})], "nothing measurable",
     [("+ 24 ms", {"bold": True}), (" — one RSA signature per Verifier nonce", {})]],
    [[("zk", {"font": MONO, "bold": True})],
     [("+ 4.5 s", {"bold": True, "color": RED}), (" — one proof, reused by all", {})], "nothing measurable"],
], col_w=[1.9, 5.4, 4.83], top=4.30, size=13, head_size=13, row_h=0.44, head_h=0.38)

nb = box(s, MARGIN, 6.05, BODY_W, 0.9); nb.text_frame.word_wrap = True
para(nb.text_frame, [("So the choice depends on Verifier count. ", {"bold": True}),
                     ("tee", {"font": MONO}), (" costs 1.8 % over ", {}), ("qualify", {"font": MONO}),
                     (" at one Verifier and 3.4 % at five, because it pays per Verifier. ", {}),
                     ("zk", {"font": MONO}), (" costs roughly 2× at any count, because it pays once per cycle.", {})],
     13, first=True, space_after=0)

# ------------------------------------------- 21b. the /qualify handshake
s = slide("The /qualify handshake",
          "The default mode. A redaction competence test: the Verifier invents a log and checks the RP cleans it exactly as it would.")

bullets(s, [
    [("1.", B), ("  The Verifier draws a seed and a salt, generates a ", {}),
     ("40-entry", B), (" synthetic log, and redacts it ", {}), ("itself", B), (" — the golden answer.", {})],
    [("2.", B), ("  The RP fetches the challenge and redacts the same log with the same salt.", {})],
    [("3.", B), ("  The RP signs ", {}), ("(redacted log ‖ salt)", {"font": MONO}), (" with AK_r and submits it.", {})],
    [("4.", B), ("  The Verifier checks the signature, then compares the two redactions ", {}),
     ("byte for byte", B), (".", {})],
    [("5.", B), ("  Match → a grant, valid 180 s, shared with every Verifier through ", {}),
     ("qualified_rps.txt", {"font": MONO}), (".", {})],
], top=1.95, size=12.5, width=6.05, left=MARGIN, gap=6)

wire(s, "Verifier", "RP", "/qualify", [
    ("challenge_log", "40 entries, 5210 B, synthetic"),
    ("salt", "32 B — the Verifier's own"),
], left=6.90, top=1.98, width=5.83, fsize=11.5)
wire(s, "RP", "Verifier", "/qualify_submit", [
    ("submitted_redacted_log", "the RP's answer"),
    ("rp_signature", "AK_r over (answer || salt)"),
    ("rp_public_key", "AK_r, checked in the anchor"),
], left=6.90, top=3.28, width=5.83, fsize=11.5)
wire(s, "Verifier", "RP", "", [
    ("qualified", "1 = granted, 0 = refused"),
    ("expires_at", "epoch seconds the grant runs to"),
], left=6.90, top=4.92, width=5.83, fsize=11.5)

nb = box(s, MARGIN, 4.48, 6.05, 0.95); nb.text_frame.word_wrap = True
para(nb.text_frame, [("The salt travels here", {"bold": True, "color": RED}),
         (" — the one exception to “never transmitted”, and safe only because this log is fabricated. Both sides must produce identical bytes, which a fresh salt would make impossible. Real evidence is always redacted with a salt the RP alone knows.", {})],
     12.5, first=True, space_after=0)
cb = box(s, MARGIN, 5.62, 6.05, 1.2); cb.text_frame.word_wrap = True
para(cb.text_frame, [("Costs ", {}), ("238 ms", B), (", of which ", {}), ("210 ms", B),
         (" is one TPM signature. Paid only when the grant has lapsed — re-checking a held grant costs ", {}),
         ("0.023 ms", B), (". It proves the redaction ", {}), ("output", B), (", never which code produced it.", {})],
     12.5, first=True, space_after=0)

# ------------------------------------------------- 22b. TEE mode
s = slide("TEE mode — the real thing, and what this PoC simulates",
          "A Trusted Execution Environment can prove which code is running. Here that primitive is simulated in software.")

hb = box(s, MARGIN, 1.92, 5.9, 0.36)
para(hb.text_frame, [("A real TEE", {"bold": True, "color": ACCENT}),
                     ("   — SGX, Nitro, TrustZone", {"color": MUTED})], 17, first=True, space_after=0)
bullets(s, [
    "Hardware-isolated: the OS, the hypervisor and root cannot see inside.",
    [("The loader ", {}), ("measures the code image", B),
     (" — the hardware computes that hash, so the enclave cannot lie about it.", {})],
    [("The signing key ", {}), ("never leaves the chip", B), (" and chains to a vendor root.", {})],
    [("Result: an unforgeable “this exact code is running, and here is a value it attests”.", {"color": MUTED})],
], top=2.38, size=12.5, width=5.9, left=MARGIN, gap=7)

hb = box(s, 6.95, 1.92, 5.78, 0.36)
para(hb.text_frame, [("This PoC", {"bold": True, "color": RED}),
                     ("   — src/core/TEE.c", {"color": MUTED, "font": MONO})], 17, first=True, space_after=0)
bullets(s, [
    [("“The enclave image” → ", {}), ("SHA-256 over 3 source files", B), (", 71 KB, in a fixed order.", {})],
    [("“The key that never leaves” → an RSA keypair in that file's static memory, generated once per process, never exported.", {})],
    [("No vendor root. Instead ", {}), ("AK_r certifies the TEE's public key", B),
     (", and AK_r is in the trust anchor.", {})],
    [("Chain: trust anchor → AK_r → TEE key → document.", {"color": MUTED})],
], top=2.38, size=12.5, width=5.78, left=6.95, gap=7)

table(s, [
    ["The document's two fields", "What it answers", "Value"],
    ["file_hash", "which code ran", "SHA256(3 source files)"],
    ["report_data", "on which data, in which round", "SHA256(verifier_nonce ‖ pcrdigest_a ‖ log_r)"],
], col_w=[2.5, 3.4, 6.23], top=4.62, size=12.5, head_size=12.5, row_h=0.40,
   head_h=0.36, mono_cols=(0, 2))

nb = box(s, MARGIN, 5.92, BODY_W, 1.0); nb.text_frame.word_wrap = True
para(nb.text_frame, [("What stays broken without real hardware: ", {"bold": True}),
                     ("it hashes source files on disk, not the running binary, and an attacker who runs the genuine code and then lies before signing is out of reach. That is why ", {}),
                     ("tee", {"font": MONO}), (" only ", {}), ("names", {"bold": True}),
                     (" the code, where ", {}), ("zk", {"font": MONO}), (" proves the redaction was actually done correctly.", {})],
     12.5, first=True, space_after=0)

# ------------------------------------------------- 22c. ZK mode explained
s = slide("ZK mode — the real thing, and what this PoC proves",
          "A zero-knowledge proof shows a statement is true without revealing why it is true.")

hb = box(s, MARGIN, 1.92, 5.9, 0.36)
para(hb.text_frame, [("A zero-knowledge proof", {"bold": True, "color": ACCENT}),
                     ("   — in general", {"color": MUTED})], 17, first=True, space_after=0)
bullets(s, [
    [("The prover holds a ", {}), ("secret witness", B),
     ("; the verifier learns only that the statement holds, never the secret.", {})],
    [("Succinct", B), (": the proof stays small and cheap to check however large the computation behind it.", {})],
    [("In production for private payments and rollups — thousands of transactions settled by one small proof.", {})],
    [("Nothing is trusted about the prover; the maths is what convinces.", {"color": MUTED})],
], top=2.38, size=12.5, width=5.9, left=MARGIN, gap=7)

hb = box(s, 6.95, 1.92, 5.78, 0.36)
para(hb.text_frame, [("This PoC", {"bold": True, "color": RED}),
                     ("   — zk/circuit/src/main.nr", {"color": MUTED, "font": MONO})], 17, first=True, space_after=0)
bullets(s, [
    [("The statement: ", {}), ("every cleaned path in log_r commits to a real path", B),
     (" that replays to the Attester's TPM-signed ", {}), ("pcrdigest_a", {"font": MONO}), (".", {})],
    [("Written in ", {}), ("Noir", B), (", 839,117 gates, proved with Barretenberg ", {}), ("UltraHonk", B), (".", {})],
    [("So the RP proves the redaction was done correctly ", {}),
     ("without revealing a single path", B), (".", {})],
    [("Compiled for at most 33 entries — raising that needs a recompile and a new vk.", {"color": MUTED})],
], top=2.38, size=12.5, width=5.78, left=6.95, gap=7)

nb = box(s, MARGIN, 4.75, BODY_W, 1.0); nb.text_frame.word_wrap = True
para(nb.text_frame, [("The proof travels; its public inputs do not. ", {"bold": True}),
                     ("The Verifier rebuilds every one of them itself — commitments and file hashes out of log_r, ", {}),
                     ("pcrdigest_a", {"font": MONO}),
                     (" out of the Quote_a it has already verified. Taking any of them from the RP would let a genuine proof of a fabricated log verify.", {})],
     12.5, first=True, space_after=0)

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
                   "charra_privacy_attestation_slides_v2.pptx")
prs.save(out)
print(f"{len(prs.slides.__iter__.__self__._sldIdLst)} slides -> {out}")

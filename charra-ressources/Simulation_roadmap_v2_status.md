# Simulation Roadmap — Status Report

**What has been built since the starting point**

---

**1) Introduction:**

The original `Simulation_roadmap` document described the plan for building a
remote attestation simulation system on top of the IETF proof-of-concept
implementation. This document reports what has actually been built since.

Throughout, **"the starting point"** means the codebase as it stood when that
roadmap was written, and **"now"** means the system as it stands today. The two
are compared directly, file by file and symbol by symbol.

Measured across the two:

| | starting point | now |
|---|:--:|:--:|
| Source files in `src/` (`.c` + `.h`) | 35 | 85 |
| Lines of C in `src/` | 8 057 | 17 733 |
| Binaries built | 5 | 6 |
| CoAP resources served | 4 | 7 |
| Marshalled message types (`msg_*_dto`) | 2 | 10 |
| Test suites | 0 | 16 (358 assertions) |

---

**2) Protocols and encoding:**

Unchanged from the roadmap. The system still uses:

- **CoAP** for all communication between roles, over UDP.
- **CBOR** (QCBOR) to marshal every payload.
- **DTLS** support remains present in the code but is **not enabled** — the
  running system logs `DTLS-PSK enabled: false` and `DTLS-RPK enabled: false`.
  The `*.der` raw-public-key material in `keys/` is therefore unused for
  transport today. One of those files has acquired a second, unrelated job:
  `verifier.der` is also the key every Verifier signs its `/appraise` verdict
  with (see 4.5), and that use is independent of whether DTLS is on.

What changed is not the protocols but how much travels over them: 2 marshalled
message types have become 10, and 4 CoAP resources have become 7.

---

**3) What was already implemented at the starting point:**

This is the part of the roadmap that was already complete before any of the work
below, and it is more than the roadmap anticipated. The starting point was
**not** the bare IETF two-party proof of concept. It already contained:

- `relying_party` and `trust_manager` binaries, alongside `attester`,
  `verifier` and `verifier_old`.
- The inverted verifier role the roadmap called for: the Verifier receives
  evidence rather than requesting it, appraises it, and returns a result.
- Three of the four CoAP resources it served: `/nonce`, `/appraise` and
  `/get_verifiers`. The fourth, `/attest`, came from the IETF PoC itself.
- Multi-verifier fan-out with one thread per Verifier, and **majority voting**
  over the returned results.
- The benchmark sweep and statistics code (`calculate_stats`).

In roadmap terms, both staged milestones — "Figure 3" (RP plus multiple
Verifiers) and the trust manager integration — were already reached. The work
since has been of a different kind.

---

**4) What has been implemented since:**

Everything in this section is absent from the starting point and present now;
each item was checked by symbol lookup in both versions.

**4.1 Privacy: log redaction and a second quote.** Previously the Relying Party
forwarded the Attester's evidence as received. It now has
`charra_sdk_redact_ima_log()`,
which rewrites each log entry's path, and `charra_event_log` / IMA log replay
(`charra_replay_ima_log`). Because the redacted log is no longer the log the
Attester measured, the RP cannot forward the Attester's PCR value; it replays
the redacted log into **its own TPM** to rebuild `PCR_r` and signs a second
quote, `Quote_r`, over it (`rp_quote_pcr_with_ak`). **That replay is the single
most expensive operation in the system** — not the quote that follows it, and
not the redaction that necessitates it. See `charra_measurements_v2` for the
figures and **Appendix A** for how the mechanism works.

**4.2 An identity mechanism.** There was none before. There is now a flat trust
anchor, `keys/trusted_keys.txt`, holding the public halves of the two
TPM-resident signing keys, plus `charra_trusted_keys_check()` and a new binary,
`provision_trusted_keys`, to populate it. **Appendix B** explains what this
does and does not establish.

**4.3 A TPM identity for the Relying Party.** Previously the RP used **no TPM at
all**: `src/relying_party.c` contained no `CHARRA_TCTI` reference and no quote
or signing call, because it had no key of its own to prove. Only the Attester
and the old Verifier opened a TPM. The RP now has its own attestation key, so
the two roles are separated: the run scripts start one simulator per role —
Attester on `:2321`, RP on `:2325` — and launch each process with its own
`CHARRA_TCTI` value.

The reason is **impersonation, not key collision.** The two identities use
different templates — the Attester's is the *restricted* quoting key, the RP's
the *unrestricted* `Quote_r` signing key — and `TPM2_CreatePrimary` derives from
the hierarchy seed **and the template**, so even one shared TPM would yield two
distinct keys. The danger is subtler: on a shared TPM the RP's own device can
derive the restricted primary too, which is exactly the key the anchor labels
`attester`. Since `TPM2_Quote` accepts a restricted key, the RP could then
produce a genuine hardware quote that satisfies the Verifier's Step 3b. Nothing
would be forged and nothing would look wrong. That is why
`provision_trusted_keys --role` emits exactly one identity per TPM: one TPM, one
role, one key.

The separation is operational rather than a code change: `RP_TCTI` is a variable
in the run scripts, not in `src/`, where both roles still read the same
`CHARRA_TCTI` environment variable.

**4.4 The RP qualification handshake.** New: `/qualify` and
`/qualify_submit`, implemented by `charra_rp_qualification` and
`charra_synthetic_log`. A Verifier generates a synthetic IMA log — 40 entries in
the measured configuration — redacts it itself to produce a golden answer, and grants the RP a time-limited
qualification only if the RP's redaction of the same log comes out
byte-identical. Grants are recorded per RP fingerprint in a registry every
Verifier reads (`verifier_qualified_rps_is_qualified`). **Appendix B** walks
through the exchange.

**4.5 Signed verdicts.** Verifiers used to return an unauthenticated result.
They now return `charra_verdict`, a signed record binding the verdict to the
challenge nonce, an `evidence_digest` over the exact submission appraised, and a
timestamp. The RP verifies each one; an unverifiable YES counts as a NO. What
each binding stops is set out in **Appendix B**.

**4.6 Policy enforcement.** New: `charra_verify_log_file_hashes_against_policy`,
checking measured file hashes against whitelist and blacklist files. This runs
on the RP only — the Verifiers do not repeat it.

**4.7 A verdict path back to the Attester.** New CoAP resource
`/attest_result`, letting the RP report the outcome to the Attester.

**4.8 Restructuring and tests.** `src/` gained `attester/`, `rp/` and
`verifier/` subdirectories; `verifier.c` shrank from 678 lines to 245 plus 11
files under `src/verifier/`. Six new modules appeared under `src/core/`:
`charra_event_log`, `charra_rp_qualification`, `charra_sdk`,
`charra_synthetic_log`, `charra_trusted_keys`, `charra_verdict`. There were
**no tests at all** before; there are now 16 suites and 358 assertions. That they need
neither a TPM nor the network is not an assumption — the suite was re-run inside
a container started with `--network none` and with `tpm_server` killed, and all
16 suites still reported 358 assertions and 0 failures.

---

**5) Status against the roadmap's questions:**

The roadmap closed by asking for validation on two points. Both are now settled
by what was built:

- *"Our PoC will use the protocols of Section 2"* — held: CoAP and CBOR
  throughout, and the code reuse the roadmap counted on did happen, though not
  untouched. Figures below.
- *"The implementation will proceed in two steps, first the subsystem with a
  relying party and multiple verifiers, then the trust manager"* — both steps
  were already complete at the starting point. The work since has gone into the
  privacy properties and the trust model, which the roadmap did not scope.

**How much of the original code survived.** Comparing the two versions file by
file:

| | count |
|---|:--:|
| Original source files still present | 35 of 35 |
| — byte-identical | 5 |
| — modified | 30 |
| Original files deleted | 0 |
| Files added | 50 |

Nothing from the original was thrown away, but little survived untouched either:
the growth is 50 new files on top of a substantially reworked 35.
`charra_marshaling.c` in particular grew from 478 lines to 1 618 — more than
triple — to carry ten message types instead of two, while lower-level pieces
such as `charra_rim_mgr.c` (28 changed lines of 241) and `charra_log.c` (34 of
171) are close to their originals. `verifier_old.c` is still in the tree as the v1
baseline.

The roadmap's Figure 2 target has been reached and exceeded. What it did not
anticipate is the cost: rebuilding `PCR_r` in the RP's TPM accounts for roughly
87 % of an attestation cycle.

---

**Appendix A (Optional reading): redaction, `PCR_r`, and why there are two
quotes**

The original Appendix A explained CoAP, because CoAP was the machinery a reader
had to understand to follow the code. The equivalent today is **log redaction**:
it is the reason the system exists, and it is the reason one operation accounts
for 87 % of an attestation. Here are the key concepts.

1\. **A measurement log.** Linux IMA records every file it measures as an entry
containing the file's content digest and its path, and extends a digest of that
entry into a TPM PCR. By default that is **PCR 10**
(`CHARRA_IMA_PCR_INDEX`). The log is the human-readable story; the PCR is the
TPM-protected summary of it.

2\. **A PCR is a running hash, not a register you can write.** Each extend
folds the new digest into the old value. A PCR value therefore has no meaning on
its own — it can only be *derived*, by starting from an all-zero PCR and
replaying every extend the TPM did, in order. That derivation is
`charra_replay_ima_log()`.

3\. **A quote binds the PCR, not the log.** `TPM2_Quote` signs the current PCR
values plus a caller-supplied nonce. So a quote proves "my PCR 10 holds value
X"; it says nothing about *why*. Whoever appraises it must replay the log and
check that the replay reproduces X. If it does, the log is exactly the log the
TPM saw.

4\. **The privacy problem.** An IMA entry's `template_data` holds two
length-prefixed fields: the content digest (`d-ng`) and the **path** (`n-ng`).
The path is the sensitive half — it reveals what software and configuration
exist on the Attester. The content digest is not: on its own it says only that
some file hashed to some value, not where that file lives.

5\. **Redaction.** `charra_sdk_redact_ima_log()` replaces each path with
`SHA256(original_path || salt)`, copying the content digest through byte for
byte. The salt is a fresh 32 bytes **per entry**, and for real evidence it is
never transmitted (the qualification handshake is the one deliberate exception —
see Appendix B). That granularity buys two distinct properties: the mapping is irreversible even
against a dictionary of guessed paths, which an unsalted `SHA256(path)` would
not be; and two entries with the *same* path redact to *different* values, so a
Verifier cannot count or correlate repeated paths. Because content digests
survive, appraisal by content hash — the whitelist/blacklist pass — still works.

6\. **Why redaction forces a second quote.** Change any entry and the replay no
longer reproduces the Attester's PCR 10. The RP therefore *cannot* forward
`Quote_a`'s PCR value alongside a redacted log: the two would not agree. It must
rebuild the PCR that the redacted log actually implies, in its own TPM, and sign
*that*.

**Example: how the Relying Party does it.**

1\. **Appraise first, redact second.** `charra_rp_appraise_evidence()` verifies
`Quote_a` against the *unredacted* log while it still can — the Attester's key
against the trust anchor, the quote signature, the nonce, each entry's
self-consistency, and the replay against the quoted digest. Redaction destroys
the ability to do this, so it happens only after the check passes.

2\. **Redact.** `charra_sdk_redact_ima_log()` produces `log_r` from the raw log.
In the measured configuration this turns 4728 bytes into 4257.

3\. **Replay into a different PCR.** `rp_replay_log_into_pcr()` extends every
`log_r` entry into **PCR 23** (`RP_REPLAY_PCR_INDEX`), not PCR 10.

The operative reason is **resettability**. Each cycle replays a fresh `log_r`
from an all-zero PCR, so the RP must *rewind* the PCR first — and PCR 10, being
in the 0–15 range, correctly refuses `TPM2_PCR_Reset`. Only PCRs 16 and 23 are
resettable from locality 0 on this platform, so 23 is one of two available
choices.

A second reason is sometimes cited — that 23 lies outside the Attester's quoted
selection (`{0..7, 10}`), so RP activity cannot perturb `Quote_a`. **In the
normal configuration that is irrelevant**: the Attester and the RP hold separate
TPMs, so nothing the RP extends on its own device can affect the Attester's PCRs
at all. It becomes load-bearing only in the fallback where both roles share one
simulator (`TWO_TPMS=0` in `run_daemon.sh`, which points the RP at the
Attester's TCTI). There, an RP replaying into PCR 10 would corrupt the very PCR
`Quote_a` attests to.

That fallback is a testing convenience, not a supported deployment: as §4.3
explains, sharing a TPM also lets the RP derive the Attester's restricted key
and quote as it.

4\. **Quote it.** `rp_quote_pcr_with_ak()` signs PCR 23 under a nonce supplied
by the Verifier, producing `Quote_r`. This happens once **per Verifier**,
because each Verifier issues its own nonce.

5\. **What the Verifier receives.** `log_r`, `Quote_r`, and the original
`Quote_a` with the Attester's public key. It replays `log_r` against `Quote_r`'s
PCR to confirm the redacted log is what the RP actually committed to, and
independently re-checks `Quote_a` to confirm the evidence originated from a
trusted Attester answering a fresh challenge.

In summary: the Attester proves what it measured, the RP proves what it forwards
is a faithful redaction of that, and the Verifier checks both without ever
seeing a path. The cost of that guarantee is step 3 — 33 TPM extends, about
86 ms each on the measured platform, and 87 % of the attestation cycle.

---

**Appendix B (Optional reading): the trust model — anchor, qualification,
verdicts**

The roadmap did not scope a trust model, so this is the part of the system with
no counterpart in the original document. Three mechanisms, each answering a
different question.

**1. Who are you? — the trust anchor**

There is no CA and there are no certificates. `keys/trusted_keys.txt` holds the
public halves of the two TPM-resident signing keys in PEM, one labelled
`attester` and one `relying-party`. **The file *is* the trust decision**:
`charra_trusted_keys_check()` accepts a key if and only if it appears there.

Two consequences worth understanding:

- **Keys are derived, not stored.** `TPM2_CreatePrimary` reproduces the same key
  on every call from two inputs: the TPM's **hierarchy seed** and the **key
  template**. Nothing is persisted inside the TPM. The template is what
  distinguishes the two identities on one device — the Attester's key is the
  restricted primary, the RP's the unrestricted one. Wipe the TPM's state and
  the seed changes, so every derived key changes, and the anchor must be
  regenerated — otherwise every signature check fails, reported as "this key is
  not a trusted identity", which reads like a rejected peer rather than a stale
  file.
- **It establishes identity, not behaviour.** Anything listed in the file is
  accepted as that identity. It cannot express "this RP redacts correctly",
  which is precisely the gap the next mechanism fills.

**2. Do you behave? — the qualification handshake**

An identity does not go stale, but behaviour can. Before any Verifier accepts a
submission, the RP must hold a qualification grant, obtained by passing a
redaction competence test:

1\. The RP asks a Verifier for a challenge over `/qualify`.

2\. The Verifier generates a **synthetic** IMA log (40 entries in the measured
configuration, about 5.2 kB) from a random seed, and redacts it *itself* with a
random salt to produce a golden answer. It returns the log **and the salt**.

3\. The RP redacts the same log through the exact pipeline it uses for real
evidence, signs `(redacted log ‖ salt)` with its attestation key, and submits
over `/qualify_submit`.

4\. The Verifier checks the signature, then compares the RP's redaction with its
golden answer **byte for byte**. A grant is issued only on an exact match.

Three design details explain the shape:

- **The salt is deliberately transmitted here** — the one exception to "the salt
  is never sent". A fresh per-entry salt could never produce a byte-identical
  answer, so the shared salt is what turns the test into an equality check
  rather than a re-derivation. This is safe specifically because the challenge
  log is synthetic: its paths are fabricated, so irreversibility and
  non-correlation — which matter only for a real device's data — give up
  nothing. Real evidence is always redacted with no caller-supplied salt.
- **The signature says *who*, not *what state*.** The grant is recorded against
  the signing key's fingerprint. The salt is folded into the signed data so a
  captured submission cannot be replayed into a later round.
- **No replay, no PCR.** Unlike the evidence path, the handshake never touches
  `TPM2_PCR_Extend`: two identical logs replay identically, so comparing bytes
  is sufficient.

The grant is time-limited (180 seconds by default), single-use per challenge,
and shared between Verifiers through `qualified_rps.txt` — so an RP that
qualified once, with any Verifier, is qualified everywhere until the deadline
that Verifier stamped.

**3. Did you really say that? — signed verdicts**

A Verifier's answer is a signed `charra_verdict` record carrying four fields:
`accepted`, `challenge_nonce`, `evidence_digest`, and `signed_at`. The RP
verifies every one; **an unverifiable YES is counted as a NO.**

| Field | What it stops |
|---|---|
| `challenge_nonce` | Replay across rounds — and, since every Verifier draws its own, a vote being counted in another Verifier's slot |
| `evidence_digest` | A verdict cast over evidence the RP did not send. The RP hashes the submission before sending and the Verifier hashes it on arrival, so an on-path swap is caught — which the nonce alone does not do, since it travelled in the clear |
| `signed_at` | Nothing cryptographically: no role has a trusted clock. It is an assertion useful for the log and a staleness bound. Freshness comes from the nonce |

In summary: the anchor establishes *who*, qualification establishes *behaves
correctly*, and the signed verdict establishes *this answer, about this
evidence, from that Verifier*. All three are needed, because each is silent
about what the other two assert.

---

**Appendix C: how the figures in this document were verified**

Every count above comes from the two versions of the codebase themselves, not
from notes:

| Claim | How it was checked |
|---|---|
| 35 → 85 source files | listing `src/` in each version, filtered to `.c`/`.h` |
| 8 057 → 17 733 lines | summing the line count of those files in each version |
| 5 → 6 binaries | the `TARGETS` line of each version's `Makefile` |
| 4 → 7 CoAP resources | `charra_coap_add_resource` call sites in each version |
| 2 → 10 message types | `} msg_*_dto;` typedefs in `src/core/charra_dto.h`. Note one of the ten, `msg_verifier_endpoint_dto`, is an array element inside the `/get_verifiers` response rather than a message that travels on its own. `CHARRA_V2_CHANGES.md` reaches the same total by excluding it and counting the signed verdict record instead |
| 0 → 16 suites, 358 assertions | listing `tests/`; totals from running `make test`, repeated in a container with no network and no TPM simulator to confirm the suite is self-contained |
| Every feature in section 4 | the symbol is present now and absent at the starting point |
| File-survival counts | comparing every source file present in both versions byte for byte |

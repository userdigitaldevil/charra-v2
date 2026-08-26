# CHARRA-v2 — project notes

Single tracked reference for what this fork is, how it works today, and
why it is shaped the way it is. Context for humans and AI assistants
working in this repo — update it alongside the code.

**This describes the system as it stands, not how it got here.** Where a
rejected alternative explains a current choice it is recorded; superseded
designs are not. Git history has the rest.

---

## Part 1 — What this repo is

CHARRA: Fraunhofer SIT's proof-of-concept for IETF RATS challenge-response
remote attestation over TPM 2.0. Classic flow: Verifier sends a nonce + PCR
selection, Attester produces a signed TPM quote over it, Verifier appraises
the quote against reference PCR values.

This fork extends the original 2-party design into a **4-role,
multi-verifier system**, implementing the CHES 2024 poster from Huawei
Shield Lab Paris (Jun Zhang, Amine Lamouchi, Houda Labiod), *"Proof of
Concept for Remote Attestation Schemes with Multiple Verifiers"*
(`charra-ressources/CHES2024_Poster_final.pdf`), plus the
privacy-preserving redaction scheme from
`charra-ressources/privacy_protectioin_v1_en_en.pptx` — see Part 2.

### Architecture

- **Attester** (`src/attester.c`, `src/attester/`) — CoAP server :5683,
  resources `attest` and `attest_result`. Runs `TPM2_Quote` over PCRs
  {0..7, 10} against its own TPM. Logs timing to `timings_attester.txt`.
- **Verifier** (`src/verifier.c`, `src/verifier/`) — passive CoAP server,
  default :31415, resources `nonce`, `appraise`, `qualify`,
  `qualify_submit`. Opens no TPM at all: every check it makes is
  public-key maths or hashing. Per-port timing to
  `durations_verifier-<port>.txt`.
- **Trust Manager** (`src/trust_manager.c`, :6000) — the poster's "Verifier
  Manager". Resource `get_verifiers`: resolves Verifier IDs to `{ip, port}`
  via `verifiers_config.txt`. A directory service, not an
  endorsement/reference-value provider despite the RATS-sounding name.
- **Relying Party** (`src/relying_party.c`, `src/rp/`) — orchestrator and
  privacy-cleansing proxy. Resolves N Verifiers, gets evidence from the
  Attester **once**, appraises it locally, redacts it, then fans the
  redacted evidence out to all N Verifiers in parallel (pthreads) and takes
  a majority vote (`2*num_true > num_verifiers`). Runs this in a loop by
  default (daemon mode); `--benchmark` selects a bounded 1→5-Verifier
  timing sweep and exits.
- **Provisioning tool** (`src/provision_trusted_keys.c`) — not a role and
  not a server. An offline utility that reads one role's public signing key
  out of that role's TPM and emits a `keys/trusted_keys.txt` fragment. Run
  once per TPM, before anything starts, via `keys/gen-trusted-keys.sh`.
- **`src/verifier_old.c`** — the original CHARRA active-client Verifier,
  kept as a benchmarking baseline. Not part of the new flow.

Wire protocol: CoAP (UDP) + CBOR (QCBOR). DTOs in `src/core/charra_dto.h`,
encode/decode in `src/core/charra_marshaling.c`, plain positional arrays
(no maps or labels) — field order is load-bearing, defined only by struct
order, with no schema self-description on the wire.

DTLS-PSK/RPK works on every leg, and is **off by default**. All four roles
take `--psk`/`--rpk`; `run_daemon.sh`'s `DTLS_MODE` sets one mode for all of
them at once, because they must agree and a mismatch does not error — the
request times out, a timeout counts as a NO vote, and the run reports 0/N as
though attestation failed.

Under `rpk` this is **mutual**: each role proves possession of its keypair in
`keys/` and checks its peer against the reference public key. It is
hop-by-hop, so it does not replace the signed verdict, which is end-to-end
and survives a compromised endpoint. The two are complementary — the
`evidence_digest` check stays load-bearing either way.

*Historical note, since it explains the shape of the code:* the transport was
complete from the first commit but **unreachable**. `relying_party.c`'s
`main()` was declared `int main(int argc CHARRA_UNUSED, char** argv
CHARRA_UNUSED)` — it included `<getopt.h>` and never called it, so
`use_psk`/`use_rpk` could only be changed by editing the source. The Attester
and Verifier parsed CLI from the start, which is what produced the
asymmetry. No commit on `main` ever set either flag true.

### Component reference table

| Role | File | Port | CoAP resource(s) | Timing log |
|---|---|---|---|---|
| Attester | `src/attester.c` | 5683 | `attest`, `attest_result` | `timings_attester.txt` |
| Verifier | `src/verifier.c` | 31415 (5684+ under `start_verifiers.sh`) | `nonce`, `appraise`, `qualify`, `qualify_submit` | `durations_verifier-<port>.txt` |
| Trust Manager | `src/trust_manager.c` | 6000 | `get_verifiers` | — |
| Relying Party | `src/relying_party.c` | n/a (client) | — | `timings_RP_multi_verifiers.txt` (`--benchmark` only) |
| Verifier (old, baseline) | `src/verifier_old.c` | n/a (client) | — | `timings_verifier.txt` |
| Provisioning tool | `src/provision_trusted_keys.c` | n/a | — (TPM only) | — |

`start_verifiers.sh` spawns N `bin/verifier` instances on consecutive ports
from 5684 and writes them into `verifiers_config.txt` as `id ip port` rows,
which `trust_manager.c` reads.

No role keeps a `state/` tree: nothing is provisioned, cached or issued at
runtime. The only two identity-related files the running system touches are
`keys/trusted_keys.txt` (read-only, generated offline) and
`qualified_rps.txt` (append-only, shared by every Verifier).

### Two TPMs

Attester and RP each get their own software TPM, started by
`run_daemon.sh`: **:2321** for the Attester, **:2325** for the RP. Each
`tpm_server` binds *two* consecutive ports — N for commands, N+1 for the
platform channel (power on/off, reset) — so the two base ports must differ
by at least 2.

This matters for more than realism. `TPM2_CreatePrimary` **derives** rather
than generates: `key = KDF(hierarchy_seed, template)`, deterministic and
reproducible across processes and restarts. One shared TPM therefore means
one seed, and AK_a and AK_r become two templates over the same secret — so
either role could derive the other's key. Separate NVChips make them
unrelated by construction. `TWO_TPMS=0` falls back to the single shared TPM
if you ever need to compare.

`provision_trusted_keys --role attester|relying-party` reads the
corresponding key from the corresponding TPM. **`--role` is a security
boundary, not ergonomics**: without it a single run would emit both
identities, putting a key the RP's own TPM can derive into the anchor
labelled `attester` — and since `TPM2_Quote` accepts restricted and
unrestricted keys alike, the RP could then issue genuine quotes that pass
Step 3b.

### Key management

Both signing keys are TPM primaries derived on demand from the owner
hierarchy, never persisted, never leaving their TPM:

- **AK_a** — the **restricted** template, because `TPM2_Quote` accepts
  nothing else for the Attester's role and a restricted key's signature
  carries the `TPM_GENERATED_VALUE` (`0xff544347`) magic that makes it
  meaningful.
- **AK_r** — the **unrestricted** template. Not for quoting: `TPM2_Quote`
  accepts either kind. It is unrestricted because `rp_sign_with_ak()` needs
  to sign a caller-supplied digest with a null validation ticket, which a
  restricted key refuses (`TPM_RC_TICKET`, measured `0x3e0` on parameter
  3). The only remaining caller is the qualification handshake.

The cost of that choice: an unrestricted key can also sign a hand-built
`TPMS_ATTEST` via `TPM2_Sign`, so "signed by AK_r" alone does not prove a
TPM built the structure. **Nothing detects this remotely** —
`objectAttributes` is sender-chosen data, the anchor stores only `n`/`e`,
and no code reads restrictedness. What closes the gap is the Verifier
replaying `log_r` in software and checking it against the quote's
`pcrDigest` (Step 3a item 4), which is why that check is load-bearing
rather than belt-and-braces.

### Concept primer

**PCR** — write-only-by-extend hash register: `PCR[i] = SHA256(PCR[i] ||
measurement)`. A tamper-evident chain of everything measured since boot,
not a snapshot. One bank per hash algorithm.

**PCR resettability** — measured on this simulator: only **16 and 23** are
resettable from locality 0. PCRs 0–15 and 17–22 return `bad locality`.
That is why the RP replays into **23**, which is also outside the
Attester's quoted selection, so RP activity cannot perturb `Quote_a`.

**TPM Quote** — `TPM2_Quote(key, PCR_selection, qualifying_data)`: the TPM
reads the selected PCRs itself, hashes them into one composite digest,
builds a `TPMS_ATTEST` (digest + `qualifyingData` + clock/firmware
metadata) and signs it. Two consequences: (1) signed payload
(`TPM2B_ATTEST`) and signature (`TPMT_SIGNATURE`) are separate wire fields,
alongside the public key needed to verify; (2) **the nonce is the
`qualifyingData`**, placed inside the signed structure by the TPM itself.

**`TPM2_Sign` vs `TPM2_Quote`** — `Sign` signs bytes you hand it; `Quote`
signs a structure the TPM builds from state only it can read. That
difference is the whole reason `Quote_r` is a quote and not a signature.

**Whoever proves replays into a TPM; whoever checks replays in software.**
The organising principle of the whole design. The RP replays `log_a` in
software (it is checking someone else's claim) and `log_r` into its own TPM
(it is making a claim). The Verifier replays `log_r` in software (checking
again). Identical arithmetic — only the proof differs.

**PCR digest matching** — appraisal compares one composite digest against
the one inside the signed `TPMS_ATTEST`, never per-register.
`reference-pcrs.txt` holds newline-separated candidate PCR sets;
`charra_rim_mgr.c` hashes each and takes the first match. Despite the "RIM"
name this is a flat-file matcher, not a TCG RIM parser.

**ESAPI / tpm2-tss** — the TCG Enhanced System API between app code and raw
TPM command bytes. Every `Esys_*` call goes through it, which is also what
lets the stack run against a software TPM with no hardware.

**CoAP** — REST-shaped (GET/POST/FETCH, resource paths) over UDP with its
own light retransmission model.

### Where this fork steps outside standard RATS

RFC 9334 assumes one Verifier → one Attestation Result. N-verifier fan-out
plus majority vote is this team's extension:

- Not Byzantine-fault-tolerant in any rigorous sense: all N Verifiers check
  the *same* evidence against the *same* reference values. It protects
  against one Verifier being compromised, down or buggy — not against a
  shared bad reference set or a compromised Attester.
- The Trust Manager has no RATS equivalent: plain ID→endpoint resolution,
  no endorsement content flows through it.
- Evidence is generated once and appraised N times, so the multiplicity is
  purely in the appraisal step — which is what the CHES poster's timing
  study measures (evidence-gathering flat against Verifier count,
  appraisal scaling roughly linearly).

### Known doc drift (pre-existing, upstream)

- `charra-ressources/charra2-manual.md` mentions tuning a
  `num_used_verifiers` variable. That name is gone; the capability is
  `--verifiers COUNT`. Only `--benchmark` still hardcodes the 1→5 sweep.
- Multi-attester support is mentioned on the poster but absent from `src/`.

---

## Part 2 — The privacy-preserving redaction scheme

### Why: the problem replay solves

A TPM Quote commits to a PCR composite digest, not to individual PCR
values. To check that digest a Verifier needs a value for every selected
PCR. Boot PCRs (0–7) are static and can be looked up in a reference file,
but the IMA PCR (conventionally PCR 10) grows every time a file is
measured, so no static reference value can exist — it must be *derived* by
replaying the measurement log from an all-zero PCR.

The log, however, contains file paths. Redaction rewrites those paths and
recomputes each entry's digest, which is what makes the log shareable — and
what makes the replayed value diverge from the Attester's original.

### The spec (supervisor's DRA-TLS write-up — authoritative)

Trust model: **the Verifier trusts the RP.** The RP validates the
Attester's evidence; the Verifier does not re-check the log content.
Attester = base station, RP App = privacy-cleansing node on the
network-management side, Verifier = independently deployed.

```
ATTESTER (base station) -> RP App:
    Evidence_a = Quote_a (quoted_data + AK signature), raw IMA log (log_a),
    Attester's EK/AK certificate
    (quoted_data = nonce + selected PCR combination digest)

RP App, Step 2a -- Local Verification (on Evidence_a, using log_a):
    1. validate Attester's EK/AK certificate
    2. verify Quote_a signature
    3. check nonce consistency
    4. recompute template_hash of each log_a entry, compare
    5. recompute PCR expansion from log_a's template hashes, compare
       against Quote_a's PCR combination digest
    6. check each entry's file hash against the baseline whitelist/
       blacklist policy
    -> pass: proceed to Step 2b.  -> fail: negative proof to Attester.

RP App, Step 2b -- Privacy Cleanup:
    output_path = PATH_Clean(input_path)   (built-in path-mapping SDK)
    rewrite every path in log_a -> log_r; recompute each entry's
    template_hash from the rewritten data
    extend a new PCR_r from the original PCR using log_r's template hashes
    TPM2_Quote, signed by the RP App's own AK          -> Quote_r
    Evidence_r = (Quote_r, log_r, EK_r/AK_r)

RP App -> VERIFIER:
    Evidence_r  = (Quote_r, log_r, EK_r/AK_r)
    Evidence_a' = (Quote_a, EK_a/AK_a)  -- log_a is STRIPPED, never forwarded

VERIFIER, Step 3a -- New Evidence Verification (Evidence_r):
    1. validate EK_r/AK_r certificate
    2. verify Quote_r signature
    3. check nonce consistency
    -> pass: proceed to Step 3b.  -> fail: negative proof to RP App.

VERIFIER, Step 3b -- Original Evidence Verification (Evidence_a'):
    1. validate EK_a/AK_a certificate
    2. verify Quote_a signature
    3. check nonce consistency
    -> pass: positive proof to RP App.  -> fail: negative proof to RP App.
```

The spec's "EK/AK certificate" wording is kept in the quotation. There are
no certificates in this implementation — see "Identity" in Part 3.

### Where the implementation goes beyond the spec

The spec lists two evidence exchanges and nothing else. It is silent on how
a nonce reaches each party and on how identity comes to exist — but Step 2a
item 3 and Steps 3a/3b item 1 do not work without both. Four things exist
that the spec text does not mention:

1. **`/nonce`** — each Verifier issues its own freshness challenge. A nonce
   the RP chose proves nothing to the Verifier, since the RP could replay
   an old `Quote_r` over a value it already knew would match.
2. **`/qualify` + `/qualify_submit`** — the deck's "RP Access Check
   Process", below.
3. **Step 3a item 4** — the Verifier replays `log_r` **in software** and
   compares against `Quote_r`'s `pcrDigest`. Not in the spec's Verifier
   checklist, and load-bearing: without it AK_r's unrestrictedness would
   let the RP assemble a `TPMS_ATTEST` by hand. It also means the spec's
   "the Verifier checks no log or PCR content" no longer describes this
   implementation.
4. **Signed verdicts** — the `/appraise` answer is a signed record, not a
   bare string. See Part 3.

RP is the sole active party throughout: Attester and Verifiers are pure
passive responders that never initiate anything.

### The current cycle, in order

`run_one_attestation_cycle()`, one attestation cycle:

1. **`/get_verifiers` (Trust Manager)** — resolve this cycle's Verifier IDs
   to IP/port. Fail-closed on a short answer: unfilled `verifiers[]` slots
   would still hold the previous cycle's endpoints while the vote
   denominator stayed at the requested count, so a short resolve abandons
   the cycle.
2. **`/attest` (Attester)** — RP picks a nonce and PCR selection
   {0..7, 10}, gets back `Quote_a` and raw `log_a`.
3. **Step 2a, locally, in software** — AK_a in the trust anchor; `Quote_a`
   signature; nonce; per-entry `template_digest == SHA256(template_data)`;
   replay `log_a` and compare against `Quote_a`'s PCR digest; file hashes
   against the whitelist/blacklist policy. All six run even after one
   fails, so a single pass reports everything. Any failure is a **hard
   stop** — nothing reaches a Verifier. The verdict goes back to the
   Attester on `/attest_result`, which is advisory only: it exists so a
   rejected device can log, alert or re-measure instead of assuming
   success. It has to be a separate RP-initiated request because the
   Attester is the *server* of `/attest`, so there is no reply slot left.
4. **Step 2b, once per cycle** — `charra_sdk_redact_ima_log()` produces
   `log_r`. Redaction is randomised, so doing it per Verifier would hand
   each of them a different `log_r` for the same attestation.
5. **Replay `log_r` into PCR 23 on the RP's TPM, once per cycle** —
   `TPM2_PCR_Reset(23)` then one `TPM2_PCR_Extend` per entry. Once per
   cycle, not per Verifier: quoting reads a PCR without consuming it, so
   one replay backs every quote in the cycle. Doing it per Verifier
   multiplied 33 TPM round trips by the Verifier count for nothing.
6. **`/qualify` + `/qualify_submit`, if the grant has lapsed** — against
   one Verifier only; the resulting grant is shared through
   `qualified_rps.txt`.
7. **Per Verifier, in parallel threads** — `/nonce`, then
   `TPM2_Quote(PCR 23, qualifyingData = that nonce)`, then `/appraise`.
   One quote each over the one shared replay.
8. **Majority vote** — fail-closed. A Verifier counts as a pass only if it
   appraised, accepted, *and* its verdict verified. Unreachable, timed
   out, never sent, or unverifiable all count as NO. The tally is logged
   and goes no further; the Attester is never told.
9. **Loop control** — stop request, `--cycles`, `--duration`, else sleep.

### Design decisions that still hold

**Why the RP replays into a real PCR.** An earlier design had the RP replay
in software and sign `PCR_r || nonce` with `TPM2_Sign`. That was replaced:
`TPM2_Quote` over a real PCR means the RP does not assemble the signed
bytes at all — the TPM reads the PCR, builds the `TPMS_ATTEST` and signs
it. That is the difference between *asserting* a PCR value and *attesting*
one. The objections that originally ruled it out (PCRs not resettable, one
round trip per entry, locking) were answered by PCR 23 being resettable, by
hoisting the replay to once per cycle, and by a single TPM mutex.

**Consequences of recomputing `template_digest`.** Because the RP
recomputes each digest from redacted `template_data`, replaying `log_r`
**cannot** reproduce the Attester's sealed `pcrDigest` — mathematically,
not by policy. The Attester's TPM is therefore not in the Verifier's chain
of trust for the PCR 10 property; the guarantee is "the RP vouches for
this", anchored by the RP's own TPM. Deliberate. It also means appraisal
can read `file_hash` directly: both it and `template_digest` are equally
RP-controlled now.

**Privacy note.** The Attester's EK certificate would be a permanent unique
identifier for that physical TPM and must stop at the RP — forwarding it
would leak a stronger identifier than any path redaction protects. (Moot
today: no certificates exist at all.)

**Redaction rule: hash the path.** An earlier draft blanked `template_data`
entirely. Rejected before being built: every redacted entry would share one
digest, so the Verifier could not distinguish "correctly redacted N
different paths" from "redacted nothing and zeroed everything". What is
implemented instead: locate the path inside `template_data`, hash *the
path* with SHA-256, replace `template_data` with those 32 raw bytes,
recompute `template_digest`. Different paths stay distinguishable
(`test_different_entries_redact_differently`). The file-content digest is
discarded, not preserved — simple on purpose.

**TEE variant (documented, not built).** With TEE capability Step 2 would
run inside the TEE, `Evidence_r` would carry a signature from the SDK's own
key, and `Evidence_a'` would not be sent at all. No TEE code exists here.

### Still open

- **Nothing proves at runtime that either AK is TPM-resident.** Both are
  genuine TPM primaries, but a Verifier's only reason to believe that is
  `keys/trusted_keys.txt` saying so. The `TPM2_MakeCredential` /
  `ActivateCredential` challenge that used to establish it live was removed
  with the rest of the identity subsystem. Step 3b still fails closed on a
  key it does not recognise — it simply recognises by file lookup.
- **Blind spot in the PCR-10 replay.** Replay folds only entries tagged for
  the target PCR, so entries for other PCRs could be added, removed or
  altered without changing the result. A hash over the whole buffer would
  close it. Scoped as an RP Step 2a/2b concern.
- **SDK-execution enforcement.** Qualification proves the RP's redaction
  *output* matches, not that it ran the genuine unmodified SDK. Closing
  this needs the RP's own IMA to measure the SDK binary — larger scope.
- **All Verifiers share one verdict-signing keypair.** See Part 3.
- **Whitelist/blacklist files are empty placeholders** in this dev setup,
  so the policy check runs in allow-by-default mode. The mode in force is
  logged, so "passed" is never ambiguous between *checked and fine* and
  *nothing to check against*.
- **The redaction SDK assumes a flat `ima-ng` layout.** Fine while it pairs
  with `charra_synth_generate_ima_log()`, which produces exactly that;
  worth revisiting against real Attester logs.

---

## Part 3 — Current implementation

### Module map

| Module | What it owns |
|---|---|
| `src/core/charra_event_log.{h,c}` | The replay primitive, shared by every role. Parsing, extending, and the Step 2a content checks. |
| `src/core/charra_synthetic_log.{h,c}` | Fabricated but well-formed IMA logs, for the qualification challenge. |
| `src/core/charra_sdk.{h,c}` | The redaction SDK (`charra_sdk_redact_ima_log()`). |
| `src/core/charra_rp_qualification.{h,c}` | Golden-answer generation and the byte-for-byte check. |
| `src/core/charra_trusted_keys.{h,c}` | The trust anchor lookup. |
| `src/core/charra_verdict.{h,c}` | The signed `/appraise` verdict record. |
| `src/core/charra_marshaling.c` | Every wire DTO's encode/decode. |
| `src/rp/` | `rp_attestation`, `rp_evidence`, `rp_qualification`, `rp_signing_key`, `rp_coap`, `rp_config`, `rp_stats`. |
| `src/verifier/` | `verifier_nonce`, `verifier_appraise`, `verifier_qualify`, `verifier_qualified_rps`, `verifier_util`. |
| `src/attester/` | `attester_attest`, `attester_result`, `attester_ima_log`, `attester_util`. |

Wire DTOs (`charra_dto.h`): `msg_attestation_request_dto`,
`msg_attestation_response_dto`, `msg_rp_evidence_dto` (Quote_a + Quote_r +
`log_r`), `msg_attestation_result_dto`, `msg_qualify_response_dto`,
`msg_qualify_submit_request_dto`/`_response_dto`,
`msg_get_verifiers_request_dto`/`_response_dto`. No certificate travels on
any of them.

#### `charra_event_log` — the invariant that must not drift

| Function | Purpose |
|---|---|
| `charra_pcr_reset` / `charra_pcr_extend` | Zero an accumulator; one extend `acc := SHA256(acc \|\| digest)`, zero-padding digests shorter than 32 bytes (SHA-1 → SHA-256 bank). **This is what must never diverge between RP and Verifier.** |
| `charra_event_log_ima_detect_digest_len` | Recovers whether template digests are 20 or 32 bytes by trial-parsing — the format does not record it. |
| `charra_replay_ima_log` | Public entry point. Extends every entry matching `target_pcr_index`. Tries both digest sizes so a well-formed log is never falsely rejected. Warns, not errors, when a non-empty log has no matching entries. |
| `charra_event_log_parse_entry` | One TLV entry. Every length check is written `need > log_len - offset`, never `offset + need > log_len`, so a hostile length field cannot overflow past the check. Rejects the legacy `"ima"` template. |
| `charra_event_log_append_u32` / `_bytes` | Write-side counterparts, kept in the same file so byte order cannot drift between reader and writer. |
| `charra_verify_log_entries_self_consistent` | Step 2a item 4: per entry, `template_digest == SHA256(template_data)`. Catches malformation, not dishonesty. |
| `charra_verify_log_matches_quote_pcr_digest` | Step 2a item 5. Generic over any single-PCR quote. |
| `charra_verify_log_file_hashes_against_policy` | Step 2a item 6. Blacklist is an explicit deny checked first; whitelist is default-deny **once it has entries** — an empty one falls back to allow-by-default, because strict default-deny against an empty file would reject every attestation on a fresh checkout, which reads as a bug and gets worked around. |

Constants: `CHARRA_IMA_PCR_INDEX` (10), `CHARRA_IMA_TEMPLATE_NAME_MAX` (64).

### Identity: a flat file, and what it does and does not establish

`keys/trusted_keys.txt` is the entire identity mechanism. It holds the PEM
public halves of the two TPM-resident signing keys under `# attester` and
`# relying-party` comments, and the rule is exactly:

> a signing key is trusted if, and only if, it appears in this file.

No EK, no CA, no chain, no expiry, no revocation, nothing provisioned or
renewed at runtime. The AK/EK binding a real deployment would prove with
`TPM2_MakeCredential` is asserted here by the file's existence. Anyone who
can write the file can add a trusted key — which is precisely what "assume
the key was vouched for out of band" buys, and precisely why this shape
belongs in a PoC and not a deployment.

The file is re-read on every lookup rather than cached: a handful of
lookups per cycle against a two-key file costs nothing next to the TPM
round trips around it, and a regenerated anchor takes effect without
restarting every daemon.

**The lookup is not role-scoped.** `charra_trusted_keys_check()` takes a key
and answers present/absent. Anything added to this file is accepted as AK_a
*and* AK_r. That is why the Verifier's verdict key lives in its own file
and not here.

**One name covers the key's whole life.** `CHARRA_ROLE_ATTESTER` /
`CHARRA_ROLE_RELYING_PARTY` are defined once in `charra_trusted_keys.h`,
and everything that has to spell an identity uses them: `--role`, the
`# name` comment written above each key, the `name_out` a successful lookup
reports, and — for the Attester — `sig_key_id` on the `/attest` wire
(`CHARRA_AK_A_KEY_ID` in `charra_key_mgr.h` is that same symbol). Upstream
sent an unrelated `"PK.RSA.default"` there, which made the wire a third
vocabulary for one key.

That field is a label, not a lookup: no TPM object carries the name, and
matching it selects the primary the Attester would have derived anyway. All
it buys is the ability to refuse a request that names something else — so
the comparison checks length before bytes, since `memcmp` over a
caller-supplied length is a prefix match.

Regenerate after any TPM reset — `run_benchmark_mode.sh` and `run_daemon.sh` do
this automatically, because wiping an NVChip changes the hierarchy seed and
therefore every derived key.

### RP qualification handshake

Before an RP is trusted to redact real evidence, a Verifier proves — using
data it fabricates itself, so it already knows the answer — that the RP's
redaction pipeline works.

```
Verifier:  generate a synthetic log, redact it locally with its own copy
           of the SDK, keep that as the golden answer, send
           (raw synthetic log, salt) to the RP
RP:        redact with the SDK, sign (redacted_log || salt) with AK_r,
           submit both
Verifier:  compare the submitted log byte-for-byte against the golden one
           pass -> record the RP's key fingerprint and a deadline
           fail -> rejected
```

**No PCR and no replay are involved.** Two identical logs replay to the
same PCR by construction, so a PCR check would only restate the log check.

The signature is not part of the redaction test — it answers a different
question: *who* is submitting. The grant is recorded against a key
fingerprint, so an unsigned submission could win a grant in another RP's
name. Binding the salt into the signature ties it to *this* challenge, so a
captured submission cannot be replayed into a later round.

**The salt is the one deliberate exception** to the SDK's "salt is never
transmitted" rule. Redaction hashes each path with a fresh random salt per
call, so two honest redactions of the same input do not match bytewise —
which silently made this handshake unpassable until the salt was shared.
Safe here specifically because the challenge log is synthetic. Never do it
for real evidence.

The grant is recorded in `qualified_rps.txt`, shared by every Verifier, so
one handshake counts for all of them. The RP learns the deadline from the
`/qualify_submit` response — it has to, because `/appraise` never says why
it refused, so an RP waiting to be rejected would have nothing to react to.
Carrying the deadline on the wire also avoids the alternative, which is two
binaries agreeing on a compile-time constant.

Design decisions: **periodic re-check**, not one-time onboarding;
**RP-initiated**, matching every other endpoint (the Verifier never opens
an outbound session), and self-enforcing even for a dishonest RP because
`/appraise` checks the grant regardless of whether the RP asks to renew.

Checked against the wall clock with **no margin**: the grant need only be
valid at the check, not for the whole round that follows. One that lapses
mid-round costs that cycle; the next one re-qualifies and corrects.

### Signed verdicts

`/appraise` used to answer with the ASCII string `Attestation successful!`
over plain UDP, and the RP counted a vote by `memcmp`-ing it. Nothing
authenticated that answer: anything that could reach the RP's socket could
cast a YES, and the majority vote sat on five forgeable strings.

The response is now a signed CBOR record (`src/core/charra_verdict.h`):

    [ payload: bstr, signature: bstr ]
    payload = [ accepted, challenge_nonce, evidence_digest, signed_at ]

Payload-then-signature deliberately: the signature covers the payload
**bytes as received**, so verification never re-encodes anything and the
two sides cannot disagree about canonical form.

`charra_verdict_verify()` is one call that checks all of it — signature
under `keys/verifier.pub.der`, the nonce that Verifier issued this round, a
SHA-256 of the evidence this thread actually sent, and `signed_at` within
`CHARRA_VERDICT_SKEW_SECONDS` (60). Every check is mandatory, so leaving
any to the caller would only create a way to forget one. Fail-closed
throughout: an unverifiable YES counts exactly as a NO.

What each bound field stops:

| field | stops |
|---|---|
| `challenge_nonce` | replay across rounds — and, since every Verifier draws its own, a vote being counted in another Verifier's slot |
| `evidence_digest` | a vote about evidence the RP did not send. Hashed by the RP before sending and by the Verifier on arrival, so an on-path swap of the plaintext `/appraise` request is caught — which the nonce alone does not do, since it travelled in the clear on `/nonce` |
| `signed_at` | nothing cryptographically — no role has a trusted clock, so it is an assertion useful for the log and a staleness bound. Freshness comes from the nonce. |

**All Verifiers share one keypair** (`keys/verifier.der`;
`start_verifiers.sh` passes no key flag, and there is no CLI flag for the
path on either side). A signature proves "some Verifier", not "Verifier 3"
— the per-slot separation is the nonce's doing. This raises the bar from
"can send a UDP packet" to "has the key file *and* a network position",
which is the line this PoC draws deliberately. Per-Verifier keys would
change only which file is opened, but need the flags first.

Both `/appraise` exits sign, including the early-fail path that never
reaches appraisal, so a NO that was never appraised is indistinguishable on
the wire from one that was — the same reason the reason list stays in the
Verifier's log. (Consequence: the early-fail path signs an all-zero
evidence digest, so those NOs are correct but not auditable.)

`charra_crypto_pk_sign_file()` / `_verify_file()` go through mbedTLS's
generic `pk` interface rather than the RSA-only paths beside them, because
this key is EC P-256 and not TPM-resident.

`verifier_verdict_verified[]` on the RP separates "voted against us" from
"sent something we could not count" — the same NO, very different faults,
and the run summary reports them differently.

### The verdict on the wire says nothing else

A Verifier's decision is a vote, not a work order. It does not tell the RP
which remedy to attempt, and the RP does not retry on its say-so. Which
checks failed, and why, stays in that Verifier's log. Uniform `2.05
Content` either way.

### Daemon mode and loop control

The RP loops by default. Tunables, all settable as environment overrides to
`run_daemon.sh`:

| env | flag | default | effect |
|---|---|---|---|
| `RP_VERIFIERS` | `--verifiers` | 5 | Verifiers per cycle (1..10); also how many get started. Sets the majority denominator. |
| `RP_INTERVAL` | `--interval` | 15s | Sleep between cycles. |
| `RP_CYCLES` | `--cycles` | 0 | Stop after N cycles; 0 = unbounded. |
| `RP_DURATION` | `--duration` | 0 | Stop after roughly N seconds; 0 = until SIGINT. |
| `RP_VERIFIER_TIMEOUT` | `--verifier-timeout` | 6s | Every Verifier-bound round trip (`/nonce`, `/qualify`, `/qualify_submit`, `/appraise`). A timeout is a NO. Does **not** cover the Trust Manager exchange, which has its own fixed 30s and no flag. |
| `RP_ATTESTER_TIMEOUT` | `--attester-timeout` | 6s | Attester round trip; exceeding it abandons the cycle. |
| `VERIFIER_QUALIFICATION_VALIDITY` | `--qualification-validity` | 180s | Verifier-side. Set below 120s to watch re-qualification mid-run. |
| `TWO_TPMS` | — | 1 | One simulator per role. |
| `ATTESTER_TPM_PORT` / `RP_TPM_PORT` | — | 2321 / 2325 | Must differ by ≥2. |
| `RESET_TPM` | `--keep-state` = 0 | 1 | Wipe each NVChip and re-run `TPM2_Startup` — which changes every AK, hence the anchor regeneration straight after. |

Three stop conditions, tested in order: a stop request (SIGINT/SIGTERM),
`--cycles`, `--duration`. Falling through all three sleeps.

`quit` is a `volatile sig_atomic_t` — a plain `bool` is neither guaranteed
atomic nor guaranteed to be re-read after a handler runs (C11 7.14.1.1p5).

**Stopping is not deferred to the sleep.** The flag is tested at every
phase boundary, and inside the two longest-running loops — the CoAP wait
and the TPM extend loop. Both of those return an error rather than success
when `quit` is what ended them: a wait loop that exits early saw no
response, and a partial replay leaves PCR 23 holding a value no log
explains, which must never be quoted. Measured: **~0.1s** when signalled
during the nap (`sleep()` is `nanosleep`, which a signal never restarts, so
the 1s slicing is portability insurance rather than the mechanism), and
**~1s** when signalled mid-round-trip.

The per-Verifier threads are joined for exactly as many as were created. An
earlier version returned straight out of the spawn loop on a
`pthread_create` failure, which unwound the frame holding the `indexes[]`
array every running thread still dereferences, and freed `log_r` out from
under threads still building messages from it.

### Tests

`make test`, 16 suites, **358 assertions**, no TPM or network required.
The suite list lives once, in the Makefile's `TEST_SUITES`; the .PHONY
list, the per-suite shortcuts and the `test` target all derive from it,
and the run stops at the first failure. Three suites once built
individually while `make test` skipped them, because that target's
prerequisite list and its recipe were maintained by hand.

| suite | assertions |
|---|---|
| `test_event_log` | 29 |
| `test_synthetic_log` | 13 |
| `test_sdk` | 23 |
| `test_rp_qualification` | 32 |
| `test_marshaling_bounds` | 18 |
| `test_trusted_keys` | 9 |
| `test_qualified_rps` | 21 |
| `test_get_verifiers_marshaling` | 17 |
| `test_rp_evidence_marshaling` | 22 |
| `test_verdict` | 27 |
| `test_hex_util` | 25 |
| `test_pcr_selection` | 16 |
| `test_message_marshaling` | 47 |
| `test_key_mgr` | 13 |
| `test_crypto_util` | 22 |
| `test_parser_util` | 24 |

The pattern worth keeping: expected values are computed independently
(hand-written reference extends, hand-encoded QCBOR) rather than by calling
the code under test, and the negative cases are the point — oversized
fields, hostile length prefixes, one-byte mutations, wrong keys, stale
nonces. `test_verdict` sweeps every byte of a signed message in turn and
requires all of them to be rejected. `test_synthetic_log` cross-validates
by feeding the generator's output into the replay module rather than
asserting against itself.

### Scripts and the container

- `run_daemon.sh` — starts both TPMs, provisions the anchor, starts every
  role, runs the RP loop. Wipes `logs/` per run.
- `start_verifiers.sh` — spawns N Verifiers and writes
  `verifiers_config.txt` (untracked).
- `run_benchmark_mode.sh` — full live run, including regenerating the anchor
  after the TPM reset.
- `docker/run.sh` — interactive shell in the dev container.
- `diagrams/rp_daemon_automaton.dot` — the daemon automaton; render with
  `dot -Tpng -Gdpi=140`.

The checkout is bind-mounted (`-v "$PWD/:/home/bob/charra"`), so edits on
the host are live inside the container with no restart. Only the compiled
binaries are not: a running role keeps the build it started with.

---

## Part 4 — Findings worth keeping

Things that cost real time to discover and would cost it again.

**Stray containers sharing one state directory.** An "intermittent" 0/N
cycle failure that looked like a stale-key bug was two containers sharing
one state tree. Check `docker ps` before blaming the code.

**A second `TPM2_Startup(CLEAR)` is a silent no-op** — exit 0, PCRs
unchanged. It resets PCRs but preserves hierarchy seeds. Only deleting
`NVChip` or `TPM2_Clear` changes seeds, and therefore AKs.

**`tpm_server` binds two ports**, N and N+1. Sending raw code `2`
(`TPM_SIGNAL_POWER_OFF`) to the platform port makes the command port return
`0x100`. Several confusing `0x100` failures were the image entrypoint's
`tpm-reset` racing the command; `--entrypoint bash` and starting the TPM
manually avoids it.

**`nanosleep` is never restarted after a signal handler**, even with
`SA_RESTART`. This is why Ctrl-C during a long nap exits immediately.

**`pkill -f` matches the invoking shell's own command line**, so a script
containing the pattern kills itself. Use `pkill -x` or exact PIDs. A
related trap: `pkill -f 'bin/relying_party'` does not match inside
`docker exec`, which once produced a 10× overstatement of stop latency.

**Graphviz**: `splines=ortho` ignores edge `label=` and needs `xlabel=`;
`rank=same` does not set left/right order (invisible chains do).

**macOS bind mounts propagate deletions asynchronously.** A test loop that
wipes `logs/` and immediately re-reads can race VirtioFS and look flaky
when the code is fine.

**An apostrophe inside a single-quoted container script** breaks the whole
heredoc. Both run scripts are scanned for this.

**Redaction is randomised**, so anything comparing two redactions
byte-for-byte needs a shared salt — the failure mode is a check that can
*never* pass rather than one that passes wrongly.

**Fail-closed is a pattern, and the `len != 0` terms are load-bearing.**
`memcmp(_, _, 0)` returns 0, so an absent nonce or an empty expected value
would otherwise match anything. Every nonce comparison in the tree carries
an explicit non-empty test for this reason.

**`memcmp` under a caller-supplied length is a prefix match, not an
equality test.** The same bug wearing different clothes: `/attest` used to
compare its signing-key name with `memcmp(key, LITERAL, key_len)`, so a
one-byte name matched, and an empty one matched too. Harmless while the
table had a single entry — it would have been key confusion the moment a
second was added. Compare the length first, always.

**A negative test that passes on the first try is suspect.** Flipping a
byte at `len/2` in `log_r` landed in `template_data`, which replay never
consumes, so tampering went undetected — the check binds *digests*, not
redacted paths. Redoing it at offset 4 (the first `template_digest`)
rejected correctly.

**Compiler-visible does not mean caller-visible.** A stub with external
linkage and no prototype in any header is uncallable, not merely uncalled —
`-Wall -Wextra` will not tell you, since `-Wmissing-prototypes` is off.

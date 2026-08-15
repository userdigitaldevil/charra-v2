# CHARRA-v2 — project notes

Single tracked reference for what this fork is, what's been added or
modified, and why. Meant as context for humans and AI assistants working in
this repo — update it alongside the code as work continues.

---

## Part 1 — What this repo is (background)

CHARRA: Fraunhofer SIT's proof-of-concept for IETF RATS challenge-response
remote attestation over TPM 2.0. Classic flow: Verifier sends a nonce + PCR
selection challenge, Attester produces a signed TPM quote over it, Verifier
appraises the quote against reference PCR values.

This fork extends the original 2-party (Attester/Verifier) design into a
**4-role, multi-verifier system**, implementing the CHES 2024 poster from
Huawei Shield Lab Paris (Jun Zhang, Amine Lamouchi, Houda Labiod): *"Proof of
Concept for Remote Attestation Schemes with Multiple Verifiers"*
(`charra-ressources/CHES2024_Poster_final.pdf`), and additionally implements
the privacy-preserving redaction scheme from
`charra-ressources/privacy_protectioin_v1_en_en.pptx` — see Part 2.

### Architecture

- **Attester** (`src/attester.c`) — CoAP server :5683, `attest` resource,
  runs `tpm2_quote()`, returns CBOR evidence. Logs timing to
  `timings_attester.txt`.
- **Verifier**, two implementations kept side by side for benchmarking:
  - `src/verifier_old.c` — original CHARRA design: active client, drives
    the attest exchange itself and appraises inline. Kept as baseline.
  - `src/verifier.c` — new design: passive CoAP server :31415, resources
    `nonce` + `appraise` + `certify_ak` + `qualify`/`qualify_submit`, meant
    to be called by an orchestrator. Logs per-step timing to
    `durations_verifier.txt`.
- **Trust Manager** (`src/trust_manager.c`, :6000) — new role, the poster's
  "Verifier Manager." Resource `get_verifiers`: takes a list of verifier
  IDs, resolves them to `{ip, port}` via `verifiers_config.txt`. Pure
  directory/lookup service, not a reference-value/endorsement provider
  despite RATS terminology.
- **Relying Party** (`src/relying_party.c`) — new orchestrator. Flow: ask
  Trust Manager to resolve N verifiers → get evidence from the Attester
  **once** → fan the same evidence out to all N verifiers in parallel
  (pthreads) → majority vote (`2*num_true > num_verifiers`) on the
  aggregate result. `main()` also doubles as the benchmark harness (sweeps
  1→5 verifiers, `NUM_RUNS = 10`, writes `timings_RP_multi_verifiers.txt`).
  **Also acts as the privacy-preserving proxy** — see Part 2.

Wire protocol: CoAP (UDP, optional DTLS-PSK/RPK) + CBOR (QCBOR), DTOs in
`src/core/charra_dto.h`, encode/decode in `src/core/charra_marshaling.c`,
plain positional arrays (no maps/labels) — field order is load-bearing,
defined only by struct order, no schema self-description on the wire.

### Component reference table

| Role | File | Port | CoAP resource(s) | Timing log |
|---|---|---|---|---|
| Attester | `src/attester.c` | 5683 | `attest` (FETCH) | `timings_attester.txt` |
| Verifier (new, passive) | `src/verifier.c` | 31415 | `nonce`, `appraise`, `certify_ak`, `qualify`, `qualify_submit` | `durations_verifier.txt` |
| Verifier (old, active — baseline) | `src/verifier_old.c` | n/a (client) | — (calls Attester's `attest`) | `timings_verifier.txt` |
| Trust Manager | `src/trust_manager.c` | 6000 | `get_verifiers` | — |
| Relying Party | `src/relying_party.c` | n/a (client) | — (calls Trust Manager + Attester + each Verifier) | `timings_RP_multi_verifiers.txt` |

`start_verifiers.sh` spawns 5 `bin/verifier` instances on ports 5684–5693,
registered in `verifiers_config.txt` as `id ip port` rows that
`trust_manager.c` reads to resolve `get_verifiers` requests.

Each Verifier port keeps its own state tree under `state/verifier/` — see
"`state/` reorganized" in Part 3 for the full layout.

**Relying Party internals:**
- `create_attestation_request()` — generates the shared nonce used across
  all verifiers for a given run. *(This nonce is RP→Verifier,
  one-directional — see Part 2's freshness discussion; it cannot be
  repurposed to prove freshness to the Verifier.)*
- `get_verifiers()` — resolves `verifier_list[]` IDs to endpoints via the
  Trust Manager.
- `get_evidence()` — single attest round-trip against the Attester on
  :5683; result cached in `last_response`.
- `get_attestation_results_thread()` — one pthread per verifier: performs
  the RP-AK-certification + qualification handshakes as needed, POSTs a
  nonce request, forwards evidence to `appraise`, stores a bool result.
- `get_attestation_results()` — spawns the threads above, joins them,
  majority vote: `2*num_true > num_verifiers`, then prints a per-verifier
  run summary (see the logging-pass entry in Part 3).

**Wire DTOs** (`src/core/charra_dto.h`): `msg_attestation_request_dto`
(`hello`, `sig_key_id`, `nonce`, PCR selection array, optional
`event_log_path`); `msg_attestation_response_dto` (Quote_a fields + optional
IMA `event_log`); `msg_rp_appraisal_dto` (Quote_a + Quote_r + both AK
certificates + `log_r`, see Part 3); `msg_certify_ak_request_dto`/
`_response_dto`; `msg_qualify_response_dto`/`msg_qualify_submit_request_dto`.

**Key management (upstream baseline, before this fork's EK/AK work)**: only
one signing key ID supported, hardcoded string `"PK.RSA.default"`
(`charra_key_mgr.c`), created via `tpm2_create_primary_key_rsa2048` — a
primary key generated fresh per request, not a persistent, certifiable AK.
Verifier loads the corresponding public key externally via
`Esys_LoadExternal` — no EK→AK certificate chain, no CA-backed provenance.
This fork's `/certify_ak` work (Part 3) replaced this for the RP side; the
Attester side is still on this baseline — see "Not yet built."

### Concept primer

**PCR (Platform Configuration Register)** — write-only-by-extend hash
register: `PCR[i] = Hash(PCR[i] || measurement)`. A tamper-evident chain of
everything measured since boot, not a snapshot. One bank per hash algorithm;
`pcr_selection_dto` picks bank + indices.

**TPM Quote** — `TPM2_Quote(key, PCR_selection, qualifying_data)`: TPM reads
selected PCRs, hashes them into one composite digest, builds a signed
`TPMS_ATTEST` (digest + qualifying_data + clock/firmware metadata), signs it.
Two consequences: (1) signed payload (`TPM2B_ATTEST`) and signature
(`TPMT_SIGNATURE`) are separate wire fields, alongside the public key needed
to verify; (2) **the nonce is the `qualifying_data`**, baked into the signed
structure by the TPM itself — freshness is guaranteed at the hardware
root-of-trust level.

**PCR digest matching** — appraisal compares one composite digest against
the one embedded in the signed `TPMS_ATTEST`, never per-register.
`reference-pcrs.txt` can hold multiple newline-separated candidate PCR sets;
`charra_rim_mgr.c`'s `charra_check_pcr_digest_against_reference()` hashes
each candidate and checks in turn, first match wins. Despite the "RIM" name,
this is a flat-file matcher, not a TCG RIM-format parser.

**EK vs AK** — real TPM attestation chains Endorsement Key (EK,
manufacturer-burned, proves genuine silicon) → Attestation Key (AK, certified
by EK, used per-quote). Upstream CHARRA skips this chain entirely; this fork
built it for the RP↔Verifier leg — see `/certify_ak` in Part 3.

**ESAPI / tpm2-tss** — the TCG "Enhanced System API" between app code and raw
TPM command bytes. Every `Esys_*` call goes through this, also what lets the
stack run against the bundled software TPM (`ibmtpm1661`) with no real
hardware.

**CoAP** — REST-shaped (GET/POST/FETCH, resource paths) over UDP with its own
light retransmission model.

**DTLS-PSK/RPK** (`coap_util.c`) — CoAP's TLS-over-UDP equivalent. PSK =
pre-shared symmetric key. RPK = raw public key, asymmetric but no X.509
chain. Neither implies a CA.

### Where this fork already stepped outside standard RATS topology (pre-existing)

RFC 9334 assumes one Verifier → one Attestation Result. N-verifier fan-out +
majority vote is this team's own extension, not RATS-native:
- Not rigorously Byzantine-fault-tolerant: all N verifiers check the *same*
  evidence against (presumably) the *same* reference values — protects
  against one verifier being compromised/down/buggy, but not against a
  shared bad reference-value set or a compromised Attester.
- Trust Manager has no RATS role equivalent — plain ID→endpoint resolution,
  no endorsement content flows through it.
- Evidence generated once, appraised N times — the multiplicity is purely in
  the appraisal/trust step, which is what the CHES poster's timing study
  measures (evidence-gathering flat vs. verifier count, appraisal scales
  ~linearly).

### Known doc/code drift (pre-existing)

- `charra-ressources/charra2-manual.md` references tuning a
  `num_used_verifiers` variable — no longer exists; code hardcodes the 1→5
  sweep + `NUM_RUNS = 10`.
- Multi-attester support (heterogeneous testbeds) is mentioned on the poster
  but not found in `src/` — likely Docker/deployment-level if it exists.

---

## Part 2 — The privacy-preserving redaction scheme

### Why: the problem replay solves

A TPM Quote commits to a PCR composite digest, not individual PCR values. To
check that digest, a Verifier needs a value for every selected PCR. Boot PCRs
(0-7) are static and can be looked up in a reference file, but the IMA PCR
(conventionally PCR10, `CONFIG_IMA_MEASURE_PCR_IDX`) grows every time a new
file is measured, so no static reference value can exist for it — it has to
be *derived* by replaying the measurement log: starting from an all-zero PCR
and re-applying every extend the TPM did.

### Target design v1 (informal — SUPERSEDED by v2 below)

Trust model: **the Verifier trusts the RP.** The RP validates the Attester's
evidence; the Verifier does not re-check it directly.

```
ATTESTER -> RP: Quote_A, raw IMA log, Attester EK/AK certificate

RP: 1. validate Attester's EK/AK certificate
    2. verify Quote_A signature
    3. replay raw log (well-formed / consistent)
    4. redact: rewrite paths in template_data, RECOMPUTE template_digest'
    5. replay the REDACTED log (software replay) -> X
    6. TPM2_Quote with its own AK, qualifyingData = X -> Quote_R

RP -> VERIFIER: redacted_log, Quote_R, RP's EK/AK cert,
                Quote_A + signature + public_key (forwarded, unused)
                NOT forwarded: Attester's EK certificate

VERIFIER: 1. validate RP's EK/AK certificate
          2. verify Quote_R's signature
          3. replay redacted_log -> X'
          4. check Quote_R.qualifyingData == X'
          5. check Quote_R.pcrDigest against reference PCRs for the RP
          6. file_hash whitelist/blacklist check
```

**Superseded**: the supervisor's formal "DRA-TLS Privacy Protection
Solution" write-up keeps the same trust model but is authoritative on which
party does which check. The correction: **the Verifier does not replay
logs, does not recompute or check any PCR digest, and does not run the
file-hash policy check at all.** All log/PCR content verification (items
3-6 above) is the RP App's own Step 2a gate, run once, before redaction —
not repeated by the Verifier. `verifier.c` matches v2, not v1.

### Target design v2 (supervisor's DRA-TLS spec — authoritative)

Same trust model, precise per-party checklist (Attester = base station, RP
App = privacy-cleansing node on the network-management side, Verifier =
independently deployed):

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

**No PCR or log content check exists anywhere in the Verifier's steps** —
intentional. Steps 4/5/6 (template-hash recompute, PCR-expansion recompute,
file-hash policy) only ever run once, in the RP App's Step 2a, against the
*original* `log_a` before redaction. The Verifier's entire job is
cryptographic + identity: quote signatures, nonce freshness, and
certificate validity, on *two* independent evidence bundles rather than one.

**RP App-side path-cleanup policy monitoring** (separate from
per-attestation appraisal): the Verifier releases the `PATH_Clean` SDK to
the RP App, periodically sends a test log `log_t`, receives `log_t'` back,
and compares it against a locally computed expected result to confirm the
RP App still runs the correct SDK — without ever seeing real path data.
**This matches the RP qualification handshake already built**
(`charra_rp_qualification.c`, Part 3) almost exactly — same
generate-synthetic-data / compare-against-golden-answer shape.

**TEE variant (documented, not built)**: if the RP App has TEE capability,
Step 2 runs inside the TEE, `Evidence_r` additionally carries a signature
from the path-mapping SDK's own key, and `Evidence_a'` is no longer sent —
Verifier checks the SDK's signature instead of Step 3b. No TEE-specific
code exists in this repo.

#### Why software replay + TPM2_Quote, not extending a real PCR

Extending the RP's actual PCR10 was rejected: PCRs 0-15 aren't resettable on
a PC Client TPM (works once per boot), needs one TPM round-trip per log
entry (minutes for a large log), and needs locking against concurrent
attestations. It also buys nothing cryptographically — the RP's *software*
chooses which digests reach the TPM either way, so a dishonest RP produces a
validly-signed wrong answer regardless. The value of `TPM2_Quote` over
`TPM2_Sign` is that the quote structure *also* carries the RP's own PCR
values in the same signed object, and putting X in `qualifyingData` (the
same field the Attester's quote uses for its nonce) binds the redacted log
to that quote in one TPM call.

#### Consequences of recomputing template_digest

Because the RP recomputes `template_digest'` from redacted `template_data`,
the replayed PCR10 **can no longer match** the Attester's TPM-sealed
`pcrDigest` — not by policy but mathematically. The TPM is therefore not in
the Verifier's chain of trust for the PCR10 property; the guarantee is "the
RP vouches for this," anchored by the RP's own TPM rather than the
Attester's. Deliberate. This also means appraisal can read `file_hash`
directly — both `template_digest` and `file_hash` are equally RP-controlled
now, so there's no reason to prefer one over the other on TPM-anchoring
grounds.

#### Privacy note

The Attester's EK certificate is a permanent unique identifier for that
physical TPM — it must stop at the RP; forwarding it to the Verifier would
leak a stronger identifier than any file path redaction protects. The RP's
*own* EK cert going to the Verifier is intentional and fine: the RP is
known infrastructure the Verifier is meant to recognise.

### Resolved (previously "deliberately out of scope" / "open")

- **Freshness / replay protection on the Verifier side — RESOLVED.** The
  nonce used to be generated by the RP and merely echoed back by the
  Verifier's passive `/nonce` endpoint, proving freshness to nobody but the
  RP itself. Fixed: `/nonce` now returns a genuine Verifier-generated
  challenge — see its own entry in Part 3.
- **Reference PCRs for the RP — not needed.** Under DRA-TLS the Verifier
  never checks any PCR digest at all (RP's or Attester's).
- **Which PCRs `Quote_r` covers — moot.** `CHARRA_IMA_PCR_INDEX`
  (`charra_event_log.h`) is hardcoded to `10` and used everywhere; `Quote_r`
  ended up being a software replay signed by RP's AK, not a real TPM quote
  with its own PCR selection.
- **AK provisioning, Verifier side — built as `/certify_ak`** (Part 3): the
  Verifier acts as its own Privacy CA via `TPM2_MakeCredential`/
  `ActivateCredential`. **Still open on the Attester/RP side**: neither
  party has a persistent AK yet, nor client logic to call `/certify_ak` and
  attach the result to `/appraise` — see "Not yet built."
- **AK-provisioning state — built as `charra_ak_state.h`/`.c`** (Part 3): a
  persisted, on-disk record of every `/certify_ak` issuance. Renewal
  automatically revokes the requester's previous record; expiry is checked
  for free by `mbedtls_x509_crt_verify()`.
- **Manufacturer root CA trust store — built.** `keys/manufacturer-root.crt`
  + `charra_crypto_verify_x509_cert_chain()` is live in
  `coap_certify_ak_handler()`'s EK check.
- **Whitelist/blacklist wiring — built.**
  `verify_log_file_hashes_against_policy()` runs every RP-side Step 2a
  evidence check. Deny-by-default; `whitelist-hashes.txt`/
  `blacklist-hashes.txt` remain empty placeholders in this dev setup.
- **Certificate handling — built, extensively.** `mbedx509` is linked;
  X.509 parsing and chain validation run throughout `verifier.c` and
  `relying_party.c`.

### Still open

- **Attester key is not currently an AK — the single largest remaining
  gap.** `charra_key_mgr.c` still mints a fresh ephemeral primary key on
  demand for the Attester: no certification path, no persistence.
  Consequence: `verifier.c`'s Step 3b special-cases
  `res.ak_certificate_len == 0` and accepts anyway with a loud `"TEMPORARY"`
  log line, because that's *always* true today. Needs: a real persistent
  Attester AK (mirroring RP's `ensure_rp_ak_keypair()`), the Attester
  calling `/certify_ak` itself, and RP verifying that certificate
  independently — see "Planned end state" under the Step 3b bypass entry in
  Part 3, rather than the Verifier's bypass being relied on forever.
- **Blind spot in the PCR10-based integrity check**: replay only folds
  entries tagged for the target PCR, so entries for *other* PCRs could be
  added/removed/altered without affecting `X`. Accepted if the check is
  scoped to PCR10 integrity only; a hash over the whole redacted buffer
  would close it. Now squarely RP's Step 2a/2b concern.

### RP access/qualification check (from the deck, "RP Access Check Process")

Separate mechanism from per-attestation appraisal. Before an RP is trusted to
redact *real* Attester evidence, the Verifier proves — using data it
fabricates itself, so it already knows the correct answer — that the RP's
redaction pipeline actually works.

```
Verifier:  generate synthetic log, run its own copy of the SDK's redaction
           logic on it locally, store the result as the "golden answer",
           send (SDK, raw synthetic log) to the RP

RP:        runs the SDK, produces (Log, Quote_R), submits both back

Verifier:  Log      -- compared byte-for-byte against the golden log
           Quote_R   -- compared on pcrDigest/extraData ONLY, never raw
                        signature bytes (RSA-PSS salts, so two honest
                        signings over identical data never match bytewise)
           pass -> qualified, credential has an expiry
           fail -> rejected
```

Decisions made (via AskUserQuestion):
- **Timing: periodic re-check**, not one-time onboarding or covert canary
  injection. RP's qualification has an expiry; real `/appraise` requests
  are gated on `qualified && !expired`.
- **RP-initiated**, matching every existing endpoint (Verifier never opens
  an outbound session). Self-enforcing even for a dishonest RP: the
  `/appraise` gate checks expiry regardless of whether RP asks to
  re-qualify.
- **SDK-execution enforcement: deferred, trust RP for now.** No proof RP
  ran the actual unmodified SDK rather than a substitute that happens to
  produce a matching answer. Closing this later needs RP's own IMA to
  measure the SDK binary specifically — real, larger scope.

#### Redaction rule for the SDK: hash the path (implemented)

An earlier draft planned blanking `template_data` entirely
(`template_data_len = 0`, digest = `SHA256("")`) — rejected before being
built: every redacted entry would share the identical digest, so the
Verifier's golden-answer comparison couldn't distinguish "RP correctly
redacted N different paths" from "RP redacted nothing and just zeroed
everything."

**What's actually implemented** (`src/core/charra_sdk.h`/`.c`,
`charra_sdk_redact_ima_log()`): per entry, locate the path inside
`template_data` (skip the `"sha256:"`/`"sha1:"` + file-digest + NUL prefix,
the layout a real `ima-ng` entry uses), hash *the path itself* with
SHA-256, replace `template_data` with nothing but that hash (32 raw bytes),
recompute `template_digest = SHA256(new template_data)`. Every other field
(`pcr_index`, `template_name`) copied through unchanged. Different original
paths now hash to different values, distinguishable from each other again
(`test_different_entries_redact_differently`, `tests/test_sdk.c`). The
file-content digest is discarded, not preserved for future appraisal —
simple on purpose. Redacted logs stay valid `charra_replay_ima_log()` input;
redaction of the same input is deterministic *unless* a salt is involved —
see "structurally broken by salted redaction" in Part 3 for why salting was
added later and what it changes.

Known limitation: assumes the `"sha256:"`/`"sha1:"` + digest + NUL + path
flat layout. A real IMA log's `ima-ng` template technically nests its own
length-prefixed sub-fields — untested against that shape (fine for now
since this pairs with `charra_synth_generate_ima_log()`, which produces
exactly the assumed layout; worth revisiting once real Attester logs are in
the picture — see "synthetic-log generator" entry in Part 3, where this was
in fact later made to match the nested layout).

---

## Part 3 — Code inventory: everything added or modified

### `src/core/charra_event_log.h`/`.c` — shared replay module

Meant to be called identically by the Relying Party (on the raw log) and
the Verifier (on the redacted log) — same function, different bytes in.

| Function | Purpose |
|---|---|
| `charra_pcr_reset` | Zero an accumulator — a PCR's power-on state. |
| `charra_pcr_extend` | One extend: `acc := SHA256(acc \|\| digest)`, zero-padding digests shorter than 32 bytes (SHA-1 → SHA-256 bank). **The invariant that must never diverge between RP and Verifier.** |
| `charra_event_log_ima_detect_digest_len` | Recovers whether template digests are 20 (SHA-1) or 32 (SHA-256) bytes by trial-parsing, since the format doesn't record it. |
| `charra_replay_ima_log` | **Public entry point.** Parses every entry, extends the ones matching `target_pcr_index`, returns the resulting PCR value. Tries both digest sizes, never falsely rejects a well-formed log. Warns (not errors) if a non-empty log has zero matching entries. |
| `charra_event_log_parse_entry` | Parses one TLV entry, advances `*offset`. Every length check written as `need > log_len - offset`, not `offset + need > log_len`, so a hostile length field can't overflow past the check. Rejects the legacy `"ima"` template outright. **Public** — the RP qualification work needed a second consumer of this exact bounds-checked parser. |
| `charra_event_log_append_u32`/`_bytes` | Write-side counterparts of the read path, kept in this file so byte order can't drift between reader and writer. Originally duplicated byte-for-byte in `charra_synthetic_log.c` and `charra_sdk.c`; factored here once spotted. |
| `read_u32` *(static)* | Little-endian `uint32` read, byte-wise (no cast/alignment assumptions). |
| `log_parses_at` *(static)* | Whole-log trial parse for digest-length detection. |
| `replay_at` *(static)* | Combined parse+extend in one pass, what `charra_replay_ima_log` calls per candidate digest size. |

Constants: `CHARRA_IMA_PCR_INDEX` (10), `CHARRA_IMA_TEMPLATE_NAME_MAX` (64).

*(An earlier iteration wired this into `verifier.c` with a composite-digest
check against the Attester's original `pcrDigest`; removed once the trust
model changed to "Verifier trusts RP." If a composite check against a
reference file is ever needed again — e.g. for the RP's own boot PCRs — the
shape that worked was adding `(replayed_pcr_value, replayed_pcr_index)` to
`charra_check_pcr_digest_against_reference()`, substituting that value into
each candidate set before hashing, `NULL` to preserve original behaviour.)*

#### Log content verification — lives here, not in `verifier.c`, per the DRA-TLS spec

Originally `static` helpers inside `verifier.c`'s `coap_appraise_handler`
under the superseded v1 design (Verifier re-checked `log_r` itself). Once
DRA-TLS confirmed this is entirely the **RP App's Step 2a** job (against
`log_a`, before redaction), relocated here and renamed to drop the `_r`
suffix — general log-verification logic, not specific to the redacted log:

| Function | Purpose |
|---|---|
| `verify_log_entries_self_consistent` | Step 2a item 4: per entry, `template_digest == SHA256(template_data)`. Catches internal malformation, not content honesty. |
| `verify_log_matches_quote_r_pcr` | Step 2a item 5: replays the log, checks the result against a quote's `pcrDigest`. Name references `quote_r` from its original context; logic is generic to any single-PCR-selection quote. |
| `verify_log_file_hashes_against_policy` | Step 2a item 6: default-deny — a digest matching neither list fails, same as an explicit blacklist match. Paths are function parameters, not globals. Reads the file-content digest from the redacted `template_data`'s known layout. |
| `compare_hashes` / `load_hash_list` / `hash_list_contains` *(static)* | `qsort`/`bsearch`-based membership check against a `whitelist-hashes.txt`/`blacklist-hashes.txt`-shaped file. |

**Status**: built, unit-tested indirectly; wiring these into
`relying_party.c`'s actual Step 2a flow is still open (see "Not yet built").

### `src/core/charra_synthetic_log.h`/`.c` — synthetic IMA log generator

For the RP qualification check. Produces a genuinely well-formed,
realistic-looking raw log, valid input to `charra_replay_ima_log()`.

| Function | Purpose |
|---|---|
| `charra_synth_generate_ima_log` | Generates `num_entries` PCR10-targeted `ima-ng` entries with fabricated-but-plausible `template_data` and a real `SHA256(template_data)` digest. Deterministic: same `(num_entries, seed)` → byte-identical output. Caller `free()`s the buffer. |
| `make_fake_file_digest` *(static)* | Fabricated 32-byte "file digest" derived from `(seed, index)` via SHA256 — reproducible, not a real hash. |

### Tests: `tests/test_event_log.c` (29), `tests/test_synthetic_log.c` (13)

`test_event_log.c`: no TPM/network required, expected PCRs computed
independently via a hand-written reference extend. Covers empty/multiple
entries, order-sensitivity, `pcr_index` filtering, redaction preserving
replay, SHA-1 zero-padding, malformed/truncated/hostile-length logs, legacy
`ima` template rejection, bad arguments.

`test_synthetic_log.c`: feeds the generator's own output into
`charra_replay_ima_log()` and confirms success (cross-validation, not
self-assertion), plus determinism, seed divergence, presence of fabricated
sensitive paths, bad-argument rejection.

### `src/core/charra_sdk.h`/`.c` — the redaction SDK

See "Redaction rule for the SDK" in Part 2. First genuine second consumer
of `charra_event_log_parse_entry()`.

| Function | Purpose |
|---|---|
| `charra_sdk_redact_ima_log` | Per entry: extract the path, replace `template_data` with `SHA256(path)` (32 raw bytes), recompute `template_digest`. `pcr_index`/`template_name` unchanged. Two-pass (count then build, since redaction can *expand* a short original `template_data`). Caller `free()`s the buffer. |
| `extract_path` *(static)* | Skips the digest-prefix to isolate the path; over-short `template_data` treated as an empty path, never read out of bounds. |

Uses `charra_event_log_append_u32`/`_bytes` from `charra_event_log.c`
(originally duplicated byte-for-byte locally; factored out once spotted).
Tested in `tests/test_sdk.c` (grew from 15 to 23 assertions across this
project's lifetime — redaction validity, PCR divergence after redaction,
determinism/salted-nondeterminism, empty log, bad arguments).

### `Makefile`

- `core` object list: `charra_event_log charra_synthetic_log charra_sdk
  charra_rp_qualification charra_ak_state charra_qualification_state
  charra_rp_key_mgr`.
- `mbedx509` linked (alongside `mbedcrypto`) once X.509 work landed.
- Test targets, one per suite, all folded into `make test`: currently 9
  binaries (`test_event_log`, `test_synthetic_log`, `test_sdk`,
  `test_rp_qualification`, `test_marshaling_bounds`, `test_x509_cert_chain`,
  `test_certify_ak_marshaling`, `test_ak_state`,
  `test_rp_appraisal_marshaling`).

### `src/core/charra_rp_qualification.h`/`.c` — RP qualification handshake logic

`charra_rp_qualification_generate()` fabricates a synthetic log, redacts it
locally, precomputes the golden answer (golden log + golden PCR);
`charra_rp_qualification_check()` compares an RP's submission against it and
sets `qualified`/`expires_at`; `charra_rp_qualification_is_valid()` is the
gate `coap_appraise_handler` applies. `tests/test_rp_qualification.c`, 28
assertions (see "salted redaction" entry below for the fix that brought it
from 4-failing to 0).

### Quote-signature verification helpers — history and current location

First attempt: a standalone, cross-role `charra_verify_tpm2_quote()`
generic over who produced the quote (Attester or RP), verified live (9/9
assertions). **Reverted**: it would have merged the per-sub-step
`clock()`-bracketed timing instrumentation `coap_appraise_handler` writes to
`durations_verifier.txt` (load/verify/nonce/PCR measured separately) into
one opaque call, for reuse that had no second caller. Decision at the time:
decompose by *readability*, not by *reuse* — small helpers callable from
`coap_appraise_handler`, kept local to `verifier.c`.

**What was built then** (as `static` functions in `verifier.c`,
`verify_quote_signature_with_tpm()` / `verify_quote_signature_mbedtls()`):
replaced ~55 lines of inline blocks with two named calls.
`verify_quote_signature_mbedtls()` preserves two-tier failure handling: a
hard RSA-conversion failure returns `false` (caller `goto cleanup`), a
mismatched signature is soft (`out_valid` out-param, folded into the
combined `attestation_result` alongside the TPM check, nonce check, PCR
check).

**Relocated, later session, into the shared modules that already own the
underlying primitive** — `verify_quote_signature_with_tpm()` →
`charra_verify_tpm2_quote_signature_with_tpm_logged()` in
`src/util/charra_util.h`/`.c` (next to
`charra_verify_tpm2_quote_signature_with_tpm()`, which it wraps);
`verify_quote_signature_mbedtls()` →
`charra_crypto_verify_quote_signature_mbedtls()` in
`src/util/crypto_util.h`/`.c`. This does not reopen the concern that caused
the earlier revert: unlike that attempt, the two calls stay separate (no
merging of load/verify/nonce steps into one opaque call), and in current
code neither call sits inside a `clock()` bracket anyway (the
`verify_signature_duration` bracket around line ~673 covers only Quote_r's
RP-signature check, not these two) — so nothing about the timing
instrumentation, granular or otherwise, changed. Both functions dropped
their old side effect of writing `verifier.c`'s file-scope `attestation_rc`
global: traced every use of that global in `coap_appraise_handler` and
confirmed the value these two wrote was always unconditionally overwritten
before ever being read, so removing the write (replaced with a purely local
`CHARRA_RC` inside each function) is behavior-preserving. Verified: clean
rebuild (zero warnings) + a full live 1–5-verifier sweep, all attestations
passing, log tags now `[crypto_util]`/untagged in place of `[verifier]`.

### `verifier.c` — AK-serial validity check relocated to `charra_ak_state.c`

`is_ak_serial_currently_valid()` — the Step 3a/3b item 1 revocation check
(looks an AK certificate's serial up in the AK-provisioning ledger, requires
`charra_ak_state_is_valid()` too, since chain validity alone doesn't know
about a since-renewed-away serial; also the identity bridge from AK serial
to `ek_fingerprint` that `charra_qualification_state.h`'s ledger is keyed
by) — was originally a `static` function in `verifier.c`. Relocated, same
later session as the quote-verification move above, to
`charra_ak_state_check_serial_valid()` in `src/core/charra_ak_state.h`/`.c`,
since it's a pure composition of that module's own
`charra_ak_state_load`/`_find_by_serial`/`_is_valid` and belongs with them.
`ak_state_file_path` (a `verifier.c` static) became an explicit first
parameter, matching every other `charra_ak_state_*` function's signature.

### `parse_utc_yyyymmddhhmmss` relocated to `crypto_util.c` as `charra_crypto_parse_utc_yyyymmddhhmmss`

Parses a `"YYYYMMDDHHMMSS"` UTC timestamp (the format
`ak_cert_not_before_utc`/`ak_cert_not_after_utc` and
`charra_crypto_sign_ak_certificate()`'s params use) into a `time_t`, used to
record an issued AK certificate's real expiry in the AK-provisioning state
by parsing the exact string that was signed into the certificate, rather
than approximating "issued_at + duration." Pure function, moved alongside
`charra_crypto_x509_days_until_expiry()` (same file) which it complements.

### `verifier.c`'s certificate-summary logger relocated to `crypto_util.c` as `charra_crypto_log_cert_summary`

Logs a successfully chain-verified certificate's subject/issuer/serial/
days-until-expiry at INFO level (previously only failures got X.509 detail).
Was `log_cert_chain_success()`, `static` in `verifier.c`; moved since it's
pure X.509 logging built entirely on `charra_crypto_x509_days_until_expiry()`,
already in `crypto_util.c`.

**Net effect of the four relocations above**: `verifier.c` dropped from
1890 to 1725 lines. The remaining bulk (~70% of the file) is the five CoAP
resource handlers themselves (`coap_appraise_handler`, `coap_nonce_handler`,
`coap_certify_ak_handler`, `coap_qualify_handler`,
`coap_qualify_submit_handler`), which were deliberately **not** further
split into separate translation units: they're tightly coupled to ~20
file-scope static globals (`quit`, `last_request`,
`verifier_challenge_nonce`, `qualification_state`, cert paths, `port`, DTLS
flags, ...), and splitting them would require either externing all of those
globals or threading a new shared context struct through every handler and
callee — judged higher risk than the payoff, given the file's length is a
navigation problem, not a logic-complexity one.

### The real RP→Verifier message shape (`msg_rp_appraisal_dto`)

The RP sends the Verifier one bundle: `Evidence_r` (`Quote_r`, `log_r`,
`EK_r`/`AK_r`) plus `Evidence_a'` (`Quote_a`, `EK_a`/`AK_a`, `log_a`
deliberately stripped). Mapped against Step 3a/3b: neither `Quote_a`+EK/AK
nor `Quote_r`+EK/AK get a PCR check (not part of the spec's Verifier steps);
`log_r` gets **no** content inspection at all — the per-entry hash check,
PCR replay, and file-hash policy (spec Step 2a items 4/5/6) are the RP
App's job against `log_a`, before redaction (see `charra_event_log.c`
above). Because redaction changes `template_digest` per entry, replaying
`log_r` would never reproduce the PCR value `Quote_a` attests to even if the
Verifier did check it — `Quote_r` functions purely as the RP's own
non-repudiation signature over "this is genuinely what I processed," same
mechanism the qualification handshake already uses on fabricated data.

**Why `Quote_r` needs its own public key + signature on the wire**:
verification needs signed data + signature + public key, and there's no
persistent key registry or EK/AK-pinning anywhere (not even
`rp_qualification_state`, which stores `qualified`/`expires_at` but not a
bound key) — so the key travels in the message, same as `Quote_a`'s already
does.

**Built**: `msg_rp_appraisal_dto` (`charra_dto.h`) — Quote_a's three fields
+ Quote_r's three (mirrored shape) + `event_log` (meaning `log_r`) + two
variable-length AK certificate fields (`ak_certificate`/`_len` for EK_a/AK_a,
`ak_certificate_rp`/`_len` for EK_r/AK_r), 9 CBOR array elements total.
`charra_marshal_rp_appraisal()`/`charra_unmarshal_rp_appraisal()`
(`charra_marshaling.c`) bounds-check every fixed-size field against its
destination `sizeof` before copying. `coap_appraise_handler` unmarshals,
re-validates bounds independently (defense in depth), and verifies both
quotes with the shared helpers from the entry above — separate
`ESYS_TR sig_key_handle_rp` / `TPMT_TK_VERIFIED* validation_rp`, both
flushed/freed in `cleanup:`. `attestation_result` folds in 8 booleans: EK/AK
+ two signature checks + one nonce check, per quote (Quote_a, Quote_r) —
spec-complete on the Verifier side, no PCR term, no `log_r` term.

Test coverage: `tests/test_rp_appraisal_marshaling.c`, 17 assertions (round-
trip on all 9 byte-string fields; empty `ak_certificate` accepted, since
that's the case every live run hits today with no Attester AK client yet;
oversized fixed-size fields rejected via hand-encoded QCBOR, covering
`tpm2_public_key` — the field bug #1 in the audit below was about —
`attestation_data`, and `tpm2_signature_rp`).

**Still genuinely unbuilt** (`relying_party.c`'s Step 2a/2b): EK/AK
validation of the Attester; calling
`verify_log_entries_self_consistent()`/`verify_log_matches_quote_r_pcr()`/
`verify_log_file_hashes_against_policy()` against `log_a`; real redaction
call (`charra_sdk_redact_ima_log()` exists, tested, uncalled here); `Quote_r`
generation; calling `charra_marshal_rp_appraisal()` to send both evidence
bundles onward, mirroring how `attester.c` calls
`charra_marshal_attestation_response()` today.

### Step 3a/3b item 1: EK/AK certificate validation

Closes the last placeholder in `coap_appraise_handler` — the Verifier's
spec-mandated scope (Step 3a/3b, all three items) is fully implemented; the
remaining gap is entirely on the Attester/RP side.

**Check**: `charra_crypto_verify_ekak_certificate()` (`crypto_util.c`) —
combines chain verification + "cert's key matches the quote's signing key."
Called once for Step 3a item 1 (RP's cert against `keys/verifier-ca.crt`,
folds into `step_3a_passed`) and once for Step 3b item 1 (Attester's cert,
only reached if Step 3a passed). Both call sites originally duplicated this
logic inline; factored into `crypto_util.c` (not a new `core/` file — judged
not worth fragmenting a two-call combinator over a directory split). The
trust anchor (`keys/verifier-ca.crt`) is read once, shared by both checks —
the same CA `coap_certify_ak_handler` itself signs with.

**Verified live** (via a temporary not-committed client minting two real AK
certificates directly with the Verifier's own CA key): with genuine
certificates, both checks log "valid!", ending in `ATTESTATION SUCCESSFUL`;
with RP's certificate tampered (one flipped byte), the chain check fails,
Step 3b is skipped entirely (early-exit gating holds), ending in
`ATTESTATION FAILED` with `Quote_a` never inspected — matching the spec's
early-exit wording.

**Reusable by RP** for its own Step 2a item 1: same
`charra_crypto_verify_ekak_certificate()`, no new state needed — see the
"Reusable by RP" note under `/certify_ak` below.

### `/certify_ak` — Verifier-as-Privacy-CA AK issuance

Implements the Verifier-side half of AK provisioning: the Verifier merges
the Privacy CA role into itself (acceptable since this project's privacy
goal is hiding file paths, not device identity from the Verifier) and issues
AK certificates via standard TPM2 Credential Activation
(`TPM2_MakeCredential`/`ActivateCredential`), no separate manual CA
enrollment step.

**Why a separate endpoint, not folded into `/appraise`**: a first-ever
uncertified-AK request can't carry a meaningful appraisal verdict, since
`ActivateCredential` (which must complete on the requester's own TPM) hasn't
happened yet. The resulting certificate is re-presented on every subsequent
`/appraise` call (Verifier is stateless per-request).

**Why the credential is a symmetric key, not the certificate itself**:
`MakeCredential`'s `credential` field is capped near a digest size, too
small for an X.509 certificate. Resolved: the credential is a fresh AES-256
key `K`; the signed AK certificate travels in the same response,
AES-256-GCM-encrypted under `K`. The requester recovers `K` via
`ActivateCredential` on their own TPM (proving EK+AK co-residency without
the EK private key ever leaving), decrypts — one round trip.

**Wire**: `msg_certify_ak_request_dto`/`msg_certify_ak_response_dto`
(`charra_dto.h`), `charra_marshal_certify_ak_request()`/
`charra_unmarshal_certify_ak_request()` + response equivalents.
`tests/test_certify_ak_marshaling.c` — 20 assertions (round-trips,
oversized-field rejection, wrong-size rejection for the fixed-size
`aes_gcm_nonce`/`aes_gcm_tag`).

**New crypto primitives** (`src/util/crypto_util.h`/`.c`):

| Function | Purpose |
|---|---|
| `charra_crypto_seeded_rng_init`/`_free` | Reusable seeded `mbedtls_ctr_drbg_context` for key parsing, cert signing, AES-GCM nonce generation. |
| `charra_crypto_verify_x509_cert_chain` | Single-root chain verification (leaf vs. one trusted root, no intermediates — this project's two-tier PKI). Validity-window check is a side effect of `mbedtls_x509_crt_verify()`; no revocation check. |
| `charra_crypto_verify_cert_public_key_matches_tpm_public_key` | Confirms a cert's embedded RSA key matches a `TPM2B_PUBLIC` — "this cert vouches for the key that signed this quote." |
| `charra_crypto_verify_ekak_certificate` | Combines the two above; deliberately generic over the caller. |
| `charra_crypto_sign_ak_certificate` | Verifier-as-CA: signs a fresh AK certificate for a given `TPM2B_PUBLIC`. |
| `charra_crypto_build_ek_tpm2b_public_from_cert` | Reconstructs the full TCG-standard RSA-2048 EK `TPM2B_PUBLIC` (fixed "low range" template) from an already-verified EK certificate — `Esys_MakeCredential` needs the whole public area, not just the modulus. Template values (`objectAttributes 0x300b2`, authPolicy digest) confirmed empirically against a real `tpm2_createek -G rsa` on this project's TPM simulator. |
| `charra_crypto_aes256gcm_encrypt`/`_decrypt` | Wraps/unwraps the AK certificate under the MakeCredential secret. Decrypt is authenticated (`mbedtls_gcm_auth_decrypt`) — tampered ciphertext or wrong key returns `CHARRA_RC_VERIFICATION_FAILED`, no plaintext. |

**Reusable by RP** for its own Step 2a item 1 (validate Attester's EK/AK):
`charra_crypto_verify_ekak_certificate()` takes no Verifier-specific state —
`crypto_util.o` is already in every binary's link. RP would call it exactly
as `coap_appraise_handler` does for Step 3a/3b item 1: against the
Attester's already-issued AK certificate and `keys/verifier-ca.crt` — the EK
is validated exactly once, at `/certify_ak` time, never re-checked. The
issuance-side functions (build-EK-template, sign-AK-cert, MakeCredential,
AES-GCM *encrypt*) stay Verifier-only; AES-GCM *decrypt* would belong to
whichever party requests certification.

**New TPM primitive** (`src/core/charra_key_mgr.h`/`.c`):
`charra_tpm_make_credential_for_ak()` wraps `Esys_MakeCredential` — loads the
requester's EK externally via `Esys_LoadExternal`, no Verifier TPM identity
needed. Trusts the caller-supplied AK name unverified — a wrong name just
fails the requester's own later `ActivateCredential`.

**Handler**: `coap_certify_ak_handler()` in `verifier.c`. Flow: unmarshal →
verify EK cert chains to `keys/manufacturer-root.crt` (else `4.01
Unauthorized`) → reconstruct EK `TPM2B_PUBLIC` → sign a fresh AK cert
(`"CN=CHARRA AK"`, issuer read from `keys/verifier-ca.crt`'s own subject,
fixed test-only validity `2024`-`2034`) → fresh AES-256 key, AES-GCM-encrypt
the cert → `Esys_MakeCredential` to wrap that key → record the issuance
(`charra_ak_state_renew()`, revoking any previous record for this EK) →
marshal + send. The state-recording step deliberately happens only after
signing and `MakeCredential` both succeed, so a later failure can never
revoke a working certificate the requester never actually received.

**Test-only PKI** (`keys/gen-ak-pki.sh`, `keys/README.md`):
`verifier-ca.{key,crt}` (self-signed), a synthetic
`manufacturer-root.{key,crt}` standing in for a real TPM manufacturer root,
`rp-ek.{key,crt}`/`attester-ek.{key,crt}` synthetic EK certs — plain
openssl RSA keys, not yet the TPM simulator's own endorsement hierarchy
(tracked in "Not yet built"). Certs are DER; keys stay PEM.

**Verified**: `tests/test_x509_cert_chain.c` (17 assertions — chain
verification valid/wrong-root/tampered, key-matching, sign-then-verify round
trip); `tests/test_certify_ak_marshaling.c` (20, above); a temporary
direct-call smoke test against the real TPM simulator (14/14: EK chain
verify → template reconstruction → real `MakeCredential` → AK signing →
AES-GCM round trip → tampered-tag rejection); a temporary end-to-end CoAP
client against real `bin/attester`+`bin/verifier` confirmed bad-EK rejection
(`4.01`), correct multi-datagram block-wise reassembly, and a full genuine
`Evidence_r`/`Evidence_a'` bundle producing `ATTESTATION SUCCESSFUL` through
`/nonce` then `/appraise`.

### AK-provisioning state — `src/core/charra_ak_state.h`/`.c`

Gives `coap_certify_ak_handler()` memory of previous issuances, on disk,
surviving separate calls and a server restart.

**Renewal policy**: requesting a new AK certificate for an EK that already
has one on file always issues a fresh certificate and revokes the previous
record for that EK (rolling renewal, not reject or serve-the-same-cert).
**Revocation trigger**: only a fresh renewal for the same EK revokes
anything — no manual/administrative trigger exists yet, deliberately.

**Record** (`charra_ak_state_record`): `ek_fingerprint` (SHA-256 of the
requester's EK cert DER), `ak_name`/`ak_name_len`, `serial` (16 bytes),
`issued_at`, `expires_at` (parsed from the exact signed
`"YYYYMMDDHHMMSS"` string, not approximated), `revoked`.

**Storage**: one line per record, whitespace-separated hex/decimal fields,
same convention as `verifiers_config.txt`/`reference-pcrs.txt`. Missing
file = zero records, not an error.

**Concurrency**: `charra_ak_state_renew()` — the only writer, and the only
function `coap_certify_ak_handler()` calls directly — takes an advisory
`flock()` on a companion `.lock` file around its revoke-then-append cycle,
safe across the multiple `bin/verifier` OS processes.

**A bug caught before shipping**: `charra_ak_state_find_by_ek_fingerprint()`
was first a forward linear scan (first match) — after 2+ renewals for the
same EK, multiple records exist (oldest first, since `_renew()` only
appends), so a forward scan would keep finding the oldest, already-revoked
one, permanently orphaning the actually-active record. Fixed to scan
backward. Regression-tested with four renewal cycles in a row, asserting
exactly the last-issued record stays unrevoked.

**`charra_crypto_sign_ak_certificate()` signature change**: gained a
`uint8_t serial_out[16]` out-param (it previously generated and discarded a
random serial internally). Updated at both call sites (`verifier.c`,
`tests/test_x509_cert_chain.c`).

**Verified**: `tests/test_ak_state.c`, 39 assertions (round-trip, find-by-
fingerprint most-recent-not-oldest, find-by-serial, `is_valid`, first
issuance, four-cycle renewal regression, bad arguments). A temporary live
check: two real `/certify_ak` requests for the same EK produced the exact
expected two-line state file (first `revoked=1`, second `revoked=0`,
different serials).

### Live end-to-end verification (Docker, real TPM simulator)

Ran the full quartet against the dev-env container's TPM simulator, no
mocks — 11 full attestation cycles succeeded (`ATTESTATION SUCCESSFUL`),
TPM-based and mbedTLS-based signature checks agreeing `valid!` every run.

Found one **environment** bug, unrelated to CHARRA's own code: the
container's `/usr/local/bin/tpm-reset` helper calls `tpm2_startup --clear`
with a stale `TPM2TOOLS_TCTI_NAME=socket` scheme this image's `tpm2-tools`
5.6 doesn't honor, so `TPM2_Startup` silently never ran (script doesn't
check its exit code) — every TPM op then fails "TPM not initialized."
Worked around with `tpm2_startup -c -T "mssim:host=127.0.0.1,port=2321"`
directly. Also: `pkill -f`/`pgrep -f` match the *full command line*,
including the invoking shell's own script text if it contains the same
substring (self-matching, self-killing) — use `pkill`/`pgrep` without `-f`,
or exact PIDs.

### Not yet built (tracked so nothing gets lost between sessions)

- RP-side Step 2a + 2b of the DRA-TLS spec — see "Still genuinely unbuilt"
  under the message-shape entry above.
- Real, persistent AK provisioning for both Attester and RP — neither has
  one yet; `charra_key_mgr.c` still mints a fresh ephemeral primary key per
  request. This is now the sole remaining blocker on `/appraise` ever
  succeeding for real (non-bypassed) evidence — Verifier-side checks are
  complete.
- Real (non-synthetic) EK certificates on the TPM simulator's actual
  endorsement hierarchy — `keys/gen-ak-pki.sh`'s EK certs are plain openssl
  keys today, not real TPM objects.
- A manual/administrative AK revocation trigger — out of scope for now; the
  only thing that revokes a record is a fresh renewal for the same EK.

### Bugs found during audit of `verifier.c` — status

**Line numbers in any earlier version of this section are stale** (repeated
refactors have shifted the file substantially); locate by function/variable
name.

1. ~~Unbounded `memcpy` into `tpm2_public_key`~~ **Fixed** —
   `charra_marshaling.c` bounds-checks every byte-string field against its
   destination `sizeof` before copying.
2. ~~`attestation_data` bounds check used the wrong `sizeof`~~ **Fixed** —
   checks against `sizeof(TPMS_ATTEST)`, not the larger `TPM2B_ATTEST`.
3. ~~Uninitialized `esys_ctx`/`tcti_ctx` read if `fopen()` fails~~ **Fixed**
   — both NULL-initialized before the `fopen()` call.
4. ~~mbedTLS signature check result discarded~~ **Fixed** — folded into the
   final `attestation_result`.
5. ~~File handle leak on every error path~~ **Fixed** — every early exit
   goes through `goto cleanup`, which unconditionally closes `p_file`.
6. **Global `last_request` risks cross-session nonce mixing — still open,
   deliberately.** Shared mutable state between `/nonce` and `/appraise`,
   overwritten by whichever RP's `/nonce` call lands most recently
   regardless of which RP is mid-appraisal. Can't forge an accept (nonces
   are random, no plausible collision), but can cause spurious appraisal
   failures if multiple RPs' exchanges interleave against one Verifier
   process. A proper fix needs pending-nonce state keyed per requesting
   session/peer; out of scope by explicit decision — same class of
   single-in-flight-round simplification `qualification_state` originally
   accepted too (though that one is now fixed, see "identity-bound and
   persisted" below).
7. ~~`relying_party.c` `strcmp` result inverted, swapped pass/fail~~
   **Fixed** — see "Live end-to-end verification on `EK/AK_rp_verifier`"
   below.

Only bug 6 remains open.

### RP qualification handshake was structurally broken by salted redaction — FIXED

`charra_rp_qualification_check()` compares an RP's submitted redacted log
against a locally-computed golden log with a byte-exact `memcmp()`.
`charra_sdk_redact_ima_log()` was separately rewritten to hash each path
with a **fresh random salt per call**, deliberately never transmitted, so
equal paths don't redact to equal values across separate redactions. Nobody
updated the qualification check for this: **an RP running the exact
correct SDK could never produce byte-identical output**, since both calls
minted independent salts — not merely stale, structurally unable to pass.
Caught via `make test` (`test_rp_qualification`, 4 failing). Consequence
once the appraisal gate landed before this fix: every `/appraise` call
rejected `4.03 Forbidden` regardless of evidence correctness.

**Fix**: `charra_sdk_redact_ima_log()` gained an optional `salt` param —
`NULL` (default, used for all real evidence) generates a fresh random salt
per entry as before; a caller-given `CHARRA_SDK_PATH_SALT_LEN`-byte salt
makes two redactions byte-identical. The one deliberate exception to "salt
is never transmitted" — safe because the qualification challenge is
Verifier-fabricated synthetic data, never real evidence. Verifier now
generates one random salt per `/qualify` challenge, redacts its own golden
copy with it, sends it alongside the raw log
(`msg_qualify_response_dto`'s `salt` field); RP redacts with that same salt
before submitting. `test_rp_qualification` 4→0 failing (27→28 assertions,
new bad-argument check for the now-mandatory salt); `test_sdk` 20→23
(new determinism test for the shared-salt path).

### RP qualification handshake wired end-to-end

- **Wire**: `msg_qualify_response_dto`/`msg_qualify_submit_request_dto` +
  matching marshal/unmarshal.
- **Verifier endpoints**: `coap_qualify_handler()` (`/qualify` — fabricates
  a fresh challenge via `charra_rp_qualification_generate()`) and
  `coap_qualify_submit_handler()` (`/qualify_submit` — chain-verifies the
  submitter's AK cert, same check as Step 3a item 1, then verifies an
  RSA-PSS/SHA-256 signature over the submitted PCR digest before calling
  `charra_rp_qualification_check()`) — backed by a new
  `qualification_state` global (single-RP assumption, matching
  `last_request`'s existing convention).
- **RP client**: `rp_perform_qualification_handshake()` — fetches the
  challenge, redacts it through the same `charra_sdk_redact_ima_log()`
  pipeline real evidence uses, replays into a PCR digest, signs with RP's
  TPM-resident AK, submits. Runs once per Verifier per attestation cycle,
  before `/appraise`. `rp_coap_fetch()` factors out the shared
  create-context/session/PDU/wait-loop boilerplate.
- **The gate**: `coap_appraise_handler` checks the requesting RP's
  persisted qualification record (see "identity-bound and persisted"
  below), rejecting `4.03 Forbidden` — deliberately not `4.01`, which RP's
  retry logic already treats as "go redo `/certify_ak`."

**Live bug found and fixed**: `coap_qualify_submit_handler()` returns
`2.05 Content` for *both* qualified and not-qualified (message text carries
the verdict). RP's first response handler treated any `2.05` as success —
fixed to `memcmp` the body against the expected success message, mirroring
the `strcmp`→`memcmp` fix from bug #7 above.

### RP qualification is now identity-bound and persisted

The gate above originally checked one in-memory `qualification_state` with
two real gaps: (1) **not bound to any RP identity** — checked *before*
reading the incoming request's own AK certificate, so a passing
qualification from RP A would also let RP B's `/appraise` through if B's
request landed inside A's still-valid window; (2) **not persisted** — a
Verifier restart forgot every RP's qualification instantly.

**Fix**: `charra_qualification_state.h`/`.c`, mirroring
`charra_ak_state.h`/`.c`'s shape (hex-encoded lines, `flock()`-guarded
`_renew()`, most-recent-wins backward scan), smaller record
(`ek_fingerprint`, `qualified_at`, `expires_at` — qualification only
expires, no revocation concept). Identity comes for free:
`coap_qualify_submit_handler()` already extracts the submitter's
`ek_fingerprint` while chain-verifying its AK cert, so a passing submission
is persisted keyed by that same fingerprint, no new wire field needed.
`coap_appraise_handler`'s gate mirrors this: after Step 3a item 1 derives
the requester's `ek_fingerprint`, a new item 1b looks it up in the
qualification ledger, folding the result into `attestation_result_
qualified`, with its own `4.03` message distinguishing "not qualified" from
"AK certificate invalid" (`4.01`, checked first).

**Deliberately still per-Verifier, not shared like the AK ledger.** Path is
`qualification-state-<port>.txt`, unique per process — preserves that an RP
must independently pass `/qualify`+`/qualify_submit` with *each* Verifier,
since qualification is each Verifier's own assessment of the RP's redaction
pipeline (unlike AK certification, one CA, valid everywhere). Confirmed
live with a 2-verifier setup: two independently-populated files, both
correctly keyed by the same `ek_fingerprint`; restarting one Verifier left
its file and the RP's earned qualification intact.

**Not addressed here, fixed later** (see "RP now caches its own
qualification client-side" below): `relying_party.c` re-ran the full
`/qualify`+`/qualify_submit` round trip every cycle, even against Verifiers
it already held a valid qualification with.

### RP AK certification is now independent per-Verifier

Even after the qualification fix above, AK *certification* wasn't
per-Verifier yet: `relying_party.c` fetched one AK certificate from
`verifiers[0]` via one `/certify_ak` call and reused it for every Verifier —
contradicting Verifier independence.

**Fix**: split into (1) **keypair**
(`ensure_rp_ak_keypair()` — the TPM-resident EK+AK, created once per RP
process, verifier-agnostic, cached at `rp-ak-public.bin`/
`rp-ak-private.bin`) and (2) **certificate**
(`ensure_rp_ak_certificate(int verifier_index)` — requested via its own
`/certify_ak` call to *each* Verifier, cached per-port, tracked in new
per-Verifier arrays instead of one shared global). Called from inside
`get_attestation_results_thread()`, so it runs once per Verifier thread.

**A second, latent bug caught before shipping**: per-Verifier *issuance* is
pointless if the Verifier-side *ledger* is still shared —
`charra_ak_state_renew()`'s policy revokes any existing record for the same
`ek_fingerprint`, so if all Verifiers wrote to one ledger file, the second
Verifier to certify RP would immediately revoke the first's freshly-issued
certificate, and so on. Fixed by making `ak_state_file_path` per-port too,
same fix already applied to `qualification_state_file_path`.

**A pre-existing race surfaced by making this concurrent**: the shared
`certify_ak_response` global was safe under call-once-per-process but not
under N per-Verifier threads calling `/certify_ak` concurrently — each
unmarshal overwrote `.ak_certificate` (a heap pointer) without freeing the
previous value. Fixed with a snapshot-then-null-out pattern under
`rp_ak_reprovision_mutex`.

**What's still shared, deliberately**: the CA key itself
(`keys/verifier-ca.key`) — every Verifier signs with the same key. The
*ledger* and *issuance* are now genuinely per-Verifier (separate calls,
certificates, serials, records) even though cryptographically they all
chain to one CA. Making the CA itself per-Verifier is a materially bigger,
out-of-scope change.

**Verified**: full suite, 0 regressions. Live 2-Verifier run: separate
`.der` files, ledger entries share `ek_fingerprint` but distinct serials,
two separate `/certify_ak`→`ActivateCredential`→decrypt sequences in the
log.

### `state/` layout (final form) — reorg history

Two intermediate renames happened before the current layout; kept here for
context since old file/path names still appear in older commit messages:

1. Verifier-side ledgers moved from repo-root loose files
   (`ak-provisioning-state.txt`, `qualification-state-<port>.txt`) to
   `state/rp-ak-provisioning/…`/`state/rp-qualification/…`, once the
   Attester's own future EK/AK made the un-prefixed names ambiguous about
   *whose* AK was being tracked.
2. Those two folders, plus RP's own runtime identity/certificate/
   qualification-cache files (previously loose in the repo root), were
   reorganized once more, this time split by **owner** (which binary
   writes it) first, then by **purpose**:

```
state/
  verifier/
    ak-provisioning/
      rp-ak-provisioning-state-<port>.txt(.lock)
    qualification/
      rp-qualification-state-<port>.txt(.lock)
  relying-party/
    identity/
      rp-ek-certificate.der
      rp-ak-public.bin
      rp-ak-private.bin
    ak-certificates/
      rp-ak-certificate-<port>.der
    qualification-cache/
      rp-qualification-until-<port>.txt
```

Both `verifier.c`'s and `relying_party.c`'s `main()` `mkdir()` their own
side of the tree up front. Several fixed-size path buffers were bumped
(`char path[64]` → `char path[96]`) to fit the deeper nesting.
`.gitignore` collapsed to a single `state/` wholesale ignore. Verified live:
a full cold-start run (fresh TPM state, RP identity from scratch) with all
5 Verifier ports produced exactly this tree; full suite still passes.

### Also fixed: synthetic-log generator template_data layout mismatch

`charra_sdk_redact_ima_log()` was rewritten to expect real `ima-ng`'s two
length-prefixed sub-fields (d-ng: algo+digest, n-ng: path+NUL), but
`charra_synth_generate_ima_log()` still emitted the old flat
`"sha256:" + digest + NUL + path` blob — every redaction of a synthetic log
failed with `"...not a well-formed ima-ng field pair"`. Caught via `make
test` (`test_sdk`, 7/20 failing). Fixed: generator now builds the same
two-field layout the SDK expects; byte-offset assertions in `test_sdk.c`
updated for the new 4-byte length prefixes. Back to 20/20.

### Rename: `charra_rp_identity` → `charra_rp_key_mgr`

Matches this codebase's existing convention (`charra_key_mgr.h`/`.c` is
already the Attester-side equivalent). Every `charra_rp_identity_*`
function renamed to `charra_rp_key_mgr_*`; include guard updated; call
sites in `relying_party.c`, `charra_dto.h` docstrings, and `Makefile`
updated. Pure rename, rebuilt clean.

### First genuine `ATTESTATION SUCCESSFUL` for the full RP/EK/AK pipeline — bugs found live

Ran the actual quartet against the real TPM simulator end to end (not unit
tests) — surfaced several bugs unit tests couldn't catch (CoAP/threading
glue), then reached a genuine `ATTESTATION SUCCESSFUL` for the first time.

- **`/nonce` sent with an empty body — RP and Verifier built to two
  incompatible designs.** RP's client deliberately sent no payload ("the
  Verifier contributes the challenge"); `verifier.c`'s
  `coap_nonce_handler()` was written to *unmarshal* a full request DTO and
  echo `req.nonce` back. Two contributors resolved the same open question
  in opposite directions. Result: every attestation died immediately
  (`"Could not get CoAP PDU data"` → `4.00` → `"Verifier returned no
  nonce"`). **Fixed** (lower-effort, verifier-compatible direction, by
  explicit decision): RP now sends `last_request` (already built, stable by
  the time any verifier thread starts) instead of `NULL, 0`. *(Superseded
  later — see "`/nonce` now returns a genuine Verifier-generated challenge"
  below, which replaces this echo with a real Verifier-side challenge.)*
- **Bug #7 confirmed and fixed**: `coap_verifier_handler_appraisal()`'s
  `strcmp()` had success/failure backwards (0-on-match took the `else`
  branch). Fixed to `memcmp(data, successful_message, data_len) == 0` —
  also correctness, not just style: `data` has no guaranteed NUL past
  `data_len`.
- **New bug: uninitialized-pointer double free on early `goto cleanup`.**
  `get_attestation_results_thread()` declared several CoAP handles after
  earlier `goto cleanup` jumps (including the common "Verifier did not
  supply a nonce" timeout path) — jumping over a C initializer leaves it
  indeterminate, not `NULL`, and the shared `cleanup:` unconditionally freed
  all of them. Reproduced live: a real verifier timeout crashed the whole
  RP process with `double free or corruption`. **Fixed** by hoisting all
  four handles to the top of the function, initialized before any `goto`
  can fire — matching this file's existing convention for the other CoAP
  handles.
- **AK-certificate-rejection retry, implemented**: on a Verifier's `4.01`
  response, `relying_party.c` sets `rp_ak_cert_rejected[]`, and
  `get_attestation_results_thread()`'s build→send→wait sequence becomes a
  2-attempt loop that re-provisions
  (`invalidate_cached_rp_ak_certificate()` + fresh
  `ensure_rp_ak_certificate()`) before retrying once. *(The single-flight
  thundering-herd guard originally needed here — `rp_ak_generation` +
  `rp_ak_reprovision_mutex` — was later deleted outright once "RP AK
  certification is now independent per-Verifier" made the shared-identity
  premise it protected against no longer true.)*
- **Temporary: Verifier accepts an empty Attester AK certificate.** Step 3b
  item 1 would otherwise hard-fail every attestation (Attester has no
  `/certify_ak` client yet), making it impossible to exercise anything
  downstream of Step 3a live. `coap_appraise_handler()` special-cases
  `ak_certificate_len == 0`: logs a loud `"TEMPORARY"` warning and accepts.
  A non-empty certificate is still validated normally.

**Planned end state (not yet implemented, as of 2026-08-14): the Verifier
is *not* meant to grow its own independent Attester EK/AK check to replace
this bypass.** Intended design: the RP performs EK/AK verification of the
Attester itself (mirroring how Verifiers validate the RP's own AK cert),
forwards a verified/not-verified signal, and the Verifier(s) trust that
signal rather than re-validating the Attester's chain themselves. So the
bypass's current unconditional-accept form is still wrong — nothing is
checked by *either* party today — but the fix is "RP gains a real EK/AK +
`/certify_ak` client," not "Verifier re-implements independent Attester-AK
validation." A deliberate trust-boundary shift worth remembering: once
built, the Attester-identity leg's security becomes fully dependent on the
RP's honesty/correctness, bigger than the shared-CA-key caveat noted
elsewhere.

**Result**: a real live run produced `ATTESTATION SUCCESSFUL` end to end —
both quotes genuinely checked, a 4/5-verifier majority vote surviving a
timed-out verifier without crashing (double-free fix confirmed under the
exact triggering condition).

`.gitignore` updated for RP's TPM identity cache and the AK-provisioning
ledger files, alongside the existing `bin/`/`obj/` ignores.

### `/nonce` now returns a genuine Verifier-generated challenge, not an echo

Raised while re-auditing bug 6 above: `coap_nonce_handler()` was echoing
`req.nonce` (RP's own Attester-facing nonce) back as "the Verifier's
nonce" for `Quote_r`'s freshness check — proves nothing about freshness
from the Verifier's side, since RP could sign an old `Quote_r` over a
self-chosen value it already knows will "match."

**Fix**: `coap_nonce_handler()` still stores RP's request DTO into
`last_request` (unchanged — `Quote_a`'s own freshness check needs the
nonce RP gave the *Attester*, a separate concern), but now also calls
`charra_random_bytes()` for a fresh 32-byte challenge of its own
(`verifier_challenge_nonce`/`_len`), returned as the `/nonce` response
body instead of `req.nonce`. Step 3a item 3 (`Quote_r`'s freshness check)
now compares against `verifier_challenge_nonce`, not `last_request.nonce` —
genuinely separate checks where before both happened to compare the same
shared value by construction. Also removed a dead, never-read
`TPM2B_DATA qualifying_data` local left from an earlier design.

`verifier_challenge_nonce` shares `last_request`'s single-in-flight-round
limitation (bug 6) — unchanged by this fix, which only corrects *what*
gets checked, not *how many sessions can be in flight at once*.

**Verified live**: RP's log shows two visibly distinct nonces (Verifier's
32-byte challenge vs. RP's own 20-byte Attester nonce); both freshness
checks pass independently; full suite still passes.

### RP now caches its own qualification client-side, and Verifier explains *why* `/appraise` was rejected

Prompted by: *if the RP process is short-lived (the benchmark harness runs
and exits), is the 24h qualification validity window actually doing
anything?* Answer: not by itself — the persisted expiry on the Verifier
side was real, but nothing on the RP side ever *acted* on remaining
validity; it re-ran the full `/qualify`+`/qualify_submit` round trip
unconditionally every cycle, both within and across process runs.

**Fix, part 1 — RP-side cache**: `rp_qualified_until[MAX_VERIFIERS]`,
backed by a per-Verifier file (`rp-qualification-until-<port>.txt`, one
decimal Unix timestamp). `rp_perform_qualification_handshake()` checks it
first (re-checked against the wall clock every call), short-circuiting to
success when still valid.

**A bug this introduced, caught before shipping**: the first version also
skipped `ensure_rp_ak_certificate()` on a cache hit, but
`charra_rp_build_evidence_message()` needs `rp_ak_cert_der[]` regardless of
whether `/qualify` itself runs. Broke evidence-building the moment a
qualification cache hit happened before the AK cert was reloaded into
memory this process. **Fixed** by always calling
`ensure_rp_ak_certificate()` first — it has its own independent disk cache,
so this doesn't reintroduce a network round trip.

**Fix, part 2 — Verifier says why, RP reacts**: `qualification_record_found`
is now tracked separately from `attestation_result_qualified`; the `4.03`
message distinguishes `"RP qualification expired!"` (record exists, expired)
from `"RP not qualified!"` (no record). Same response code either way (RP's
correct reaction is identical), message just tells a human/log which.
`coap_verifier_handler_appraisal()` branches on `4.03` the same way it
already branches on `4.01`: sets `rp_qualification_rejected[verifier_index]`,
and the existing retry loop invalidates the qualification cache and
re-handshakes once before resubmitting.

**Verified live**, forcing the mismatch scenario (RP's cache claims valid,
Verifier's ledger hand-edited to already-expired): RP skips `/qualify` on
its stale cache, gets `4.03 "RP qualification expired!"`, re-qualifies,
resubmits, reaches `"Attestation successful!"` on the retry; the following
cycle correctly reuses the freshly-earned cache. Full suite, 0 regressions.

`.gitignore` updated for `rp-qualification-until-*.txt`.

### `tests/test_rp_appraisal_marshaling.c` — 17 assertions

See "The real RP→Verifier message shape" above for what it covers — the
last DTO from the EK/AK work that had no persisted test until this suite
was added (previously exercised only via a throwaway live client).

### RP's majority-vote log line now shows the actual tally

`"Attestation successful/failed by majority vote!"` said nothing about how
close the vote was. Now `"... (%d/%d Verifiers passed)"` — pure log-message
change, `num_true`/`num_verifiers` were already computed, just never
printed.

### `run_live_test.sh` — reusable full live-run script, and a real bug it surfaced

Checked-in script wrapping the manual `docker run` + fresh-TPM +
clean-rebuild + 5-Verifier + `relying_party` sequence used throughout this
project's live verification. Uses `docker run -it` directly (not `docker
compose run`), so it also works as a plain interactive shell if invoked
without a trailing command.

**Real bug found on its first run** (pre-existing, not a script bug): the
script does a genuine TPM reset (`rm -f NVChip`, fresh `tpm_server`,
`tpm2_startup --clear`, re-randomizing storage-hierarchy seeds) but didn't
originally also clear RP's cached TPM identity — every earlier smoke test
happened to always clear both together as part of its own cleanup, so this
never surfaced. Result: every attestation failed (`Esys_Load: 0x1df` on the
old AK private blob under the new TPM state, cascading through "no AK
certificate" into every evidence build failing) — confirms the RP has no
self-healing path for "my cached AK no longer loads," it just fails
outright. Real, pre-existing gap, not worth fixing given how rarely a
genuine TPM reset without a matching identity wipe happens outside test
scripts. **Fixed for this script specifically**: also `rm -rf state` right
after the TPM reset, and wipe `logs/` fresh each run (stray files from
one-off scripts had been accumulating, e.g. `rp_run1.log`/`rp_run2.log`/
`verifier_5684_restarted.log`). Confirmed: full 5-Verifier run to
completion, `relying_party` exit 0, unanimous `Attestation successful!`.

### Use-after-free in block-wise CoAP responses (`verifier.c`) — FIXED

`coap_certify_ak_handler()`'s and `coap_qualify_handler()`'s
`coap_add_data_large_response()` calls passed `NULL, NULL` for the
release callback, then the response buffer was freed synchronously right
after — but libcoap needs that buffer alive across the full asynchronous
multi-block transmission for large (multi-datagram) responses. Symptom:
the last ~7 bytes of a large `/certify_ak`/`/qualify` response were
corrupted, causing AES-GCM decrypt failures on the RP side — reproducible
as "every Verifier's very first `/certify_ak` attempt fails, every retry
succeeds" (heap-timing-dependent, not deterministic corruption). Diagnosed
via SHA-256 ciphertext fingerprints logged on both ends (bytes matched up
to offset 721 of 728, diverged only at the tail).

**Fix**: added `release_response_data()` (mirrors the pattern already used
in `attester.c`) as the release callback, deferring the `free()` until
libcoap confirms full transmission, in both handlers. Verified via a clean
rebuild and a live 1–5-verifier sweep with the intermittent decrypt
failures gone.

### Observability/logging pass — `relying_party.c`, `verifier.c`, and shared modules

A batch of logging and diagnostics improvements, in one commit:

- **Per-thread log-line tagging**: `charra_log_set_thread_prefix()`
  (`src/common/charra_log.c`/`.h`, backed by a `__thread` buffer) tags every
  subsequent log line from a Verifier thread with `[V<n>:<port>]`, so 5
  concurrent Verifier threads' interleaved output stays attributable.
- **`CHARRA_RC` → human-readable text**: `charra_rc_describe()`
  (`src/common/charra_error.h`, header-only `static inline`) — used in new
  decrypt-failure log lines.
- **Cert-expiry helper**: `charra_crypto_x509_days_until_expiry()`
  (`crypto_util.c`) — used by the new cert-summary logging below and by
  the RP's own "cached AK cert expires in N days" log line.
- **Cert-chain success logging**: previously only chain-verification
  *failures* got X.509 detail (subject/issuer/serial); successes now do
  too, at 3 call sites (`/certify_ak`'s EK check, Step 3a item 1's RP-AK
  check, `/qualify_submit`'s submitter check) — see
  `charra_crypto_log_cert_summary()`, since relocated (its own entry
  above).
- **Ciphertext fingerprint logging**: a permanent SHA-256 fingerprint of
  the AES-GCM ciphertext, logged on both the Verifier (encrypt side) and
  RP (decrypt side) in `/certify_ak` — lets a receiver-side decrypt
  mismatch be diagnosed by diffing two short hashes instead of guessing.
  This is what made the use-after-free above diagnosable.
- **Startup config echo**: `verifier.c`, `relying_party.c`, `attester.c`,
  `trust_manager.c` each log their effective configuration (ports, state
  file paths, timeouts, blacklist path, etc.) once at startup.
- **Phase timing log lines**: `relying_party.c`'s benchmark loop now logs
  `get_verifiers`/`get_evidence`/`get_attestation_results` durations as
  they're measured, not just at the very end.
- **Redaction timing**: `charra_rp_prepare_evidence()` now times and logs
  how long log redaction itself took.
- **AK-state / blacklist lookup context**: `is_ak_serial_currently_valid()`
  (pre-relocation) and `charra_verify_log_file_hashes_not_blacklisted()`
  now log which state/blacklist file they checked against and how many
  entries it had, not just the pass/fail result.
- **Per-run summary report**: `get_attestation_results()` now prints a
  `+------------ Run Summary --------------+` block after every run — one
  line per Verifier (`PASS`/`FAIL`, `AK cached`/`fresh`, latency in ms,
  reason), plus the `log_r` redaction byte counts.

### Timeout-handling bugs, wall-clock timing rewrite, and a stale-vote bug — FIXED

Found while investigating a reproducible 1-in-5 `/certify_ak` decrypt
failure that turned out to be the use-after-free above, plus intermittent
~40-second stalls under concurrent 5-verifier load surfaced by the new
phase-timing logging.

- **`verifier_response_timeout`/`attester_response_timeout` = 6000 instead
  of 6** (`relying_party.c`) — a 1000x typo. These feed
  `coap_session_set_ack_timeout()` directly as *seconds*, so a single
  stray UDP retransmission could stall for tens of real seconds under
  load. **Fixed**: both set to `6`. Confirmed via A/B test — the stalls
  disappeared completely.
- **Self-reported-duration-sum vs. real elapsed time** (systemic, present
  identically in 6 wait loops across `relying_party.c`): each loop summed
  `coap_io_process()`'s own per-call reported duration instead of
  measuring real wall-clock elapsed time, silently under-counting time
  spent descheduled between calls under concurrent load — letting a
  correctly-configured 6-second timeout actually take 40+ real seconds to
  fire (directly observed: a "Timeout after 41924 ms" log line even after
  the 6000→6 fix above). **Fixed**: all 6 loops rewritten to use
  `clock_gettime(CLOCK_MONOTONIC, …)`-based elapsed-time checks instead —
  a purely local, per-machine stopwatch, unrelated to and no additional
  requirement on top of the protocol's own nonce-based freshness
  mechanism (RATS-style freshness is unaffected; this is a timeout
  bookkeeping fix, not a protocol change). Confirmed via clean rebuild +
  live run: no more timeouts, no more stalls.
- **`attestation_results[]` never reset — a genuine pre-existing,
  security-relevant bug**, not introduced by this session's other fixes.
  `get_attestation_results_thread()`'s `cleanup:`/`error:` paths never
  explicitly set `attestation_results[current_thread_index]`, so an early
  failure (timeout, network error, evidence-build failure) silently left
  whatever value was there from an earlier successful run — inflating the
  majority vote with a stale `PASS` instead of counting a genuine failure.
  Directly relevant to the security property a majority vote is supposed
  to provide. Surfaced by the new latency logging showing a `PASS` result
  with `n/a` latency (i.e., no real answer was ever computed this round),
  then confirmed via a verifier log showing a genuine
  `Timeout after 41924 ms` for a verifier still reported `PASS`. **Fixed**:
  `attestation_results[current_thread_index] = false;` set unconditionally
  at the very start of each Verifier thread — "no real answer yet" now
  always defaults to "treat as failed" (fail closed), matching the
  security intent of a fresh per-round vote.
- **Two smaller staleness bugs, introduced by the logging pass above and
  fixed in the same pass**: `rp_ak_cert_was_cached[]` wasn't set on the
  fast in-memory-ready path of `ensure_rp_ak_certificate()` (summary always
  showed "fresh" after the first successful run); `rejection_reason[]`/
  `verifier_latency_ms[]` weren't reset per-thread-run the way the
  existing `rp_ak_cert_rejected`/`rp_qualification_rejected` booleans
  already were, so a verifier failing for a *different* reason in a later
  round could show a stale message/latency from an earlier one. Both
  fixed alongside the `attestation_results[]` fix above.

Verified via a full clean rebuild plus a live 1-through-5-verifier sweep in
the Docker/TPM-simulator environment after each fix, confirming zero
regressions and the run summary's per-verifier fields (result, cache
status, latency, reason) staying accurate across repeated runs.

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
(`charra-ressources/CHES2024_Poster_final.pdf`), and is now additionally
implementing the privacy-preserving redaction scheme from
`charra-ressources/privacy_protectioin_v1_en_en.pptx` (see Part 2 — this was
originally unimplemented background reading; it is now the active design).

### Architecture

- **Attester** (`src/attester.c`) — CoAP server :5683, `attest` resource,
  runs `tpm2_quote()`, returns CBOR evidence. Logs timing to
  `timings_attester.txt`.
- **Verifier**, two implementations kept side by side for benchmarking:
  - `src/verifier_old.c` — original CHARRA design: active client, drives
    the attest exchange itself and appraises inline. Kept as baseline.
  - `src/verifier.c` — new design: passive CoAP server :31415, resources
    `nonce` + `appraise`, meant to be called by an orchestrator. Logs
    per-step timing to `durations_verifier.txt`.
- **Trust Manager** (`src/trust_manager.c`, :6000) — new role, the poster's
  "Verifier Manager." Resource `get_verifiers`: takes a list of verifier
  IDs, resolves them to `{ip, port}` via `verifiers_config.txt`. Pure
  directory/lookup service, not a reference-value/endorsement provider
  despite RATS terminology.
- **Relying Party** (`src/relying_party.c`, ~1190 lines) — new orchestrator.
  Flow: ask Trust Manager to resolve N verifiers → get evidence from the
  Attester **once** → fan the same evidence out to all N verifiers in
  parallel (pthreads) → majority vote (`2*num_true > num_verifiers`) on the
  aggregate result. `main()` also doubles as the benchmark harness (sweeps
  1→5 verifiers, `NUM_RUNS = 10`, writes `timings_RP_multi_verifiers.txt`).
  **Now additionally acting as the privacy-preserving proxy** — see Part 2.

Wire protocol: CoAP (UDP, optional DTLS-PSK/RPK) + CBOR (QCBOR), DTOs in
`src/core/charra_dto.h`, encode/decode in `src/core/charra_marshaling.c`,
plain positional arrays (no maps/labels) — field order is load-bearing,
defined only by struct order, no schema self-description on the wire.

### Component reference table

| Role | File | Port | CoAP resource(s) | Timing log |
|---|---|---|---|---|
| Attester | `src/attester.c` | 5683 | `attest` (FETCH) | `timings_attester.txt` |
| Verifier (new, passive) | `src/verifier.c` | 31415 | `nonce`, `appraise`, `certify_ak` | `durations_verifier.txt` |
| Verifier (old, active — baseline) | `src/verifier_old.c` | n/a (client) | — (calls Attester's `attest`) | `timings_verifier.txt` |
| Trust Manager | `src/trust_manager.c` | 6000 | `get_verifiers` | — |
| Relying Party | `src/relying_party.c` | n/a (client) | — (calls Trust Manager + Attester + each Verifier) | `timings_RP_multi_verifiers.txt` |

`start_verifiers.sh` spawns 5 `bin/verifier` instances on ports 5684–5693,
registered in `verifiers_config.txt` as `id ip port` rows that
`trust_manager.c` reads to resolve `get_verifiers` requests.

The Verifier also writes `ak-provisioning-state.txt` (repo root, same
directory as `verifiers_config.txt`) — the persisted record of every AK
certificate issued via `/certify_ak`, shared across all five instances above
since they share one CA. See "AK-provisioning state" in Part 3.

**Relying Party internals:**
- `create_attestation_request()` (~line 242) — generates the shared nonce
  used across all verifiers for a given run. *(Note: this nonce is RP→
  Verifier, one-directional; see Part 2's freshness discussion — it cannot
  be repurposed to prove freshness to the Verifier.)*
- `coap_trust_manager_handler()` / `get_verifiers()` (~line 424) — resolves
  `verifier_list[]` IDs to endpoints.
- `get_evidence()` (~line 552) — single attest round-trip against the
  Attester on :5683; result cached in `last_response`.
- `get_attestation_results_thread()` (~line 770) — one pthread per verifier:
  POST nonce to that verifier's `nonce` resource, forward cached evidence to
  its `appraise` resource, store bool result.
- `get_attestation_results()` (~line 1147) — spawns the threads above, joins
  them, majority vote (~lines 1173–1184): `2*num_true > num_verifiers`.

**Wire DTOs** (`src/core/charra_dto.h`):
- `msg_attestation_request_dto` — `hello`, `sig_key_id`, `nonce`
  (≤ `sizeof(TPMU_HA)`), array of `pcr_selection_dto`, optional
  `event_log_path`.
- `msg_attestation_response_dto` — `attestation_data` (`TPM2B_ATTEST`),
  `tpm2_signature` (`TPMT_SIGNATURE`), `tpm2_public_key` (`TPM2B_PUBLIC`),
  optional IMA `event_log`. **Growing — see Part 2 for new fields needed**
  (`rp_signature`/Quote_R, RP's EK/AK cert).

**Key management (as of upstream, before this fork's EK/AK work)**: only one
signing key ID supported, hardcoded string `"PK.RSA.default"`
(`charra_key_mgr.c:35`), created via `tpm2_create_primary_key_rsa2048`
(`tpm2_util.c:32`) — a primary key generated fresh per request, not a
persistent, certifiable AK. Verifier loads the corresponding public key
externally via `Esys_LoadExternal` — no EK→AK certificate chain, no CA-backed
provenance. PoC-grade trust bootstrapping only. **This needs replacing** —
see Part 2's open items.

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
by EK, used per-quote). Upstream CHARRA skips this chain entirely. **This
fork is actively adding it** — see Part 2.

**ESAPI / tpm2-tss** — the TCG "Enhanced System API" between app code and raw
TPM command bytes. Every `Esys_*` call goes through this, also what lets the
stack run against the bundled software TPM (`ibmtpm1661`) with no real
hardware.

**CoAP** — REST-shaped (GET/POST/FETCH, resource paths) over UDP with its own
light retransmission model.

**DTLS-PSK/RPK** (`coap_util.c`) — CoAP's TLS-over-UDP equivalent. PSK =
pre-shared symmetric key. RPK = raw public key, asymmetric but no X.509
chain. Neither implies a CA.

### Where this fork already stepped outside standard RATS topology (pre-existing, before this session's work)

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
  sweep + `NUM_RUNS = 10` (`relying_party.c:28,159`).
- Multi-attester support (heterogeneous testbeds) is mentioned on the poster
  but not found in `src/` — likely Docker/deployment-level if it exists.

---

## Part 2 — The privacy-preserving redaction scheme (this session's work)

### Why: the problem replay solves

A TPM Quote commits to a PCR composite digest, not individual PCR values. To
check that digest, a Verifier needs a value for every selected PCR. Boot PCRs
(0-7) are static and can be looked up in a reference file, but the IMA PCR
(conventionally PCR10, `CONFIG_IMA_MEASURE_PCR_IDX`) grows every time a new
file is measured, so no static reference value can exist for it — it has to
be *derived* by replaying the measurement log: starting from an all-zero PCR
and re-applying every extend the TPM did.

### Target design v1 (agreed with supervisor, informal — SUPERSEDED below)

Trust model: **the Verifier trusts the RP.** The RP validates the Attester's
evidence; the Verifier does not re-check it directly.

```
ATTESTER -> RP:
    Quote_A (= attestation_data + tpm2_signature), raw IMA log,
    Attester EK/AK certificate

RP:
    1. validate Attester's EK/AK certificate  (is this a real TPM?)
    2. verify Quote_A signature
    3. replay raw log                          (well-formed / consistent)
    4. redact: rewrite paths in template_data AND RECOMPUTE
       template_digest' from the redacted template_data
    5. replay the REDACTED log (new digests)  -> X   (SOFTWARE replay,
                                                      charra_replay_ima_log;
                                                      no TPM involved)
    6. TPM2_Quote with its own AK:            -> Quote_R
           pcrSelection   = RP's OWN boot PCRs
           qualifyingData = X

RP -> VERIFIER:
    redacted_log, Quote_R (+ its signature), RP's EK/AK certificate,
    Quote_A + tpm2_signature + tpm2_public_key  (forwarded, currently UNUSED)
    NOT forwarded: Attester's EK certificate

VERIFIER:
    1. validate RP's EK/AK certificate         (is the RP a real, known TPM?)
    2. verify Quote_R's signature using RP's AK
    3. replay redacted_log                     -> X'
    4. check Quote_R.qualifyingData == X'      (binds the log to the quote)
    5. check Quote_R.pcrDigest against reference PCRs FOR THE RP
                                               (is the RP running known-good
                                                proxy code?)
    6. second pass over entries: file_hash whitelist/blacklist check
```

**This design is superseded.** The supervisor later sent a formal write-up
("DRA-TLS Privacy Protection Solution") that keeps the same trust model and
general shape but is authoritative on exactly which party does which check —
see "Target design v2" immediately below. The biggest correction: **the
Verifier does not replay logs, does not recompute or check any PCR digest,
and does not run the file-hash policy check at all.** All log/PCR content
verification (items 3-6 in the "RP:" block above) is the RP App's own
Step 2a gate, run once, before redaction — not something the Verifier
repeats. `verifier.c` has been updated to match (see Part 3).

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
    -> pass: proceed to Step 2b.
    -> fail: negative proof result back to the Attester.

RP App, Step 2b -- Privacy Cleanup:
    output_path = PATH_Clean(input_path)   (built-in path-mapping SDK)
    rewrite every path in log_a -> log_r; recompute each entry's
    template_hash from the rewritten data
    extend a new PCR_r from the original PCR using log_r's template hashes
    TPM2_Quote, signed by the RP App's own AK          -> Quote_r
    Evidence_r = (Quote_r, log_r, EK_r/AK_r)

RP App -> VERIFIER:
    Evidence_r  = (Quote_r, log_r, EK_r/AK_r)
    Evidence_a' = (Quote_a, EK_a/AK_a)     -- log_a is STRIPPED, never
                                               forwarded to the Verifier

VERIFIER, Step 3a -- New Evidence Verification (Evidence_r):
    1. validate EK_r/AK_r certificate
    2. verify Quote_r signature
    3. check nonce consistency
    -> pass: proceed to Step 3b.
    -> fail: negative proof result to the RP App (network-management node).

VERIFIER, Step 3b -- Original Evidence Verification (Evidence_a'):
    1. validate EK_a/AK_a certificate
    2. verify Quote_a signature
    3. check nonce consistency
    -> pass: positive proof result to the RP App.
    -> fail: negative proof result to the RP App.
```

**No PCR or log content check exists anywhere in the Verifier's steps.**
That is intentional, not an oversight: Steps 4/5/6 (template-hash recompute,
PCR-expansion recompute, file-hash policy) only ever appear once, in the RP
App's Step 2a, run against the *original* `log_a` before it ever gets
redacted. The Verifier's entire job is cryptographic + identity: quote
signatures, nonce freshness, and certificate validity, on *two* independent
evidence bundles (`Evidence_r` and `Evidence_a'`) rather than one.

**RP App-side path privacy cleanup policy monitoring** (separate mechanism
from per-attestation appraisal, from the same supervisor doc): the Verifier
releases the `PATH_Clean` SDK to the RP App, then periodically sends a test
log `log_t`, receives back `log_t'`, and compares it against a locally
computed expected result to confirm the RP App is still running the correct
redaction SDK (without the Verifier ever seeing real path data, since the
RP App can audit the SDK's own code to confirm it can't be used to infer
real paths). **This matches the RP qualification handshake already built**
(`charra_rp_qualification.c`, see below) almost exactly — same
generate-synthetic-data / compare-against-golden-answer shape, same
periodic-recheck timing decision already made independently in this repo.

**TEE variant (documented, not built):** if the RP App has TEE capability,
Step 2 runs inside the TEE. `Evidence_r` then additionally carries a
signature from the path-mapping SDK's own key (proving the *correct,
unmodified* SDK ran, from inside the TEE); `Evidence_a'` no longer needs to
be sent at all, and the Verifier skips Step 3b entirely, checking only the
SDK's signature instead. Not started — no TEE-specific code exists in this
repo.

#### Why software replay + TPM2_Quote (rather than extending a real PCR)

Extending the RP's actual PCR10 was rejected: PCRs 0-15 are not resettable on
a PC Client TPM, so it would work only once per boot; it would need one TPM
round-trip per log entry (minutes for a large log); and it would need locking
against concurrent attestations. It also buys nothing cryptographically —
the RP's *software* chooses which digests reach the TPM either way, so a
dishonest RP produces a validly-signed wrong answer regardless.

The value of TPM2_Quote over TPM2_Sign is not that the TPM witnesses the
replay — it's that the quote structure *also* carries the RP's own PCR
values, attesting the RP's software state in the same signed object. Putting
X in `qualifyingData` (the same field the Attester's quote uses for its
nonce) binds the redacted log to that quote in one TPM call.

#### Consequences of recomputing template_digest

Because the RP recomputes `template_digest'` from redacted `template_data`,
the replayed PCR10 **can no longer match** the Attester's TPM-sealed
`pcrDigest` — not by policy but mathematically, since the digests differ by
construction. The TPM is therefore not in the Verifier's chain of trust for
the PCR10 property; the guarantee is "the RP vouches for this," anchored by
the RP's own TPM rather than the Attester's. Deliberate decision.

This also invalidates an earlier argument for keying appraisal off
`template_digest` instead of `file_hash`: that reasoning depended on
`template_digest` being TPM-anchored, which it no longer is. Both fields are
equally RP-controlled now, so appraisal can read `file_hash` directly.

#### Privacy note

The Attester's EK certificate is a permanent unique identifier for that
physical TPM. It must stop at the RP — forwarding it to the Verifier would
leak a stronger identifier than any file path the redaction step protects.
The RP's *own* EK cert going to the Verifier is intentional and fine: the RP
is known infrastructure the Verifier is meant to recognise.

### Deliberately out of scope (for now)

- **Freshness / replay protection on the Verifier side.** `rp_signature`
  covers only `X`, which is not time-varying, so a recorded
  `(redacted_log, rp_signature)` pair remains valid indefinitely — the
  Verifier cannot distinguish a fresh attestation from a replayed recording.

  The existing nonce cannot be repurposed for this: it is generated by the
  **RP** (`relying_party.c:246`) and pushed to the Verifier's passive
  `"nonce"` endpoint (`verifier.c:253`). A nonce only proves freshness to
  whoever generated it, so a Verifier receiving one from the RP learns
  nothing.

  If revisited: the Verifier must contribute its own unpredictable challenge
  *before* the RP signs — RP signs `SHA256(X || challenge)`, or uses
  `TPM2_Quote` over `X` with the challenge as qualifyingData. Either way
  inverts the current CoAP direction and needs a new round-trip.

### Open / undecided

- **Reference PCRs for the RP — RESOLVED as not needed.** Under the DRA-TLS
  spec the Verifier never checks any PCR digest at all (RP's or Attester's),
  so no second reference-PCR file for the RP is required. (RP's own Step 2a
  PCR recompute compares against `Quote_a`'s own embedded digest directly,
  not a static reference file either.)
- **Which PCRs `Quote_r` covers** — still open, but now purely an RP-side
  concern (Step 2b, not yet implemented by anyone): must be PCR10 alone to
  match the single-PCR assumption baked into
  `verify_log_matches_quote_r_pcr()` (see Part 3) — whoever writes RP's
  `tpm2_quote()` call needs to select PCR10 only.
- **AK provisioning — Verifier side RESOLVED, implemented as `/certify_ak`**:
  the Verifier now acts as its own Privacy CA, issuing AK certificates via
  `TPM2_MakeCredential`/`ActivateCredential` credential activation. See the
  new "`/certify_ak` — Verifier-as-Privacy-CA AK issuance" entry in Part 3
  for the full design and code inventory. **Still open on the Attester/RP
  side**: neither party has a persistent AK yet, nor client-side logic to
  call `/certify_ak` and attach the resulting certificate to `/appraise`
  requests — see "Not yet built" below.
- **AK-provisioning state — RESOLVED, implemented as `charra_ak_state.h`/`.c`**:
  a persisted, on-disk record of every AK certificate `/certify_ak` has
  issued. Closes the CRL-style local table this bullet used to ask for:
  renewal now automatically revokes a requester's previous record, and the
  lookup a future revocation check would need (by serial number) already
  exists. See the new "AK-provisioning state" entry in Part 3. Expiry itself
  is still checked for free by `mbedtls_x509_crt_verify()`; this module adds
  the *before-expiry* revocation piece OCSP would otherwise be needed for —
  without the Verifier ever making an outbound call, preserving its
  passive-server invariant.
- **Attester key is not currently an AK**: `charra_key_mgr.c:32` calls
  `tpm2_create_primary_key_rsa2048()`, a primary key on demand with no
  certification path. Needs replacing with a real persistent AK.
- **Manufacturer root CA trust store** — needed by whoever validates EK
  certs. No config, file, or loading code exists.
- **Whitelist/blacklist semantics — DECIDED and implemented**: deny-by-default
  (a hash matching neither list is a hard failure, same as an explicit
  blacklist match); format is `"0x" + 64 hex chars`, one per line, `#`
  comments/blank lines skipped (`whitelist-hashes.txt`/
  `blacklist-hashes.txt`, currently empty placeholders at the repo root).
  Implemented as `verify_log_file_hashes_against_policy()` in
  `charra_event_log.c` (see Part 3) — this is Step 2a item 6, RP-side, not
  yet wired into `relying_party.c`.
- **Blind spot in the PCR10-based integrity check**: replay only folds
  entries tagged for the target PCR, so entries for *other* PCRs could be
  added/removed/altered without affecting `X`. Accepted if the check is
  scoped to PCR10 integrity only; a hash over the whole redacted buffer would
  close it. (Still relevant — this is now squarely RP's Step 2a/2b concern.)
- **No certificate handling exists yet** — no X.509 parsing, no chain
  validation, no EK/AK anywhere. All new, and per the spec this is now the
  single largest remaining gap on *both* sides: `mbedx509` isn't even linked
  in the Makefile yet (only `mbedcrypto` is).

### RP access/qualification check (from the deck, "RP Access Check Process")

Separate mechanism from per-attestation appraisal. Before an RP is trusted to
redact *real* Attester evidence, the Verifier proves — using data it
fabricates itself, so it already knows the correct answer — that the RP's
redaction pipeline actually works.

```
Verifier:  generate synthetic log (charra_synth_generate_ima_log)
           run its own copy of the SDK's redaction logic on it locally
           store the result as the "golden answer"
           send (SDK, raw synthetic log) to the RP

RP:        runs the SDK, produces (Log, Quote_R)
RP:        submits (Log, Quote_R) back

Verifier:  Log      -- compared byte-for-byte against the golden log
           Quote_R   -- compared on pcrDigest/extraData ONLY, never raw
                        signature bytes (RSA-PSS includes a random salt;
                        two honest signings over identical data never
                        produce identical bytes)
           pass -> qualified, credential has an expiry
           fail -> rejected
```

Decisions made (via AskUserQuestion):
- **Timing: periodic re-check.** Not one-time onboarding, not covert canary
  injection into real traffic. RP's qualification has an expiry; real
  `/appraise` requests get gated on `qualified && !expired`.
- **RP-initiated**, matching every existing endpoint (`/nonce`, `/appraise`
  are both RP-as-client, Verifier-as-passive-server; Verifier has never
  opened an outbound session to anyone). Self-enforcing even for a dishonest
  RP: the `/appraise` gate checks expiry regardless of whether RP asks to
  re-qualify, so staying silent doesn't evade scrutiny — it just cuts RP off
  once the credential lapses.
- **SDK-execution enforcement: deferred, trust RP for now.** No proof RP ran
  the actual unmodified SDK rather than substituting its own logic that
  happens to produce a matching answer. Same category as "no freshness check
  for now." Closing this later needs RP's own IMA to measure the SDK binary
  specifically — real, larger scope.

#### Redaction rule for the SDK: hash the path (implemented — supersedes an earlier "blank everything" plan)

An earlier draft of this section planned blanking `template_data` entirely
(`template_data_len = 0`, digest = `SHA256("")`). Superseded before being
built: it made every redacted entry share the identical recomputed digest,
which is a weaker qualification test than necessary — the Verifier's "golden
answer" comparison would still work, but it can't distinguish "RP correctly
redacted N different paths" from "RP redacted nothing and just zeroed
everything," since both produce the same output.

**What's actually implemented** (`src/core/charra_sdk.h`/`.c`,
`charra_sdk_redact_ima_log()`): per entry, locate the path inside
`template_data` (skip the `"sha256:"`/`"sha1:"` + file-digest + NUL prefix —
the exact layout `charra_synth_generate_ima_log()` produces, and the layout a
real `ima-ng` entry uses), hash *the path itself* with SHA-256, and replace
`template_data` with nothing but that hash — 32 raw bytes, no prefix, no
separator. `template_digest` is then recomputed as `SHA256(new template_data)`,
per the design's requirement. Every field except `template_data`/
`template_digest` (`pcr_index`, `template_name`) is copied through unchanged.

Consequence, now the *good* kind: different original paths hash to different
values, so redacted entries are distinguishable from each other again —
proven by `test_different_entries_redact_differently` in `tests/test_sdk.c`.
The file-content digest portion is still discarded (not preserved for future
appraisal, as an even-more-careful design might do) — simple on purpose,
appraisal isn't in scope. `test_sdk.c` also confirms: redacted logs stay
valid `charra_replay_ima_log()` input; redaction is deterministic (same input
→ identical output); and — expected, given "Consequences of recomputing
template_digest" above — the redacted log's replayed PCR is *different* from
the raw log's, since the digests genuinely changed. 15 assertions, 0
failures; 29 + 13 + 15 = 57 tests total across all three suites.

Known limitation: assumes the `"sha256:"`/`"sha1:"` + digest + NUL + path
layout specifically (derived from the detected digest size, so it handles
both). A real IMA log's `ima-ng` template technically nests its own
length-prefixed sub-fields rather than this flat prefix — untested against
that shape. Fine for now since this is paired with
`charra_synth_generate_ima_log()`, which produces exactly the assumed layout;
worth revisiting once real Attester logs are in the picture.

---

## Part 3 — Code inventory: everything added or modified

### New: `src/core/charra_event_log.h` / `.c`

The shared replay module. `charra_replay_ima_log()` is meant to be called
identically by the Relying Party (on the raw log) and the Verifier (on the
redacted log) — same function, different bytes in.

| Function | Signature | Purpose |
|---|---|---|
| `charra_pcr_reset` | `void charra_pcr_reset(charra_pcr_accumulator* acc)` | Zero an accumulator — a PCR's power-on state. |
| `charra_pcr_extend` | `CHARRA_RC charra_pcr_extend(charra_pcr_accumulator* acc, const uint8_t* digest, uint16_t digest_len)` | One extend: `acc := SHA256(acc \|\| digest)`. Zero-pads digests shorter than 32 bytes (SHA-1 → SHA-256 bank). **The invariant that must never diverge between RP and Verifier.** |
| `charra_event_log_ima_detect_digest_len` | `CHARRA_RC charra_event_log_ima_detect_digest_len(const uint8_t* log, uint32_t log_len, uint16_t* digest_len_out)` | Recovers whether template digests are 20 (SHA-1) or 32 (SHA-256) bytes by trial-parsing, since the format doesn't record it (boot-time kernel choice, `ima_hash=`). |
| `charra_replay_ima_log` | `CHARRA_RC charra_replay_ima_log(const uint8_t* log, uint32_t log_len, uint32_t target_pcr_index, uint8_t pcr_out[TPM2_SHA256_DIGEST_SIZE])` | **The public entry point.** Parses every entry, extends the ones matching `target_pcr_index`, returns the resulting PCR value. Peeks at the first entry to guess digest size, tries the other size as fallback if wrong — never a false rejection of a well-formed log, worst case a second pass. Logs a warning (not an error) if a non-empty log has zero matching entries. |
| `charra_event_log_parse_entry` | `CHARRA_RC charra_event_log_parse_entry(const uint8_t* log, uint32_t log_len, uint32_t* offset, uint16_t digest_len, charra_event_log_entry* out)` | Parses one TLV entry, advances `*offset`. Every length check written as `need > log_len - offset` (not `offset + need > log_len`) so a hostile length field can't overflow past the check. Rejects the legacy `"ima"` template outright rather than guessing its unprefixed layout. **Public** (not static) — exposed deliberately since the RP qualification work needs a second, genuine consumer of the same bounds-checked parser; reusing it beats writing a second one. |
| `charra_event_log_append_u32` | `void charra_event_log_append_u32(uint8_t* buf, uint32_t* offset, uint32_t value)` | Writes a `uint32` at `buf[*offset]` in the same byte order `charra_event_log_parse_entry`/`read_u32` read, advances `*offset`. **Public** — the write-side counterpart of `read_u32`, kept in the same file so the byte-order convention can't drift between reader and writer. Originally duplicated (byte-for-byte identical) in both `charra_synthetic_log.c` and `charra_sdk.c`; factored here once that duplication was spotted. |
| `charra_event_log_append_bytes` | `void charra_event_log_append_bytes(uint8_t* buf, uint32_t* offset, const void* data, uint32_t len)` | Copies `len` bytes to `buf[*offset]`, advances `*offset`. Same factoring history as above. |
| `read_u32` *(static)* | `uint32_t read_u32(const uint8_t* p)` | Reads a little-endian `uint32` byte-wise — avoids relying on host cast/alignment behavior. |
| `log_parses_at` *(static)* | `bool log_parses_at(const uint8_t* log, uint32_t log_len, uint16_t digest_len)` | Whole-log trial parse: true iff every entry is well-formed and the last one ends exactly at `log_len`. Backs digest-length detection. |
| `replay_at` *(static)* | `bool replay_at(...)` | Combined parse+extend in one pass — what `charra_replay_ima_log` actually calls per candidate digest size, so a successful trial doesn't need to be re-walked to replay it. |

Constants: `CHARRA_IMA_PCR_INDEX` (10, Linux's default), `CHARRA_IMA_TEMPLATE_NAME_MAX` (64).

**Status:** standalone, unwired. Takes log bytes in, returns one PCR value
out. Does not know about PCR0-7, `reference-pcrs.txt`, or the signed
composite `pcrDigest`. Nothing in the existing binaries calls it yet — it's
built and tested, ready for both RP's and the Verifier's redesigned
pipelines to call once those land.

*(An earlier iteration wired it into `verifier.c` with a composite-digest
check against the Attester's original `pcrDigest`. That was removed once the
trust model changed to "Verifier trusts RP" — see Part 2. `src/verifier.c`,
`src/verifier_old.c`, `src/core/charra_rim_mgr.{c,h}` are currently back to
upstream, unmodified. If a composite check against a reference file is
needed again — e.g. for the RP's own boot PCRs — the shape that worked was:
add `(const uint8_t* replayed_pcr_value, uint32_t replayed_pcr_index)` to
`charra_check_pcr_digest_against_reference()`, substitute that value into
each candidate reference set before its digest is computed, `NULL` to
preserve original behaviour.)*

#### Log content verification — moved here from `verifier.c` to match the DRA-TLS spec

Originally built as `static` helpers inside `verifier.c`'s
`coap_appraise_handler`, under the (superseded) v1 design where the Verifier
re-checked `log_r` itself. Once the supervisor's DRA-TLS spec confirmed this
content verification is entirely the **RP App's Step 2a** job (run against
`log_a`, before redaction — not the Verifier's job on `log_r`), these were
relocated here and renamed to drop the `_r` suffix, since they're general
log-verification logic, not specific to the redacted log:

| Function | Signature | Purpose |
|---|---|---|
| `verify_log_entries_self_consistent` | `bool verify_log_entries_self_consistent(const uint8_t* log, uint32_t log_len)` | Step 2a item 4. Per entry: `template_digest == SHA256(template_data)`. Catches internal malformation (corruption, a redaction bug, a tampered field) — does **not** by itself prove a log's *content* is honest, only that it's self-consistent. |
| `verify_log_matches_quote_r_pcr` | `bool verify_log_matches_quote_r_pcr(const uint8_t* log, uint32_t log_len, TPMS_ATTEST* attest_struct_rp)` | Step 2a item 5. Replays the log via `charra_replay_ima_log()` and checks the result against a quote's `pcrDigest` via `compute_and_check_PCR_digest()`. Name kept referencing `quote_r` from its original RP-context use; logic is generic to any single-PCR-selection quote. |
| `verify_log_file_hashes_against_policy` | `bool verify_log_file_hashes_against_policy(const uint8_t* log, uint32_t log_len, const char* whitelist_path, const char* blacklist_path)` | Step 2a item 6. Default-deny: a file-content digest matching neither list fails, same as an explicit blacklist match. Paths are now function parameters (not globals), since this no longer lives next to `verifier.c`'s config. Reads the file-content digest straight out of the redacted `template_data`'s known layout (`"sha256:" + 32-byte digest + 32-byte path hash`, see `charra_sdk.h`). |
| `compare_hashes` *(static)* | `int compare_hashes(const void* a, const void* b)` | `memcmp`-based `qsort`/`bsearch` comparator over raw 32-byte hash chunks. |
| `load_hash_list` *(static)* | `CHARRA_RC load_hash_list(const char* path, uint8_t** hashes_out, uint32_t* count_out)` | Parses a `whitelist-hashes.txt`/`blacklist-hashes.txt`-shaped file (`"0x<64 hex>"` per line, `#`/blank skipped) into a `qsort()`-sorted flat array for `bsearch()`. |
| `hash_list_contains` *(static)* | `bool hash_list_contains(const uint8_t* hashes, uint32_t count, const uint8_t* needle)` | `bsearch()` membership check against a `load_hash_list()`-sorted array. |

**Status:** built, tested indirectly (via the same primitives
`test_event_log.c`/`test_sdk.c` already cover), but **unwired** — nothing in
`relying_party.c` calls any of these yet. That wiring (plus EK/AK
validation) is the actual remaining RP-side work for Step 2a.

### New: `src/core/charra_synthetic_log.h` / `.c`

Synthetic IMA log generator for the RP qualification check. Produces a
genuinely well-formed, realistic-looking raw log — not random bytes — so
it's valid input to `charra_replay_ima_log()` and to whatever redaction
logic gets exercised against it.

| Function | Signature | Purpose |
|---|---|---|
| `charra_synth_generate_ima_log` | `CHARRA_RC charra_synth_generate_ima_log(uint32_t num_entries, uint32_t seed, uint8_t** log_out, uint32_t* log_len_out)` | Generates `num_entries` entries, each PCR10-targeted, `ima-ng` template, with fabricated-but-plausible `template_data` (`"sha256:" + fake_digest + '\0' + a sensitive-looking path from a fixed pool`) and a real `SHA256(template_data)` as `template_digest`. Deterministic: same `(num_entries, seed)` → byte-identical output — reproducibility matters more than unpredictability for fabricated test data. Caller `free()`s the returned buffer. |
| `make_fake_file_digest` *(static)* | — | A fabricated 32-byte "file digest" derived from `(seed, index)` via SHA256. Not a real file hash; just needs to look plausible and be reproducible. |

**Status:** standalone, unwired (nothing calls it from a binary yet — it's
the input side of the qualification check, whose CoAP endpoints don't exist
yet either).

### New: `tests/test_event_log.c` — 29 assertions

No TPM/network/`/sys` required — logs synthesized in memory, expected PCR
computed independently via a hand-written reference extend so the tests
don't assert against themselves. Covers: empty log, single/multiple entries,
order-sensitivity, dropped entries, `pcr_index` filtering (mixed-PCR logs),
**redaction preserves replay** (different `template_data`, same PCR), empty
`template_data`, SHA-1 zero-padding, malformed/truncated logs, hostile length
fields (no overflow), legacy `ima` template rejection, bad arguments.

### New: `tests/test_synthetic_log.c` — 13 assertions

Strongest check: feeds the generator's own output straight into
`charra_replay_ima_log()` and confirms it succeeds — cross-validating
against the already-proven replay function rather than asserting against
itself. Also: determinism (same seed → same bytes), different seeds diverge,
fabricated sensitive paths are actually present in the raw output, bad
arguments rejected.

### New: `src/core/charra_sdk.h` / `.c`

The Verifier's "desensitization and cleaning module (SDK)" — see "Redaction
rule for the SDK" above for the full design rationale. First real, genuine
second consumer of `charra_event_log_parse_entry()`, which is exactly why
that function was made public rather than staying `static`.

| Function | Signature | Purpose |
|---|---|---|
| `charra_sdk_redact_ima_log` | `CHARRA_RC charra_sdk_redact_ima_log(const uint8_t* raw_log, uint32_t raw_log_len, uint8_t** redacted_log_out, uint32_t* redacted_log_len_out)` | Per entry: extract the path from `template_data`, replace `template_data` with `SHA256(path)` (32 raw bytes, nothing else), recompute `template_digest` from that. `pcr_index`/`template_name` copied through unchanged. Two-pass: count entries first (output size can't be derived from input size alone, since a short original `template_data` can *expand* after redaction to a fixed 32-byte hash), then build. Caller `free()`s the returned buffer. |
| `extract_path` *(static)* | — | Skips the `"sha256:"`/`"sha1:"` + digest + NUL prefix inside `template_data` to isolate the path. Prefix choice derived from the detected digest length, not hardcoded. Treats an over-short `template_data` as an empty path rather than reading out of bounds. |

Uses `charra_event_log_append_u32`/`charra_event_log_append_bytes` from
`charra_event_log.c` for serialization — originally duplicated locally (an
earlier version of this note called that duplication a deliberate choice,
"not worth the coupling"; on inspection the two copies were byte-for-byte
identical, so that call was wrong and got corrected by factoring them out).

Tested in `tests/test_sdk.c` (15 assertions), built directly on top of
`charra_synth_generate_ima_log()` — generates a synthetic log, redacts it,
and checks: still valid replay input; replayed PCR *differs* from the raw
log's (expected, since digests were recomputed); deterministic; different
entries redact to different digests (not collapsed to one constant); empty
log handled; bad arguments and malformed input rejected.

### New: `tests/test_sdk.c` — 15 assertions

See above — exercises `charra_sdk_redact_ima_log()` together with
`charra_synth_generate_ima_log()`, the way they're meant to be used in
practice (Verifier generates synthetic data, then redacts it to compute the
"golden answer" — see the qualification check design).

**All three suites: 57/57 passing.** Run with `make test`.

### Modified: `Makefile`

- `core` object list grew across this fork's work:
  `charra_event_log charra_synthetic_log charra_sdk charra_rp_qualification
  charra_ak_state`.
- `mbedx509` linked (alongside the pre-existing `mbedcrypto`) — needed once
  X.509 parsing/signing landed for the `/certify_ak` work; previously only
  raw crypto primitives were linked, no certificate handling at all.
- Test targets added over time, one per new suite:
  `test_event_log`, `test_synthetic_log`, `test_sdk`,
  `test_rp_qualification`, `test_marshaling_bounds`, `test_x509_cert_chain`,
  `test_certify_ak_marshaling`, `test_ak_state` — all folded into the `test`
  target, which now runs all eight (175 assertions total).

### Verified so far

- `charra_event_log.c`, `charra_synthetic_log.c`, and `charra_sdk.c` compiled
  standalone (stub TSS2/mbedTLS headers, real SHA-256 via CommonCrypto); all
  57 tests pass.
- Cross-checked `charra_replay_ima_log` against an independent Python
  re-implementation on a 423-byte 4-entry log: both produce
  `0269fe49...2b49efd` for PCR10, byte for byte.
- Raw vs. redacted log (different paths, 153 vs 140 bytes) replay to the
  same PCR10, confirming redaction of `template_data` does not disturb the
  chain.
- **Now compiled and run against real TSS2/libcoap/QCBOR/mbedTLS** in the
  project's own Docker dev-env image (`fraunhofer-sit/charra-dev-env:1.9.0`,
  linux/amd64 under emulation on this arm64 dev machine) — a prior session
  only had macOS stub headers available. `make` builds all five binaries
  and all five standalone test suites (94 assertions, `make test`) cleanly,
  no warnings. See "Live end-to-end verification" below for a real
  Attester→Trust Manager→Verifier→Relying Party run against the container's
  TPM simulator, not just unit tests.

### `charra_rp_qualification.h`/`.c` — RP qualification handshake logic (built)

The `rp_qualification_state` struct + comparison function this list used to
call "not yet built" now exist (`src/core/charra_rp_qualification.h`/`.c`,
`tests/test_rp_qualification.c`, 27 assertions). `charra_rp_qualification_generate()`
fabricates a synthetic log, redacts it locally, and precomputes the golden
answer (golden log + golden PCR); `charra_rp_qualification_check()` compares
an RP's submission against it and sets `qualified`/`expires_at`;
`charra_rp_qualification_is_valid()` is the gate a future
`coap_appraise_handler`-style caller would apply. Deliberately still stubs
Quote_R itself down to a raw `pcrDigest` byte-compare — see
`charra_verify_tpm2_quote()` below for the piece that would replace that
stub with a real signature check.

### Quote verification factored into small `static` helpers in `verifier.c` (built, then redirected)

First attempt: extracted the load-key / TPM-verify / mbedTLS-verify /
unmarshal sequence into a standalone reusable `charra_verify_tpm2_quote()`
in `src/util/charra_util.h`/`.c`, generic over who produced the quote
(Attester or RP). Verified live against the container's TPM simulator
(9/9 assertions: genuine quote accepted, tampered signature rejected,
corrupted public key rejected, bad arguments rejected) — the logic itself
was sound.

**Reverted**, on the grounds that a cross-module reusable function would
have swallowed the fine-grained `clock()`-bracketed timing instrumentation
`coap_appraise_handler` writes to `durations_verifier.txt` per sub-step
(load/verify/nonce/PCR each measured separately) into one opaque call,
trading that away for reuse that has no second caller yet anyway. Decision:
keep verification logic local to `verifier.c` and decompose by *readability*
instead of by *reuse* — small `static` helper functions callable from
`coap_appraise_handler`, not shared across files.

**What's actually built**, in `verifier.c`: `verify_quote_signature_with_tpm()`
and `verify_quote_signature_mbedtls()`, both `static`, defined right above
`coap_appraise_handler()`. Together they replace what used to be ~55 lines
of inline `{ }`-scoped blocks with two named calls, while every `clock()`
bracket stays exactly where it was in the handler (wrapping the calls, not
hidden inside them) — so per-step timing survives the refactor. Both
helpers assign the file-scope `attestation_rc` global as a side effect,
matching exactly what the inline code did before extraction (this file
already leans on module-level globals for this kind of state, e.g.
`last_request` — matching that existing style rather than introducing a
new convention). `verify_quote_signature_mbedtls()` preserves the original
two-tier failure handling: a hard RSA-conversion failure returns `false`
(caller does `goto cleanup`, same as the original inline `goto`), while a
mismatched signature is soft — recorded via an `out_valid` out-param, not
fatal, so the handler can still fold it into the combined
`attestation_result` alongside the TPM-based check, the nonce check, and
the PCR check.

Verified live end to end afterward (11 successful attestation cycles
against the container's TPM simulator) — log output for both signature
checks (`"TPM Quote signature is valid!"`, twice, once per check) is
byte-identical to before the refactor, confirming it's purely a
readability change with no behavior difference.

### The real RP→Verifier message shape — struct landed, marshal bodies + RP-side wiring still open

Confirmed the architecture, now aligned with the DRA-TLS spec's terminology:
the RP sends the Verifier one bundle — `Evidence_r` (`Quote_r`, `log_r`,
`EK_r`/`AK_r`) plus `Evidence_a'` (`Quote_a`, `EK_a`/`AK_a`, with `log_a`
deliberately stripped, never forwarded). Mapped against the spec's
Verifier-side checklist (Step 3a/3b — see "Target design v2" above):

- `Quote_a` + `EK_a`/`AK_a` (Step 3b) → signature + nonce checked in
  `coap_appraise_handler`; EK/AK chain validation still wholly unbuilt (see
  below). **No PCR check** — not part of the spec's Verifier steps.
- `Quote_r` + `EK_r`/`AK_r` (Step 3a) → same: signature + nonce checked;
  EK/AK unbuilt. **No PCR check, no log_r check** — same reasoning.
- `log_r` → the Verifier does **not** inspect its content at all anymore.
  The per-entry hash check, PCR replay, and file-hash policy check (spec
  Step 2a items 4/5/6) are the RP App's job, run against `log_a` *before*
  redaction — see the "Log content verification" entry in Part 3's
  `charra_event_log` section above. `verifier.c` no longer contains any of
  this logic; it was moved out and renamed this session.

Important structural point worth remembering: because redaction
deliberately changes `template_digest` per entry, replaying `log_r` would
never reproduce the PCR value `Quote_a` attests to even if the Verifier did
check it — that's intentional (see "Consequences of recomputing
template_digest" earlier in this doc). `Quote_r` functions as the RP's own
non-repudiation signature over "this is genuinely what I processed," the
same trust mechanism the qualification handshake already uses on fabricated
data, just now applied to real evidence.

**Why `Quote_r` needs its own public key + signature on the wire, not just
identity metadata**: signature verification fundamentally requires three
things — the signed data, the signature, and the public key — and there is
no persistent key registry or EK/AK-pinning anywhere yet (not even in
`rp_qualification_state`, which stores `qualified`/`expires_at` but doesn't
bind that trust decision to a *specific* RP key). So `Quote_r`'s key has to
travel in the message, exactly the same unauthenticated-at-the-transport-level
situation `Quote_a`'s key is already in today.

**What's actually built:**

- `msg_rp_appraisal_dto` (`charra_dto.h`) — **landed** (pushed by the other
  intern working the RP side, pulled in via rebase). Six fixed-size fields
  (Quote_a's three, Quote_r's three — mirroring shape exactly) plus
  `event_log`, whose *meaning* is `log_r` ("RP's redacted log"), not
  Attester's raw log.
- `charra_marshal_rp_appraisal()` / `charra_unmarshal_rp_appraisal()`
  (`charra_marshaling.c`) — **implemented**, following
  `charra_marshal_attestation_response()`'s exact internal/size/marshal/
  unmarshal pattern. Originally the RP-side intern's assigned scope (still
  their DTO to own going forward); written here only to unblock a real
  end-to-end build+test run of the `/certify_ak` and Step 3a/3b work below —
  see "Live end-to-end CoAP verification" in Part 3. All six fixed-size
  fields are bounds-checked on unmarshal exactly as the header docstring
  specifies (`attestation_data_len <= sizeof(TPMS_ATTEST)` etc.), so bug #1's
  class of overflow does not reappear here.
- `verifier.c`'s `coap_appraise_handler` — unmarshals via
  `charra_unmarshal_rp_appraisal()`, re-validates bounds on the fixed-size
  fields independently of the unmarshaler (defense in depth, same style as
  the rest of the function), and verifies `Quote_r` with the *same*
  `verify_quote_signature_with_tpm()`/`verify_quote_signature_mbedtls()`
  helpers used for `Quote_a` — separate `ESYS_TR sig_key_handle_rp` and
  `TPMT_TK_VERIFIED* validation_rp`, both flushed/freed in `cleanup:`. Both
  RP results (`attestation_result_signature_rp`,
  `attestation_result_signature_rp_mbedtls`) fold into the final
  `attestation_result`, alongside a nonce check on `Quote_r`
  (`attestation_result_nonce_rp`, reusing `last_request.nonce` — same
  session nonce as `Quote_a`'s check, closes a "replay just RP's half"
  attack). **`attestation_result` now also folds in the EK/AK check for
  each evidence bundle** (`attestation_result_ekak_rp`,
  `attestation_result_ekak` — see "Step 3a/3b item 1: EK/AK certificate
  validation" below) — eight booleans total: EK/AK + two signature checks +
  one nonce check, per quote. Still no PCR term, no log_r term — matches
  Step 3a/3b exactly, spec-complete on the Verifier side.

**Build status**: `msg_rp_appraisal_dto` and its marshal/unmarshal bodies
both now exist, so `bin/verifier` compiles *and* links cleanly.
`attester`/`verifier_old`/`relying_party`/`trust_manager` are unaffected and
build clean. All 175 assertions across the existing test suites pass (8
suites: `test_event_log` 29, `test_synthetic_log` 13, `test_sdk` 20,
`test_rp_qualification` 27, `test_marshaling_bounds` 10,
`test_x509_cert_chain` 17, `test_certify_ak_marshaling` 20, `test_ak_state`
39) — none of these 8 suites cover the wire-format/Step 3a/3b item 1 work
below yet; that was verified live only (see its own entry), not via a
persisted unit test. Worth adding one.

Still genuinely unbuilt:
- Everything in `relying_party.c` for the actual Step 2a/2b flow: EK/AK
  validation of the Attester, calling the relocated
  `verify_log_entries_self_consistent()`/`verify_log_matches_quote_r_pcr()`/
  `verify_log_file_hashes_against_policy()` against `log_a`, redaction
  (`charra_sdk_redact_ima_log()` exists and is tested but uncalled), `Quote_r`
  generation (must select PCR10 only — see "Open / undecided" above), and
  calling `charra_marshal_rp_appraisal()` to send `Evidence_r` +
  `Evidence_a'` onward. **`coap_appraise_handler` now hard-requires both AK
  certificates to be present and valid** (see below) — until RP/Attester
  actually provision and attach one, `/appraise` will always fail, even in
  ad-hoc testing.

### Step 3a/3b item 1: EK/AK certificate validation (built)

Closes the last placeholder in `coap_appraise_handler` — both "Step 3a/3b
item 1 — NOT YET IMPLEMENTED" comments are gone, replaced with real checks.
The Verifier's spec-mandated scope (Step 3a/3b, both items 1-3) is now
fully implemented; the gap that remains is entirely on the Attester/RP side
(see "Still genuinely unbuilt" above).

**Wire format**: `msg_rp_appraisal_dto` (`charra_dto.h`) gained two
variable-length fields, heap-allocated on unmarshal like `event_log`:
`ak_certificate`/`ak_certificate_len` (EK_a/AK_a — the Attester's AK
certificate, forwarded by RP, positioned right after `tpm2_public_key` to
group with `Quote_a`'s other fields) and `ak_certificate_rp`/
`ak_certificate_rp_len` (EK_r/AK_r — RP's own, positioned after
`tpm2_public_key_rp`). `charra_marshal_rp_appraisal()`/
`charra_unmarshal_rp_appraisal()` (`charra_marshaling.c`) updated to match;
the CBOR array grew from 7 to 9 elements. **Consequence**: `/appraise` now
hard-requires both certificates — a request without them fails
`charra_crypto_verify_x509_cert_chain()`'s zero-length check immediately,
so nothing that doesn't yet attach a real AK certificate (which is
everything today, see "Still genuinely unbuilt") can get a positive result
anymore. This is intentional, matching the spec exactly, not a bug to
work around.

**Verifier-side check**: `charra_crypto_verify_ekak_certificate()`
(`crypto_util.c`) — see its own table entry above. `coap_appraise_handler`
calls it once for Step 3a item 1 (RP's `ak_certificate_rp` against
`keys/verifier-ca.crt`, folded into `attestation_result_ekak_rp` →
`step_3a_passed`) and once for Step 3b item 1 (the Attester's
`ak_certificate`, only reached if Step 3a already passed, folded into
`attestation_result_ekak` → the final `attestation_result`). Both call
sites originally had this logic written inline, duplicated between them;
factored into the shared `crypto_util.c` function instead — deliberately
placed there rather than a new `core/` file (a real design discussion, not
a default): the two functions it combines are genuinely generic crypto
primitives, but the file/directory split was judged not worth fragmenting
a single two-call combinator over. The trust anchor (`keys/verifier-ca.crt`)
is read once, before Step 3a, and shared by both checks — the same CA
`coap_certify_ak_handler` itself signs with, since the Verifier is the sole
issuer for both parties.

**Verified live** (not yet covered by a persisted unit test — see "Build
status" above): a temporary, not-committed client minted two real AK
certificates directly with the Verifier's own CA key (same shortcut
`test_x509_cert_chain.c`'s own round-trip test uses, standing in for a
genuine `/certify_ak` round trip that can't complete today — see
`/certify_ak` entry below), built a genuine `msg_rp_appraisal_dto`, and sent
it to a live `bin/verifier`. Confirmed: (a) with genuine certificates, both
checks log "... AK certificate is valid!", Step 3a passes and proceeds to
Step 3b, ending in `ATTESTATION SUCCESSFUL`; (b) with RP's certificate
deliberately tampered (one byte flipped in the DER body), the chain check
fails, `step_3a_passed` becomes false, Step 3b is skipped entirely (the
early-exit gating still holds), ending in `ATTESTATION FAILED` — Quote_a
never even inspected, matching the spec's early-exit wording. Re-run after
the factoring above to confirm it changed no observable behavior — same
log lines, same outcome, in both the pass and fail cases.

**Reusable by RP**: see the "Reusable by RP for its own Step 2a item 1"
note under the `/certify_ak` entry below — the same
`charra_crypto_verify_ekak_certificate()` function, no new state needed.

### `/certify_ak` — Verifier-as-Privacy-CA AK issuance (built)

Implements the Verifier-side half of "AK provisioning" (see "Open /
undecided" above): the Verifier merges the Privacy CA role into itself
(acceptable here since this project's privacy goal is hiding file paths, not
hiding device identity from the Verifier) and issues AK certificates via the
standard TPM2 "Credential Activation" protocol
(`TPM2_MakeCredential`/`TPM2_ActivateCredential`), rather than requiring a
separate manual CA enrollment step.

**Why a separate endpoint, not folded into `/appraise`**: a first-ever
request for an uncertified AK can't simultaneously carry a meaningful
appraisal verdict, since `ActivateCredential` (which must complete on the
*requester's own* TPM) hasn't happened yet at request time. Provisioning
happens once (or on renewal, once renewal exists — see "Not yet built"); the
resulting certificate must then be re-presented on every subsequent
`/appraise` call, since the Verifier is stateless per-request with no
session/identity tracking.

**Why the credential is a symmetric key, not the certificate itself**:
`TPM2_MakeCredential`'s `credential` field is capped near a digest size
(~32-64 bytes) — too small for an X.509 certificate. Resolved by making the
credential a fresh AES-256 key `K`; the actual signed AK certificate travels
in the *same* response, AES-256-GCM-encrypted under `K`. The requester
recovers `K` via `ActivateCredential` on their own TPM (proving co-residency
of EK + the named AK, without the EK's private key ever leaving that TPM),
then decrypts the certificate — one round trip, not two.

Request/response shape — `msg_certify_ak_request_dto` /
`msg_certify_ak_response_dto` (`charra_dto.h`), marshaled by
`charra_marshal_certify_ak_request()` / `charra_unmarshal_certify_ak_request()`
and the response-side equivalents (`charra_marshaling.c`), following this
codebase's established internal/size/marshal/unmarshal pattern exactly.
Tested in `tests/test_certify_ak_marshaling.c` (20 assertions: round-trips
for both DTOs, oversized-field rejection, and — since `aes_gcm_nonce`/
`aes_gcm_tag` are fixed-size, not just capped — wrong-size rejection too, not
only oversized).

**New crypto primitives** (`src/util/crypto_util.h`/`.c`):

| Function | Purpose |
|---|---|
| `charra_crypto_seeded_rng_init`/`_free` | Reusable seeded `mbedtls_ctr_drbg_context`, needed by several of the below (key parsing, cert signing, AES-GCM nonce generation). |
| `charra_crypto_verify_x509_cert_chain` | Single-root chain verification (leaf vs. one trusted root, no intermediate support — matches this project's two-tier PKI). Checks validity window as a side effect of `mbedtls_x509_crt_verify()`; no revocation check (see "Open/undecided"). |
| `charra_crypto_verify_cert_public_key_matches_tpm_public_key` | Confirms a certificate's embedded RSA key is the same key as a `TPM2B_PUBLIC` — ties "this cert is valid" to "this cert vouches for the key that signed this specific quote." Called via `charra_crypto_verify_ekak_certificate()` below, from `coap_appraise_handler`'s Step 3a/3b item 1. |
| `charra_crypto_verify_ekak_certificate` | Combines the two functions above: an AK certificate chains to a trusted CA *and* its key matches a quote's signing key. Deliberately generic over the caller — see "Step 3a/3b item 1" below and the "Reusable by RP" note further down. |
| `charra_crypto_sign_ak_certificate` | Verifier-as-CA: signs a fresh AK certificate (`mbedtls_x509write_crt`) for a given `TPM2B_PUBLIC`, issued under the Verifier's own CA key. |
| `charra_crypto_build_ek_tpm2b_public_from_cert` | Reconstructs the full TCG-standard RSA-2048 EK `TPM2B_PUBLIC` (fixed "low range" template — type/nameAlg/objectAttributes/authPolicy/parameters, only the modulus varies) from an already-verified EK certificate. Needed because `Esys_MakeCredential` requires the EK's whole public area, not just its bare RSA key — a real Privacy CA is expected to know this fixed template. **Template values confirmed empirically** against a real `tpm2_createek -G rsa` output on this project's TPM simulator (`objectAttributes` raw `0x300b2`, authPolicy digest `837197...69aa`), not just recalled from the TCG spec. |
| `charra_crypto_aes256gcm_encrypt`/`_decrypt` | Wraps/unwraps the AK certificate under the MakeCredential secret. Decrypt is authenticated (`mbedtls_gcm_auth_decrypt`, not the non-verifying `mbedtls_gcm_crypt_and_tag`) — a tampered ciphertext or wrong key returns `CHARRA_RC_VERIFICATION_FAILED` with no plaintext output, not a silently-wrong decrypt. |

**Reusable by RP for its own Step 2a item 1** (validate Attester's EK/AK
certificate): `charra_crypto_verify_ekak_certificate()` takes no
Verifier-specific state — no build change needed, since `crypto_util.o` is
already in the shared `OBJECTS` list every binary links (`relying_party.c`
already `#include`s `util/crypto_util.h`). RP would call it exactly the way
`coap_appraise_handler` does for Step 3a/3b item 1 (see below): against the
Attester's *already-issued* AK certificate (once the Attester has one via
`/certify_ak`) and `keys/verifier-ca.crt` as the trusted CA — **not** a raw
EK certificate check against `manufacturer-root.crt`. Under this project's
resolved design the EK is validated exactly once, at `/certify_ak` time; it
is not part of `Evidence_a` and RP's Step 2a item 1 does not re-check it
either, symmetric with how the Verifier's own Step 3a/3b item 1 works. The
issuance-side functions
(`charra_crypto_build_ek_tpm2b_public_from_cert`,
`charra_crypto_sign_ak_certificate`, `charra_tpm_make_credential_for_ak`,
AES-GCM *encrypt*) stay Verifier-only, since only the Verifier acts as
Privacy CA in this design — RP only ever validates certs, never issues them.
AES-GCM *decrypt* would be needed by whichever party requests certification
(Attester, to unwrap its own `/certify_ak` response) — not RP's concern
either way.

**New TPM primitive** (`src/core/charra_key_mgr.h`/`.c`):
`charra_tpm_make_credential_for_ak()` wraps `Esys_MakeCredential` — loads the
requester's EK externally (same `Esys_LoadExternal` mechanism used elsewhere
in this file for quote-verification keys), no TPM identity of the Verifier's
own required (MakeCredential is pure public-key crypto against the supplied
EK). Trusts the caller-supplied AK name unverified — a wrong name just makes
the requester's own later `ActivateCredential` fail, nothing is lost.

**Handler**: `coap_certify_ak_handler()` in `verifier.c`, registered as the
new `certify_ak` CoAP resource alongside `appraise`/`nonce`. Flow: unmarshal
request → verify EK cert chains to `keys/manufacturer-root.crt` (else
`4.01 Unauthorized`) → reconstruct EK `TPM2B_PUBLIC` → sign a fresh AK cert
(subject `"CN=CHARRA AK"`, issuer read from `keys/verifier-ca.crt`'s own
subject name, fixed test-only validity window `2024`-`2034`) → generate a
fresh AES-256 key, AES-GCM-encrypt the certificate under it → `Esys_MakeCredential`
to wrap that key against the EK/AK pair → record the issuance in the
AK-provisioning state (`charra_ak_state_renew()`, revoking any previous
record for this EK — see "AK-provisioning state" below) → marshal + send the
response. The state-recording step deliberately happens here, only once
signing and `MakeCredential` have both already succeeded, not right after
signing — so a later failure can never revoke a working certificate in favor
of one the requester never actually receives.

**Test-only PKI** (`keys/gen-ak-pki.sh`, see `keys/README.md`):
`verifier-ca.{key,crt}` (Verifier's own Privacy CA, self-signed), a synthetic
`manufacturer-root.{key,crt}` standing in for a real TPM manufacturer root
(the dev-env's software TPM has none), and `rp-ek.{key,crt}`/
`attester-ek.{key,crt}` synthetic EK certificates signed by that root —
**plain openssl RSA keys, not yet the TPM simulator's own endorsement-hierarchy
key** (tracked in "Not yet built"). Certs are DER (real wire format, avoids
PEM NUL-termination requirements in mbedtls); keys stay PEM.

**Verified**:
- `tests/test_x509_cert_chain.c` (17 assertions) — chain verification
  (valid/wrong-root/tampered), key-matching, and a full sign-then-verify
  round trip against the real CA key.
- `tests/test_certify_ak_marshaling.c` (20 assertions) — see above.
- A temporary (not committed) direct-call smoke test proved the full
  pipeline against the real TPM simulator: EK cert chain verify → EK
  `TPM2B_PUBLIC` reconstruction → a genuine `Esys_MakeCredential` call that
  succeeds with the reconstructed template → AK cert signing → AES-256-GCM
  encrypt/decrypt round trip → tampered-tag rejection. 14/14 passed.
- A temporary (not committed) end-to-end CoAP client, run against real
  `bin/attester` + `bin/verifier` processes and the real TPM simulator,
  confirmed: (a) a single-packet `/certify_ak` request with a bad EK cert
  correctly returns `4.01 Unauthorized`; (b) a full block-wise (multi-UDP-
  datagram) `/certify_ak` upload with a real EK certificate is received,
  reassembled, and processed correctly by the handler; (c) sending a
  complete, genuine `Evidence_r`/`Evidence_a'` bundle — Attester's real
  `Quote_a` fetched from `bin/attester`, plus a real RP-side `Quote_r`
  produced against the same TPM simulator (standing in for `relying_party.c`,
  which doesn't build this yet) — through `/nonce` then `/appraise` produced
  a genuine `ATTESTATION SUCCESSFUL` from `coap_appraise_handler`'s Step
  3a-then-3b gated flow, confirming that logic end to end with real crypto
  over a real network, not just via unit tests. (Intermittent response
  delivery under back-to-back heavy requests was observed and traced to
  TPM-simulator/transport load, not handler logic — the identical request
  succeeds cleanly in isolation.)

### AK-provisioning state (built) — persisted record of `/certify_ak` issuance

`coap_certify_ak_handler()` was otherwise fully stateless: every call signed
a fresh certificate with no memory of any previous one for that requester.
`src/core/charra_ak_state.h`/`.c` gives it that memory, on disk, surviving
both across separate `/certify_ak` calls and a server restart, and shared
across the multiple `bin/verifier` processes `start_verifiers.sh` spawns
(all of which share one CA, so a renewal or future revocation needs to be
visible to all of them, not just whichever instance handled the request).

**Renewal policy (decided)**: requesting a new AK certificate for an EK that
already has one on file always issues a fresh certificate and revokes the
previous record for that EK — a rolling renewal, not a reject or a
serve-the-same-cert-again. **Revocation trigger (decided, scoped)**: nothing
else in this pass sets a record `revoked` — no manual/administrative trigger
exists yet, deliberately; this module is groundwork for one, not the
mechanism itself.

**Record** (`charra_ak_state_record`): `ek_fingerprint` (SHA-256 of the
requester's EK certificate DER — the stable identity a renewal is matched
against, not anything the requester merely claims), `ak_name`/`ak_name_len`,
`serial` (the issued certificate's own 16-byte serial), `issued_at`,
`expires_at` (parsed from the exact same `"YYYYMMDDHHMMSS"` string passed to
`charra_crypto_sign_ak_certificate()`, not approximated as
"issued_at + duration" — so it can never drift from what the certificate
itself actually says), `revoked`.

**Storage**: one line per record in `ak-provisioning-state.txt` (repo root,
same convention as `verifiers_config.txt`/`reference-pcrs.txt`) —
whitespace-separated hex/decimal fields, not meant to be hand-edited.
`charra_ak_state_load()`/`_save()` do a full read/rewrite (small-scale, same
approach as the whitelist/blacklist loaders); a missing file is zero
records, not an error (a fresh deployment hasn't issued anything yet).

**Concurrency**: `charra_ak_state_renew()` — the only function that ever
writes, and the only one `coap_certify_ak_handler()` calls directly rather
than `_load()`/`_save()` — takes an advisory `flock()` on a companion
`.lock` file around its whole revoke-then-append cycle, safe across the
multiple `bin/verifier` OS processes mentioned above. No in-process locking
is needed; `verifier.c`'s own event loop is single-threaded.

**A bug caught before it shipped**: `charra_ak_state_find_by_ek_fingerprint()`
was first written as a forward linear scan returning the first match. After
two or more renewals for the same EK, multiple records with that fingerprint
exist (oldest first, since `_renew()` only ever appends) — a forward scan
would keep finding the *oldest, already-revoked* one, meaning the second
renewal would re-revoke an already-revoked record instead of the actually-
active one, permanently orphaning it as "active" forever. Fixed to scan
backward, always returning the most recently issued record for a
fingerprint. Caught and fixed before writing tests, then specifically
regression-tested (`test_renew_revokes_previous_and_survives_multiple_cycles`,
four renewal cycles in a row, asserts exactly one record stays unrevoked and
it's the last one issued).

**Verified**:
- `tests/test_ak_state.c` (39 assertions) — load/save round-trip, find-by-
  fingerprint (including the most-recent-not-oldest case above), find-by-
  serial, `is_valid` (revoked / expired / both), first issuance, the
  four-cycle renewal regression test, bad-argument rejection.
- A temporary (not committed) live check against a real running
  `bin/verifier`: two genuine `/certify_ak` requests for the same real EK
  certificate produced exactly the expected two-line state file — first
  record `revoked=1`, second `revoked=0`, different serials (genuinely
  different signed certificates, not a stub) — confirming
  `coap_certify_ak_handler()` actually calls `charra_ak_state_renew()`
  correctly, not just that the module works in isolation.

**One existing function's signature changed to support this**:
`charra_crypto_sign_ak_certificate()` gained a `uint8_t serial_out[16]`
out-param — it previously generated a random serial internally and
discarded it, leaving the caller with no way to know what it had just
issued. Updated at both call sites (`verifier.c`, `tests/test_x509_cert_chain.c`).

### Live end-to-end verification (Docker, real TPM simulator)

Ran the actual quartet — `trust_manager` + `attester` + `verifier` +
`relying_party` — against the dev-env container's TPM simulator, no mocks,
to confirm the bug fixes below introduced no regressions against genuine
TPM operations. 11 full attestation cycles succeeded end to end
(`ATTESTATION SUCCESSFUL`), with both the TPM-based and the
now-actually-gated mbedTLS-based signature checks (bug 4) agreeing `valid!`
on every single run.

Found and worked around one **environment** bug along the way, unrelated to
CHARRA's own code: the container's own `/usr/local/bin/tpm-reset` helper
calls `tpm2_startup --clear` with a stale `TPM2TOOLS_TCTI_NAME=socket` /
`TPM2TOOLS_SOCKET_*` env-var scheme that this image's `tpm2-tools` 5.6
doesn't honor, so `TPM2_Startup` was silently never executing (the script
doesn't check its exit code). Every TPM operation then fails with "TPM not
initialized." Worked around by calling
`tpm2_startup -c -T "mssim:host=127.0.0.1,port=2321"` directly. Also
learned the hard way: `pkill -f`/`pgrep -f` match the *full command line*,
including the invoking shell's own script text if it happens to contain the
same substring (e.g. `pkill -f 'bin/verifier'` inside a `bash -c "..."` that
itself contains that string self-matches and kills its own shell) — use
`pkill`/`pgrep` without `-f` (matches process name only) or exact PIDs
instead.

### Not yet built (tracked here so nothing gets lost between sessions)

- ~~The two new CoAP endpoints for the qualification handshake~~ **Built**
  (see "RP qualification handshake wired end-to-end" below) — `/qualify`
  and `/qualify_submit` now exist on the Verifier, with a matching RP
  client and the gate wired into `coap_appraise_handler`.
- RP-side (Step 2a + 2b of the DRA-TLS spec), nothing started: EK/AK
  validation of the Attester (can reuse `charra_crypto_verify_ekak_certificate()`
  as-is — see "Step 3a/3b item 1" entry in Part 3); calling the relocated
  `verify_log_entries_self_consistent()` / `verify_log_matches_quote_r_pcr()`
  / `verify_log_file_hashes_against_policy()` (now in `charra_event_log.c`,
  see Part 3) against `log_a`; real redaction (`charra_sdk_redact_ima_log()`
  exists and is tested, just uncalled); `Quote_r` generation (PCR10-only
  selection — see "Open / undecided"); calling
  `charra_marshal_rp_appraisal()` to send `Evidence_r` + `Evidence_a'`
  onward, now including both AK certificates (mirroring how `attester.c`
  calls `charra_marshal_attestation_response()` today).
- Real, persistent AK provisioning for both Attester and RP (currently:
  neither has one — `charra_key_mgr.c` still creates a fresh primary key per
  request) and client-side logic on both to call the now-built `/certify_ak`
  endpoint and attach the resulting certificate to `/appraise` requests. This
  is now the sole remaining blocker on `/appraise` ever succeeding for real
  evidence — the Verifier-side checks (Step 3a/3b, all three items) are
  complete and wired in.
- Real (non-synthetic) EK certificates and EK residency on the TPM
  simulator's actual endorsement hierarchy — `keys/gen-ak-pki.sh`'s EK certs
  are plain openssl keys today, not real TPM objects (see `/certify_ak`
  entry in Part 3 for exactly what this blocks).
- Wiring the AK-provisioning state module's `charra_ak_state_find_by_serial()`
  into `coap_appraise_handler`'s Step 3a/3b item 1 EK/AK check (now built —
  see its own Part 3 entry) to reject revoked certificates. The check itself
  currently only verifies chain + key match, not revocation status; the
  lookup function is ready, nothing calls it yet.
- A persisted unit test for `msg_rp_appraisal_dto`'s marshal/unmarshal
  (including the two new AK certificate fields) — currently only verified
  via a temporary, not-committed live client (see "Step 3a/3b item 1" entry
  in Part 3), unlike every other DTO this session, which all have one.
- A manual/administrative revocation trigger — deliberately out of scope for
  now (see "AK-provisioning state" entry in Part 3): the only thing that
  currently revokes a record is a fresh renewal for the same EK.

### Bugs found during audit of `verifier.c` (2026 audit, not yet fixed)

**Line numbers below are stale** — this session's DRA-TLS-alignment work
(moving `log_r` checks to `charra_event_log.c`, removing the PCR-vs-reference
check) shifted most of the file by hundreds of lines; treat line references
as approximate, re-locate by function/variable name. **Bug 4 also appears
already fixed**: `attestation_result_signature_mbedtls` is folded into the
final `attestation_result` in current `coap_appraise_handler` code, contrary
to what's described below — likely fixed incidentally during the
"small `static` helpers" refactor (see above), not verified against the
original finding. The other six bugs have not been re-checked against
current code this session.

Most severe first — full details/failure scenarios were reported via
ReportFindings during the session that found them; summarized here for
persistence:

1. **Unbounded `memcpy` into `tpm2_public_key`** (`charra_marshaling.c:441`)
   — no length check before copying attacker-controlled CBOR bytes into a
   fixed-size struct field. Most severe: no cap at all on the overflow.
2. **`attestation_data` bounds check uses wrong `sizeof`**
   (`verifier.c:342`/`406`) — checks against the whole `TPM2B_ATTEST` struct
   but writes into a smaller sub-field; ~2-byte overflow window.
3. **Uninitialized `esys_ctx`/`tcti_ctx` read if `fopen()` fails**
   (`verifier.c:300`) — a `goto cleanup` jumps over their declarations;
   undefined behavior if the working directory isn't writable.
4. **mbedTLS signature check result is discarded** (`verifier.c:447`) — the
   "defense in depth" second signature check never actually gates the
   attestation result; only the TPM-based check does.
5. **File handle leak on every error path** (`verifier.c:296`) —
   `durations_verifier.txt` only gets `fclose`'d on full success.
6. **Global `last_request` risks cross-session nonce mixing**
   (`verifier.c:66`) — shared mutable state between `/nonce` and `/appraise`;
   already hinted at in the code's own TODO comment.
7. **(Different file) `relying_party.c:366`** — `strcmp` result inverted,
   swaps pass/fail when interpreting the Verifier's own response message.
   Outside `verifier.c` but directly consumes its output. **FIXED** — see
   "Live end-to-end verification on `EK/AK_rp_verifier`" below.

Bugs 1, 2, 3, 5, 6 not fixed yet; flagging here so they aren't lost.

### Known issue: RP qualification handshake is structurally broken by salted redaction (found on `EK/AK_rp_verifier`, not fixed)

`charra_rp_qualification_check()` (`charra_rp_qualification.c`) compares an
RP's submitted redacted log against a locally-computed "golden log" with a
byte-exact `memcmp()`. `charra_sdk_redact_ima_log()` was rewritten in
`afdde44` ("RP privacy cleaning...") to hash each path with a **fresh random
salt per call** (`hash_path_salted()`, deliberately never transmitted, so
equal paths don't redact to equal values across separate redactions). Nobody
updated the qualification check to account for this: **an RP running the
exact correct, unmodified SDK can never produce byte-identical output to the
Verifier's own golden-log redaction**, since both calls mint independent
random salts. The check is not merely stale — it cannot pass for a correctly
behaving RP anymore, by construction. This was caught because rebuilding this
branch in Docker and running `make test` surfaced 4 failing assertions in
`test_rp_qualification` (`"an RP that redacts correctly qualifies"`); not
fixed yet, left for a future session. Fix needs a real design decision (e.g.
a salt parameter so the qualification challenge can use a fixed/known salt
while real `/appraise` redaction keeps using a random one — safe since
qualification only ever touches fabricated synthetic paths — or dropping the
byte-exact log comparison in favor of a structural/PCR-only check).

**Update: this is now enforced live, not just in `test_rp_qualification`
(see "RP qualification handshake wired end-to-end" below).** As of the
`coap_appraise_handler` gate landing, this known-broken comparison means
**every `/appraise` call is currently rejected with `4.03 Forbidden`,
regardless of how correct the RP's evidence is** — confirmed live: a full
attester → RP → verifier run now ends in "Attestation failed!" purely
because `/qualify/submit` never passes, never reaching Step 3a/3b at all.
This is the intended, explicitly-requested state of this branch for now
(the wiring was built ahead of the salt fix, deliberately) — but it is a
real behavior change from the previous session's "`ATTESTATION SUCCESSFUL`
end to end" result, and the salt-handling design decision above is now the
sole blocker on `/appraise` passing again, not a nice-to-have.

### RP qualification handshake wired end-to-end (built this session, salt issue above deliberately left unfixed)

The four pieces the "Not yet built" list used to describe as missing are
now built and confirmed live:

- **Wire protocol**: `msg_qualify_response_dto` / `msg_qualify_submit_
  request_dto` (`charra_dto.h`) + matching CBOR marshal/unmarshal
  (`charra_marshaling.c`).
- **Verifier endpoints**: `coap_qualify_handler()` (`/qualify` — fabricates
  a fresh challenge via `charra_rp_qualification_generate()`, a random seed
  each call) and `coap_qualify_submit_handler()` (`/qualify_submit` —
  chain-verifies the submitter's AK certificate against the Verifier's own
  CA, same check Step 3a item 1 uses, then verifies an RSA-PSS/SHA-256
  signature over the submitted PCR digest before ever calling
  `charra_rp_qualification_check()`) — both in `verifier.c`, backed by a
  new global `qualification_state` (single-RP assumption, same convention
  `last_request` already uses).
- **RP client**: `rp_perform_qualification_handshake()` in
  `relying_party.c` — fetches the challenge, redacts it through the exact
  same `charra_sdk_redact_ima_log()` pipeline real evidence uses, replays
  it into a PCR digest, signs that digest with RP's TPM-resident AK (same
  short-lived-connection pattern `charra_rp_build_evidence_message()`
  uses for Quote_r), and submits. Run once per Verifier per attestation
  cycle from `get_attestation_results_thread()`, before `/appraise` —
  Verifier-local state, unlike AK provisioning, so it can't be done once
  against `verifiers[0]` the way `ensure_rp_ak_certificate()` is. A new
  `rp_coap_fetch()` helper factors out the create-context/session/PDU/
  wait-loop boilerplate this and the two new endpoints share with the
  existing `/certify_ak` call.
- **The gate**: `coap_appraise_handler` now checks
  `charra_rp_qualification_is_valid(&qualification_state, time(NULL))`
  before Step 3a/3b, rejecting with **`4.03 Forbidden`** — deliberately
  *not* `4.01 Unauthorized`, which RP's own retry logic
  (`rp_ak_cert_rejected`) already treats as "go redo `/certify_ak`"; reusing
  it here would send a qualification failure into a pointless AK-
  reprovisioning loop instead of redoing `/qualify`.

One live bug found and fixed during this work: `coap_qualify_submit_
handler()` responds with `2.05 Content` for *both* "qualified" and "not
qualified" (same convention `/appraise` already uses — the message text
carries the verdict, not the response code). The first version of RP's
`coap_qualify_submit_response_handler()` treated any `2.05` as "qualified,"
so the RP logged "RP QUALIFIED" immediately after the Verifier's own log
said "Qualification failed!" — caught by actually reading the live log
output side by side, not by the build or `make test`. Fixed to `memcmp`
the response body against the expected success message, mirroring
`coap_verifier_handler_appraisal()`'s own `strcmp`→`memcmp` fix earlier
this branch (bug #7).

### Also found and fixed this session: synthetic-log generator was still emitting the pre-`afdde44` flat `template_data` layout

`afdde44` rewrote `charra_sdk_redact_ima_log()` to expect real `ima-ng`'s two
length-prefixed sub-fields (d-ng: algo+digest, n-ng: path+NUL) but left
`charra_synth_generate_ima_log()` (`charra_synthetic_log.c`) emitting the old
flat `"sha256:" + digest + NUL + path` blob the *previous* SDK version
expected. Every redaction of a synthetically-generated log therefore failed
with `"Entry N's template_data is not a well-formed ima-ng field pair"` —
caught via `make test` in Docker on this branch (`test_sdk`, 7/20 failing).
Fixed: `charra_synth_generate_ima_log()` now builds the same two-field
layout `charra_sdk.c` expects (`d_field = u32(39) + "sha256:" + 32-byte fake
digest`, `n_field = u32(path_len+1) + path + NUL`), and
`tests/test_sdk.c`'s byte-offset assertions were updated to account for the
new 4-byte length prefixes (redacted `template_data` is now 79 bytes, not
71). `test_sdk` is back to 20/20. One remaining test in that suite
(`test_deterministic`, renamed `test_salted_nondeterministic`) was also
updated: it previously asserted two redactions of the same log produce
byte-identical output, which is now false by design per the salting above —
it now asserts the opposite (same length, different bytes).

### Rename: `charra_rp_identity` → `charra_rp_key_mgr`

`charra_rp_identity.h`/`.c` (RP's TPM-resident EK/AK creation, persistence,
`ActivateCredential`, AK-signing — introduced in `bb0eeed`) renamed to match
this codebase's existing naming convention: `charra_key_mgr.h`/`.c` is
already the Attester-side equivalent, so `charra_rp_key_mgr` makes the
parallel explicit rather than leaving two unrelated-sounding names for
mirror-image modules. Every `charra_rp_identity_*` function renamed to
`charra_rp_key_mgr_*` (`create_ek`, `create_ak`, `load_ak`,
`activate_credential`, `sign`, `public_key_to_der`, `save_public`/
`load_public`, `save_private`/`load_private`), include guard
`CHARRA_RP_IDENTITY_H` → `CHARRA_RP_KEY_MGR_H`. Call sites updated in
`relying_party.c`, references in `charra_dto.h`'s docstrings, `Makefile`'s
`OBJECTS` list. Pure rename, no logic changed; rebuilt clean in Docker
afterward to confirm.

### Live end-to-end verification on `EK/AK_rp_verifier` — first genuine `ATTESTATION SUCCESSFUL` for the full RP/EK/AK pipeline

Ran the actual quartet (`trust_manager` + `attester` + up to 5 `verifier`
instances + `relying_party`) against the dev-env container's real TPM
simulator, no mocks — not unit tests, the actual CoAP wire protocol end to
end. This surfaced and fixed several bugs that unit tests couldn't catch
(they all live in the CoAP/threading glue, not in logic the existing test
suites exercise), then reached a genuine `ATTESTATION SUCCESSFUL` for the
first time.

**Bug: `/nonce` request sent with an empty body — RP and Verifier were built
to two different, incompatible nonce designs.** `relying_party.c`'s `/nonce`
client code carried an explicit comment: *"The request carries no payload —
the Verifier contributes the challenge, which is the whole point: a nonce
the RP generated could never prove freshness TO the Verifier."* But
`verifier.c`'s `coap_nonce_handler()` was written the other way around: it
unconditionally unmarshals a full `msg_attestation_request_dto` from the
incoming request and echoes back `req.nonce` — its own comment says this is
what lets `Quote_r`'s freshness check later byte-compare against
`last_request.nonce`. Two different contributors independently resolved the
open "who generates the freshness challenge?" question (see "Deliberately
out of scope" in Part 2) in opposite directions, and nobody reconciled them.
Concretely: RP sends zero bytes → `coap_get_data_large()` on the Verifier
side returns 0 → immediate `"Could not get CoAP PDU data"` → Verifier
responds `4.00 Bad Request` with no body → RP's `coap_verifier_handler_nonce()`
finds no data → `"Verifier returned no nonce"` → every single attestation
died right here, before `Quote_r` could ever be built. **Fixed** (lower-effort,
verifier-compatible direction, per explicit decision): RP's `/nonce` request
now sends `last_request` (the same request DTO already built for the
Attester, stable and read-only by the time this fires — populated once in
`get_evidence()`, which always completes before `get_attestation_results()`
spawns any verifier thread) marshaled via the already-existing
`charra_marshal_attestation_request()`, instead of `NULL, 0`.

**Bug 7 (audit list above), confirmed and fixed**: `coap_verifier_handler_appraisal()`'s
`if (strcmp((const char*)data, successful_message))` had success and failure
backwards (`strcmp` returns 0 on a match, i.e. exactly when the attestation
*succeeded*, which took the `else`/`false` branch). Fixed to
`memcmp(data, successful_message, data_len) == 0` — also switched off
`strcmp` entirely: `data` points into the CoAP PDU buffer with no guaranteed
NUL terminator past `data_len` bytes (the Verifier sends `strlen(message)`
bytes, excluding the terminator), so comparing by exact received length is
correctness, not just style.

**New bug found and fixed (not in the original audit list): uninitialized-pointer
double free on early `goto cleanup`.** `get_attestation_results_thread()`
declared `coap_context_verifier_appraisal`/`coap_session_verifier_appraisal`/
`coap_options_verifier_appraisal` (and, independently, `res_buf`) well after
several earlier `goto cleanup` jumps — including the "Verifier did not supply
a nonce" path, which fires whenever a verifier times out. Jumping over a C
variable's initializer leaves it with an indeterminate value, not `NULL`; the
shared `cleanup:` label then unconditionally passed all three (plus `res_buf`)
to `charra_free_if_not_null_ex()`/`charra_free_if_not_null()`, calling
`coap_free_context()`/`coap_session_release()`/`coap_delete_optlist()`/`free()`
on garbage stack pointers. Reproduced live: a real timed-out verifier during a
multi-verifier sweep crashed the whole RP process with
`double free or corruption (out)` — happened in the very first live run this
session, before any other change, so pre-existing, not introduced by this
session's other edits. **Fixed** the same way this file's own convention
already handles `coap_context`/`coap_session`/`coap_options` (comment: *"set
variables here such that they are valid in case of a goto cleanup"*): hoisted
all four (`nonce_req_buf`, `res_buf`, and the three
`coap_*_verifier_appraisal` handles) to the top of the function, initialized
before any `goto cleanup` can fire.

**AK-certificate-rejection retry, implemented** (explicit ask: RP should call
`/certify_ak` both on first run with no cert *and* whenever a Verifier
rejects an existing one as invalid/expired, then retry `/appraise`):
- `verifier.c`'s `coap_appraise_handler()` now signals this case distinctly:
  when `attestation_result_ekak_rp` (Step 3a item 1, RP's own AK/EK check —
  chain validity *or* `is_ak_serial_currently_valid()`) is false, the
  response is `4.01 Unauthorized` with body `"RP AK certificate invalid or
  expired!"`, instead of the generic `2.05 Content` + `"Attestation failed!"`
  every other failure gets. Same response code `/certify_ak` itself already
  uses for a bad EK certificate — consistent "your credential, not your
  evidence, is the problem" signal.
- `relying_party.c`'s `coap_verifier_handler_appraisal()` checks
  `coap_pdu_get_code(received)` first: on `4.01`, sets a new per-verifier
  `rp_ak_cert_rejected[]` flag instead of parsing the body as pass/fail.
- `get_attestation_results_thread()`'s build-evidence → send → wait sequence
  is now a `for (attempt = 0; attempt < 2; ++attempt)` loop. On rejection
  (attempt 0 only), re-provisions before retrying: `invalidate_cached_rp_ak_certificate()`
  (new function — deletes the cached AK public/private/cert files and
  in-memory state, deliberately leaves the cached EK certificate alone since
  the EK itself didn't expire and `charra_rp_key_mgr_create_ek()` would just
  reproduce it identically anyway) followed by a fresh
  `ensure_rp_ak_certificate()` call.
- **Thundering-herd guard**: several verifier threads can discover a
  rejection at once (they share one Verifier-side CA and one
  `ak-provisioning-state.txt`, so one bad/expired cert is bad for all of
  them simultaneously). Naively re-provisioning per-thread would have each
  thread's renewal revoke the previous thread's freshly-issued cert (renewal
  semantics: issuing always revokes the prior record for the same EK — see
  "AK-provisioning state" above), so retries could livelock. Fixed with a
  single-flight pattern: a new `rp_ak_generation` counter (bumped once per
  actual re-provision) plus `rp_ak_reprovision_mutex`. Each attempt records
  the generation its evidence was built under; on rejection, a thread only
  performs the actual re-provisioning itself if the generation hasn't moved
  since — otherwise another thread already refreshed it, so this one just
  retries against the now-current cached identity. The same mutex also
  guards every read of `rp_ak_cert_der`/`rp_public_key_der` during evidence
  building, closing a data race against a concurrent re-provision freeing/
  replacing those buffers mid-read.
- Not yet exercised by a real rejection in a live run (Step 3a keeps passing
  on the first try once the nonce bug above was fixed, so the retry path
  hasn't fired) — logic verified by code review and successful compilation,
  not by observing an actual retry happen.

**Temporary: Verifier accepts an empty Attester AK certificate.** Step 3b
item 1 previously hard-failed every attestation once RP started forwarding a
real `msg_rp_appraisal_dto` (`ak_certificate_len == 0`, since the Attester
has no `/certify_ak` client yet — see "Still genuinely unbuilt" above) — by
design, correctly, per the spec. But that made it impossible to exercise
*anything* downstream of Step 3a live (Quote_a's own signature/nonce checks,
the full success path, this session's other fixes) since every single
attestation died at Step 3b no matter what. `coap_appraise_handler()` now
special-cases `res.ak_certificate_len == 0`: logs a loud
`charra_log_error()` (*"Attester's AK certificate is EMPTY — accepting
anyway (TEMPORARY: Attester AK provisioning is not implemented yet)"*) and
sets `attestation_result_ekak = true` instead of calling
`charra_crypto_verify_ekak_certificate()`. A non-empty certificate is still
validated normally (chain + key match + not expired/revoked) — this only
bypasses the "nothing was ever provisioned" case.

**Planned end state (as of 2026-08-14, not yet implemented): the Verifier is
*not* meant to grow its own independent Attester EK/AK check to replace this
bypass.** The intended final design has the RP perform EK/AK verification of
the Attester itself (mirroring how Verifiers currently validate the RP's own
AK cert), then forward a verified/not-verified signal to the Verifier(s),
who trust that the RP already did the check rather than re-validating the
Attester's certificate chain themselves. So this bypass's *current* form
(unconditionally accepting an empty cert with a loud warning) is still
wrong — nothing is checked by *either* party today — but the fix is
"RP gains a real EK/AK + `/certify_ak` client and does this check," not
"Verifier re-implements independent Attester-AK validation." Worth being
explicit about this because it's a deliberate trust-boundary shift: once
built, Verifier security for the Attester-identity leg becomes fully
dependent on the RP's honesty/correctness, with no independent check left on
that leg at all — a bigger concession than the shared-CA-key caveat noted
elsewhere in this doc, and one to keep in mind when reasoning about the
system's overall threat model. Tracked here specifically so the bypass isn't
mistaken for permanent behavior, and so the eventual fix isn't built in the
wrong place.

**Result**: with all of the above, a real live run produced
`ATTESTATION SUCCESSFUL` end to end — Attester's `Quote_a` (TPM + mbedTLS
signature checks, nonce check) and RP's `Quote_r` (signature, nonce, AK
certificate chain — all genuinely checked, not bypassed) all passing over
real CoAP, real TPM simulator crypto, a 4/5-verifier majority vote surviving
verifiers that timed out on `/nonce` without crashing (the double-free fix,
confirmed under the exact condition that used to trigger it) — the first
time this session's EK/AK work has been observed working as a whole, not
just in isolated unit tests.

**`.gitignore` updated**: RP's TPM identity cache (`rp-ek-certificate.der`,
`rp-ak-public.bin`, `rp-ak-private.bin`, `rp-ak-certificate.der`) and the
AK-provisioning ledger (`ak-provisioning-state.txt`, `.lock`) are
regenerated at runtime in the repo root (same convention as
`verifiers_config.txt`) — running the binaries from a checkout of this repo
(as opposed to some other working directory) writes them straight into the
working tree. Added to `.gitignore` alongside `bin/`/`obj/` so a stray
`git add -A` can't accidentally commit real (test) private key material.

**Still open after this session**: `relying_party.c`'s AK-cert-rejection
retry path is implemented but unexercised live (see above); the seven-bug
audit list above still has bugs 1/2/3/5/6 unfixed; the RP qualification
handshake's salted-redaction incompatibility (see its own entry above)
remains unfixed; the Attester still has no real AK (Step 3b's bypass above
is a stopgap, not a fix).

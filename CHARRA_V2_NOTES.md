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
| Verifier (new, passive) | `src/verifier.c` | 31415 | `nonce`, `appraise` | `durations_verifier.txt` |
| Verifier (old, active — baseline) | `src/verifier_old.c` | n/a (client) | — (calls Attester's `attest`) | `timings_verifier.txt` |
| Trust Manager | `src/trust_manager.c` | 6000 | `get_verifiers` | — |
| Relying Party | `src/relying_party.c` | n/a (client) | — (calls Trust Manager + Attester + each Verifier) | `timings_RP_multi_verifiers.txt` |

`start_verifiers.sh` spawns 5 `bin/verifier` instances on ports 5684–5693,
registered in `verifiers_config.txt` as `id ip port` rows that
`trust_manager.c` reads to resolve `get_verifiers` requests.

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

### Target design (agreed with supervisor)

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

- **Reference PCRs for the RP.** Checking `Quote_R.pcrDigest` needs known-good
  boot PCR values *for the RP machine* — a second reference file, distinct
  from any Attester reference PCRs. Same `charra_check_pcr_digest_against_reference()`
  machinery, pointed at the RP.
- **Which PCRs the RP quotes** — its boot PCRs 0-7 presumably; must match
  whatever the RP's reference file records.
- **AK provisioning**: Privacy CA issuing an AK cert, vs
  `TPM2_MakeCredential`/`ActivateCredential` challenge-response. Affects both
  Attester and RP.
- **Attester key is not currently an AK**: `charra_key_mgr.c:32` calls
  `tpm2_create_primary_key_rsa2048()`, a primary key on demand with no
  certification path. Needs replacing with a real persistent AK.
- **Manufacturer root CA trust store** — needed by whoever validates EK
  certs. No config, file, or loading code exists.
- **Whitelist/blacklist semantics**: deny-by-default (miss = fail) vs
  allow-by-default (miss = inconclusive); hard failure vs flag on a miss;
  reference hash list format/location.
- **Blind spot in the PCR10-based integrity check**: replay only folds
  entries tagged for the target PCR, so entries for *other* PCRs could be
  added/removed/altered without affecting `X`. Accepted if the check is
  scoped to PCR10 integrity only; a hash over the whole redacted buffer would
  close it.
- **No certificate handling exists yet** — no X.509 parsing, no chain
  validation, no EK/AK anywhere. All new.

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

#### Redaction rule for the SDK: blank `template_data` entirely (very simple, current choice)

No `ima-ng` sub-structure parsing (algorithm prefix / file hash / path
split) — the whole field becomes empty (`template_data_len = 0`, already a
tested, supported case per `test_empty_template_data`), then
`template_digest` is recomputed as `SHA256("")`.

Consequence worth being deliberate about: every redacted entry gets the
**same** recomputed digest, since they all hash identical (empty) content.
Fine for proving the mechanical pipeline (parse → transform → recompute →
re-serialize → replay) works end-to-end; not realistic, and the first thing
to revisit if this needs to look like genuine per-entry redaction later (e.g.
keep the file-hash portion, once appraisal is confirmed in scope).

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

### New: `tests/test_synth_log.c` — 13 assertions

Strongest check: feeds the generator's own output straight into
`charra_replay_ima_log()` and confirms it succeeds — cross-validating
against the already-proven replay function rather than asserting against
itself. Also: determinism (same seed → same bytes), different seeds diverge,
fabricated sensitive paths are actually present in the raw output, bad
arguments rejected.

**Both suites: 42/42 passing.** Run with `make test`.

### Modified: `Makefile`

- `charra_event_log`, `charra_synthetic_log` added to the `core` object list.
- `test`, `test_event_log`, `test_synth_log` targets added.

### Verified so far

- `charra_event_log.c` and `charra_synthetic_log.c` compiled standalone (stub
  TSS2/mbedTLS headers, real SHA-256 via CommonCrypto); all 42 tests pass.
- Cross-checked `charra_replay_ima_log` against an independent Python
  re-implementation on a 423-byte 4-entry log: both produce
  `0269fe49...2b49efd` for PCR10, byte for byte.
- Raw vs. redacted log (different paths, 153 vs 140 bytes) replay to the
  same PCR10, confirming redaction of `template_data` does not disturb the
  chain.
- **Not yet compiled** against real TSS2/libcoap/QCBOR headers — none
  available on this dev machine (macOS, no local TSS2/mbedTLS install).
  Needs a first `make` in the Docker/Linux build to confirm.

### Not yet built (tracked here so nothing gets lost between sessions)

- The SDK's actual redaction step as real code (rule is decided — blank
  `template_data`, recompute digest — but not yet implemented as a callable
  function)
- The two new CoAP endpoints for the qualification handshake
  (`/qualify`-style request, `/qualify/submit`-style response)
- `rp_qualification_state` struct + the comparison function
- The gate added to `coap_appraise_handler` (`qualified && !expired`)
- RP-side: EK/AK validation of the Attester, real redaction, Quote_R
  generation — all per the Part 2 design, none of it started
- Verifier-side: EK/AK validation of the RP, Quote_R verification,
  file_hash whitelist/blacklist pass
- Real AK provisioning for both Attester and RP (currently: neither has one)
- Manufacturer root CA trust store

### Bugs found during audit of `verifier.c` (2026 audit, not yet fixed)

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
   Outside `verifier.c` but directly consumes its output.

None of these fixed yet; flagging here so they aren't lost.

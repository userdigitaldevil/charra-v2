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
    `nonce`, `appraise`, `certify_ak`, `qualify` + `qualify_submit`, meant
    to be called by an orchestrator. Logs per-step timing to
    `durations_verifier-<port>.txt` (per port, appended).
- **Trust Manager** (`src/trust_manager.c`, :6000) — new role, the poster's
  "Verifier Manager." Resource `get_verifiers`: takes a list of verifier
  IDs, resolves them to `{ip, port}` via `verifiers_config.txt`. Pure
  directory/lookup service, not a reference-value/endorsement provider
  despite RATS terminology.
- **Relying Party** (`src/relying_party.c`) — new orchestrator. Flow: ask
  Trust Manager to resolve N verifiers → get evidence from the Attester
  **once** → fan the same evidence out to all N verifiers in parallel
  (pthreads) → majority vote (`2*num_true > num_verifiers`) on the
  aggregate result. Runs that cycle in a **loop by default** (daemon mode:
  attest, renew qualification if it is near expiry, sleep `--interval`,
  repeat until SIGINT); `--benchmark` selects the bounded 1→5-verifier
  timing sweep (`NUM_RUNS = 5` measured cycles per step, after one discarded
  warm-up; writes `timings_RP_multi_verifiers.txt`)
  and exits instead. **Also acts as the privacy-preserving proxy** — see
  Part 2.

Wire protocol: CoAP (UDP, optional DTLS-PSK/RPK) + CBOR (QCBOR), DTOs in
`src/core/charra_dto.h`, encode/decode in `src/core/charra_marshaling.c`,
plain positional arrays (no maps/labels) — field order is load-bearing,
defined only by struct order, no schema self-description on the wire.

### Component reference table

| Role | File | Port | CoAP resource(s) | Timing log |
|---|---|---|---|---|
| Attester | `src/attester.c` | 5683 | `attest`, `certify_ak_of_attester` (both FETCH) | `timings_attester.txt` |
| Verifier (new, passive) | `src/verifier.c` | 31415 | `nonce`, `appraise`, `certify_ak`, `qualify`, `qualify_submit` | `durations_verifier-<port>.txt` |
| Verifier (old, active — baseline) | `src/verifier_old.c` | n/a (client) | — (calls Attester's `attest`) | `timings_verifier.txt` (no reader since `timing_atomic.py` was removed) |
| Trust Manager | `src/trust_manager.c` | 6000 | `get_verifiers` | — |
| Relying Party | `src/relying_party.c` | n/a (client) | — (calls Trust Manager + Attester + each Verifier) | `timings_RP_multi_verifiers.txt` (`--benchmark` only) |

`start_verifiers.sh` spawns 5 `bin/verifier` instances on ports 5684–5693,
registered in `verifiers_config.txt` as `id ip port` rows that
`trust_manager.c` reads to resolve `get_verifiers` requests.

Each Verifier port keeps its own state tree under `state/verifier/` — see
"`state/` layout (final form)" in Part 3 for the full layout.

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
  `num_used_verifiers` variable — no longer exists under that name, but the
  capability is back: `--verifiers COUNT` sets how many Verifiers each
  daemon-mode cycle uses. Only `--benchmark` still hardcodes the 1→5 sweep
  (at `NUM_RUNS = 5`, not the manual's 10).
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

**Both of Step 2a's spec obligations that were previously partial are now
built.** Item 6 checks a real whitelist/blacklist *policy*
(`charra_verify_log_file_hashes_against_policy()`): the blacklist is an
explicit deny checked first, the whitelist is default-deny but only once it
has entries — an empty one falls back to allow-by-default, since strict
default-deny against the currently-empty `whitelist-hashes.txt` would reject
every attestation on a fresh checkout, which reads as a bug and gets worked
around. Under default-deny an unreadable or non-SHA-256 digest is rejected
rather than skipped. The mode in force is logged, so "passed" is never
ambiguous between *checked and fine* and *nothing to check against*.
And Step 2a's `-> fail: negative proof to Attester` branch exists: the new
`/attest_result` resource carries RP's verdict back
(`msg_attestation_result_dto`). It needs to be a separate RP-initiated
request because the Attester is the *server* of `/attest` — its evidence is
the last message of that exchange, so unlike Steps 3a/3b there is no reply
slot to reject it in. RP sends it from `get_evidence()` after the CoAP loop,
never from inside the response handler (that would re-enter libcoap
mid-dispatch). Advisory only: nothing downstream depends on it, but a
rejected device can now log/alert/re-measure instead of assuming success.

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

#### Beyond the spec: the full current request flow

The diagram above lists the two evidence exchanges (Attester→RP, RP→
Verifier) and nothing else — it's silent on freshness (how a nonce
actually gets to each party) and identity (how EK/AK certificates come to
exist and stay revocable). Those aren't optional extras this fork bolted
on for fun: Step 2a item 3 ("check nonce consistency") and Step 3a/3b item
1 ("validate EK/AK certificate") don't work at all without them — the spec
assumes a live nonce and a valid, checkable certificate already exist.
Four resources exist purely to make that true: `/nonce`, `/qualify`
(+`/qualify/submit`), `/certify_ak`, `/certify_ak_of_attester`. None of the
four appear in the spec text above.

RP is the sole active party throughout this whole flow — Attester and
every Verifier are pure passive responders, never initiating anything
themselves (see "Decided" note under `/certify_ak_of_attester`). The
actual order `run_one_attestation_cycle()` runs things in, for one cycle
(daemon mode repeats this on a timer — see "RP daemon mode" below):

1. **`/get_verifiers` (Trust Manager)** — resolve this round's Verifier
   IDs to IP/port (`get_verifiers()`). A static config lookup, nothing
   cryptographic.
2. **Attester identity provisioning, once ever** —
   `ensure_attester_identity_provisioned()`: FETCH the Attester's EK
   cert/AK public key/AK name, validate the EK chain locally, sign +
   deliver an AK certificate under RP's own CA (DELIVER_RP). Gated by a
   cache file; every call after the first no-ops. (The Verifier-CA leg is
   deferred to step 4's per-Verifier phase — see "RP AK certification is
   now independent per-Verifier" / "`/certify_ak_of_attester`" above.)
3. **`/attest` (Attester)** — `get_evidence()`: RP generates its own nonce
   + PCR selection, sends one request, gets back `Evidence_a` (`Quote_a`,
   raw `log_a`, the Attester's evidence). The instant the response lands,
   RP runs **Step 2a** entirely locally against the *raw* log
   (`charra_rp_appraise_evidence()`): validate the Attester's RP-issued AK
   cert, verify `Quote_a`'s signature, check nonce freshness, recompute
   each log entry's template hash, recompute the PCR digest and compare,
   check file hashes against the blacklist. Any failure here is a hard
   stop — nothing gets forwarded to any Verifier.
4. **`get_attestation_results(num_verifiers)`** — shared setup, then
   per-Verifier work:
   - **Step 2b, once**: `charra_rp_prepare_evidence()` — redact `log_a`
     into `log_r` (the SDK), recompute the PCR digest from the redacted
     log, sign `Quote_r` under RP's own AK. Done once, not per-Verifier:
     redaction uses fresh randomness, and every Verifier this round must
     see the *same* `log_r`.
   - **`/qualify` + `/qualify/submit`, once**: against whichever Verifier
     answers first — the qualification ledger is shared across every
     Verifier, so one answer counts for all of them. Hard gate: nobody
     qualified means the cycle aborts before any per-Verifier thread
     starts.
   - **One thread per Verifier**, each independently:
     1. `ensure_rp_ak_certificate(i)` — RP's own AK cert with Verifier
        `i` (cached after the first time; `/certify_ak` CHALLENGE/CONFIRM
        if not).
     2. `ensure_attester_identity_certified_by_verifier(i)` — the
        Attester's AK cert issued by Verifier `i`'s *own* CA (cached
        after the first time; `/certify_ak` CHALLENGE relayed through
        `/certify_ak_of_attester` ACTIVATE, then CONFIRM, if not).
     3. **`/nonce` (Verifier `i`)** — a genuinely Verifier-`i`-generated
        freshness value, independent of every other Verifier's own nonce
        and of the nonce RP gave the Attester in step 3 (each
        `bin/verifier` process has its own RNG state; nothing shared).
     4. Build Verifier `i`'s own evidence message: `Quote_r` (signed over
        `PCR_r || Verifier i's nonce`), RP's cert for Verifier `i`,
        `log_r`, the Attester's nonce/`Quote_a`/signature/public key, and
        both Attester AK certs (RP-issued, and Verifier `i`'s own
        issuance).
     5. **`/appraise` (Verifier `i`)** — the first and only point
        `/appraise` gets called, once per Verifier, near the end of the
        cycle, not the start. Runs **Step 3a** (`Evidence_r`: RP's AK cert
        against Verifier `i`'s own CA + RP's qualification, `Quote_r`
        signature, nonce) **and Step 3b** (`Evidence_a'`: Attester's cert
        against Verifier `i`'s own CA, `Quote_a` signature, nonce). Both
        run unconditionally — see "Verifier verdicts" below for why the
        3a→3b gate was removed.
     6. Any failed check is a NO vote. No retry, and no out-of-band status
        telling RP which remedy to attempt.
5. Threads join; RP tallies pass/fail per Verifier into a majority vote
   and prints the run summary.

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
- **Certificate renewal is expiry-driven, on all three certificates.** Each
  disk cache is re-provisioned once it is within `--ak-renew-margin`
  (RP-side, default one day) of expiring, the same "renew while the
  current grant is still good" rule the qualification refresh margin uses:
  RP's own AK certificate per Verifier (`/certify_ak`), and the Attester's
  AK certificate as issued by RP's CA and by each Verifier's CA
  (`/certify_ak_of_attester`). This is not optional tidiness. The caches
  were keyed purely on the file existing, and a Verifier gives no distinct
  signal for a stale certificate — it just votes NO — so an expired
  certificate would be resent and rejected every cycle forever, with
  nothing to break the loop but deleting `state/` by hand. Masked today by
  the ten-year defaults; reachable the moment `--ak-validity` or
  `--attester-ak-validity` is shortened.
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

- ~~**Attester key is not currently an AK**~~ **— resolved.** The Attester
  now has a real, persistent EK+AK (`ensure_attester_ak_keypair()`,
  mirroring RP's), certified by RP's own CA *and* independently by every
  Verifier's CA via the RP-relayed `/certify_ak_of_attester` flow. The
  `"TEMPORARY"` accept-an-empty-certificate bypass is gone from
  `verifier.c` (`grep -c TEMPORARY src/verifier.c` → 0): Step 3b now fails
  closed on a missing certificate, chain-checks the one it gets, **and**
  cross-checks the serial against that Verifier's own issuance ledger. See
  "`/certify_ak_of_attester`" and "Per-Verifier CA keys" above.
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
| `charra_verify_log_entries_self_consistent` | Step 2a item 4: per entry, `template_digest == SHA256(template_data)`. Catches internal malformation, not content honesty. |
| `charra_verify_log_matches_quote_pcr_digest` | Step 2a item 5: replays the log, checks the result against a quote's `pcrDigest`. Generic to any single-PCR-selection quote, not specific to `Quote_r` (renamed from `_quote_r_pcr` — see the 2026-08-17 update below). |
| `charra_verify_log_file_hashes_not_blacklisted` | Step 2a item 6: default-deny — a digest matching neither list fails, same as an explicit blacklist match. Paths are function parameters, not globals. Reads the file-content digest from the redacted `template_data`'s known layout. Renamed from `_against_policy` — see the 2026-08-17 update below. |
| `compare_hashes` / `load_hash_list` / `hash_list_contains` *(static)* | `qsort`/`bsearch`-based membership check against a `whitelist-hashes.txt`/`blacklist-hashes.txt`-shaped file. |

**Status**: built, unit-tested indirectly. Wiring into `relying_party.c`'s
actual Step 2a flow was open when this was written; done since — see the
2026-08-17 update further below (`charra_rp_appraise_evidence()`).

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
`durations_verifier-<port>.txt` (load/verify/nonce/PCR measured separately) into
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
`CHARRA_RC` inside each function) is behavior-preserving. That reasoning
turned out to hold for *every* write to it: the later verifier-folder audit
found `attestation_rc` was write-only across the whole Verifier binary — a
leftover from `verifier_old.c`, where `main()` genuinely did read it as the
process exit status. It has since been deleted along with its 14 assignments
in `coap_appraise_handler`. Verified: clean
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
The ledger path (a `verifier.c` static, now `rp_ak_state_file_path`)
became an explicit first parameter, matching every other
`charra_ak_state_*` function's signature.

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
1890 to 1725 lines. The remaining bulk was the five CoAP resource handlers
themselves, since split out — see below.

### `relying_party.c` and `verifier.c` split into per-role module folders

Both entry points now hold only their globals, `main()`, and the signal
handler; everything else lives in a folder named for that role.
`relying_party.c` went 4808 → 750 lines across `src/rp/` (attestation,
attester_identity, identity, evidence, qualification, config, coap, stats),
and `verifier.c` 2231 → 450 across `src/verifier/`:

| Module | Holds |
|---|---|
| `verifier_appraise.c` | `coap_appraise_handler` (Steps 3a + 3b) |
| `verifier_nonce.c` | `coap_nonce_handler` |
| `verifier_certify_ak.c` | both `/certify_ak` legs + the pending-challenge table |
| `verifier_qualify.c` | `/qualify` and `/qualify_submit` |
| `verifier_util.c` | `hex_prefix`, `release_response_data` |

**On the globals.** An earlier note argued the handlers couldn't be split
because they're coupled to ~20 file-scope statics. That coupling is real,
but it doesn't actually block the split: `verifier_shared.h` declares what
crosses module boundaries, which is enough for the moved code to compile
unchanged. Threading a context struct through every handler was never a
prerequisite — it's a separate, larger job, and the one that would actually
lift the "one attestation round in flight per Verifier" limit those globals
impose. `src/rp/rp_shared.h` does the same.

Each item is now *defined by the module that produces it*, not parked in
`verifier.c`: `last_request` and `verifier_challenge_nonce` in
`verifier_nonce.c` (issued by `/nonce`, consumed by `/appraise`), the
outstanding `qualification_state` and `CHARRA_RP_QUALIFICATION_NUM_ENTRIES`
in `verifier_qualify.c`, `attestation_round_counter` in `verifier_nonce.c`.
Anything a single module owns end to end is `static` there and absent from
`verifier_shared.h` entirely — so the header now lists only genuine
cross-module state plus the paths `main()` finalizes once `--port` is known.
`verifier.c` keeps configuration and `main()`, which is all an entry point
should hold.

Both folders are wired through their own `$(RP_OBJECTS)`/
`$(VERIFIER_OBJECTS)` lists rather than `$(OBJECTS)`, which links into all
five binaries — the Attester and Trust Manager have no business pulling in
Verifier state.

**The splits were mechanical, and verified as such**: every moved body was
diffed against the original and confirmed byte-identical modulo the removed
`static`, and `nm -g` checked for symbol collisions with the shared
modules. This matters because a refactor that silently changes behavior is
much worse than one that fails to build.

**The RP split exposed a real pre-existing race.**
`processing_nonce_response` and `processing_appraisal_response` were single
globals shared by every Verifier thread, so one thread's response handler
could clear the flag another was waiting on; the woken thread then found no
nonce and reported `Verifier n° N did not supply a nonce` for a Verifier
that had in fact answered. Both are now `[MAX_VERIFIERS]` arrays indexed by
thread, matching `verifier_nonces[]` and `attestation_results[]`. The
pre-split code passed the same test 3/3 — that was luck, not correctness;
separate translation units changed the interleaving enough to surface it.

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

**Update (2026-08-17): everything below except the first bullet is now
built.** `relying_party.c`'s Step 2a/2b actually runs today —
`charra_rp_appraise_evidence()` calls `charra_verify_log_entries_self_consistent()`,
`charra_verify_log_matches_quote_pcr_digest()` (renamed from the
`_quote_r_pcr` name this paragraph originally used), and
`charra_verify_log_file_hashes_not_blacklisted()` (renamed from
`_against_policy`) against `log_a`, gated together into "RP Appraisal
Successful/Failed"; `charra_rp_prepare_evidence()` calls
`charra_sdk_redact_ima_log()` for real and builds `Quote_r`
(`charra_rp_build_evidence_message()`, RSA-PSS-signs `pcr_r ||
verifier_nonce` under the RP's TPM-resident AK). Confirmed live: every
`relying_party.log` from a live run shows "RP Appraisal Successful" and a
"RP Privacy Cleaning" block before evidence ever reaches a Verifier.

**Resolved (2026-08-17): `charra_rp_appraise_evidence()` now validates the
Attester's RP-issued AK certificate (Step 2a item 1).** Added as the new
first check, ahead of the quote-signature check (renumbering the rest):
`charra_crypto_verify_ekak_certificate()` — the same shared chain+key-match
helper the Verifier uses for its own Step 3a/3b item 1 — against
`res->ak_certificate_attester_by_rp`, `keys/rp-ca.crt`, and
`res->tpm2_public_key` (the key that actually signed `Quote_a`). Unlike the
Verifier-issued leg, RP also cross-checks the resulting serial against its
own issuance ledger (`charra_ak_state_check_serial_valid()` against
`attester_ak_state_file_path`) — RP signed this cert itself, so unlike the
Verifier it isn't blocked by the shared-CA-key/no-cross-instance-ledger
caveat noted elsewhere. Folded into `appraisal_ok` as a new `ekak_ok` gate;
an empty/unprovisioned certificate now fails appraisal outright instead of
silently passing. Confirmed live: 5/5 verifiers pass across a full 1-5
sweep with `"chain and key valid!"` + `"serial is currently valid"` logged
on every run. This closes the gap the `/certify_ak` section below tracks —
see the correction under its "Planned end state" note.

**Correction — the message-sending step below is done, but not via
`charra_marshal_rp_appraisal()`.** That DTO and its marshal/unmarshal pair
have since been **deleted** (along with `tests/test_rp_appraisal_
marshaling.c`): nothing outside `charra_marshaling.c` and that test ever
called them, so they were ~200 lines of maintained-but-unreachable code.
The section below is kept as design history. The design actually shipped as a leaner, separate DTO —
`msg_rp_evidence_dto`/`charra_marshal_rp_evidence()`/
`charra_unmarshal_rp_evidence()` — which `charra_rp_build_evidence_message()`
calls to send `Quote_r`+`log_r`+`Quote_a` onward, and which
`coap_appraise_handler()` (`verifier.c`) actually unmarshals. See "The real
RP→Verifier message shape" below for how the two DTOs relate — that
section documents `msg_rp_appraisal_dto`'s design as originally planned;
treat it as superseded background, not the current wire format.
**That gap is now closed**: `tests/test_rp_evidence_marshaling.c` (30
assertions) covers the message that actually travels on every `/appraise`,
which previously had no bounds test of its own — the only such test then
covered `msg_rp_appraisal_dto`, since deleted as dead code.
Round-trips all 12 fields; rejects an oversized `verifier_nonce`,
`rp_signature`, `rp_public_key`, `attester_nonce`, `attestation_data`,
`tpm2_signature` and `tpm2_public_key`; rejects a `pcr_r` that is either
too long *or* too short (it is the one field checked for an exact length
rather than a cap — a SHA-256 digest, so short is as wrong as long);
rejects a truncated array; and accepts the empty-certificate shape an
un-provisioned Attester legitimately produces.

### Step 3a/3b item 1: EK/AK certificate validation

Closes the last placeholder in `coap_appraise_handler` — the Verifier's
spec-mandated scope (Step 3a/3b, all three items) is fully implemented; the
remaining gap is entirely on the Attester/RP side.

**Check**: `charra_crypto_verify_ekak_certificate()` (`crypto_util.c`) —
combines chain verification + "cert's key matches the quote's signing key."
Called once for Step 3a item 1 (RP's cert against this instance's own
`keys/verifier-ca-<port>.crt`, folds into `step_3a_passed`) and once for
Step 3b item 1 (Attester's cert, only reached if Step 3a passed). Both
call sites originally duplicated this logic inline; factored into
`crypto_util.c` (not a new `core/` file — judged not worth fragmenting a
two-call combinator over a directory split). The trust anchor is read once,
shared by both checks — the same per-port CA `coap_certify_ak_handler`
itself signs with.

**Verified live** (via a temporary not-committed client minting two real AK
certificates directly with the Verifier's own CA key): with genuine
certificates, both checks log "valid!", ending in `ATTESTATION SUCCESSFUL`;
with RP's certificate tampered (one flipped byte), the chain check fails,
Step 3b is skipped entirely (early-exit gating holds), ending in
`ATTESTATION FAILED` with `Quote_a` never inspected — matching the spec's
early-exit wording.

**Reused by RP** for its own Step 2a item 1: same
`charra_crypto_verify_ekak_certificate()`, no new state needed — done as of
2026-08-17, see the "Resolved" note under the message-shape section further
below (`charra_rp_appraise_evidence()`).

### `/certify_ak` — Verifier-as-Privacy-CA AK issuance

Implements the Verifier-side half of AK provisioning: the Verifier merges
the Privacy CA role into itself (acceptable since this project's privacy
goal is hiding file paths, not device identity from the Verifier) and issues
AK certificates via standard TPM2 Credential Activation
(`TPM2_MakeCredential`/`ActivateCredential`), no separate manual CA
enrollment step.

**Now a two-leg challenge-response exchange** (CHALLENGE then CONFIRM) --
see "/certify_ak is now a two-leg handshake" below, which supersedes the
one-shot flow the rest of this entry describes.

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

**Reused by RP** for its own Step 2a item 1 (validate Attester's EK/AK):
`charra_crypto_verify_ekak_certificate()` takes no Verifier-specific state —
`crypto_util.o` is already in every binary's link. RP calls it exactly as
`coap_appraise_handler` does for Step 3a/3b item 1, but against its *own*
CA (`keys/rp-ca.crt`, not any Verifier's `keys/verifier-ca-<port>.crt`) —
see the "Resolved" note under the message-shape section further below. The issuance-side
functions (build-EK-template, sign-AK-cert, MakeCredential, AES-GCM
*encrypt*) stay Verifier-only; AES-GCM *decrypt* belongs to whichever party
requests certification.

**New TPM primitive** (`src/core/charra_key_mgr.h`/`.c`):
`charra_tpm_make_credential_for_ak()` wraps `Esys_MakeCredential` — loads the
requester's EK externally via `Esys_LoadExternal`, no Verifier TPM identity
needed. Trusts the caller-supplied AK name unverified — a wrong name just
fails the requester's own later `ActivateCredential`.

**Handler**: `coap_certify_ak_handler()` in `verifier.c`. Flow: unmarshal →
verify EK cert chains to `keys/manufacturer-root.crt` (else `4.01
Unauthorized`) → reconstruct EK `TPM2B_PUBLIC` → sign a fresh AK cert
(`"CN=CHARRA AK"`, issuer read from this instance's own
`keys/verifier-ca-<port>.crt` subject, fixed test-only validity
`2024`-`2034`) → fresh AES-256 key, AES-GCM-encrypt
the cert → `Esys_MakeCredential` to wrap that key → record the issuance
(`charra_ak_state_renew()`, revoking any previous record for this EK) →
marshal + send. The state-recording step deliberately happens only after
signing and `MakeCredential` both succeed, so a later failure can never
revoke a working certificate the requester never actually received.

**Test-only PKI** (`keys/gen-ak-pki.sh`, `keys/README.md`):
`verifier-ca-<port>.{key,crt}` (self-signed, one independent pair per port
in `verifiers_config.txt` — see "RP AK certification is now independent
per-Verifier" below), a synthetic `manufacturer-root.{key,crt}` standing
in for a real TPM manufacturer root, `rp-ek.{key,crt}`/
`attester-ek.{key,crt}` synthetic EK certs — plain openssl RSA keys, not
yet the TPM simulator's own endorsement hierarchy (tracked in "Not yet
built"). Certs are DER; keys stay PEM. **Those two static `*-ek.crt` files
are not what runs**: see the entry below.

#### All entities share one TPM, therefore one EK (PoC caveat)

Measured, not inferred: `openssl x509 -pubkey | sha256` over
`state/relying-party/identity/rp-ek-certificate.der` and
`state/attester/identity/attester-ek-certificate.der` gives the **same
digest** (`fbe2fd39…82b2`). Different subjects and serials, one identical
public key.

Why: `run_live_test.sh` starts a *single* container with a *single*
`tpm_server`, and `CHARRA_TCTI` is unset, so all eight processes (RP,
Attester, 5 Verifiers, Trust Manager) drive one simulated TPM. An EK is a
*primary* key — `Esys_CreatePrimary(ESYS_TR_RH_ENDORSEMENT, …)` derives it
deterministically from the endorsement seed plus template — so every entity
on that simulator derives bit-for-bit the same EK. Each then mints its own
EK certificate over that shared key (`charra_crypto_sign_ak_certificate(
ek_public, "CN=CHARRA RP EK (test only)", …, manufacturer_root_key_path…)`),
which is why the static `keys/*-ek.crt` pair (genuinely different keys)
never gets used for this and the runtime pair collides.

Consequences worth knowing before reading any live result as a security
claim:
- The AK-provisioning ledgers key on `SHA-256(EK certificate DER)`, and the
  two certificates differ, so the identities don't collide *in the ledger*.
  That is the only reason this works at all.
- `TPM2_MakeCredential` binds to **EK public + AK Name**. The EK half no
  longer separates RP from Attester here, so the **AK Name is carrying the
  entire weight** of identity separation. The AKs are genuinely distinct
  (separate `Esys_Create` calls, non-deterministic), so the proof still
  functions.
- Because one TPM can unwrap either AK blob, any process in the container
  that reads the other's `*-ak-private.bin` can impersonate it. **Identity
  separation in this testbed is filesystem permissions, not cryptography.**
- Both entities also hold `manufacturer-root.key` and self-sign their own
  EK certificates. In reality only the TPM vendor holds that key and the EK
  certificate ships with the device.

On real hardware all four collapse into real guarantees: distinct
endorsement seeds → distinct EKs → `MakeCredential` binds to one physical
device, AK blobs load only on their own TPM, and no host holds the
manufacturer key. Accepted for a PoC; **a passing attestation here does not
demonstrate device-identity binding.**

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

### `/certify_ak_of_attester` — Attester AK provisioning, RP-mediated

Closes the empty-AK-certificate gap: the Attester holds a real, persistent
AK identity, independently certified by RP's own CA (once) *and* by every
Verifier's own CA (once per Verifier, symmetric with how RP's own AK is
certified — see "RP AK certification is now independent per-Verifier"
below) — none of them trusting another's issuance. The Attester and every
Verifier stay fully passive throughout; only the RP initiates.

**Attester's identity**: dedicated EK (deterministic, mirrors
`ensure_rp_ak_keypair()`) + AK, both under `state/attester/`. The AK is
*restricted* (`charra_identity_key_mgr_create_restricted_ak()` —
RP's own `create_ak()` is deliberately unrestricted, see that module's
header) so it doubles as the real `Quote_a`-signing key
(`coap_attest_handler()` loads it instead of the old `"PK.RSA.default"`
key) — otherwise the certified key and the quoting key would be two
different keys, and Step 3b's cert-matches-quoting-key check could never
pass.

**`charra_rp_key_mgr` → `charra_identity_key_mgr`**: the module was
already fully generic (no RP-specific state), so it was renamed and
reused as-is by the Attester rather than duplicated.

**One Attester resource, `/certify_ak_of_attester`**, RP-initiated,
discriminated by a `kind` field (`FETCH` / `DELIVER_RP` / `ACTIVATE` /
`DELIVER_VERIFIER`) in `msg_certify_ak_of_attester_request_dto`:
- `FETCH`: Attester responds with EK cert + AK public key + AK name
  (`msg_ak_identity_response_dto`).
- `DELIVER_RP`: RP delivers a credential-wrapped, RP-CA-signed cert
  (reuses `msg_certify_ak_response_dto`'s shape); Attester unwraps via
  `ActivateCredential` + AES-GCM decrypt and persists it.
- `ACTIVATE`: RP relays a Verifier's `/certify_ak` CHALLENGE
  (`credential_blob`/`wrapped_secret`); Attester's `ActivateCredential`
  recovers the secret and returns it (`msg_activate_credential_response_
  dto`) for RP to relay onward as that Verifier's CONFIRM.
- `DELIVER_VERIFIER`: RP delivers the plaintext cert a Verifier released
  after CONFIRM succeeded — informational only for the Attester (see
  below), no unwrap needed since ACTIVATE already proved possession.

**RP side, two independent CA relationships**:
- **RP-CA leg** (`ensure_attester_identity_provisioned()`, runs once per
  process): FETCHes the identity, validates the Attester's EK chain itself
  (`manufacturer-root.crt`) as a hard local gate — aborts the whole cycle
  on failure — signs with RP's own CA keypair (`keys/rp-ca.{key,crt}`),
  wraps via `charra_tpm_make_credential_for_ak()`, records issuance in
  RP's own ledger (`state/relying-party/ak-provisioning/
  attester-ak-state.txt`), delivers.
  Also caches the fetched identity (`attester_identity_cached`, deep
  copy) for the per-Verifier leg below to reuse without re-FETCHing.
- **Verifier-CA leg** (`ensure_attester_identity_certified_by_verifier
  (verifier_index)`): runs the CHALLENGE/ACTIVATE/CONFIRM/DELIVER_VERIFIER
  sequence against `verifier_index`'s own `/certify_ak`, called once *per
  Verifier* from that Verifier's own thread in
  `get_attestation_results_thread()` — the exact same place and pattern
  `ensure_rp_ak_certificate(current_thread_index)` already uses for RP's
  own AK. Every Verifier now signs with its own CA key (see "RP AK
  certification is now independent per-Verifier" below), so this is
  genuinely independent per Verifier, not one issuance relayed to all:
  each result is cached both in memory
  (`attester_ak_cert_by_verifier_ready/_der/_der_len[MAX_VERIFIERS]`,
  mirroring `rp_ak_cert_ready/_der/_der_len`) and on disk
  (`state/relying-party/attester-ak-certificates/
  attester-ak-certificate-verifier-<port>.der`, mirroring
  `rp-ak-certificate-<port>.der`), and each Verifier records the issuance
  in its own ledger (`state/verifier/ak-provisioning/attester/
  attester-ak-provisioning-state-<port>.txt`). New mutex
  `attester_identity_relay_mutex`, held for the whole per-Verifier
  function body (unlike `rp_ak_reprovision_mutex`, which only wraps
  individual `/certify_ak` exchanges) — protects the Attester-relay round
  trips' shared response globals (`activate_credential_response` and
  friends) against concurrent Verifier threads. Held for the whole body,
  not just per-exchange, because there's no concurrency to preserve:
  `attester.c` has no threads of its own, so it serializes these requests
  regardless of how RP locks.

**`charra_rp_build_evidence_message()` substitutes its own cached
`attester_ak_cert_by_verifier_der[verifier_index]`** into each Verifier's
evidence, rather than forwarding whatever `msg_attestation_response_dto.
ak_certificate_attester_by_verifier` the Attester's own `/appraise`
response carries. RP already holds the authoritative plaintext copy from
its own CONFIRM exchange, and only RP knows which certificate belongs to
which Verifier now that there are N of them — not a trust shortcut, since
a certificate's validity depends only on its own CA signature, not on who
carried the bytes. This makes the Attester's own `DELIVER_VERIFIER`-leg
storage (a single file on the Attester's side) purely informational: still
delivered for the Attester's own records, but whichever Verifier's
certificate arrives *last* is simply what ends up there; nothing reads it
back for correctness, and `attester.c` needed no changes for this.

**Both certs reach the Verifier**: `msg_attestation_response_dto` and
`msg_rp_evidence_dto` each carry two fields —
`ak_certificate_attester_by_verifier` (what Step 3b actually checks,
against that Verifier's own CA) and `ak_certificate_attester_by_rp`
(forwarded to the Verifier but not independently validated there — it has
no reason to trust a CA it doesn't recognize; RP's own Step 2a validates
this one locally instead, see "Step 3a/3b item 1" above).

**Step 3b now also checks revocation.** The lookup used to be skipped
because a single relayed Verifier certified the Attester, so every other
Verifier's ledger had no record and the check would fail spuriously. Once
each Verifier began certifying the Attester under its own CA and recording
it in its own `attester/` ledger, that premise disappeared — the Verifier
appraising a certificate always has its own record of the serial in it. So
Step 3b item 1 now chain-checks *and* calls
`charra_ak_state_check_serial_valid(attester_ak_state_file_path, …)`,
symmetric with Step 3a item 1's RP check, and rejects a certificate that
chains correctly but was superseded by a later renewal.

**Verified live**: full 5-verifier sweep, all 5 Verifiers independently
issuing (and ledgering) their own distinct Attester certificate — 5
separate `attester-ak-certificate-verifier-<port>.der` files, 5 separate
`attester-ak-provisioning-state-<port>.txt` ledger entries, confirmed via
`openssl x509 -issuer` that each chains to a genuinely different CA
(`CN = CHARRA Verifier CA <port>`) — unanimous `Attestation successful by
majority vote! (5/5 Verifiers passed)`, `make test` all 11 suites passing
(0 failed). Marshaling coverage: `tests/test_certify_ak_of_attester_
marshaling.c` (24 assertions: round-trips for both DTOs, oversized/
wrong-size field rejection).

### Not yet built (tracked so nothing gets lost between sessions)

- ~~RP-side Step 2a + 2b of the DRA-TLS spec~~ **Done, as of 2026-08-17** —
  `relying_party.c` genuinely runs log self-consistency, PCR-digest replay,
  file-hash blacklist checks, real redaction, and `Quote_r` generation; see
  the corrected "Still genuinely unbuilt" entry under the message-shape
  section above (only the Attester EK/AK-validation piece remains open).
- ~~Real, persistent AK provisioning: RP has it, Attester does not~~ **Done,
  2026-08-17** — see "`/certify_ak_of_attester` — Attester AK provisioning,
  RP-mediated" below. The empty-AK-certificate bypass in
  `coap_appraise_handler()` is removed; Step 3b now genuinely checks the
  Attester's AK cert.
- Real (non-synthetic) EK certificates on the TPM simulator's actual
  endorsement hierarchy — `keys/gen-ak-pki.sh`'s EK certs are plain openssl
  keys today, not real TPM objects. Still accurate as of 2026-08-17.
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

**Superseded (2026-08-17): now deliberately SHARED across every Verifier,
not per-Verifier.** The "each Verifier independently assesses the RP's
redaction pipeline" reasoning above turned out not to require separate
files: `charra_qualification_state_renew()` only ever *appends*, never
revokes-on-write the way `charra_ak_state_renew()` does (that revoke step
is the actual reason AK certification has to stay per-Verifier-file —
concurrent Verifiers sharing one AK ledger would revoke each other's
freshly-issued certs), and `ek_fingerprint` was already Verifier-agnostic
(one RP EK/AK keypair, reused for every Verifier). So a single shared file,
written by concurrent Verifier processes and serialized by the `flock()`
already inside `_renew()`, is safe. Path is now
`state/verifier/qualification/rp-qualification-state.txt`, no port suffix
— qualifying with one Verifier now qualifies with all of them. RP side
(`relying_party.c`) changed to match: `rp_perform_qualification_handshake(
verifier_index)` became `rp_perform_qualification_handshake_once(
num_verifiers)`, run once per attestation cycle (before any per-Verifier
thread starts, not once per thread) against whichever Verifier is reachable
first, with `rp_qualified_until` and its on-disk cache collapsing from a
per-Verifier array/per-port file to a single scalar/file. AK certification
is untouched by this — still genuinely per-Verifier.

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
certificate, and so on. Fixed by making the ledger path (now
`rp_ak_state_file_path`) per-port too, same fix applied to
`qualification_state_file_path` at the time (since reverted for
qualification only — see "RP qualification is now identity-bound and
persisted" above; `rp_ak_state_file_path` stays per-port, that
revoke-on-write collision is still real for it).

**A pre-existing race surfaced by making this concurrent**: the shared
`certify_ak_response` global was safe under call-once-per-process but not
under N per-Verifier threads calling `/certify_ak` concurrently — each
unmarshal overwrote `.ak_certificate` (a heap pointer) without freeing the
previous value. Fixed with a snapshot-then-null-out pattern under
`rp_ak_reprovision_mutex`.

**The CA key itself is also independent per Verifier now.** Originally
every `bin/verifier` instance signed with one shared
`keys/verifier-ca.{key,crt}` — genuine key material shared across
"independent" Verifiers, despite the ledger and issuance already being
separate. `keys/gen-ak-pki.sh` now generates one CA keypair per port
listed in `verifiers_config.txt` (`verifier-ca-<port>.{key,crt}`), and
`verifier.c` computes its own `verifier_ca_cert_path`/`verifier_ca_key_
path` from `port` at startup, same mechanism as `rp_ak_state_file_path`.
A compromised or unavailable Verifier's CA no longer affects any other
Verifier's ability to issue or validate certificates — the same fix later
motivated making the Attester's own Verifier-CA certification per-Verifier
too (see `/certify_ak_of_attester` above): with a shared CA key, one
Verifier certifying the Attester was as good as all of them; with
independent keys, that becomes a single point of failure, so it's no
longer done that way either.

**Verified**: full suite, 0 regressions. Live 2-Verifier run (RP AK
independence): separate `.der` files, ledger entries share `ek_fingerprint`
but distinct serials, two separate `/certify_ak`→`ActivateCredential`→
decrypt sequences in the log. Live 5-Verifier run (independent CA keys):
`openssl x509 -issuer` on each Verifier-issued certificate confirmed 5
distinct issuers (`CN = CHARRA Verifier CA <port>`).

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
    verifier-<port>.lock
    ak-provisioning/
      rp/
        rp-ak-provisioning-state-<port>.txt(.lock)
      attester/
        attester-ak-provisioning-state-<port>.txt(.lock)
    qualification/
      rp-qualification-state.txt(.lock)
  relying-party/
    relying-party.lock
    identity/
      rp-ek-certificate.der
      rp-ak-public.bin
      rp-ak-private.bin
    ak-certificates/
      rp-ak-certificate-<port>.der
    qualification-cache/
      rp-qualification-until.txt
    attester-ak-certificates/
      attester-ak-certificate-rp.der
      attester-ak-certificate-verifier-<port>.der
    ak-provisioning/
      attester-ak-state.txt(.lock)
  attester/
    identity/
      attester-ek-certificate.der
      attester-ak-public.bin
      attester-ak-private.bin
    ak-certificates/
      attester-ak-certificate-rp.der
      attester-ak-certificate-verifier.der
```

Both `verifier.c`'s and `relying_party.c`'s `main()` `mkdir()` their own
side of the tree up front. Several fixed-size path buffers were bumped
(`char path[64]` → `char path[96]`) to fit the deeper nesting.
`.gitignore` collapsed to a single `state/` wholesale ignore. Verified live:
a full cold-start run (fresh TPM state, RP identity from scratch) with all
5 Verifier ports produced exactly this tree; full suite still passes.

**Extended since**: `verifier/ak-provisioning/` split into `rp/`/`attester/`
subdirectories (see "`/certify_ak_of_attester`" above) and `attester/` was
added as its own top-level owner once the Attester got a persistent
identity (same section). `verifier/qualification/` and `relying-party/
qualification-cache/` both dropped their `-<port>` suffix and became single
shared files (see "RP qualification is now identity-bound and persisted"
above). `relying-party/attester-ak-certificates/` gained one
`attester-ak-certificate-verifier-<port>.der` per Verifier once that leg
became per-Verifier too (see "RP AK certification is now independent
per-Verifier" above) — it used to be a single `attester-ak-certificate-
verifier.der`. `relying-party/attester-ak-state.txt` moved into its own
`relying-party/ak-provisioning/` subfolder, mirroring the Verifier side's
split between certificate-byte caches and issuance ledgers (RP is a CA for
the Attester's RP-issued leg, so it keeps a ledger the same way).

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
- **AK-certificate-rejection retry** — *since removed outright; see
  "Verifier verdicts" below. Kept as history.* On a Verifier's `4.01`
  response, `relying_party.c` set `rp_ak_cert_rejected[]`, and
  `get_attestation_results_thread()`'s build→send→wait sequence became a
  2-attempt loop that re-provisioned
  (`invalidate_cached_rp_ak_certificate()` + fresh
  `ensure_rp_ak_certificate()`) before retrying once. *(The single-flight
  thundering-herd guard originally needed here — `rp_ak_generation` +
  `rp_ak_reprovision_mutex` — was later deleted outright once "RP AK
  certification is now independent per-Verifier" made the shared-identity
  premise it protected against no longer true.)*
- **Temporary: Verifier accepts an empty Attester AK certificate.** *(Since
  removed — the Attester has a real certified AK now; Step 3b fails closed
  on an empty certificate. Kept here as history.)* Step 3b item 1 would
  otherwise have hard-failed every attestation (the Attester had no
  `/certify_ak` client yet), making it impossible to exercise anything
  downstream of Step 3a live, so `coap_appraise_handler()` special-cased
  `ak_certificate_len == 0`: logged a loud `"TEMPORARY"` warning and
  accepted. A non-empty certificate was still validated normally.

**Planned end state (not yet implemented, as of 2026-08-17): the Verifier
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

**Decided (2026-08-17): the Attester will never talk to a Verifier
directly, for `/certify_ak` or anything else.** When the Attester needs its
AK certified, it talks only to the RP — same as today (Attester is a pure
passive responder to the RP; it has no CoAP client logic of its own, no
knowledge of which Verifiers exist). **Implemented as `/certify_ak_of_
attester`, see that section above** — one correction from this original
plan: RP relays to only *one* Verifier, not each one, since all instances
share a single CA key (discovered during implementation, see that
section's own tradeoff note). This also sidesteps a problem direct-to-
-Verifier Attester calls would otherwise create: each Verifier is its own
independent CA, so an Attester with N Verifiers to satisfy would need N
certs from N different CAs; fanning that out itself would mean duplicating
the Trust-Manager-lookup-plus-per-Verifier-loop logic the RP already has.
Consequence worth being explicit about: this extends the RP's existing
trust role from "verifies the Attester's identity and forwards a signal"
(above) to "verifies the Attester's identity *and* is the one that obtains
its Verifier-facing credentials" — not a new category of trust, but the RP
now sits on both halves of the Attester-identity leg instead of one.

**Correction (2026-08-17): the "Planned end state" above did not ship as
signal-forwarding.** No verified/not-verified signal is forwarded from RP
to Verifier for the Attester's identity. Instead each party independently
validates the half it's the trust root for: RP validates
`ak_certificate_attester_by_rp` against its own CA
(`charra_rp_appraise_evidence()`, see the Step 2a section above), and each
Verifier independently validates `ak_certificate_attester_by_verifier`
against its own CA (Step 3b item 1). Simpler than signal-forwarding (no new
DTO field, no new trust-in-a-boolean issue), and matches
`ensure_attester_identity_certified()`'s own framing: "Two independent CAs
certify the Attester's AK identity, neither trusting the other's issuance."

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

Prompted by: *if the RP process is short-lived (back when `main()` only ran
the benchmark sweep and exited), is the qualification validity window
(24h at the time; 5 min by default now, and the Verifier's to set via
`--qualification-validity`) actually doing anything?* Answer: not by itself — the persisted expiry on
the Verifier side was real, but nothing on the RP side ever *acted* on
remaining validity; it re-ran the full `/qualify`+`/qualify_submit` round
trip unconditionally every cycle, both within and across process runs.
(The cache below is what made the window mean something; daemon mode later
built on it again — see "RP daemon mode" for the idle-window renewal that
keeps a near-expiry `/qualify` out of the attestation path entirely.)

**Fix, part 1 — RP-side cache**: originally
`rp_qualified_until[MAX_VERIFIERS]`, backed by a per-Verifier file
(`rp-qualification-until-<port>.txt`, one decimal Unix timestamp).
`rp_perform_qualification_handshake_once()` checks it first (re-checked
against the wall clock every call), short-circuiting to success when still
valid. *Both later collapsed to a single value and a single
`rp-qualification-until.txt`* once the Verifier-side ledger became shared
across instances — qualifying with one Verifier qualifies with all of them
— see "RP qualification is now identity-bound and persisted" below. The
deadline itself is no longer computed locally at all: the Verifier reports
it on the wire (see "RP daemon mode").

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

`.gitignore` updated for `rp-qualification-until-*.txt` at the time; now
moot — see "state/ layout (final form)" above, `.gitignore` ignores
`state/` wholesale.

### RP daemon mode

`relying_party.c`'s `main()` used to be only a benchmark harness: sweep
1→5 Verifiers, write `timings_RP_multi_verifiers.txt`, exit. That made the
qualification validity window largely theoretical — the process rarely
outlived one grant. RP now runs a real loop by default:

```
while (!quit) {
    run_one_attestation_cycle(--verifiers);
    stop if --cycles reached;
    idle_until = now + min(--interval, time left of --duration);
    while (now < idle_until) {                 /* the idle window */
        renew anything already inside its margin;
        sleep until min(idle_until, next renewal deadline);
    }
    stop if --duration elapsed;
}
```

`--benchmark` selects the original sweep instead (unchanged output, still
what `plot_multi_verifiers.py` reads). Both modes call the same
`run_one_attestation_cycle()`, so they cannot drift apart. `quit`/SIGINT
were already declared but never checked — dead code inherited from
upstream's own commented-out `TODO(any): Enable periodic attestations`
scaffold in `verifier.c`; now actually wired, and the sleep runs in
1-second steps so Ctrl+C responds within a second.

**Stopping it.** Unbounded by default. `--duration SECONDS` and
`--cycles COUNT` both bound the run and exit through *exactly* the same
path as a signal, so shutdown stays one code path rather than three; the
final log line reports which of the three ended it. The nap is clamped to
whatever remains of `--duration`, so `--duration 30 --interval 60` stops at
~30s instead of overshooting by a full interval, and `--cycles` is
evaluated after a completed cycle, so `--cycles 3` means three finished
attestations. **SIGTERM shares the SIGINT handler**: `timeout`,
`docker stop` and systemd all send SIGTERM, and without that they
hard-killed the process straight past the cleanup that releases the last
cycle's evidence buffers.

**Why no dedicated renewal thread**: renewal only matters *at attestation
time*, so doing it in the idle window between cycles is sufficient, and a
timer thread would add locking for no correctness gain. It runs *after* the
attestation rather than before, so a near-expiry renewal never lands inside
one.

**Renewal is deadline-driven, not tied to the loop cadence.** The idle
window computes when the next credential actually falls due
(`rp_next_renewal_due()` — the minimum of `rp_qualified_until` and every
certificate's recorded expiry, each less its margin), sleeps exactly that
long, renews whatever is due, then sleeps out the remainder against a
*fixed* `idle_until`, so the interval is preserved rather than extended.
Nothing is detected while asleep: every deadline is already held in memory,
so the wake time is arithmetic, not polling. `rp_renew_due_credentials()`
then sweeps all four credentials, but each `ensure_*` checks its own expiry
first and returns without I/O when it is not due — cheaper to ask
everything than to track which one caused the wake, and anything falling
due in the same second is picked up in one wake.

This replaced a check that ran *once per loop iteration*, which coupled the
margin to `--interval`: a margin shorter than the interval let the loop step
straight over the renewal window, and the work landed inside the next
attestation instead. Measured cost of that: **~+0.38s on a 0.65s appraisal
phase** (0.65s when the grant was live, 1.03s when it had to re-qualify
inline) — not a failure, since `get_attestation_results()` re-qualifies at
margin 0 and proceeds, but exactly the latency the margin exists to remove.
With the deadline-driven window the `margin > interval` bound is gone, along
with the startup warning that enforced it. Only `margin < validity` still
matters: a margin at or above the whole window is never satisfiable, so the
credential would be renewed continuously and its cache would stop meaning
anything.

**AK certificates renew in the idle window too**, not only inside a cycle.
Previously the only thing that ever renewed them was `ensure_*` running
mid-attestation, so certificate renewal *always* paid its cost inside the
measured path — the opposite of what the qualification margin was built to
achieve.

**One attempt per idle window.** If a renewal fails, the credential stays
due, so the recomputed deadline is in the past, the `due > now` guard fails,
and RP sleeps out the rest of the window rather than spinning. The retry
comes sooner than the next window anyway: the next cycle's own `ensure_*`
calls attempt it inline. If renewal never succeeds the credential genuinely
expires and the Verifier votes NO with a specific reason — fail-closed, not
silently accepted.

**The qualification window moved onto the wire.** It is the Verifier's
parameter — it is what stamps `expires_at` into its own ledger — so
`--qualification-validity` lives on `bin/verifier` alone. Previously
`/qualify/submit` answered with a bare status string, forcing RP to
*assume* the same compile-time constant to size its client-side cache: a
silent contract between two separate binaries. New
`msg_qualify_submit_response_dto` (`{qualified, expires_at}`, CBOR) carries
the granted deadline, RP uses it verbatim, and RP has no validity flag at
all. The human-readable message stayed, but only in the Verifier's log.

**AK certificate validity became a duration**, `--ak-validity` on the
Verifier (certificates it issues via `/certify_ak`) and
`--attester-ak-validity` on RP (the Attester certificate RP signs under its
own CA). These are independent — unlike the qualification window, an X.509
certificate carries its own `notAfter`, so consumers read the real value
and the two never need to agree. Both replaced the hardcoded absolute
`20240101000000`–`20340101000000` pair, which was wrong for a long-running
issuer: with a fixed `notAfter`, a certificate issued later simply lives
for less time. New `charra_crypto_format_utc_yyyymmddhhmmss()` (inverse of
the existing parser) formats `now`/`now + validity` at issuance.

**Daemon-safety fixes found while building this:**
- **Per-cycle leak**: `charra_unmarshal_attestation_response()` heap-
  allocates `event_log` plus both Attester AK certificates (~6 KB), and
  `last_response = res` overwrote the previous cycle's pointers wholesale.
  Harmless when the process exited immediately; ~8.6 MB/day at a 60s
  interval otherwise. Added `charra_free_attestation_response()`, called
  before the assignment and on the appraisal-failure path where `res`
  never reaches `last_response`.
- **`coap_cleanup()`** tears down libcoap's *global* state but was called
  per cycle from three places, including each Verifier thread. Now called
  once, at process exit.

**Leak-verified under valgrind**, since "it compiles and runs" says nothing
about a process meant to stay up for weeks: 111 cycles / 111 unanimous
votes / 11 qualification renewals at `--interval 1 --verifiers 2`, with
`definitely lost: 0, indirectly lost: 0, possibly lost: 0` — 75,055 allocs
against 75,050 frees over 30.4 MB churned, the 5-block difference being the
constant `still reachable` libcoap/OpenSSL globals rather than growth. The
same run before the `last_response` fix would have orphaned roughly 666 KB
(111 x ~6 KB). That run also reported `ERROR SUMMARY: 2 errors from
2 contexts`, which were worth chasing rather than dismissing as
not-a-leak: **uninitialised heap bytes were being transmitted.**
`Esys_TR_GetName()` initialises only the first `2 + size` bytes of the
68-byte `TPM2B_NAME` it allocates, but `attester.c` and `relying_party.c`
both copied the *whole* struct into their DTO, so ~34 bytes of stale heap
went onto the wire on every `/certify_ak` CHALLENGE and
`/certify_ak_of_attester` FETCH — valgrind caught it where libcoap read
those bytes building the PDU. A minor information-disclosure bug, not a
crash or a leak. Fixed by copying only the meaningful prefix and zeroing
the remainder; the field stays fixed-size, so the wire format is unchanged.
Re-verified: `ERROR SUMMARY: 0 errors from 0 contexts`, leak counts still
all zero, 3/3 votes.

**Verified live**: 7 daemon cycles, 7/7 unanimous votes, clean SIGINT
shutdown; with `bin/verifier --qualification-validity 90 --ak-validity 600`
and `bin/relying_party --interval 15 --qualify-renew-margin 40
--attester-ak-validity 900`, RP logged `90 second(s) from now, as granted
by this Verifier` (never the 300s default, confirming the value crosses the
wire), and `openssl x509 -dates` showed exactly 600s and 900s spans on the
two issued certificates. A logging bug surfaced here first: the "valid
until" line printed the compile-time constant rather than the granted
value, which looked exactly like the flag being ignored — the countdown
values (max 74s, not ~285s) are what showed the behaviour was already
correct.

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
  line per Verifier (`PASS`/`FAIL`, `AK cached`/`issued`, latency in ms,
  reason), plus the `log_r` redaction byte counts.

### `/certify_ak` is now a two-leg handshake: the requester must echo the secret back

**The bug this closes.** The one-shot exchange had the Verifier sign the
certificate, wrap the AES key via `MakeCredential`, **and call
`charra_ak_state_renew()` — which revokes the requester's previous
certificate** — all before sending the response, i.e. before it had any
evidence the requester could actually open it. The request itself carries
only the EK *certificate* (public data) plus the AK's public key/name;
nothing in it proves possession of the EK private key. So anyone holding a
copy of a legitimate EK certificate could send a `/certify_ak` request and
knock out that identity's working certificate, while being cryptographically
unable to read or use the replacement. A denial of service, not a theft --
confidentiality was never the weak part, `MakeCredential` covered that.

**The fix.** `/certify_ak` gained a `kind` discriminator
(`CHARRA_CERTIFY_AK_CHALLENGE` / `_CONFIRM`, `charra_dto.h`) and split in two:

- **CHALLENGE**: Verifier validates the EK chain, generates a random 32-byte
  secret, wraps it via `MakeCredential` against that EK/AK pair, returns only
  the wrapped secret. **Signs nothing, records nothing** -- an unanswered
  challenge leaves no trace.
- **CONFIRM**: requester echoes back the secret it recovered via
  `ActivateCredential`. Only a TPM genuinely holding that EK private key with
  that AK loaded can produce it. On a match the Verifier signs, calls
  `charra_ak_state_renew()`, and returns the certificate.

Every irreversible step now sits behind the proof.

**Pending-challenge state** (`certify_ak_pending[]`, `verifier.c`): keyed by
EK fingerprint, 60s TTL, 8 slots (the RP's own handshake and one relayed for
the Attester can overlap), in memory only -- a handshake spans seconds and a
restart mid-flight just means a retry. Lookups are **single-use**: a matching
entry is copied out and cleared, so neither a replay nor a retry after a
wrong guess can reuse it. The secret is compared in constant time.

**CONFIRM certifies the key bound into the CHALLENGE**, not one it re-supplies
-- `ak_public_key`/`ak_name` are deliberately absent from the CONFIRM leg, so
even a leaked secret can't be redirected onto a different key. CONFIRM also
needs no TPM at all (the proof was produced by the requester's), which removes
it from TPM-simulator contention entirely.

**The certificate now travels in the clear.** The AES-256-GCM wrapping (and
`aes_gcm_nonce`/`aes_gcm_tag`) is gone from `msg_certify_ak_response_dto`:
it only ever served as an *implicit* possession proof, which CONFIRM now
makes explicit. Keeping it would also have been self-defeating, since CONFIRM
puts that same secret on the wire. The certificate was never secret anyway --
identical bytes travel unencrypted in every later `/appraise`.

**Attester relay adapted.** Only the Attester's TPM can activate a challenge
meant for it, so `/certify_ak_of_attester` gained a fourth kind, `ACTIVATE`:
RP relays the Verifier's CHALLENGE, the Attester activates and returns the
secret (`msg_activate_credential_response_dto`), and the RP relays that as
the Verifier's CONFIRM. `DELIVER_VERIFIER` then carries a plaintext
certificate. `DELIVER_RP` is unchanged -- the RP is its own CA on that leg
and still uses the one-shot wrapped form, so the Attester's unwrap is what
proves possession there. Making that leg symmetrical is a follow-up.

**RP client**: `ensure_rp_ak_certificate()` now does CHALLENGE →
`ActivateCredential` → CONFIRM. The ~120 lines of inline CoAP boilerplate it
carried were replaced with the existing `rp_coap_fetch()` helper, wrapped in
a new `rp_certify_ak_exchange()` that preserves the established
"reprovision mutex, then TPM mutex, never nested" lock discipline.

**Verified**: all 11 suites pass (246 assertions; `test_certify_ak_marshaling`
20 → 29, covering the new `kind`/`secret` fields, the certificate-less
CHALLENGE response shape, and the ACTIVATE DTO). Live 1-through-5-verifier
sweep: unanimous `5/5 Verifiers passed`, zero `ERROR` lines across all eight
component logs, both identities (RP's own and the relayed Attester's) visible
completing CHALLENGE → CONFIRM in the Verifier log. A throwaway
(not-committed) client then confirmed the actual security property against a
live Verifier holding a valid certificate: an abandoned CHALLENGE, a CONFIRM
with a wrong secret (4.01), and a CONFIRM with no live challenge (4.01, also
proving single-use consumption) all left the AK-provisioning ledger
byte-identical -- nothing revoked.

### The multi-verifier sweep was measuring onboarding, not steady state — FIXED

`--benchmark` ran `NUM_RUNS = 1` cycle per Verifier count, which made every
published number wrong in the same direction, for a reason that is invisible
in the output.

`timing->appraisal` brackets `get_attestation_results()`, and inside that call
each per-Verifier thread runs `ensure_rp_ak_certificate()`. On a cold state
directory that is a full two-leg `/certify_ak` with credential activation. So
at step *k* of the sweep, Verifiers 1..*k*-1 are already certified but Verifier
*k* has never been seen — every sample was "*k*-1 steady-state appraisals plus
one onboarding", and the step-to-step delta read as per-Verifier scaling when
most of it was a one-off cost. With a single sample there was also nothing to
average, so `calculate_stats()` reported `stddev: 0.000000` throughout — an
error bar that was zero by construction, not by precision.

The sweep now runs **one discarded warm-up cycle per step, then `NUM_RUNS = 5`
measured cycles**. The warm-up is not thrown away: onboarding is the expensive
TPM path, so it is reported as its own `Onboarding …` lines rather than blended
into the averages. `plot_multi_verifiers.py` draws two panels from that —
steady state with real error bars, onboarding as a separate dashed series.

The correction is large enough to change the conclusion:

| Appraisal phase | 1 Verifier | 4 Verifiers | marginal cost |
|---|---|---|---|
| Old (blended, n=1) | 2.954s | 4.013s | ~0.35s/Verifier |
| New (steady state, n=5) | 0.646s | 2.583s | ~0.65s/Verifier |
| New (onboarding, one-off) | 2.881s | 3.969s | — |

The old curve understated the marginal cost of a Verifier by roughly half and
inflated the one-Verifier baseline more than fourfold — it was, in effect, a
plot of the onboarding panel. Steady state is now clean and very nearly linear
(0.646 / 1.273 / 1.931 / 2.583 / 3.211s for 1–5 Verifiers, stddev 0.006–0.021s
over 5 samples).

`get_evidence` shows the same artifact at step 1 only: 3.23s in the onboarding
cycle versus 0.38s steady, the difference being the Attester's one-time AK
provisioning, which the old sweep charged to the 1-Verifier measurement.

**Benchmarking rule this establishes:** wipe `state/` **and** `/tmp/NVChip`
together between whole sweeps and restart every daemon — never mid-sweep. The
RP holds its keypair, per-Verifier certificates and qualification grant in
memory, and both `verifier.c` and `relying_party.c` `mkdir()` their state
subtree once at startup, so `rm -rf state` under a running daemon deletes
directories it will never recreate. Within a sweep, adding a Verifier needs no
wipe — just the warm-up cycle above.

### `run_live_test.sh` — shared-mount guard, non-interactive use, contamination check

Three gaps closed after the shared-state investigation above:

- It removed a leftover container named `charra`, but nothing stopped a
  container under **any other name** from having this checkout mounted — the
  exact situation that caused the ledger-revocation failure. It now enumerates
  running containers, compares each one's mount sources against `$PWD`, and
  refuses with the offending container names and a ready-to-paste
  `docker stop` line.
- `docker run -it` fails outright without a terminal, so the script could not
  run from CI or a non-interactive shell. `-t` is now added only when
  `[ -t 0 ]`.
- After the sweep it checks every log for NUL padding (`wc -c` versus
  `tr -d '\0' | wc -c`) and warns that the run is contaminated. That is the
  fingerprint of two processes sharing one log file, and it is worth failing
  loudly on rather than letting the timings look trustworthy.

### One state directory, many owners — the "intermittent 0/2 cycle" failure, FIXED

A long-standing intermittent failure: a clean RP would pass two or three
cycles, then **every** Verifier would reject a cycle at once, with the same
four reasons — RP AK certificate `REVOKED or EXPIRED in this Verifier's
ledger`, qualification `NOT EVALUATED`, `Quote_r signature MISMATCH`, and the
Attester's AK certificate `WRONG`. It reproduced roughly one run in three to
five and resisted several rounds of diagnosis, because every one of those
reasons points at the RP's credentials and none of them point at the actual
cause.

**Root cause: nothing stopped two instances from owning one `state/` tree.**
Three abandoned Docker containers from earlier experiments were still running,
each bind-mounting the same host checkout at `/home/bob/charra`, each with its
own `tpm_server`, Verifiers on ports 5684/5685, and a long-running
`relying_party` — twelve processes sharing one `state/` and one `logs/`. Every
one of those RPs periodically re-certifies its AK, and
`charra_ak_state_renew()` deliberately **revokes any existing record for the
same EK fingerprint** before appending the new one. So each RP's provisioning
silently revoked the others' certificates in the shared per-port ledger, and
each one's cache writes left the others presenting a certificate that no
longer matched the key they signed `Quote_r` with. Both halves of the symptom,
from one cause.

Two artifacts in the captured logs identify this unambiguously, and are worth
knowing as fingerprints of the general condition:

- **NUL padding.** `logs/FAIL-v5684.log` was 110 855 bytes on disk but only
  15 742 bytes of text — the rest NUL. That hole is what a file looks like
  when one process truncates it while another still holds a descriptor at a
  large offset: two writers, one path.
- **A discontinuous round counter.** `attestation_round_counter` increments
  once per `/nonce`, in the same statement that prints the delimiter, so the
  banners cannot skip. The log showed rounds 1, 2, then **15**, against
  exactly three `/nonce` requests — the file was interleaving two Verifier
  processes.

**Fix: `charra_io_lock_state_dir()` (`src/util/io_util.h`/`.c`)**, called from
both `main()`s right after the `mkdir()` block. RP takes
`state/relying-party/relying-party.lock`; each Verifier takes a **per-port**
`state/verifier/verifier-<port>.lock`, matching the granularity of the ledgers
it guards — two Verifiers on different ports are *meant* to share
`state/verifier/`, two on the same port are two owners of one ledger. A second
instance now refuses to start and names the holder rather than corrupting it.

It deliberately does **not** use `flock()`, and this is the point worth
remembering: **`flock()` is silently a no-op on the macOS Docker bind mount.**
Measured directly — two processes locking the same file under
`/home/bob/charra` both got `ACQUIRED`, while the identical test on the
container's own filesystem correctly returned `EWOULDBLOCK`. A `flock`-based
guard would have been inert in precisely the environment that produced the
bug. The lock is an atomic `open(O_RDWR|O_CREAT|O_EXCL)` holding
`"<pid> <hostname>"`, removed via `atexit()` on normal exit, and reclaimed
automatically when it names a PID **on this host** that no longer exists.
Cross-host staleness is deliberately not auto-reclaimed — PIDs are
per-namespace, so a PID from another container may well be live here by
coincidence — so that case prints the path and asks for a manual delete.

**Known consequence, not fixed here:** `charra_ak_state_renew()` and
`charra_qualification_state_*` serialise their read-modify-write cycles with
`flock()` on a `<file>.lock` companion, and by the same measurement those are
inert under the dev environment's bind mount too. The startup lock makes it
moot in practice (single owner per ledger, and each owner serialises its own
threads), but the ledger-level guard is weaker than it reads.

**Verified:** the lock refuses a second RP, refuses a second Verifier on the
same port, allows a Verifier on a different port, releases on normal exit, and
reclaims a lock left by a `SIGKILL`ed instance. With the stray containers
stopped, six consecutive isolated runs of
`bin/relying_party --verifiers 2 --interval 60 --qualify-renew-margin 30
--duration 250` passed all 4 cycles each — 24 for 24, with no failed
majorities, no Verifier NO votes, and no NUL-padded logs.

The reproduction harness itself needs the TPM simulator reset per run
(`rm -f /tmp/NVChip`, restart `tpm_server`, `tpm2_startup --clear`), exactly as
`run_live_test.sh` does: `state/` is meaningless against a re-randomized TPM,
and a simulator left running across repeated `SIGKILL`s degrades into
`the Attester's public key could not be loaded into the TPM (Step 3b item 2)`
— a failure that looks like an appraisal bug and is not one.

**Debugging note that cost the most time here:** a false vote is logged by
`coap_verifier_handler_appraisal()` at INFO (`] False`), not ERROR. Grepping
only for `ERROR` returns nothing and reads as "clean run". Grep for `] False`
and `Voting NO`.

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

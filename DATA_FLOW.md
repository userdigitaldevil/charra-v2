# CHARRA-v2 — Data Flow

What actually moves between the four processes, and what each one does with
it internally. Four flows, each given twice: a **high-level** pass (who talks
to whom, in what order, and why) and a **low-level** pass (functions, wire
fields, TPM calls, files touched).

Companion docs: `CLI_GUIDE.md` (how to run it), `CHARRA_V2_NOTES.md` (why the
design is shaped this way).

---

## Cast and vocabulary

| Party | Binary | Role in data flow |
|---|---|---|
| **Attester** | `bin/attester` | Produces `Quote_a` + raw IMA log (`log_a`). Pure responder |
| **RP** | `bin/relying_party` | The only party that initiates anything. Appraises `log_a`, redacts it to `log_r`, produces `Quote_r`, and vouches for its own appraisal/cleaning code via a simulated TEE |
| **Verifier** ×N | `bin/verifier` | Appraises what RP forwards. Pure responder |
| **Trust Manager** | `bin/trust_manager` | ID → `ip:port` lookup. Pure responder |

| Term | Meaning |
|---|---|
| `Quote_a` | Attester's TPM quote: `attestation_data` + `tpm2_signature` + `tpm2_public_key` |
| `log_a` | Attester's **raw** IMA event log — real file paths. Never leaves the RP |
| `log_r` | The redacted log. Each entry's path replaced by `SHA256(salt‖path)` |
| `PCR_r` | The composite digest inside `Quote_r` — a genuine TPM2_Quote over the PCR the RP replayed `log_r` into (`RP_REPLAY_PCR_INDEX`, see `rp_signing_key.h`), not a software-only computation |
| `Quote_r` | A genuine `TPM2_Quote`, signed by RP's TPM-resident (unrestricted) signing key, with `extraData` = `verifier_nonce` and `pcrDigest` = `PCR_r` |
| trust anchor | `keys/trusted_keys.txt` — the flat file of PEM public keys every role checks a signing key against. See `charra_trusted_keys.h`. There is no certificate, no CA and no ledger anywhere in this system any more |

**One structural fact drives everything below:** every exchange is
RP-initiated CoAP FETCH with a CBOR body. The Attester and Verifiers never
open outbound sessions, so anything that looks like "the Attester asks the
Verifier" is really the RP relaying in both directions.

---

# 1. The attestation cycle

## 1.1 High level

```
                    ┌─────────────────┐
                    │  Trust Manager  │
                    └────────▲────────┘
                       ① IDs │ ip:port
                             │
┌──────────┐   ② /attest   ┌─┴────────┐  ④ /nonce  ┌────────────┐
│ Attester ├──────────────►│    RP    ├───────────►│ Verifier 1 │
│          │◄──────────────┤          │◄───────────┤            │
└──────────┘  Quote_a,log_a│          │  nonce_v   └────────────┘
                           │  ③ Step  │  ⑤ /appraise    ...  ×N
                           │  2a + 2b │───────────►┌────────────┐
                           └──────────┘◄───────────┤ Verifier N │
                              ⑥ vote    pass/fail  └────────────┘
```

① **Resolve.** RP asks the Trust Manager to turn Verifier IDs `1..N` into
endpoints.

② **Collect.** RP generates a 20-byte nonce and FETCHes `/attest`. The
Attester quotes its PCRs with that nonce as `qualifyingData`, under a
signing key derived fresh from its TPM every call, and returns `Quote_a`
plus the raw `log_a`.

③ **Appraise, then cleanse — the heart of the design.** RP runs the full
six-check Step 2a gate against the *raw* log, then Step 2b redacts it and
replays the result into its own TPM. This is the only place the raw log is
ever examined. RP also sends its verdict back to the Attester
(`/attest_result`), advisory only.

④ **Challenge.** Each Verifier thread FETCHes `/nonce` and gets back a
**Verifier-generated** 32-byte challenge — not an echo of RP's own nonce.
Freshness has to be proven to the Verifier with a value the Verifier picked.

⑤ **Submit.** Each thread has its TPM produce a genuine `Quote_r` over the
already-replayed PCR, under that Verifier's own nonce as `extraData`, signs
a simulated-TEE Attestation Document vouching for the code that did the
appraisal and cleaning, and FETCHes `/appraise`. The Verifier runs Steps
3a/3b and answers `2.05` with `Attestation successful!` or
`Attestation failed!` — a **vote, not a work order**. No reason codes travel;
the reasons stay in the Verifier's own log.

⑥ **Vote.** `2 × passes > N`. Fail-closed: anything that is not an explicit
pass — timeout, transport error, a Verifier that never answered — counts as
NO.

**What is deliberately *not* forwarded:** `log_a` (defeats redaction). There
is no EK, and no certificate of any kind, anywhere in this system — see
"trust anchor" above.

## 1.2 Low level

### Phase ① — resolve verifiers

`get_verifiers()` → `rp_attestation.c:305`

```
RP → TM   FETCH /get_verifiers   msg_get_verifiers_request_dto{ verifier_ids[] }
TM → RP   2.05                   msg_get_verifiers_response_dto{ {ip,port}[] }
```

`coap_trust_manager_handler()` unmarshals via
`charra_unmarshal_get_verifiers_response()`, which bounds-checks the declared
count against what actually arrived, and copies into `verifiers[]`. A short
response is logged and truncated, not over-read.

### Phase ② — get evidence

`get_evidence()` → `rp_attestation.c:355`

`create_attestation_request()` builds:

| Field | Value |
|---|---|
| `nonce` | 20 random bytes — `charra_random_bytes_from_tpm()` if `USE_TPM_FOR_RANDOM_NONCE_GENERATION`, else software |
| `sig_key_id` | `"PK.RSA.default"` — selects which of the TPM's deterministic primaries to derive; see `charra_load_tpm2_key()` |
| `pcr_selections` | SHA-256 bank, `tpm_pcr_selection` (default `0-7,10`) |
| `event_log_path` | `ima_test_logs.txt` or the real IMA path |

Stored in the `last_request` global — Step 2a's nonce check and the
`attester_nonce` field of the outgoing evidence both read it back.

Attester side, `coap_attest_handler()` → `attester_attest.c`:

1. `charra_load_tpm2_key()` derives the TPM's deterministic RESTRICTED
   signing primary -- the same key on every call and every process
   restart, since it comes from `TPM2_CreatePrimary` over a fixed template
   and the TPM's owner-hierarchy seed. No provisioning: its public half was
   written into `keys/trusted_keys.txt` offline (see "trust anchor" above).
2. `qualifying_data ← req.nonce`, then `Esys_Quote()` with that key.
   Restricted matters: only a restricted key may sign `TPM2_Quote` output,
   which is what lets the Verifier's Step 3b item 1 check the *same* key
   against the trust anchor that produced this quote.
3. Reads `log_a` from disk.

`msg_attestation_response_dto` — exactly **four** CBOR fields, in this order:

| # | Field | Contents |
|---|---|---|
| 1 | `attestation_data` | The signed `TPM2B_ATTEST`. Unmarshals to `TPMS_ATTEST`: `magic`, `type`, `qualifiedSigner`, **`extraData` ← the nonce**, `clockInfo`, `firmwareVersion`, and `attested.quote` = `{pcrSelect, pcrDigest}` |
| 2 | `tpm2_signature` | `TPMT_SIGNATURE` — RSA-PSS/SHA-256 over field 1 |
| 3 | `tpm2_public_key` | `TPM2B_PUBLIC` of the quoting key — the key field 2 verifies under, and the key both RP (Step 2a item 1) and every Verifier (Step 3b item 1) look up in the trust anchor |
| 4 | `event_log` | `log_a`, **raw**, real paths |

**No separate nonce field.** The nonce is not sent alongside the quote — it
is `TPMS_ATTEST.extraData`, *inside* the TPM-signed blob. That is the whole
point: a nonce sitting beside the signature could be swapped freely, whereas
one baked into the signed structure by the TPM cannot. Both RP (Step 2a
item 3) and every Verifier (Step 3b item 3) recover it by unmarshalling
field 1 and comparing `extraData` against the nonce they expect.

There is no EK, no AK certificate, and no per-Verifier identity to
substitute here any more: `tpm2_public_key` *is* the whole identity claim,
checked the same way by everyone who receives it.

### Phase ③ — Step 2a appraisal (the gate)

`charra_rp_appraise_evidence()` → `rp_evidence.c:56`, called from inside the
response handler. Six checks, **all six run** even after one fails, so one
cycle reports every problem:

| # | Check | Function |
|---|---|---|
| 1 | `tpm2_public_key` is in the trust anchor | `charra_trusted_keys_check()` |
| 2 | `Quote_a` signature under `tpm2_public_key` | `charra_crypto_rsa_verify_signature()` (mbedTLS, **not** TPM) |
| 3 | `qualifyingData == last_request.nonce` | `charra_verify_tpm2_quote_qualifying_data()` |
| 4 | Every entry: `template_digest == SHA256(template_data)` | `charra_verify_log_entries_self_consistent()` |
| 5 | Replay `log_a` → compare against `Quote_a`'s PCR digest | `charra_verify_log_matches_quote_pcr_digest()` |
| 6 | File hashes vs whitelist/blacklist, **default-deny** | `charra_verify_log_file_hashes_against_policy()` |

> Check 2 uses mbedTLS on purpose. Verifying RSA-PSS needs no TPM, and the RP
> opening a TPM session here while fanning out to N verifier threads is how
> the testbed deadlocks.

`appraisal_ok = 1 && 2 && … && 6`. On failure the cycle aborts — evidence is
never forwarded. Either way `rp_send_attestation_result()` FETCHes
`/attest_result` with the verdict; the Attester only logs it.

### Phase ③b — Step 2b privacy cleaning

`charra_rp_prepare_evidence()` → `rp_evidence.c`. Runs **once per cycle,
before any thread starts** — redaction is randomised, so per-thread redaction
would hand each Verifier a different `log_r` for the same attestation, and
the replay below is likewise shared by every Verifier's later `Quote_r`.

```
charra_sdk_redact_ima_log(log_a, …, → rp_log_r)
```

A fresh random salt is generated per entry and never transmitted. Per entry:
locate the path inside the `ima-ng` `n-ng` field, replace `template_data`
with `SHA256(salt‖path)`, recompute `template_digest`. `pcr_index` and
`template_name` pass through.

Then `rp_replay_log_into_pcr()` (`rp_signing_key.h`) resets
`RP_REPLAY_PCR_INDEX` (23, not 10 — that PCR must be rewindable before each
cycle's replay, and only 16/23 are on this TPM profile) and extends
`log_r`'s entries into it, one `TPM2_PCR_Extend` per entry. A local software
replay of the same entries (`charra_replay_ima_log()`) is also computed and
logged, purely as a diagnostic prediction of what the TPM is about to
arrive at.

> **Consequence, by design:** because `template_digest` is recomputed,
> the composite digest over `log_r` can never equal `Quote_a`'s PCR digest
> — not by policy but arithmetically. `PCR_r` living in a genuine TPM
> PCR (rather than being asserted in software, as it was before this
> change) closes one gap, but the guarantee remains "the RP vouches for
> this redaction", anchored by RP's own TPM plus the simulated TEE
> Attestation Document that names the exact code that produced it (Step
> 3a item 5, below).

### Phase ④/⑤ — per-Verifier threads

`get_attestation_results()` → one `pthread` per Verifier.

Each `get_attestation_results_thread()`:

1. `charra_log_set_thread_prefix("[V<n>:<port>]")` — makes N interleaved log
   streams attributable.
2. `attestation_results[i] = false` — **fail-closed reset**, so an early
   `goto cleanup` can never leave a stale PASS from a previous cycle in the
   tally.
3. FETCH `/nonce`, sending `last_request`. Verifier's `coap_nonce_handler()`
   stores it (for Step 3b item 3) and returns its **own** 32-byte
   `verifier_challenge_nonce`.
4. `charra_rp_build_evidence_message(i)` — `rp_quote_pcr_with_ak()` (see
   `rp_signing_key.h`) has RP's TPM produce a genuine `TPM2_Quote` over the
   PCR the earlier replay left `PCR_r` in, with this Verifier's nonce as
   `qualifyingData` — a short-lived TPM session held under `rp_tpm_mutex`,
   deriving the signing key fresh and never caching it. Then RP's TEE signs
   an Attestation Document over `(file_hash, report_data)`, where
   `report_data = hash(verifier_nonce ‖ pcrdigest_a ‖ log_r)`.
5. FETCH `/appraise`.

```
RP → Verifier  msg_rp_evidence_dto {
   rp_attestation_data, rp_signature, rp_public_key,     ← Quote_r (real TPM2_Quote)
   attester_nonce,
   attestation_data, tpm2_signature, tpm2_public_key,    ← Quote_a fwd (Step 3b-2/1)
   log_r,                                                ← NO content check
   tee_file_hash, tee_report_data,
   tee_signature, tee_public_key }                       ← simulated TEE Attestation Document
```

Neither `verifier_nonce` nor `PCR_r` travels as its own field any more --
both live *inside* `rp_attestation_data`, the same way the Attester's own
nonce and PCR digest live inside `attestation_data`. There is no
per-Verifier substitution to make here, unlike the old certificate-
forwarding dance: RP's signing key and the Attester's are each checked the
same way by every Verifier, against the one shared trust anchor.

### Phase ⑤b — Verifier Steps 3a/3b

`coap_appraise_handler()` → `verifier_appraise.c`

**Step 3a — new evidence (`Evidence_r`)**

| Item | Check | On failure |
|---|---|---|
| 1 | `rp_public_key` is in the trust anchor | `ekak_rp_why` |
| 2 | `rp_signature` over `rp_attestation_data` -- mbedTLS RSA-PSS, no TPM opened | |
| 3 | `rp_attestation_data`'s `extraData == verifier_challenge_nonce` -- plain byte compare, after unmarshaling the TPMS_ATTEST | |
| 4 | replaying `log_r` (software, `charra_replay_ima_log()`) reproduces `rp_attestation_data`'s `pcrDigest` -- this is what ties `Quote_r` to `log_r` at all | |
| 5 | simulated TEE Attestation Document (see `TEE.h`): `tee_signature` valid under `tee_public_key`, `tee_file_hash` matches this Verifier's own hash of the appraisal/cleaning source, `tee_report_data == hash(verifier_nonce ‖ pcrdigest_a ‖ log_r)` | `tee_why` |

**Step 3b — original evidence (`Evidence_a'`)**

| Item | Check |
|---|---|
| 1 | `tpm2_public_key` is in the trust anchor |
| 2 | `Quote_a` signature -- mbedTLS RSA-PSS only; no TPM is opened anywhere in `/appraise` any more |
| 3 | `Quote_a`'s `qualifyingData == last_request.nonce` |

Step 3b runs **even when 3a failed** — its checks read only received fields,
so nothing depends on RP's identity having verified. Running it always means
one appraisal reports every problem instead of leaking them one round trip at
a time. The verdict is still fail-closed: all eight booleans ANDed (4 from
Step 3a's own gate, `attestation_result_ekak`, `attestation_result_signature`,
`attestation_result_nonce` from Step 3b, and `attestation_result_tee`).
Step 3a item 5 is computed inside the Step 3b code block, since it needs
`Quote_a`'s unmarshaled `pcrDigest` — Step 3b's own item 3 already unmarshals
it — but it is still ANDed into the final verdict regardless of which step
number it is filed under.

`log_r` gets **no replay/hash/policy inspection** beyond item 4 above (which
only checks it against `Quote_r`'s own `pcrDigest`, not against a policy).
The self-consistency, whitelist/blacklist checks are Step 2a's job, already
done by the RP against the raw log — the TEE Attestation Document (item 5)
is what lets the Verifier trust that Step 2a actually ran, and ran the real
code, rather than trusting the RP's word for it.

> **`attester_nonce` is sent but never read.** The evidence message carries
> `attester_nonce`, documented in `charra_dto.h` as letting the Verifier
> "see which challenge the Attester's quote answers". In the current code
> nothing in `src/verifier/` reads it: Step 3b item 3 compares `Quote_a`'s
> `extraData` against **`last_request.nonce`** — the nonce that arrived
> earlier on the *`/nonce`* call and was stashed in the Verifier's
> `last_request` global.
>
> That is the safer of the two choices (checking the quote against a value
> the RP supplied *in the same message* would let a replayed quote carry its
> own matching nonce), but it does mean Step 3b item 3 depends on `/nonce`
> and `/appraise` being correlated through a single-in-flight global. Two RPs
> interleaving against one Verifier can therefore cause spurious Step 3b
> failures — bug #6 in `CHARRA_V2_NOTES.md`, open by explicit decision.

### Phase ⑥ — vote

```c
if (2 * num_true > num_verifiers) "Attestation successful by majority vote!"
```

# 5. Cross-cutting mechanics

## 5.1 State on disk

There is essentially none. No role provisions, caches or revokes anything at
runtime; the `state/` directory this section used to document is gone along
with the certificate PKI it existed for. The one thing that has to persist
across process restarts is which signing keys are trusted, and that lives in
a single file, generated offline rather than written by any of the four
binaries at runtime:

| Path | Writer | Content |
|---|---|---|
| `keys/trusted_keys.txt` | `bin/provision_trusted_keys` (offline, via `keys/gen-trusted-keys.sh`) | PEM public keys for the Attester's and RP's TPM-resident signing keys — see `charra_trusted_keys.h` |

Regenerate it after any TPM reset: both keys are derived from the TPM's
owner-hierarchy seed, so a reset changes them and every signature check
starts failing as "key not in the trust anchor".

## 5.2 Locks

| Mutex | Guards |
|---|---|
| `rp_tpm_mutex` | Every RP TPM session -- both the once-per-cycle `log_r` replay and every per-Verifier `Quote_r`. The simulator accepts **one connection at a time**; an RP that held one open for its whole run once starved a Verifier's own TPM work indefinitely. Every use is open → one operation → close |

## 5.3 Freshness — two independent nonces

| Nonce | Chosen by | Carried in | Checked by |
|---|---|---|---|
| 20 B `last_request.nonce` | RP | `Quote_a.qualifyingData` | RP (Step 2a-3) and each Verifier (Step 3b-3) |
| 32 B `verifier_challenge_nonce` | **Verifier** | `Quote_r` signed data | That Verifier (Step 3a-3) |

The second exists because `/nonce` used to echo RP's own nonce back, which
proves freshness to nobody but the RP — it could replay an old signature over
a value it chose itself. A Verifier's challenge must be a value the *Verifier*
picked.

## 5.4 Wire format

CoAP FETCH over UDP (optional DTLS-PSK/RPK) with CBOR bodies (QCBOR), encoded
as **plain positional arrays** — no maps, no labels. Field order is
load-bearing and defined only by struct order in `charra_dto.h`; there is no
schema self-description on the wire.

Every unmarshaler bounds-checks each byte-string against its destination
`sizeof` before copying, and handlers re-check independently before
`memcpy`ing into fixed-size structs (defence in depth). Large responses go
through `coap_add_data_large_response()` with a **release callback** —
freeing the buffer synchronously once corrupted the tail of multi-datagram
responses, which surfaced as intermittent block-wise-transfer failures under
load.

## 5.5 Failure semantics

`/appraise` always answers `2.05` with `Attestation successful!` or
`Attestation failed!`. Any failed check is simply a NO. The Verifier logs
every reason locally; **the wire carries only the verdict**.

This replaced a scheme where the Verifier answered distinct `4.xx` codes to
tell the RP which remedy to attempt and the RP re-provisioned and retried on
each. That made the verdict a *work order* rather than a vote, and put RP's
retry logic at the mercy of codes another party chose. There is nothing left
to remedy or retry now: every identity is either in the trust anchor or it
isn't, decided offline, long before any attestation cycle runs.

Even the exits that reject a request *before* appraising it — malformed CBOR,
an oversized field, a Verifier-side error opening its own duration log —
answer with the same `2.05` + `Attestation failed!`, so the RP sees a failed
vote rather than a distinct status it would have to interpret.

The majority vote is fail-closed at every level: `attestation_results[i]` is
reset to `false` at thread entry, so a timeout, transport error, or early
exit counts as NO. Not completing the exchange is never a reason to accept.

## 5.6 What is *not* authenticated

Worth stating explicitly, since the flows above are otherwise dense with
identity checks:

- **`/attest` has no caller authentication.** The Attester quotes for anyone
  who asks. It is a pure responder with no notion of which RP it is talking
  to; DTLS-PSK/RPK, if enabled, is the only thing gating access.
- **`/attest_result` is advisory.** The Attester logs RP's Step 2a verdict
  and does nothing else with it. Nothing downstream depends on delivery, and
  the Attester does not verify who sent it.
- **`/nonce` is unauthenticated too.** It hands out a freshly generated
  challenge to any caller. It commits the Verifier to nothing — the identity
  checks happen at `/appraise`, where the RP has to produce a signature
  under a key that appears in the trust anchor.
- **The Trust Manager authenticates nobody**, and carries no endorsement
  content — it is plain ID → endpoint resolution.
- **There is no EK, and no certification step, anywhere in this system.**
  A signing key is trusted the instant it appears in `keys/trusted_keys.txt`
  — see "trust anchor" in the vocabulary table up top, and
  `charra_trusted_keys.h`.

---

# 6. Message catalogue — every field on every wire

Authoritative source: the `charra_marshal_*_internal()` encoders in
`src/core/charra_marshaling.c`. Bodies are **positional CBOR arrays** — no
maps, no labels — so the order below *is* the format. Adding, removing, or
reordering a field silently breaks the peer.

`u32` = length-prefixed byte string, `→` = heap pointer (unbounded length,
borrowed from the marshaled buffer on unmarshal), fixed = fixed-size array.

### `/get_verifiers` — RP ↔ Trust Manager

| Dir | DTO | Fields in order |
|---|---|---|
| → | `msg_get_verifiers_request_dto` | `verifier_ids[]` (array of int) |
| ← | `msg_get_verifiers_response_dto` | `verifiers[]` — each `{ip_address, port_number}` |

### `/attest` — RP ↔ Attester

| Dir | DTO | Fields in order |
|---|---|---|
| → | `msg_attestation_request_dto` | `hello` (bool), `sig_key_id`, `nonce`, `pcr_selections[]` (each `{tcg_hash_alg_id, pcrs[]}`), `event_log_path` |
| ← | `msg_attestation_response_dto` | `attestation_data`, `tpm2_signature`, `tpm2_public_key`, `event_log`→ |

### `/attest_result` — RP → Attester (advisory)

| Dir | DTO | Fields in order |
|---|---|---|
| → | `msg_attestation_result_dto` | `accepted` (u32, 1/0), `reason` (≤128 B) |

No response body is consumed. The Attester logs and returns.

### `/nonce` — RP ↔ Verifier

| Dir | Body |
|---|---|
| → | `msg_attestation_request_dto` (the same DTO as `/attest`; the Verifier keeps `nonce` in `last_request` for Step 3b item 3) |
| ← | **Raw bytes, not CBOR** — the 32-byte `verifier_challenge_nonce` |

### `/appraise` — RP ↔ Verifier

| Dir | DTO | Fields in order |
|---|---|---|
| → | `msg_rp_evidence_dto` | 1 `rp_attestation_data` · 2 `rp_signature` · 3 `rp_public_key` (`TPM2B_PUBLIC`) · 4 `attester_nonce` · 5 `attestation_data` · 6 `tpm2_signature` · 7 `tpm2_public_key` · 8 `log_r`→ · 9 `tee_file_hash` (32 B) · 10 `tee_report_data` (32 B) · 11 `tee_signature` · 12 `tee_public_key` |
| ← | **Plain text** | `"Attestation successful!"` or `"Attestation failed!    "`, always `2.05` |

Fields 1–3 are `Quote_r` -- a genuine `TPM2_Quote`, so `verifier_nonce` and
`PCR_r` live *inside* field 1 (`extraData`, `pcrDigest`) rather than
travelling as fields of their own; 3 is Step 3a item 1's input. 4 is unused
(see §1.2); 5–7 are `Quote_a` forwarded verbatim, and 7 is Step 3b item 1's
input; 8 is checked only against field 1's `pcrDigest` (Step 3a item 4), not
inspected for content -- that is Step 2a's job, already done, against the
raw log. 9–12 are the simulated TEE Attestation Document (see `TEE.h`) --
Step 3a item 5's input, checked against field 8 (`log_r`) and against
`attest_struct`'s `pcrDigest` inside field 5 (`attestation_data`).

There is no `/certify_ak` and no `/certify_ak_of_attester` any more, and no
certificate of any kind travels on any wire in this system. Every identity
check anywhere (RP's Step 2a item 1, the Verifier's Step 3a item 1 and Step
3b item 1) is the same lookup against the same file, `keys/trusted_keys.txt`
— see `charra_trusted_keys.h`.

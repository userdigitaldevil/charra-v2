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
| **RP** | `bin/relying_party` | The only party that initiates anything. Appraises `log_a`, redacts it to `log_r`, produces `Quote_r` |
| **Verifier** ×N | `bin/verifier` | Appraises what RP forwards. Also its own Privacy CA. Pure responder |
| **Trust Manager** | `bin/trust_manager` | ID → `ip:port` lookup. Pure responder |

| Term | Meaning |
|---|---|
| `Quote_a` | Attester's TPM quote: `attestation_data` + `tpm2_signature` + `tpm2_public_key` |
| `log_a` | Attester's **raw** IMA event log — real file paths. Never leaves the RP |
| `log_r` | The redacted log. Each entry's path replaced by `SHA256(salt‖path)` |
| `PCR_r` | Composite digest from a **software replay** of `log_r`, not a live PCR read |
| `Quote_r` | RSA-PSS signature by RP's TPM-resident AK over `PCR_r ‖ verifier_nonce` |
| `ek_fingerprint` | `SHA-256(EK certificate DER)` — the identity key for every ledger |

**Key names carry the owner; certificate names also carry the issuer.** There
is exactly one `AK_a` and one `AK_r` — what multiplies is the certificates
over them, because each CA issues its own:

| Name | What it is | Wire field (`msg_rp_evidence_dto`) | Checked at |
|---|---|---|---|
| `AK_a_byRP` | `AK_a` certified by **RP's** CA | `ak_certificate_attester_by_rp` | Step 2a item 1 (RP) |
| `AK_a_byV` | `AK_a` certified by **Verifier i's** CA | `ak_certificate_attester_by_verifier` | Step 3b item 1 |
| `AK_r_byV` | `AK_r` certified by **Verifier i's** CA | `ak_certificate_rp` | Step 3a item 1 |

`_byV` is *per Verifier*: each holds an independent CA key, so N Verifiers
mean N distinct certificates over that one same key. `AK_r` has no RP-issued
form — the RP does not certify itself. A bare `AK_a` / `AK_r` below always
means the key.

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
Attester quotes its PCRs with that nonce as `qualifyingData` and returns
`Quote_a`, the raw `log_a`, and both `AK_a_byRP` and `AK_a_byV`.

③ **Appraise, then cleanse — the heart of the design.** RP runs the full
six-check Step 2a gate against the *raw* log, then Step 2b redacts it. This
is the only place the raw log is ever examined. RP also sends its verdict
back to the Attester (`/attest_result`), advisory only.

④ **Challenge.** Each Verifier thread FETCHes `/nonce` and gets back a
**Verifier-generated** 32-byte challenge — not an echo of RP's own nonce.
Freshness has to be proven to the Verifier with a value the Verifier picked.

⑤ **Submit.** Each thread signs `PCR_r ‖ that Verifier's nonce` into a
per-Verifier `Quote_r` and FETCHes `/appraise`. The Verifier runs Steps
3a/3b and answers `2.05` with `Attestation successful!` or
`Attestation failed!` — a **vote, not a work order**. No reason codes travel;
the reasons stay in the Verifier's own log.

⑥ **Vote.** `2 × passes > N`. Fail-closed: anything that is not an explicit
pass — timeout, transport error, a Verifier that never answered — counts as
NO.

**What is deliberately *not* forwarded:** `log_a` (defeats redaction) and the
Attester's **EK** certificate (a permanent hardware identifier — a stronger
identifier than any path the redaction protects).

## 1.2 Low level

### Phase ① — resolve verifiers

`get_verifiers()` → `rp_attestation.c:321`

```
RP → TM   FETCH /get_verifiers   msg_get_verifiers_request_dto{ verifier_ids[] }
TM → RP   2.05                   msg_get_verifiers_response_dto{ {ip,port}[] }
```

`coap_trust_manager_handler()` unmarshals via
`charra_unmarshal_get_verifiers_response()`, which bounds-checks the declared
count against what actually arrived, and copies into `verifiers[]`. A short
response is logged and truncated, not over-read.

### Phase ② — get evidence

`get_evidence()` → `rp_attestation.c:495`

`create_attestation_request()` builds:

| Field | Value |
|---|---|
| `nonce` | 20 random bytes — `charra_random_bytes_from_tpm()` if `USE_TPM_FOR_RANDOM_NONCE_GENERATION`, else software |
| `sig_key_id` | `"PK.RSA.default"` (legacy; the Attester now ignores it and uses its restricted AK) |
| `pcr_selections` | SHA-256 bank, `tpm_pcr_selection` (default `0-7,10`) |
| `event_log_path` | `ima_test_logs.txt` or the real IMA path |

Stored in the `last_request` global — Step 2a's nonce check and the
`attester_nonce` field of the outgoing evidence both read it back.

Attester side, `coap_attest_handler()` → `attester.c:1305`:

1. `ensure_attester_ak_keypair()` **before** ESAPI init — the simulator
   accepts one connection at a time.
2. `qualifying_data ← req.nonce`, then `Esys_Quote()` with the **restricted**
   AK. Restricted matters: the same key is certified by `/certify_ak_of_attester`,
   so Step 3b's "cert matches the quoting key" check can pass.
3. Reads `log_a` from disk and both cached certificates (`AK_a_byRP`, `AK_a_byV`)
   (`state/attester/ak-certificates/attester-ak-certificate-{rp,verifier}.der`).

`msg_attestation_response_dto` — exactly **six** CBOR fields, in this order:

| # | Field | Contents |
|---|---|---|
| 1 | `attestation_data` | The signed `TPM2B_ATTEST`. Unmarshals to `TPMS_ATTEST`: `magic`, `type`, `qualifiedSigner`, **`extraData` ← the nonce**, `clockInfo`, `firmwareVersion`, and `attested.quote` = `{pcrSelect, pcrDigest}` |
| 2 | `tpm2_signature` | `TPMT_SIGNATURE` — RSA-PSS/SHA-256 over field 1 |
| 3 | `tpm2_public_key` | `TPM2B_PUBLIC` of the quoting AK — the key field 2 verifies under |
| 4 | `event_log` | `log_a`, **raw**, real paths |
| 5 | `ak_certificate_attester_by_verifier` | **`AK_a_byV`** (DER) — Step 3b item 1's input |
| 6 | `ak_certificate_attester_by_rp` | **`AK_a_byRP`** (DER) — Step 2a item 1's input |

Two things are **not** in this message, and both are deliberate:

- **No separate nonce field.** The nonce is not sent alongside the quote — it
  is `TPMS_ATTEST.extraData`, *inside* the TPM-signed blob. That is the whole
  point: a nonce sitting beside the signature could be swapped freely, whereas
  one baked into the signed structure by the TPM cannot. Both RP (Step 2a
  item 3) and every Verifier (Step 3b item 3) recover it by unmarshalling
  field 1 and comparing `extraData` against the nonce they expect.
- **No EK certificate.** Only the two *AK* certificates travel. The Attester's
  EK certificate is a permanent, unique hardware identifier; it reaches the RP
  exactly once, on the `/certify_ak_of_attester` FETCH leg (§4), and never
  goes any further. Forwarding it to a Verifier would leak a stronger
  identifier than the path redaction protects.

Both certificates are re-read **from disk on every `/attest` call** rather
than cached in memory, because `DELIVER_VERIFIER` can rewrite the
Verifier-issued one at any time between calls.

### Phase ③ — Step 2a appraisal (the gate)

`charra_rp_appraise_evidence()` → `rp_evidence.c:32`, called from inside the
response handler. Six checks, **all six run** even after one fails, so one
cycle reports every problem:

| # | Check | Function |
|---|---|---|
| 1 | **`AK_a_byRP`** chains to **RP's own CA** + matches the quoting key, and its serial is live in RP's ledger | `charra_crypto_verify_ekak_certificate()` + `charra_ak_state_check_serial_valid()` |
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

`charra_rp_prepare_evidence()` → `rp_evidence.c:183`. Runs **once per cycle,
before any thread starts** — redaction is randomised, so per-thread redaction
would hand each Verifier a different `log_r` for the same attestation.

```
charra_sdk_redact_ima_log(log_a, …, salt = NULL, → rp_log_r)
```

`salt = NULL` means **a fresh random salt per entry, never transmitted**.
(The one exception is `/qualify`, §2.) Per entry: locate the path inside the
`ima-ng` `n-ng` field, replace `template_data` with `SHA256(salt‖path)`,
recompute `template_digest`. `pcr_index` and `template_name` pass through.

Then replay `log_r` → per-PCR accumulators → `hash_sha256_array()` → `PCR_r`.

> **Consequence, by design:** because `template_digest` is recomputed,
> `PCR_r` can never equal `Quote_a`'s PCR digest — not by policy but
> arithmetically. The TPM is therefore *not* in the Verifier's chain of trust
> for PCR10 content; the guarantee is "the RP vouches for this", anchored by
> RP's own TPM.

### Phase ④/⑤ — per-Verifier threads

`get_attestation_results()` → one `pthread` per Verifier. Before spawning:
`rp_perform_qualification_handshake_once()` (§2) runs **once** for all of
them; if it fails, the cycle aborts rather than spawning N threads that would
all be rejected identically.

Each `get_attestation_results_thread()`:

1. `charra_log_set_thread_prefix("[V<n>:<port>]")` — makes N interleaved log
   streams attributable.
2. `attestation_results[i] = false` — **fail-closed reset**, so an early
   `goto cleanup` can never leave a stale PASS from a previous cycle in the
   tally.
3. `ensure_rp_ak_certificate(i)` and
   `ensure_attester_identity_certified_by_verifier(i)` — both per-Verifier
   (independent CAs). On failure it **still sends**, letting that Verifier
   judge and log its own decision.
4. FETCH `/nonce`, sending `last_request`. Verifier's `coap_nonce_handler()`
   stores it (for Step 3b item 3) and returns its **own** 32-byte
   `verifier_challenge_nonce`.
5. `charra_rp_build_evidence_message(i)` — signs `PCR_r ‖ verifier_nonce[i]`
   under RP's AK via a short-lived TPM session held under `rp_tpm_mutex`.
6. FETCH `/appraise`.

```
RP → Verifier  msg_rp_evidence_dto {
   pcr_r, verifier_nonce, rp_signature, rp_public_key,   ← Quote_r
   ak_certificate_rp,                                    ← AK_r_byV   (Step 3a-1)
   attester_nonce,
   attestation_data, tpm2_signature, tpm2_public_key,    ← Quote_a fwd (Step 3b-2)
   ak_certificate_attester_by_verifier,                  ← AK_a_byV   (Step 3b-1)
   ak_certificate_attester_by_rp,                        ← forwarded, not checked
   log_r }                                               ← NO content check
```

`ak_certificate_attester_by_verifier` is substituted from RP's **own
per-Verifier cache**, not from what `last_response` carried — only RP knows
which Verifier's CA issued which certificate. Not a trust shortcut: validity
depends on the CA signature, not on who relayed the bytes.

> **Asymmetry worth knowing.** The Attester stores exactly **one**
> `attester-ak-certificate-verifier.der`, overwritten by whichever
> DELIVER_VERIFIER ran last, and re-reads it from disk on every `/attest`.
> The RP stores **N**, one per port. So the copy the Attester ships in its
> `/attest` response is essentially vestigial for appraisal — RP overrides it
> per Verifier here. Only `ak_certificate_attester_by_rp` is forwarded as the
> Attester sent it, since there is just one RP CA.

### Phase ⑤b — Verifier Steps 3a/3b

`coap_appraise_handler()` → `verifier_appraise.c`

**Step 3a — new evidence (`Evidence_r`)**

| Item | Check | On failure |
|---|---|---|
| 1 | **`AK_r_byV`** chains to **this Verifier's** CA, matches `rp_public_key`, serial live in `rp/` ledger | `ekak_rp_why` |
| 1b | `ek_fingerprint` (derived in 1) is present and unexpired in the **shared** qualification ledger | see §2 |
| 2 | `rp_signature` over `pcr_r ‖ verifier_nonce` | |
| 3 | `verifier_nonce == verifier_challenge_nonce` — plain byte compare | |

**Step 3b — original evidence (`Evidence_a'`)**

| Item | Check |
|---|---|
| 1 | `ak_certificate_attester_by_verifier` chains to this Verifier's CA, matches the key that signed `Quote_a`, serial live in `attester/` ledger |
| 2 | `Quote_a` signature — verified **twice**, once TPM-backed (`Esys_VerifySignature`) and once mbedTLS |
| 3 | `Quote_a`'s `qualifyingData == last_request.nonce` |

Step 3b runs **even when 3a failed** — its checks read only received fields,
so nothing depends on RP's identity having verified. Running it always means
one appraisal reports every problem instead of leaking them one round trip at
a time. The verdict is still fail-closed: all nine booleans ANDed.

`log_r` gets **no content inspection at all** — no replay, no hash check, no
policy. That is Step 2a's job, already done, against the raw log.

> **`attester_nonce` is sent but never read.** The evidence message carries
> `attester_nonce` (field 6), documented in `charra_dto.h` as letting the
> Verifier "see which challenge the Attester's quote answers". In the current
> code nothing in `src/verifier/` reads it: Step 3b item 3 compares
> `Quote_a`'s `extraData` against **`last_request.nonce`** — the nonce that
> arrived earlier on the *`/nonce`* call and was stashed in the Verifier's
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

---

# 2. `/qualify` + `/qualify_submit` — proving RP's redaction pipeline works

## 2.1 High level

Separate from per-attestation appraisal. Before a Verifier trusts an RP to
redact real evidence, it proves — using data it **fabricates itself**, so it
already knows the right answer — that the RP's SDK actually works.

```
RP ──FETCH /qualify────────────►  Verifier
                                  fabricate synthetic log
                                  redact it locally  → golden_log, golden_pcr
   ◄──── challenge_log + salt ──  (keeps golden answer in memory)

RP  redacts challenge_log with that salt
    replays → pcr_digest
    signs pcr_digest with its AK

   ──FETCH /qualify_submit─────►  chain-verify submitter's AK_r_byV
                                  verify signature over pcr_digest
                                  memcmp(submitted, golden)
   ◄──── qualified + expires_at ─ persist to SHARED ledger, keyed by ek_fingerprint
```

Three things make this work:

**The salt is transmitted — the one and only place that happens.** Redaction
normally mints a fresh secret salt per entry, so two honest redactions of the
same log never match bytewise. That would make a byte-exact comparison
structurally impossible. So `/qualify` ships the salt alongside the challenge.
Safe **only** because `challenge_log` is synthetic — fabricated paths, not a
real device's.

**The grant is shared across all Verifiers.** The ledger file
(`state/verifier/qualification/rp-qualification-state.txt`, no port suffix) is
one file every `bin/verifier` opens. So RP runs this handshake **once per
validity window against whichever Verifier answers first**, and every other
Verifier sees the result. Safe because
`charra_qualification_state_renew()` only ever *appends* — unlike
`charra_ak_state_renew()`, which revokes-on-write and therefore genuinely
needs per-Verifier files.

**The grant is identity-bound.** Keyed by `ek_fingerprint`, so RP A's passing
grant cannot let RP B's `/appraise` through.

## 2.2 Low level

### Leg 1 — `/qualify`

`coap_qualify_handler()` → `verifier_qualify.c:52`. Ignores the request body
entirely; nothing about the challenge is caller-supplied.

```c
charra_rp_qualification_state_free(&qualification_state);  // drop prior round
charra_random_bytes(&seed);  charra_random_bytes(salt);
charra_rp_qualification_generate(NUM_ENTRIES=5, seed, salt, &state,
                                 &challenge_log, &len);
```

Inside `charra_rp_qualification_generate()`:

1. `charra_synth_generate_ima_log(5, seed)` → a well-formed `ima-ng` log with
   fabricated-but-plausible paths. Deterministic in `(entries, seed)`.
2. `charra_sdk_redact_ima_log(raw, salt)` → **`state.golden_log`**
3. `charra_replay_ima_log(golden_log, PCR 10)` → **`state.golden_pcr`**

```
Verifier → RP   msg_qualify_response_dto { challenge_log, salt[16] }
```

State lives in one `qualification_state` global — a single outstanding
challenge at a time.

### Leg 2 — RP computes

`rp_perform_qualification_handshake_once()` → `rp_qualification.c:147`

Cache short-circuit first:

```c
if (rp_qualified_until <= now)
        rp_qualified_until = rp_qualification_cache_load();
if (rp_qualified_until > now) return SUCCESS;   // skip entirely
```

There is no renewal margin: a grant is re-earned only once it has genuinely
expired, so the handshake always runs inside the attestation cycle that
discovers the expiry.

Then, per candidate Verifier in order — transport failure moves to the next,
a received *verdict* stops the search (it would be identical everywhere):

1. `ensure_rp_ak_certificate(i)` — `/qualify_submit` needs a cert that Verifier can chain
2. FETCH `/qualify`
3. `charra_sdk_redact_ima_log(challenge_log, qualify_challenge_salt)` — the
   **same** pipeline real evidence uses, with the received salt
4. `charra_replay_ima_log(..., CHARRA_IMA_PCR_INDEX)` → `submitted_pcr_digest`
5. `charra_identity_key_mgr_sign()` under `rp_tpm_mutex`
6. FETCH `/qualify_submit`

The whole loop is held under `rp_qualification_mutex` — every response global
(`qualify_challenge_log`, `qualify_response_rc`, …) is shared, and the
retry path can call this from more than one thread.

### Leg 3 — `/qualify_submit`

`coap_qualify_submit_handler()` → `verifier_qualify.c:153`. Three gates, in
order — the first two are authentication, only the third is the actual test:

| Gate | Check | Failure |
|---|---|---|
| 1 | **`AK_r_byV`** chains to this Verifier's CA, matches `rp_public_key`, serial live → yields `ek_fingerprint` | `4.01` |
| 2 | `rp_signature` verifies over `submitted_pcr_digest` under that certified key | `4.01` |
| 3 | `charra_rp_qualification_check()` | `2.05` + `qualified=0` |

Without gates 1–2 anyone could submit an arbitrary log with no proof they ever
ran a real RP's pipeline.

Gate 3 is two `memcmp`s:

```c
log_matches = len == golden_log_len && memcmp(submitted, golden_log, len) == 0;
pcr_matches = memcmp(submitted_pcr_digest, golden_pcr, 32) == 0;
```

On pass: `expires_at = now + validity`, and a record
`{ek_fingerprint, qualified_at, expires_at}` is appended to the shared ledger
under `flock()`.

```
Verifier → RP   msg_qualify_submit_response_dto { qualified, expires_at }
```

`expires_at` is on the wire deliberately: the Verifier owns the window
(`--qualification-validity`), so RP reads the real deadline instead of
assuming a matching constant. RP caches it to
`state/relying-party/qualification-cache/rp-qualification-until.txt`.

---

# 3. `/certify_ak` — Verifier as Privacy CA

## 3.1 High level

The Verifier merges the Privacy CA role into itself and issues AK
certificates via standard TPM2 Credential Activation. **Two legs**, and the
split is the whole security property:

```
RP ──CHALLENGE (EK cert, AK pub, AK name)──►  Verifier
                                              verify EK chains to mfr root
                                              rebuild EK TPM2B_PUBLIC
                                              random 32-byte secret
                                              Esys_MakeCredential(secret)
                                              ── signs NOTHING, records NOTHING
   ◄──── credential_blob + wrapped_secret ──

RP  Esys_ActivateCredential  → recovers secret     (only its TPM can)

   ──CONFIRM (EK cert, secret)──────────────►  constant-time compare
                                              single-use: entry consumed
                                              NOW sign + record + revoke prior
   ◄──── ak_certificate (plaintext) ────────
```

**Why two legs.** The one-shot version signed a certificate, wrapped it, *and*
called `charra_ak_state_renew()` — which **revokes the requester's previous
certificate** — all before any proof the requester could open the response.
The request carries only the EK *certificate*, which is public data. So anyone
holding a copy could knock out a working identity while being cryptographically
unable to use the replacement. A denial of service, not a theft.

Now every irreversible step sits behind the proof.

**Why the credential is a symmetric key, not the certificate.**
`MakeCredential`'s payload is capped near a digest size — far too small for
X.509. So it carries a 32-byte secret instead.

**Why the certificate now travels in the clear.** It used to be AES-GCM
wrapped, which only ever served as an *implicit* possession proof — which
CONFIRM now makes explicit. Keeping it would be self-defeating anyway, since
CONFIRM puts that same secret on the wire. The certificate was never secret;
identical bytes travel unencrypted in every later `/appraise`.

## 3.2 Low level

### CHALLENGE — `certify_ak_do_challenge()` → `verifier_certify_ak.c:173`

```
RP → V   msg_certify_ak_request_dto {
           kind = CHALLENGE, subject = RP | ATTESTER,
           ek_certificate, ak_public_key, ak_name }
```

`subject` routes the issuance to a separate ledger per identity kind — an RP
AK and a relayed Attester AK must never be tracked, or revoked, as the same
thing. It is bound into the pending challenge, so CONFIRM's routing uses the
CHALLENGE-time value regardless of what CONFIRM sends.

1. `charra_crypto_verify_x509_cert_chain(ek_certificate, manufacturer-root.crt)`
   → else `4.01`
2. `charra_crypto_build_ek_tpm2b_public_from_cert()` — `Esys_MakeCredential`
   needs the whole TCG "low range" public area, not just the modulus.
   Template values were confirmed empirically against `tpm2_createek -G rsa`.
3. `charra_random_bytes(32)` → `secret`;
   `ek_fingerprint = SHA256(ek_certificate)`
4. `charra_tpm_make_credential_for_ak()` — wraps `Esys_MakeCredential`,
   loading the requester's EK via `Esys_LoadExternal`. **No Verifier TPM
   identity needed.** The caller-supplied `ak_name` is trusted unverified: a
   wrong name simply fails the requester's own `ActivateCredential`.
5. `certify_ak_pending_store()` — 8 slots, **60s TTL**, in memory only.

```
V → RP   msg_certify_ak_response_dto { credential_blob, wrapped_secret }
```

### RP activates — `ensure_rp_ak_certificate()` → `rp_identity.c:425`

Two **separate, short-lived** TPM sessions, each taking `rp_tpm_mutex` and
closing before the next network call — never holding the simulator's single
connection slot across a round trip:

- Session 1: load AK, read `ak_name`, build the CHALLENGE. Closed *before*
  sending.
- Session 2: `charra_identity_key_mgr_activate_credential()` →
  `Esys_ActivateCredential(ak_handle, ek_handle, blob, secret)` → the
  32-byte secret. Closed before CONFIRM is sent.

### CONFIRM — `certify_ak_do_confirm()` → `verifier_certify_ak.c:330`

```
RP → V   msg_certify_ak_request_dto { kind = CONFIRM, ek_certificate, secret }
```

`ak_public_key`/`ak_name` are deliberately **absent**: the Verifier certifies
the key it already bound into the challenge, so even a leaked secret cannot be
redirected onto a different key.

1. `certify_ak_pending_take(ek_fingerprint)` — copies out **and clears** the
   slot. Single-use: neither a replay nor a retry after a wrong guess can
   reuse it. Missing/expired → `4.01`.
2. `constant_time_equal(req.secret, challenge.secret, 32)` → else `4.01`,
   *nothing signed, nothing revoked*.
3. `charra_crypto_sign_ak_certificate(challenge.ak_public_key, …)` — issuer
   read from that port's own `verifier-ca-<port>.crt`, validity
   `now … now + --ak-validity`, random 16-byte serial returned out-param.
4. `charra_ak_state_renew(subject_ledger, ek_fingerprint, record)` — appends
   `{ek_fingerprint, ak_name, serial, issued_at, expires_at, revoked}` and
   **revokes any prior record for the same EK**, under `flock()`.

CONFIRM needs **no TPM at all** — the proof was produced by the requester's —
which removes it from simulator contention entirely.

```
V → RP   msg_certify_ak_response_dto { ak_certificate }   ← plaintext DER
```

RP caches to `state/relying-party/ak-certificates/rp-ak-certificate-<port>.der`.

---

# 4. `/certify_ak_of_attester` — Attester AK provisioning, RP-mediated

## 4.1 High level

The Attester needs a certified AK, but it is a **pure passive responder** — it
cannot call anyone. So the RP drives everything, and the Attester's single
`/certify_ak_of_attester` resource is discriminated by a `kind` field.

The Attester ends up with **two independently-issued certificates for the same
AK**, from two CAs that do not trust each other's issuance:

```
        ┌───── Track A: RP's own CA (RP is the CA) ─────┐

RP ──FETCH─────────────────────────────────────► Attester
   ◄── EK cert + AK pub + AK name ──────────────
RP  validates EK chain itself  ── HARD GATE, aborts cycle on failure
RP  signs cert with keys/rp-ca.key
RP  MakeCredential(AES key) + AES-GCM(cert)
   ──DELIVER_RP (wrapped)──────────────────────► ActivateCredential → decrypt
                                                  persist

        ┌── Track B: a Verifier's CA (RP is only a relay) ──┐

RP ──/certify_ak CHALLENGE (subject=ATTESTER)──► Verifier
   ◄── credential_blob + wrapped_secret ────────
   ──ACTIVATE (relayed blob)────────────────────► Attester
   ◄── recovered secret ────────────────────────  (only its TPM can)
   ──/certify_ak CONFIRM (that secret)─────────► Verifier signs + records
   ◄── ak_certificate ─────────────────────────
   ──DELIVER_VERIFIER (plaintext)──────────────► Attester persists
```

**Why ACTIVATE exists.** Only the Attester's TPM can activate a challenge
meant for it. The RP cannot answer on its behalf — which is precisely the
point: the possession proof reaching the Verifier is one the relay could not
have forged.

**Why the two tracks are asymmetric.** On Track A the RP *is* the CA, so it
still uses the one-shot wrapped form — the Attester's unwrap is itself the
possession proof. On Track B the RP is only a relay, so the Verifier needs
the explicit CHALLENGE/CONFIRM proof. Making Track A symmetrical is noted as
follow-up work.

**Track A's EK check is a hard local gate.** If the Attester's EK certificate
does not chain to the manufacturer root, RP aborts the whole attestation cycle
rather than proceed with an unverified Attester identity.

**Track B is per-Verifier.** Each Verifier has an independent CA key, so one
Verifier's certificate does not validate anywhere else. Track B therefore runs
once per Verifier, cached as
`attester-ak-certificate-verifier-<port>.der`.

## 4.2 Low level

### FETCH

```
RP → A   msg_certify_ak_of_attester_request_dto { kind = FETCH }
A  → RP  msg_ak_identity_response_dto { ek_certificate, ak_public_key, ak_name }
```

Attester opens a short TPM session **purely** to read `ak_name` — no
ActivateCredential, no signing on this leg.

> The AK here is a *dedicated identity keypair*, created by
> `charra_identity_key_mgr_create_restricted_ak()`. **Restricted** is
> load-bearing: it doubles as the real `Quote_a`-signing key, so the certified
> key and the quoting key are the same key and Step 3b item 1 can pass.
> (RP's own AK is deliberately *un*restricted — it must sign
> `PCR_r ‖ nonce`, caller-supplied data a restricted key cannot sign without
> a validation ticket.)
>
> `ak_name` copies only `size + size bytes` and zeroes the tail —
> `Esys_TR_GetName()` leaves the rest of the allocation uninitialised, and
> copying the whole struct put stale heap bytes on the wire (caught by
> valgrind).

### Track A — `ensure_attester_identity_provisioned()` → `rp_attester_identity.c:116`

Once per process, under `attester_identity_provision_mutex`.

1. `charra_crypto_verify_x509_cert_chain(ek, manufacturer-root.crt)` — hard gate
2. `charra_crypto_sign_ak_certificate(ak_public_key, …, keys/rp-ca.key)`
3. Random AES-256 key → `charra_crypto_aes256gcm_encrypt(cert)` → nonce + tag
4. `charra_tpm_make_credential_for_ak()` wraps the **AES key** (under
   `rp_tpm_mutex`)
5. `charra_ak_state_renew("state/relying-party/ak-provisioning/attester-ak-state.txt")`
6. DELIVER_RP

```
RP → A   { kind = DELIVER_RP, credential_blob, wrapped_secret,
           aes_gcm_nonce, aes_gcm_tag, ak_certificate }   ← ciphertext
```

Attester: `ActivateCredential` → AES key → `charra_crypto_aes256gcm_decrypt()`
(authenticated — wrong key or tampered ciphertext yields
`CHARRA_RC_VERIFICATION_FAILED`, never plaintext) → persist.

RP caches the plaintext cert and the fetched identity, so Track B never
re-FETCHes.

### Track B — `ensure_attester_identity_certified_by_verifier(i)` → `rp_attester_identity.c:660`

Per Verifier, under `attester_identity_relay_mutex`. Disk cache checked first,
and **expiry is acted on, not merely logged**: the Verifier gives RP no
distinct signal for "the Attester's cert is stale" (Step 3b folds it into an
ordinary NO), so without this check an expired certificate would be reloaded,
re-sent, and rejected every cycle forever — a stuck state only a manual delete
could clear.

```
RP → V   /certify_ak { kind = CHALLENGE, subject = ATTESTER,
                       ek_certificate, ak_public_key, ak_name }   ← Attester's
V  → RP  { credential_blob, wrapped_secret }

RP → A   { kind = ACTIVATE, credential_blob, wrapped_secret }
A  → RP  msg_activate_credential_response_dto { secret }          ← the proof

RP → V   /certify_ak { kind = CONFIRM, ek_certificate, secret }
V  → RP  { ak_certificate }                                        ← plaintext

RP → A   { kind = DELIVER_VERIFIER, ak_certificate }               ← plaintext
```

`subject = ATTESTER` routes the Verifier's ledger write to
`state/verifier/ak-provisioning/attester/`, keeping it entirely separate from
its `rp/` ledger. DELIVER_VERIFIER carries no credential wrapping — the
preceding ACTIVATE already supplied the possession proof.

---

# 5. Cross-cutting mechanics

## 5.1 State on disk

| Path | Writer | Content |
|---|---|---|
| `state/verifier/ak-provisioning/rp/…-<port>.txt` | Verifier | AK issuances for RP identities — **per port** |
| `state/verifier/ak-provisioning/attester/…-<port>.txt` | Verifier | AK issuances for Attester identities — **per port** |
| `state/verifier/qualification/rp-qualification-state.txt` | Verifier | Qualification grants — **SHARED across ports** |
| `state/relying-party/identity/` | RP | RP's EK cert + AK keypair blobs |
| `state/relying-party/ak-certificates/…-<port>.der` | RP | `AK_r_byV`, one per Verifier |
| `state/relying-party/attester-ak-certificates/` | RP | Attester certs RP holds (RP-issued + one per Verifier) |
| `state/relying-party/ak-provisioning/` | RP | RP-as-CA issuance ledger for the Attester |
| `state/relying-party/qualification-cache/…until.txt` | RP | One epoch timestamp — **single file** |
| `state/attester/` | Attester | Its EK/AK + both delivered certs |

**Why AK ledgers are per-port but the qualification ledger is not:**
`charra_ak_state_renew()` *revokes* any existing record for the same
`ek_fingerprint` before appending. Share that file across Verifiers and the
second Verifier to certify an RP instantly revokes the first's freshly-issued
certificate. `charra_qualification_state_renew()` only appends, so sharing is
safe — and is exactly what makes one `/qualify` suffice for all N Verifiers.

Both use `flock()` on a companion `.lock` file, safe across the separate
`bin/verifier` OS processes. Both scan **backward** on lookup: after N
renewals for one EK, up to N−1 superseded records exist oldest-first, so a
forward scan would keep returning the stale one.

## 5.2 Locks

| Mutex | Guards |
|---|---|
| `rp_tpm_mutex` | Every RP TPM session. The simulator accepts **one connection at a time**; an RP that held one open for its whole run once starved a Verifier's `/certify_ak` indefinitely. Every use is open → one operation → close |
| `rp_ak_reprovision_mutex` | `/certify_ak` response globals — N threads can legitimately be mid-exchange |
| `rp_qualification_mutex` | `/qualify` response globals |
| `attester_identity_provision_mutex` | Track A, once per process |
| `attester_identity_relay_mutex` | Track B relay |

Discipline: **reprovision mutex, then TPM mutex, never nested the other way.**

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
freeing the buffer synchronously corrupted the tail of multi-datagram
responses, which surfaced as "every Verifier's first `/certify_ak` fails,
every retry succeeds".

## 5.5 Failure semantics

`/appraise` always answers `2.05` with `Attestation successful!` or
`Attestation failed!`. Any failed check is simply a NO. The Verifier logs
every reason locally; **the wire carries only the verdict**.

This replaced a scheme where the Verifier answered `4.01`/`4.03`/`4.12` to
tell the RP which remedy to attempt and the RP re-provisioned and retried on
each. That made the verdict a *work order* rather than a vote, and put RP's
retry logic at the mercy of codes another party chose. `4.01` still exists,
but only on `/certify_ak` and `/qualify_submit`, where it is a genuine
authentication failure rather than an appraisal outcome.

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
- **`/nonce` and `/qualify` are unauthenticated too.** Both hand out
  freshly generated challenges to any caller. Neither commits the Verifier to
  anything — the identity checks happen at `/appraise` and
  `/qualify_submit`, where the RP has to prove possession of a certified key.
- **The Trust Manager authenticates nobody**, and carries no endorsement
  content — it is plain ID → endpoint resolution.
- **The Attester's EK certificate is validated exactly once**, by the RP at
  `/certify_ak_of_attester` time. It is never re-checked per attestation
  cycle, and never reaches a Verifier at all.

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
| ← | `msg_attestation_response_dto` | `attestation_data`, `tpm2_signature`, `tpm2_public_key`, `event_log`→, `ak_certificate_attester_by_verifier`→, `ak_certificate_attester_by_rp`→ |

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
| → | `msg_rp_evidence_dto` | 1 `pcr_r` (32 B) · 2 `verifier_nonce` · 3 `rp_signature` · 4 `rp_public_key` · 5 `ak_certificate_rp`→ · 6 `attester_nonce` · 7 `attestation_data` · 8 `tpm2_signature` · 9 `tpm2_public_key` · 10 `ak_certificate_attester_by_verifier`→ · 11 `ak_certificate_attester_by_rp`→ · 12 `log_r`→ |
| ← | **Plain text** | `"Attestation successful!"` or `"Attestation failed!    "`, always `2.05` |

Fields 1–4 are `Quote_r`; 5 is Step 3a item 1's input; 6 is unused (see §1.2);
7–9 are `Quote_a` forwarded verbatim; 10 is Step 3b item 1's input; 11 is
forwarded but not checked by the Verifier; 12 is never inspected.

### `/qualify` + `/qualify_submit` — RP ↔ Verifier

| Dir | DTO | Fields in order |
|---|---|---|
| → | *(none)* | Request body ignored entirely |
| ← | `msg_qualify_response_dto` | `challenge_log`→, `salt` (16 B) |
| → | `msg_qualify_submit_request_dto` | `submitted_redacted_log`→, `submitted_pcr_digest` (32 B), `rp_signature`, `rp_public_key`, `ak_certificate_rp`→ |
| ← | `msg_qualify_submit_response_dto` | `qualified` (u32), `expires_at` (u64 epoch) |

### `/certify_ak` — requester ↔ Verifier

One DTO pair for both legs; `kind` selects which fields are meaningful.

| Dir | DTO | Fields in order |
|---|---|---|
| → | `msg_certify_ak_request_dto` | `kind`, `subject`, `ek_certificate`→, `ak_public_key`, `ak_name`, `secret` (32 B) |
| ← | `msg_certify_ak_response_dto` | `credential_blob`, `wrapped_secret`, `ak_certificate`→ |

| `kind` | Request carries | Response carries |
|---|---|---|
| `CHALLENGE` (0) | `subject`, `ek_certificate`, `ak_public_key`, `ak_name` | `credential_blob`, `wrapped_secret` |
| `CONFIRM` (1) | `ek_certificate`, `secret` | `ak_certificate` |

`subject`: `RP` (0) or `ATTESTER` (1) — chooses the ledger. Bound at CHALLENGE
time, so CONFIRM's routing cannot be redirected. `ak_public_key`/`ak_name` are
deliberately absent from CONFIRM.

### `/certify_ak_of_attester` — RP ↔ Attester

| Dir | DTO | Fields in order |
|---|---|---|
| → | `msg_certify_ak_of_attester_request_dto` | `kind`, `credential_blob`, `wrapped_secret`, `aes_gcm_nonce` (12 B), `aes_gcm_tag` (16 B), `ak_certificate`→ |
| ← (FETCH) | `msg_ak_identity_response_dto` | `ek_certificate`→, `ak_public_key`, `ak_name` |
| ← (ACTIVATE) | `msg_activate_credential_response_dto` | `secret` (32 B) |

| `kind` | Request carries | Response |
|---|---|---|
| `FETCH` (0) | `kind` only | `msg_ak_identity_response_dto` |
| `DELIVER_RP` (1) | `credential_blob`, `wrapped_secret`, `aes_gcm_nonce`, `aes_gcm_tag`, `ak_certificate` **(ciphertext)** | status only |
| `DELIVER_VERIFIER` (2) | `ak_certificate` **(plaintext)** | status only |
| `ACTIVATE` (3) | `credential_blob`, `wrapped_secret` | `msg_activate_credential_response_dto` |

### Where each certificate and key actually travels

| Artifact | `/attest` | `/appraise` | `/certify_ak` | `/certify_ak_of_attester` |
|---|---|---|---|---|
| Attester **EK** cert | — | — | ✔ both legs (relayed by RP) | ✔ FETCH response |
| Attester **AK** cert, RP-issued | ✔ | ✔ (forwarded, unchecked) | — | ✔ DELIVER_RP (encrypted) |
| Attester **AK** cert, Verifier-issued | ✔ | ✔ (RP substitutes per port) | ✔ CONFIRM response | ✔ DELIVER_VERIFIER |
| RP **EK** cert | — | — | ✔ both legs | — |
| RP **AK** cert | — | ✔ | ✔ CONFIRM response | — |
| RP AK **public key** (DER) | — | ✔ | — | — |
| Attester AK public key | ✔ (`tpm2_public_key`) | ✔ (forwarded) | ✔ CHALLENGE | ✔ FETCH response |

The two EK certificates never reach a Verifier's appraisal path and never
appear in `/appraise` at all — each is validated once, at certification time,
by whoever acts as CA for that identity.

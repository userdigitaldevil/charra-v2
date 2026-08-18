# CHARRA-v2 — Security findings register

Open findings from a replay/authentication audit of the CoAP endpoints.
Nothing here is fixed yet — this is the backlog.

Each entry states how it was established: **verified** (proved against
compiled code or observed live) or **derived** (read from source, attack
chain reasoned but not executed). Treat *derived* as high-confidence but
unproven until someone runs it.

Scope: replay resistance, freshness, and caller authentication. Not a
review of the crypto primitives themselves.

## Summary

| ID | Endpoint | Issue | Severity | Basis | Status |
|---|---|---|---|---|---|
| [V-1](#v-1) | `/qualify_submit` | Zero-state accepts an empty submission — qualification obtainable without ever running the SDK | **High** | verified | ✅ **FIXED** |
| [V-2](#v-2) | `/certify_ak_of_attester` + `/certify_ak` | Unauthenticated ACTIVATE oracle → anyone can force re-certification, revoking the live Attester cert | **High** | derived | open |
| [V-3](#v-3) | `/certify_ak_of_attester` | `DELIVER_VERIFIER` persists an arbitrary certificate with zero validation | **High** | verified | open |
| [V-4](#v-4) | `/qualify` + `/qualify_submit` | Challenge is not consumed — valid submission replayable within the window | Medium | verified | ✅ **FIXED** |
| [V-5](#v-5) | `/appraise` | `verifier_challenge_nonce` not consumed → whole evidence bundle replayable within the window | Medium | verified | ✅ **FIXED** |
| [V-6](#v-6) | `/certify_ak_of_attester` | `FETCH` hands the Attester's **EK certificate** to any caller | Medium | verified | open |
| [V-7](#v-7) | `/nonce`, `/qualify` | Unauthenticated state reset → trivial DoS of an in-flight round | Low–Medium | verified | open |
| [V-8](#v-8) | `/certify_ak_of_attester` | `DELIVER_RP` forgeable once the EK cert is known (via V-6) | Medium | derived | open |
| [V-9](#v-9) | `/appraise` | Zero-length nonce matched a fresh Verifier's zero-length challenge | **High** | verified | ✅ **FIXED** |

**The common root cause** in V-1, V-4 and V-5 is the same: state that should
be *single-use* is left in place after use. `/certify_ak` already gets this
right — `certify_ak_pending_take()` copies out and clears in one step. The
qualification and nonce paths do not.

**The common root cause** in V-2, V-3, V-6 and V-8 is that
`/certify_ak_of_attester` has **no caller authentication of any kind** on any
of its four legs. It was designed on the assumption that only the RP would
ever call it, but nothing enforces that.

---

## V-1 — `/qualify_submit` accepts an empty submission against a zeroed state {#v-1}

**Severity: High. Basis: verified. Status: FIXED.**

> **Fix applied.** `charra_rp_qualification_check()`
> (`src/core/charra_rp_qualification.c`) now rejects outright when no
> challenge is outstanding:
> ```c
> if (state->golden_log == NULL || state->golden_log_len == 0) {
>     return CHARRA_RC_VERIFICATION_FAILED;
> }
> ```
> Placed in the primitive rather than the call site so every caller
> inherits it. Regression test added
> (`tests/test_rp_qualification.c:test_no_outstanding_challenge_rejects_empty_submission`,
> covering both a fresh state and a consumed one); the original probe that
> demonstrated the bug now reports `rejected`.

`charra_rp_qualification_check()` (`src/core/charra_rp_qualification.c:70`)
has no guard for "no challenge is outstanding":

```c
bool log_matches = submitted_log_len == state->golden_log_len &&
        (submitted_log_len == 0 || memcmp(...) == 0);
bool pcr_matches = memcmp(submitted_pcr_digest, state->golden_pcr, 32) == 0;
```

A Verifier that has never served `/qualify`, or that served one and freed it,
has `qualification_state` all zeros — `golden_log_len == 0`, `golden_pcr` 32
zero bytes. (`charra_rp_qualification_state_free()` ends in
`memset(state, 0, sizeof(*state))`.)

Submitting `submitted_redacted_log_len = 0` and a 32-zero-byte
`submitted_pcr_digest` therefore satisfies **both** comparisons.

Proved against the compiled `charra_rp_qualification.o`:

```
check() on a ZEROED state with empty log + zero digest -> SUCCESS (qualified!)
state.qualified = true
```

**Reachability.** The two gates in front of it
(`verifier_qualify.c:211-274`) still apply: the submitter needs an AK
certificate chaining to that Verifier's CA, and a valid signature over
`submitted_pcr_digest`. Neither blocks this — an RP signs whatever digest it
chooses, and 32 zero bytes is a perfectly signable digest. So **any RP
holding a valid AK certificate can qualify without ever calling `/qualify`
or executing the redaction SDK.**

**Impact.** Qualification exists solely to prove the RP runs the correct
`PATH_Clean` SDK. The Verifier never inspects `log_r` content
(`verifier_appraise.c` — Step 3b has no log term, by design). So the entire
privacy guarantee — that real file paths are redacted before evidence
leaves the RP — rests on this handshake, and this bypasses it.

**Proposed fix.** Reject when no challenge is outstanding:

```c
if (state->golden_log == NULL || state->golden_log_len == 0) {
    return CHARRA_RC_VERIFICATION_FAILED;   /* nothing was ever issued */
}
```

Add a regression test asserting a zeroed state rejects an empty submission.

---

## V-2 — Unauthenticated ACTIVATE oracle enables forced re-certification {#v-2}

**Severity: High. Basis: derived** (each step read in source; chain not executed).

`/certify_ak_of_attester` performs **no caller authentication** on any leg
(`src/attester.c:1028-1300` — no chain check, no signature check, no
fingerprint check anywhere in the handler). The `ACTIVATE` leg will run
`Esys_ActivateCredential` on *any* credential blob presented by *any* caller
and return the recovered secret in plaintext.

That turns the Attester into a decryption oracle for its own EK, which is
exactly the possession proof `/certify_ak`'s CONFIRM leg relies on.

**Attack chain — no privileged position required, only network reach:**

```
1. attacker → Attester   FETCH
                         ← EK cert, AK public key, AK name        (V-6, unauthenticated)

2. attacker → Verifier   /certify_ak CHALLENGE
                           { subject = ATTESTER, ek_cert, ak_pub, ak_name }
                         ← credential_blob, wrapped_secret

3. attacker → Attester   ACTIVATE { credential_blob, wrapped_secret }
                         ← secret                                  ← the oracle

4. attacker → Verifier   /certify_ak CONFIRM { ek_cert, secret }
                         ← new ak_certificate
                         …and charra_ak_state_renew() REVOKES the prior record
```

Step 4's revocation is the payload (`verifier_certify_ak.c:469` — *"record
the issuance, revoking any prior one for this identity"*).

**Impact.** The RP's cached Attester certificate for that Verifier is now
revoked. Step 3b item 1 calls
`charra_ak_state_check_serial_valid()`, finds the serial revoked, and votes
NO. Every subsequent attestation against that Verifier fails until the RP
re-provisions. Repeating the loop keeps it failing — **a complete,
sustained attestation DoS.**

This is precisely the attack class the two-leg `/certify_ak` redesign
eliminated (see `CHARRA_V2_NOTES.md`, *"/certify_ak is now a two-leg
handshake"*). That fix protected the **RP's** identity, which is safe because
the RP is a client and exposes no activation service. The Attester
reintroduces the hole by offering one to anyone.

**Proposed fix.** Options, roughly in order of preference:

1. Authenticate `/certify_ak_of_attester` — the Attester should only accept
   these legs from the RP (DTLS-RPK peer key, or an RP signature over the
   request).
2. Bind ACTIVATE to an outstanding, RP-initiated exchange rather than
   serving arbitrary blobs.
3. Rate-limit / require operator approval for re-certification of an
   identity that already holds a valid certificate.

Worth noting independently: **revoke-on-renew is itself the weapon.** Making
issuance additive — leaving the prior certificate valid until it expires —
would blunt this and several related attacks.

---

## V-3 — `DELIVER_VERIFIER` persists an unvalidated certificate {#v-3}

**Severity: High. Basis: verified** (read directly; no validation exists).

`src/attester.c:1260-1262`:

```c
charra_r = charra_io_write_file(out_path,
        is_rp_leg ? ak_cert_der : req.ak_certificate,
        req.ak_certificate_len);
```

On the `DELIVER_VERIFIER` path (`is_rp_leg == false`) the request's
`ak_certificate` bytes go **straight to disk**. There is no chain
verification, no signature check, no check that the embedded key is the
Attester's AK, and no possession proof on this leg at all.

The DTO comment says the preceding ACTIVATE "already supplied the possession
proof" — but the two legs are separate CoAP requests with **nothing binding
them together**. A caller can send `DELIVER_VERIFIER` on its own.

**Impact.** Any party that can reach the Attester's port can overwrite
`state/attester/ak-certificates/attester-ak-certificate-verifier.der` with
arbitrary bytes. The Attester then serves those bytes in every `/attest`
response. Denial of service; and it silently corrupts the Attester's view of
its own identity.

Partly mitigated in the current attestation path by an accident of design:
the RP **substitutes its own per-Verifier cached copy** when building
evidence (`rp_evidence.c:393-396`), so the Attester's corrupted copy is not
what reaches a Verifier. That is fragile — it depends on RP-side caching
that exists for an unrelated reason.

**Proposed fix.** Before persisting, verify the certificate chains to a
known CA and that its public key matches the Attester's own AK. Bind
DELIVER_VERIFIER to the preceding ACTIVATE (e.g. require the recovered
secret to be echoed back). Plus the authentication in V-2.

---

## V-4 — Qualification challenge is not consumed {#v-4}

**Severity: Medium. Basis: verified. Status: FIXED.**

> **Fix applied.** `coap_qualify_submit_handler()`
> (`src/verifier/verifier_qualify.c`) now captures the result and the
> granted expiry, then frees `qualification_state` **before** branching —
> so the challenge is spent whether the submission passed or failed. A
> replayed submission then hits the V-1 guard (no challenge outstanding)
> and is rejected. A genuine retry needs a fresh `/qualify`.

`qualification_state` is freed only at the **start of the next `/qualify`**
(`verifier_qualify.c:71`), never after a submission is checked. A captured,
valid `/qualify_submit` body can therefore be replayed any number of times
while the same challenge remains outstanding, renewing the grant on each
replay.

Lower impact on its own — a replay renews a grant the legitimate RP had
already earned — but it compounds V-1, and it is the same class of defect.

**Proposed fix.** Consume on use: free `qualification_state` once
`charra_rp_qualification_check()` has been consulted, pass or fail. Mirrors
`certify_ak_pending_take()`.

---

## V-5 — `verifier_challenge_nonce` is not consumed {#v-5}

**Severity: Medium. Basis: verified. Status: FIXED.**

> **Fix applied.** Step 3a item 3 (`src/verifier/verifier_appraise.c`) now
> snapshots the expected nonce for its failure diagnostic, then zeroes
> `verifier_challenge_nonce` and its length immediately after the
> comparison — pass or fail. A replayed bundle then finds no challenge
> outstanding and fails item 3.
>
> The fix **required** adding a `verifier_challenge_nonce_len != 0` term to
> the comparison; without it, consuming the nonce would have converted
> V-9 from a fresh-start-only window into a permanent one. See V-9.

`verifier_challenge_nonce` (`src/verifier.c:88`) is written only in
`coap_nonce_handler()` and compared in `verifier_appraise.c:466-468`. It is
**never cleared after a successful appraisal** and is **not bound to a
session or peer** — it is a plain file-scope global.

So the window between one `/nonce` call and the next accepts unlimited
replays of a captured `/appraise` bundle: Step 3a item 2 passes (the
signature is genuine) and item 3 passes (the nonce is still current).

**Impact.** Bounded. The replayed evidence is genuine, so an attacker
re-asserts a true statement rather than forging a false one — but it defeats
freshness, which is the only thing item 3 exists to provide. Requires an
on-path position to capture the bundle.

Related to, but distinct from, bug #6 in `CHARRA_V2_NOTES.md`. Bug #6 is
about *spurious failures* when two RPs interleave; this is about *replay
acceptance*. Fixing #6 properly (per-peer pending-nonce state) would close
both.

**Proposed fix.** Zero `verifier_challenge_nonce` once consumed by an
appraisal. Ideally key it per peer/session rather than one global.

---

## V-6 — `FETCH` discloses the Attester's EK certificate to anyone {#v-6}

**Severity: Medium. Basis: verified.**

`/certify_ak_of_attester` `FETCH` returns `ek_certificate`, `ak_public_key`
and `ak_name` to any caller, unauthenticated.

The EK certificate is a **permanent, unique hardware identifier for that
TPM.** The design is explicit that it must not spread — `CHARRA_V2_NOTES.md`
and `DATA_FLOW.md` both record that it deliberately stops at the RP and is
never forwarded to a Verifier, precisely because it is a stronger identifier
than any file path the redaction protects.

Handing it to unauthenticated callers undermines that. It is also the
enabling precondition for V-2 and V-8.

**Proposed fix.** Authenticate FETCH (same mechanism as V-2).

---

## V-7 — Unauthenticated state reset on `/nonce` and `/qualify` {#v-7}

**Severity: Low–Medium. Basis: verified.**

Both handlers unconditionally overwrite Verifier-global state:

- `/nonce` regenerates `verifier_challenge_nonce` and overwrites
  `last_request`
- `/qualify` frees and regenerates `qualification_state`

Neither authenticates the caller. An attacker calling either in a loop
invalidates whatever round the legitimate RP has in flight: its
`/appraise` fails Step 3a item 3, or its `/qualify_submit` no longer matches
the golden answer.

**Impact.** Cheap, sustained DoS of attestation. No forgery.

**Proposed fix.** Per-peer state rather than globals (the real fix for bug
#6), which removes the cross-talk entirely.

---

## V-8 — `DELIVER_RP` forgeable once the EK certificate is known {#v-8}

**Severity: Medium. Basis: derived.**

`DELIVER_RP` does require `ActivateCredential` plus an authenticated AES-GCM
decrypt, so it is meaningfully stronger than V-3. But the credential blob is
produced by `MakeCredential`, which needs only the **EK public key** (in the
EK certificate) and the **AK name** — both handed out by the unauthenticated
`FETCH` leg (V-6).

An attacker can therefore construct a valid blob against a key it chooses,
AES-GCM-encrypt arbitrary bytes under it, and have the Attester decrypt and
persist them to `attester-ak-certificate-rp.der`.

**Impact.** Same as V-3 for the RP-issued certificate slot. Requires more
work (a MakeCredential implementation) but no secrets.

**Proposed fix.** As V-3: validate the certificate before persisting, and
authenticate the caller.

---

## V-9 — Zero-length nonce matched a fresh Verifier's zero-length challenge {#v-9}

**Severity: High. Basis: verified. Status: FIXED.**

Found while fixing V-5, and pre-existing — not introduced by it.

`verifier_challenge_nonce_len` is initialised to `0` (`src/verifier.c:89`)
and the unmarshaler bounds-checks `verifier_nonce_len` only from above, so a
zero-length nonce is accepted off the wire. The original Step 3a item 3 test
was:

```c
res.verifier_nonce_len == verifier_challenge_nonce_len &&
memcmp(res.verifier_nonce, verifier_challenge_nonce,
       verifier_challenge_nonce_len) == 0
```

Against a Verifier that had **not yet served any `/nonce` call**, an
`/appraise` carrying `verifier_nonce_len = 0` gives `0 == 0` and
`memcmp(_, _, 0) == 0` — both true. Item 3 passes with no freshness proof
whatsoever. Structurally identical to V-1: an all-zero "expected" value that
an all-zero submission matches by accident.

Narrow in practice (only before the first `/nonce` on a given Verifier
process), but it would have become **permanent** once V-5's consume-on-use
landed, since every appraisal thereafter leaves the length at 0. That is why
the guard was mandatory rather than defensive.

**Fix applied.** Added `verifier_challenge_nonce_len != 0` as the leading
term, so "no challenge outstanding" can never satisfy the comparison. The
failure diagnostic now distinguishes *no challenge outstanding* from *wrong
nonce*.

**Follow-up worth considering:** the same accidental-match shape has now
appeared three times (V-1, V-9, and the V-5 interaction). It is worth
auditing every remaining `memcmp`-against-stored-state comparison for the
zero-length/zero-value case — `constant_time_equal()` in
`verifier_certify_ak.c` is guarded by an explicit length check and is fine,
but the pattern deserves a sweep rather than case-by-case discovery.

---

## Not findings — checked and sound

Recorded so the same ground is not re-covered.

- **Impersonation via a stolen certificate + public key.** RP-B replaying
  RP-A's `ak_certificate_rp` and `rp_public_key` passes Step 3a items 1 and
  1b (both are public data, and `ek_fingerprint` resolves to RP-A) but
  **fails item 2**: it cannot produce a signature verifying under RP-A's
  public key. The AK private key is TPM-resident and non-exportable. The
  certificate is copyable; the signature is not.
- **`/certify_ak` CONFIRM replay.** `certify_ak_pending_take()` copies the
  entry out and clears it in one operation, so a replayed CONFIRM finds no
  live challenge and gets `4.01`. Correct, and the model the other paths
  should follow.
- **`/certify_ak` CHALLENGE flooding.** The 8-slot table evicts the
  soonest-expiring entry when full, and a per-fingerprint slot is reused
  rather than duplicated, so an attacker cannot cheaply evict a specific
  victim's pending challenge. TTL is 60s.
- **The RP's own identity is not vulnerable to V-2.** The RP is a client and
  exposes no activation service, so there is no oracle to complete a CONFIRM
  on its behalf. The asymmetry with the Attester is entirely due to
  `/certify_ak_of_attester` being a server resource.
- **`/attest` replay against the RP.** The RP checks `Quote_a`'s
  `qualifyingData` against the nonce it generated for that cycle
  (`rp_evidence.c` Step 2a item 3), so a stale quote is rejected.

---

## Suggested order of work

1. ~~**V-1**~~ — done. ~~**V-4 / V-5**~~ — done, and V-9 fixed alongside.
2. **V-2 / V-6 / V-3 / V-8 together** — all four dissolve if
   `/certify_ak_of_attester` authenticates its caller. Worth designing once
   rather than patching four times. **This is now the top priority**: V-2 is
   a sustained attestation DoS reachable by anyone with network access.
3. **V-7** — per-peer state instead of globals. Naturally bundled with a
   proper fix for bug #6 in `CHARRA_V2_NOTES.md`.

### Still outstanding for the fixed items

The three fixes above are unit-tested (V-1) or verified by inspection and a
clean build (V-4, V-5, V-9), but **none has been exercised in a live
multi-Verifier run**. Before considering them closed, run
`./run_live_test.sh` and confirm:

- a normal cycle still qualifies and attests (consume-on-use has not broken
  the happy path — in particular that RP calls `/nonce` exactly once per
  `/appraise`, which it does today, so nothing legitimately reuses a spent
  challenge);
- a second `/appraise` replayed against the same nonce is now rejected;
- `/qualify_submit` replayed twice is rejected the second time.

Consider also revisiting **revoke-on-renew** (`charra_ak_state_renew()`).
It is the mechanism that converts several of these from nuisance to DoS.
Letting a superseded certificate remain valid until its own `notAfter` would
remove that amplification without weakening revocation that matters.

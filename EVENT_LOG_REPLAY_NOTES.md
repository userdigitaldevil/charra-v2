# Event log replay — implementation reference

Untracked (not in `.gitignore`, not committed — delete or `git add` at will).
Tracks every function and logic change added on top of upstream CHARRA-v2 for
IMA event log replay. Update this alongside the code as the RP side lands.

## New files

### `src/core/charra_event_log.h` / `.c`

The shared replay module. `charra_replay_ima_log()` is meant to be called
identically by the Relying Party (on the raw log) and the Verifier (on the
redacted log) — same function, different bytes in.

| Function | Signature | Purpose |
|---|---|---|
| `charra_pcr_reset` | `void charra_pcr_reset(charra_pcr_accumulator* acc)` | Zero an accumulator — a PCR's power-on state. |
| `charra_pcr_extend` | `CHARRA_RC charra_pcr_extend(charra_pcr_accumulator* acc, const uint8_t* digest, uint16_t digest_len)` | One extend: `acc := SHA256(acc \|\| digest)`. Zero-pads digests shorter than 32 bytes (SHA-1 → SHA-256 bank). **The invariant that must never diverge between RP and Verifier.** |
| `charra_event_log_ima_detect_digest_len` | `CHARRA_RC charra_event_log_ima_detect_digest_len(const uint8_t* log, uint32_t log_len, uint16_t* digest_len_out)` | Recovers whether template digests are 20 (SHA-1) or 32 (SHA-256) bytes by trial-parsing, since the format doesn't record it (it's a boot-time kernel choice, `ima_hash=`). |
| `charra_replay_ima_log` | `CHARRA_RC charra_replay_ima_log(const uint8_t* log, uint32_t log_len, uint32_t target_pcr_index, uint8_t pcr_out[TPM2_SHA256_DIGEST_SIZE])` | **The public entry point.** Parses every entry, extends the ones matching `target_pcr_index`, returns the resulting PCR value. Logs a warning (not an error) if a non-empty log has zero matching entries — likely sign of a PCR-index mismatch (e.g. non-default `CONFIG_IMA_MEASURE_PCR_IDX`). |
| `read_u32` *(static)* | `uint32_t read_u32(const uint8_t* p)` | Reads a little-endian `uint32` byte-wise — avoids relying on host cast/alignment behavior. |
| `parse_next_entry` *(static)* | `CHARRA_RC parse_next_entry(const uint8_t* log, uint32_t log_len, uint32_t* offset, uint16_t digest_len, charra_event_log_entry* out)` | Parses one TLV entry (`pcr_index`, `template_digest`, `template_name`, `template_data`), advances `*offset`. Every length check written as `need > log_len - offset` (not `offset + need > log_len`) so a hostile length field can't overflow past the check. Rejects the legacy `"ima"` template outright rather than guessing its unprefixed layout. |
| `log_parses_at` *(static)* | `bool log_parses_at(const uint8_t* log, uint32_t log_len, uint16_t digest_len)` | Whole-log trial parse: true iff every entry is well-formed and the last one ends exactly at `log_len`. Backs digest-length detection. |

Constants: `CHARRA_IMA_PCR_INDEX` (10, Linux's default), `CHARRA_IMA_TEMPLATE_NAME_MAX` (64).

### `tests/test_event_log.c`

Standalone test suite, no TPM/network/`/sys` required — logs synthesized in
memory, expected PCR computed independently via a hand-written reference
extend so the tests don't just assert against themselves. 29 assertions,
covering: empty log, single/multiple entries, order-sensitivity, dropped
entries, `pcr_index` filtering (mixed-PCR logs), **redaction preserves
replay** (different `template_data`, same PCR), empty `template_data`,
SHA-1 zero-padding, malformed/truncated logs, hostile length fields (no
overflow), legacy `ima` template rejection, bad arguments.

Run with `make test`.

## Modified files

### `Makefile`

- `charra_event_log` added to the `core` object list.
- `test` / `test_event_log` targets added, building `tests/test_event_log.c`
  against the same `OBJECTS`.

## Scope: replay only, deliberately

`charra_replay_ima_log()` is currently **standalone and unwired**. It takes
log bytes in and returns one PCR value out. It does not know about PCR0-7,
`reference-pcrs.txt`, or the signed composite `pcrDigest`, and nothing in the
existing binaries calls it yet.

An earlier iteration also wired it into `verifier.c` and added a
`replayed_pcr_value` override to
`charra_check_pcr_digest_against_reference()` in `charra_rim_mgr.c`, so the
replayed PCR10 was folded together with reference PCR0-7 and compared against
the signed digest. **That layer was removed** — `src/verifier.c`,
`src/verifier_old.c`, `src/core/charra_rim_mgr.{c,h}` are back to upstream,
unmodified. If the composite check is wanted later, the shape that worked was:
add `(const uint8_t* replayed_pcr_value, uint32_t replayed_pcr_index)` to
`charra_check_pcr_digest_against_reference()`, substitute that value into each
candidate reference set before its digest is computed, and pass NULL from
`verifier_old.c` to preserve original behaviour.

## Verified so far

- `charra_event_log.c` compiled standalone (stub TSS2/mbedTLS headers, real
  SHA-256 via CommonCrypto) and all 29 tests pass.
- Cross-checked against an independent Python re-implementation on the same
  423-byte 4-entry log: both produce `0269fe49...2b49efd` for PCR10, byte for
  byte.
- Raw vs redacted log (different paths, 153 vs 140 bytes) replay to the same
  PCR10, confirming redaction of `template_data` does not disturb the chain.
- Compiled only against stub headers so far; a first `make` in the
  Docker/Linux build is still needed to confirm it builds against the real
  TSS2 headers.

## Target design (agreed with supervisor)

Trust model: **the Verifier trusts the RP.** The RP is responsible for
validating the Attester's evidence; the Verifier does not re-check it.

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

### Why software replay + TPM2_Quote (rather than extending a real PCR)

Extending the RP's actual PCR10 was rejected: PCRs 0-15 are not resettable on
a PC Client TPM, so it would work only once per boot; it would need one TPM
round-trip per log entry (minutes for a large log); and it would need locking
against concurrent attestations. It also buys nothing cryptographically --
the RP's *software* chooses which digests reach the TPM either way, so a
dishonest RP produces a validly-signed wrong answer regardless.

The value of TPM2_Quote over TPM2_Sign is not that the TPM witnesses the
replay -- it is that the quote structure *also* carries the RP's own PCR
values, attesting the RP's software state in the same signed object. Putting
X in `qualifyingData` (the same field the Attester's quote uses for its nonce)
binds the redacted log to that quote in one TPM call.

### Consequences of recomputing template_digest

Because the RP recomputes `template_digest'` from redacted `template_data`,
the replayed PCR10 **can no longer match** the Attester's TPM-sealed
`pcrDigest` — not by policy but mathematically, since the digests differ by
construction. The TPM is therefore not in the Verifier's chain of trust for
the PCR10 property; the guarantee is "the RP vouches for this," anchored by
the RP's own TPM rather than the Attester's. This was a deliberate decision.

Note this also invalidates an earlier argument for keying appraisal off
`template_digest` instead of `file_hash`: that reasoning depended on
`template_digest` being TPM-anchored, which it no longer is. Both fields are
equally RP-controlled now, so appraisal can read `file_hash` directly.

### Privacy note

The Attester's EK certificate is a permanent unique identifier for that
physical TPM. It must stop at the RP — forwarding it to the Verifier would
leak a stronger identifier than any file path the redaction step protects.
The RP's *own* EK cert going to the Verifier is intentional and fine: the RP
is known infrastructure the Verifier is meant to recognise.

## Deliberately out of scope (for now)

- **Freshness / replay protection on the Verifier side.** Accepted decision,
  not an oversight. `rp_signature` covers only `X`, which is not time-varying,
  so a recorded `(redacted_log, rp_signature)` pair remains valid
  indefinitely — the Verifier cannot distinguish a fresh attestation from a
  replayed recording.

  Note the existing nonce cannot be repurposed for this: it is generated by
  the **RP** (`relying_party.c:246`) and pushed to the Verifier's passive
  `"nonce"` endpoint (`verifier.c:253`). A nonce only proves freshness to
  whoever generated it, so a Verifier receiving one from the RP learns
  nothing — an attacker replays the old nonce along with everything else.

  If revisited, the Verifier must contribute its own unpredictable challenge
  *before* the RP signs: RP signs `SHA256(X || challenge)`, or uses
  `TPM2_Quote` over `X` with the challenge as qualifyingData (= `Quote_R`
  from the presentation slides, which additionally attests the RP's own PCR
  state). Either way this inverts the current CoAP direction and needs a new
  round-trip.

## Open / undecided
- **Reference PCRs for the RP.** Now required: checking `Quote_R.pcrDigest`
  means the Verifier needs known-good boot PCR values *for the RP machine* —
  a second reference file, distinct from any Attester reference PCRs. Note
  this is the same `charra_check_pcr_digest_against_reference()` machinery
  that was reverted earlier, now needed again but pointed at the RP.
- **Which PCRs the RP quotes** — its boot PCRs 0-7 presumably; needs deciding
  and must match whatever the RP's reference file records.
- **AK provisioning**: how the AK is bound to the EK (Privacy CA issuing an AK
  cert, vs `TPM2_MakeCredential`/`ActivateCredential` challenge-response).
  Affects both Attester and RP.
- **Attester key is not currently an AK**: `charra_key_mgr.c:32` calls
  `tpm2_create_primary_key_rsa2048()`, creating a primary key on demand with
  no certification path. Needs replacing with a real persistent AK.
- **Manufacturer root CA trust store** — needed by whoever validates EK certs.
  No config, file, or loading code exists.
- **Whitelist/blacklist semantics**: deny-by-default (miss = fail) vs
  allow-by-default (miss = inconclusive); whether a miss is a hard failure or
  a flag; where the reference hash list lives and its format.
- **Blind spot in the PCR10-based integrity check**: replay only folds entries
  tagged for the target PCR, so entries for *other* PCRs could be added,
  removed or altered without affecting `X`. Accepted if the check is scoped to
  PCR10 integrity only; a hash over the whole redacted buffer would close it.
- **Nothing in the codebase does certificate handling yet** — no X.509
  parsing, no chain validation, no EK/AK anywhere. All new.

# CHARRA-v2 — what changed, and what we have now

| | baseline (`a6c4739`) | now (`fresh`) |
|---|---|---|
| Source files in `src/` | 35 | 85 |
| Lines of C | ~8 000 | ~17 400 |
| Test suites | 0 | 16 (358 assertions) |
| Binaries | 5 | 6 |
| CoAP resources | 4 | 7 |
| Marshalled payloads | 2 | 10 |

Counting **payloads that travel on their own**: nine `msg_*_dto` messages
plus the signed verdict record, which is not a `msg_` DTO. It excludes
`msg_verifier_endpoint_dto`, which is an array element inside the
`/get_verifiers` response rather than a message.

---

## 1. Factorisation

The baseline had three monolithic role files. Each is now a thin `main()`
plus a directory of single-responsibility modules.

| File | Before | After | Split into |
|---|---|---|---|
| `src/relying_party.c` | 1191 | 510 | `src/rp/` — 15 files, 2816 lines |
| `src/verifier.c` | 678 | 245 | `src/verifier/` — 11 files, 1669 lines |
| `src/attester.c` | 505 | 196 | `src/attester/` — 9 files, 957 lines |

What each `main()` keeps: CLI parsing, global definitions, CoAP context
setup, resource registration, signal handling. Everything else moved out.

### The module directories

**`src/rp/`** — the orchestrator pipeline, one module per cycle phase.

| Module | Owns |
|---|---|
| `rp_attestation` | The cycle itself: `/get_verifiers`, `/attest`, the per-Verifier thread fan-out, the majority vote. |
| `rp_evidence` | Step 2a local appraisal, Step 2b redaction, building each Verifier's evidence message. |
| `rp_qualification` | The `/qualify` + `/qualify_submit` handshake and its client-side deadline. |
| `rp_signing_key` | Every TPM interaction: AK_r derivation, the PCR replay, `Quote_r`. |
| `rp_coap` | One generic request/response exchange helper, replacing per-endpoint duplicates. |
| `rp_config` | CLI parsing, effective-configuration logging, interruptible sleep. |
| `rp_stats` | Benchmark statistics. |
| `rp_shared.h` | The cross-module globals, declared once. |

**`src/verifier/`** — one module per resource group, plus shared state.

| Module | Owns |
|---|---|
| `verifier_nonce` | `/nonce`: this Verifier's own freshness challenge for `Quote_r`, and the round delimiter in its log. |
| `verifier_appraise` | `/appraise`: Steps 3a and 3b, then the signed verdict. The only module that reaches a decision. |
| `verifier_qualify` | `/qualify` + `/qualify_submit`: fabricates the synthetic challenge log, keeps the golden redaction, checks the RP's submission. |
| `verifier_qualified_rps` | The grant file **every** Verifier reads and writes — the RP qualifies once and all of them honour it. |
| `verifier_util` | The libcoap release callback that frees a marshalled response once the PDU has been sent. |
| `verifier_shared.h` | Per-round state one module produces and another consumes — the nonce, the paths. Nothing a single module owns end to end appears here. |

**`src/attester/`** — one module per CoAP resource, plus the log machinery.

| Module | Owns |
|---|---|
| `attester_attest` | `/attest`: produces `Quote_a` over the requested PCR selection with the TPM's restricted key. |
| `attester_result` | `/attest_result`: receives the RP's Step 2a verdict. Advisory — nothing depends on it, but a rejected device can log, alert or re-measure instead of assuming success. |
| `attester_ima_log` | The IMA measurement log: ASCII↔binary conversion, caching, and replay into the TPM's real PCRs. |
| `attester_util` | The libcoap release callback shared by both handlers. |
| `attester_shared.h` | The little state that genuinely crosses module boundaries. Deliberately short. |

### Shared logic pulled into `src/core/`

Code that had been duplicated or embedded in role files became shared
modules, so the two sides of every algorithm cannot drift:

`charra_event_log` (replay + Step 2a content checks) ·
`charra_sdk` (redaction) · `charra_synthetic_log` ·
`charra_rp_qualification` · `charra_trusted_keys` · `charra_verdict`.

### Additions to pre-existing modules

One new file — `src/util/hex_util.{h,c}` — plus new functions in
`coap_util`, `crypto_util`, `charra_util`, `cli_util`, `io_util`,
`tpm2_util`, `charra_log` and `charra_marshaling`. They are listed
individually in §4.

---

## 2. CLI reference

### `relying_party` — the only role with a substantial CLI

| Flag | Default | Effect |
|---|---|---|
| `-B, --benchmark` | off | Run the bounded 1..5-Verifier timing sweep and exit, instead of the daemon. |
| `-n, --verifiers=COUNT` | 5 | Verifiers per attestation cycle (1..10). Sets the majority denominator. |
| `-I, --interval=SECONDS` | 15 | Sleep between cycles. |
| `-C, --cycles=COUNT` | 0 | Stop after COUNT cycles. 0 = unbounded. |
| `-D, --duration=SECONDS` | 0 | Stop after roughly SECONDS. 0 = until SIGINT/SIGTERM. |
| `--verifier-timeout=SECONDS` | 6 | Bounds every Verifier-bound round trip (`/nonce`, `/qualify`, `/qualify_submit`, `/appraise`). A timeout counts as a NO vote. The Trust Manager exchange is **not** covered — it has its own fixed 30s timeout with no flag. |
| `--attester-timeout=SECONDS` | 6 | Exceeding it abandons the cycle. |
| `-l, --log-level=LEVEL` | INFO | TRACE…FATAL. |
| `-v, --verbose` | off | Shorthand for DEBUG. |

**Daemon mode is now the default.** The baseline ran one attestation and
exited; `--benchmark` selects the old sweep behaviour.

### `verifier`

| Flag | Default | Effect |
|---|---|---|
| `--qualification-validity=SECONDS` | 180 | How long a passed RP qualification stays valid. Verifier-side only — the RP learns the deadline from the response. |
| `--port=PORT` | 31415 | Listen port. |

Plus the inherited log-level and DTLS-PSK/RPK options.

### `provision_trusted_keys` — new binary

| Flag | Default | Effect |
|---|---|---|
| `--role <name>` | — | Emit **only** `attester` or `relying-party`, headerless, so each TPM is provisioned separately and the fragments concatenated. |
| `--out <path>` | `keys/trusted_keys.txt` | Where to write. |

`--role` is a security boundary, not ergonomics: without it one run emits
both identities, which would put a key the RP's own TPM can derive into the
anchor labelled `attester`.

### `attester`

No new flags. `--port`, log-level and the DTLS-PSK/RPK options are all
inherited from upstream CHARRA and unchanged.

### `trust_manager`

Takes no options beyond `--help`. Port (6000) and config path are compiled
in.

### In practice you pass none of these

`run_daemon.sh` sets every flag above from its own `TUNABLES` block, and
each of those is overridable from the environment. See §6.

---

## 3. Data flow

**See `diagrams/rp_daemon_automaton.svg`** for the full automaton — every
step, guard, abort path, tunable and peer interaction.

The one-paragraph version: the Relying Party is the only active party.
Once per cycle it resolves Verifiers from the Trust Manager, takes evidence
from the Attester **once**, appraises it locally, redacts the log, replays
the redacted log into its own TPM, then fans that single piece of evidence
out to N Verifiers in parallel and takes a majority vote.

```
RP ──/get_verifiers───▶ Trust Manager
RP ──/attest──────────▶ Attester       once per cycle
RP ──/attest_result───▶ Attester       RP's own Step 2a verdict, advisory
RP ──/qualify─────────▶ Verifier k     ┐ only when the grant has lapsed;
RP ──/qualify_submit──▶ Verifier k     ┘ ONE Verifier, the first reachable
RP ──/nonce───────────▶ Verifier i     ┐ once per Verifier,
RP ──/appraise────────▶ Verifier i     ┘ in parallel threads
```

Two structural properties worth stating:

- **Whoever proves replays into a TPM; whoever checks replays in
  software.** The RP replays the Attester's raw log in software (it is
  checking a claim) and the redacted log into PCR 23 of its own TPM (it is
  making one). The Verifier replays the redacted log in software.
- **Attester and Verifiers are pure passive responders.** Neither ever
  initiates a request.

---

## 4. New functions

### `charra_event_log` — the replay primitive, shared by every role

| Function | Purpose |
|---|---|
| `charra_replay_ima_log` | Replays a log into a PCR value. The single shared implementation both RP and Verifier use, so their arithmetic cannot diverge. |
| `charra_event_log_parse_entry` | Parses one TLV entry with overflow-safe bounds checks. |
| `charra_pcr_reset` / `charra_pcr_extend` | The extend primitive, `acc := SHA256(acc ‖ digest)`. |
| `charra_event_log_ima_detect_digest_len` | Recovers whether digests are 20 or 32 bytes — the format does not record it. |
| `charra_verify_log_entries_self_consistent` | Step 2a item 4: each entry's digest matches its data. |
| `charra_verify_log_matches_quote_pcr_digest` | Step 2a item 5: the log replays to the quote's PCR digest. |
| `charra_verify_log_file_hashes_against_policy` | Step 2a item 6: whitelist/blacklist. |
| `charra_replay_ima_log_pcrs` | Replays into several PCRs at once, for a multi-PCR selection. |
| `charra_event_log_entry_file_digest` | Pulls the file-content digest out of one entry's `template_data`. |
| `charra_event_log_append_u32` / `_bytes` | The write side, kept beside the read side so byte order cannot drift between them. |

### `charra_sdk` — the redaction SDK

| Function | Purpose |
|---|---|
| `charra_sdk_redact_ima_log` | Rewrites every entry's path to a salted SHA-256 of that path and recomputes the entry digest. Randomised per call, so it runs once per cycle. |

### `charra_synthetic_log`

| Function | Purpose |
|---|---|
| `charra_synth_generate_ima_log` | Fabricates a well-formed IMA log from `(entries, seed)`. Deterministic — the Verifier needs a challenge whose answer it already knows. |

### `charra_trusted_keys` — the identity mechanism

| Function | Purpose |
|---|---|
| `charra_trusted_keys_check` | The entire identity check: a signing key is trusted **iff** it appears in `keys/trusted_keys.txt`. No CA, no chain, no expiry. |

### `charra_rp_qualification` — the RP access check

| Function | Purpose |
|---|---|
| `charra_rp_qualification_generate` | Fabricates the challenge log and precomputes the golden redaction. |
| `charra_rp_qualification_check` | Byte-for-byte comparison of the RP's submission against the golden answer. |
| `charra_rp_qualification_is_valid` | The gate `/appraise` applies. |
| `charra_rp_qualification_set_validity_seconds` / `_get_validity_seconds` | Pushes `--qualification-validity` into the module after CLI parsing, and reads it back for the log line. |
| `charra_rp_qualification_state_free` | Releases the golden answer. Idempotent. |

### `charra_verdict` — the signed `/appraise` answer

| Function | Purpose |
|---|---|
| `charra_verdict_sign` | Encodes a verdict and signs it with the Verifier's key. |
| `charra_verdict_verify` | One call checking signature, nonce, evidence digest and clock skew. Fail-closed: an unverifiable YES counts as a NO. |

### `src/rp/` — pipeline entry points

| Function | Purpose |
|---|---|
| `get_verifiers` | Resolve this cycle's Verifier IDs. Abandons the cycle on a short answer. |
| `get_evidence` | One `/attest` round trip, then Step 2a, then `/attest_result`. |
| `rp_send_attestation_result` | Sends the Step 2a verdict to the Attester. Only ever called from `get_evidence`, never from a response handler — that would re-enter libcoap mid-dispatch. |
| `charra_rp_appraise_evidence` | Step 2a's six checks. All run even after one fails, so one pass reports everything. |
| `charra_rp_prepare_evidence` | Step 2b: redact, then replay into the TPM. Once per cycle. |
| `charra_rp_build_evidence_message` | Per-Verifier message assembly, including that Verifier's `Quote_r`. |
| `charra_rp_release_evidence` / `charra_free_attestation_response` | Release what a cycle allocated. |
| `rp_replay_log_into_pcr` | Reset PCR 23, then one extend per entry. Once per cycle — quoting does not consume a PCR. |
| `rp_quote_pcr_with_ak` | `TPM2_Quote` over PCR 23 under one Verifier's nonce. Once per Verifier. |
| `rp_sign_with_ak` | Signs a caller-supplied digest with AK_r. Used only by qualification. |
| `rp_perform_qualification_handshake_once` | The `/qualify` + `/qualify_submit` exchange. |
| `get_attestation_results` | Thread fan-out, join, majority vote, run summary. |
| `get_attestation_results_thread` | One Verifier's whole exchange: `/nonce`, quote, `/appraise`, verdict check. One thread each. |
| `rp_coap_exchange` | One generic CoAP request/response, replacing per-endpoint duplication. |
| `rp_interruptible_sleep` | Sliced sleep so a stop request is acted on promptly. |
| `parse_rp_command_line` / `rp_log_effective_configuration` | CLI parsing, and one log line stating the configuration actually in force. |

### `src/attester/`

| Function | Purpose |
|---|---|
| `coap_attest_handler` | `/attest`: derives AK_a, quotes the requested PCRs, attaches the IMA log. |
| `coap_attest_result_handler` | `/attest_result`: logs the RP's Step 2a verdict. |
| `charra_get_ima_log` | Returns the binary IMA log, loading and caching it on first use. The cached bytes are the ones the PCRs were extended from, so every response must carry exactly those. |
| `charra_ima_log_ascii_to_binary` | Converts an ASCII IMA log into the binary `ima-ng` layout, rebuilding `template_data` and recomputing `template_digest` so the result satisfies its own self-consistency check by construction. |
| `charra_extend_pcrs_from_binary_log` | Extends every entry of a binary log into the PCR it names — how the simulator's PCR 10 comes to hold a value the log explains. |
| `attester_release_data` | libcoap release callback, freeing a response buffer once the PDU has been sent. |

### `src/verifier/`

| Function | Purpose |
|---|---|
| `coap_nonce_handler` | Issues this Verifier's own freshness challenge. |
| `coap_appraise_handler` | Steps 3a and 3b, then a signed verdict. |
| `coap_qualify_handler` / `coap_qualify_submit_handler` | The two halves of the access check. |
| `verifier_qualified_rps_add` / `_is_qualified` / `_fingerprint` | The grant file every Verifier shares, keyed by RP key fingerprint. |
| `release_response_data` | libcoap release callback, freeing a marshalled response once sent. |

### `charra_marshaling` — seven new message pairs

The baseline marshalled two messages. Each new one is a
`charra_marshal_*` / `charra_unmarshal_*` pair; see §5 for what each
carries.

| Pair | Message |
|---|---|
| `charra_marshal_rp_evidence` / `charra_unmarshal_rp_evidence` | `/appraise` request — the largest of them |
| `charra_marshal_attestation_result` / `charra_unmarshal_attestation_result` | `/attest_result` |
| `charra_marshal_qualify_response` / `charra_unmarshal_qualify_response` | `/qualify` response |
| `charra_marshal_qualify_submit_request` / `charra_unmarshal_qualify_submit_request` | `/qualify_submit` request |
| `charra_marshal_qualify_submit_response` / `charra_unmarshal_qualify_submit_response` | `/qualify_submit` response |
| `charra_marshal_get_verifiers_request` / `charra_unmarshal_get_verifiers_request` | `/get_verifiers` request |
| `charra_marshal_get_verifiers_response` / `charra_unmarshal_get_verifiers_response` | `/get_verifiers` response |

The `/get_verifiers` pair replaced something rather than adding to it: the
baseline sent a raw C `int` array and the Trust Manager `memcpy`'d it into
a stack VLA sized by the received length. Every unmarshaller now
bounds-checks each field against its destination `sizeof` before copying.

### `src/util` — additions

| Function | Purpose |
|---|---|
| `charra_crypto_pk_sign_file` / `_verify_file` | Generic mbedTLS `pk` sign/verify for file-backed (non-TPM) keys — currently the Verifier's verdict key. |
| `charra_crypto_verify_quote_signature_mbedtls` | A software cross-check of a quote signature, independent of any TPM. |
| `charra_verify_tpm2_quote_signature_with_tpm_logged` | The TPM-side check, with the outcome logged rather than silently folded in. |
| `charra_hex_encode` / `_prefix` / `charra_hex_decode` | Lowercase hex. `_prefix` truncates into a fixed buffer rather than overflowing — every key fingerprint in a log goes through it. |
| `charra_coap_server_start` / `_run` / `_stop` / `_log_config` | The server lifecycle each role's `main()` used to open-code. |
| `charra_coap_get_payload` | One payload accessor for every handler; also rejects an empty body. |
| `charra_coap_log_peer_address` | Logs who a request came from. |
| `charra_cli_parse_uint_arg` | Bounded unsigned option parsing that logs its own reason, naming the option, so callers only branch on success. |
| `charra_cli_flag_was_given` / `_mark_given` / `charra_cli_default_tag` | Whether an option actually appeared on the command line, so the configuration log can mark the rest "(default)". |
| `charra_log_set_thread_prefix` | Tags a thread's log lines (`[V3:5686]`), so five concurrent Verifier threads do not interleave into one indistinguishable stream. |
| `charra_log_level_to_str` / `charra_rc_describe` | Human-readable names for a log level and a `CHARRA_RC`. |
| `charra_io_write_file` | The write-side counterpart to the existing reader. |
| `tpm2_pcr_reset` / `tpm2_create_primary_key_rsa2048_unrestricted` | The two TPM primitives `Quote_r` needs. |
| `calculate_stats` | Mean and population standard deviation, for `--benchmark`. |

---

## 5. Wire messages and their DTOs

All messages are CBOR (QCBOR), encoded as **positional arrays** — no maps,
no labels. Field order is load-bearing. Marshalling lives in
`src/core/charra_marshaling.c`, one `charra_marshal_*` / `charra_unmarshal_*`
pair per message; DTOs in `src/core/charra_dto.h`.

**Reading the direction labels.** The RP initiates *every* exchange, so the
resource name alone never tells you which way a payload travels. Each block
below is therefore labelled with its own arrow: `RP → Verifier` is what the
RP sent, `Verifier → RP` is what came back. Several of the most important
payloads — the qualification challenge and its salt, every nonce, every
verdict — flow **back** to the RP on a request the RP itself made.

### 5.1 `/get_verifiers` — RP calls the Trust Manager

**Request · RP → Trust Manager · `msg_get_verifiers_request_dto`**

| Field | Meaning |
|---|---|
| `verifier_ids_len`, `verifier_ids[]` | Which Verifier IDs to resolve. |

**Response · Trust Manager → RP · `msg_get_verifiers_response_dto`**

| Field | Meaning |
|---|---|
| `verifiers_len` | How many were resolved. Compared against the request; a short answer abandons the cycle. |
| `verifiers[]` | `msg_verifier_endpoint_dto` — `ip_address`, `port_number`. |

### 5.2 `/attest` — RP calls the Attester

**Request · RP → Attester · `msg_attestation_request_dto`**

| Field | Meaning |
|---|---|
| `hello` | Protocol marker. |
| `sig_key_id` | The name of the Attester's signing identity, always `"attester"` — the **same string** `--role attester` provisions under and the `# attester` label carries in the trust anchor. No such key object exists in the TPM: matching the name selects `tpm2_create_primary_key_rsa2048()`, which derives the restricted primary from the owner-hierarchy seed. The Attester would use that key regardless; the field only lets it refuse a request naming anything else. Upstream CHARRA sent `"PK.RSA.default"` here — renamed so one name covers the key's whole life. |
| `nonce` | **RP-chosen.** Becomes `qualifyingData` inside `Quote_a`. |
| `pcr_selections` | Which PCRs to quote — `{0..7, 10}`. |
| `event_log_path` | Where the Attester should read its IMA log from. |

**Response · Attester → RP · `msg_attestation_response_dto`**

| Field | Meaning |
|---|---|
| `attestation_data` | The `TPMS_ATTEST` the Attester's TPM built — `Quote_a`. |
| `tpm2_signature` | AK_a's signature over it. |
| `tpm2_public_key` | AK_a's public half, checked against the trust anchor. |
| `event_log` | The **raw** IMA log, `log_a`. Never forwarded further. |

### 5.3 `/attest_result` — RP calls the Attester

**Request · RP → Attester · `msg_attestation_result_dto`**

The Attester replies with a bare status code — `2.05` on success, `4.00` on
a malformed request — and no payload.

| Field | Meaning |
|---|---|
| `accepted` | The RP's Step 2a verdict. |
| `reason` | Human-readable, for the Attester's log. |

Advisory only, and a separate RP-initiated request because the Attester is
the *server* of `/attest` — there is no reply slot left to reject it in.

### 5.4 `/qualify` — RP asks a Verifier for a challenge

The RP sends **no payload**; everything here travels back to it.

**Response · Verifier → RP · `msg_qualify_response_dto`**

| Field | Meaning |
|---|---|
| `challenge_log` | A synthetic log **the Verifier fabricates**, so it already knows the correct redaction. |
| `salt` | **Generated by the Verifier**, freshly per challenge, and sent to the RP. The one deliberate exception to the SDK's "salt is never transmitted" rule: redaction salts each path, so two honest redactions of the same log do not match bytewise, and the byte-for-byte comparison in 5.5 is only possible if both sides use the same salt. Safe only because the log is synthetic. |

### 5.5 `/qualify_submit` — RP answers the challenge

**Request · RP → Verifier · `msg_qualify_submit_request_dto`**

| Field | Meaning |
|---|---|
| `submitted_redacted_log` | The RP's redaction, compared byte-for-byte against the golden answer. No PCR, no replay. |
| `rp_signature` | AK_r over `(log ‖ salt)` — the salt being the one the Verifier sent in 5.4. Answers *who* is submitting: the grant is recorded against a key fingerprint, so an unsigned submission could win a grant in another RP's name. Folding in the salt binds the signature to *this* challenge. |
| `rp_public_key` | AK_r's public half. |

**Response · Verifier → RP · `msg_qualify_submit_response_dto`**

| Field | Meaning |
|---|---|
| `qualified` | Pass/fail. |
| `expires_at` | Absolute deadline. On the wire because `/appraise` never says *why* it refused, so the RP must know when to renew. |

### 5.6 `/nonce` — RP asks a Verifier for a challenge

**Request · RP → Verifier** — the RP's own attestation request, reused as
the body. The Verifier keeps only its `nonce` field: that is the value the
RP gave the Attester, needed later for Step 3b item 3.

**Response · Verifier → RP** — 32 raw bytes, **generated by that Verifier**.
Not CBOR, and not a DTO. A nonce the RP chose proves nothing to the
Verifier, since the RP could replay an old `Quote_r` over a value it
already knew would match — so the challenger picks it.

### 5.7 `/appraise` — RP submits evidence

**Request · RP → Verifier · `msg_rp_evidence_dto`** — the largest message
in the system.

| Group | Fields | Meaning |
|---|---|---|
| `Quote_r` | `rp_attestation_data`, `rp_signature`, `rp_public_key` | A genuine `TPM2_Quote` over PCR 23 on the RP's own TPM. The nonce and PCR digest live *inside* the signed structure, so neither travels as its own field. |
| Attester nonce | `attester_nonce` | The **RP-chosen** nonce from 5.2, forwarded so the Verifier can check `Quote_a`'s freshness in Step 3b. Not to be confused with the Verifier's own nonce from 5.6, which is inside `Quote_r` rather than beside it. |
| `Quote_a` forwarded | `attestation_data`, `tpm2_signature`, `tpm2_public_key` | Verbatim from the Attester. |
| Redacted log | `log_r` | The redacted log. `log_a` is **stripped** — forwarding it would defeat the redaction. |

### 5.8 `/appraise` — the Verifier answers

**Response · Verifier → RP** — not a DTO in `charra_dto.h`, but a
self-contained signed record owned by `src/core/charra_verdict.h`.

```
[ payload: bstr, signature: bstr ]
payload = [ accepted, challenge_nonce, evidence_digest, signed_at ]
```

| Field | Purpose |
|---|---|
| `accepted` | The vote. |
| `challenge_nonce` | The nonce this Verifier issued this round. Stops replay across rounds, and stops a vote landing in another Verifier's slot. |
| `evidence_digest` | SHA-256 over the **whole `/appraise` request** — the entire `msg_rp_evidence_dto` blob from 5.7. The RP hashes the bytes before sending; the Verifier hashes what arrived, before parsing, and signs that digest in. On the reply the RP compares the two. This is what proves the vote is about *the RP's own* evidence: the transport is plaintext UDP, so an on-path attacker can swap the request for a bundle of its own, and the nonce would not catch it — that nonce travelled in the clear on `/nonce`, so the attacker can put it in the substitute. The nonce proves *when* a vote was cast; the digest proves *what about*. |
| `signed_at` | Wall clock. An assertion, not proof — no role has a trusted clock. Freshness comes from the nonce. |

The signature covers the **payload bytes as received**, so verification
never re-encodes anything and the two sides cannot disagree about canonical
form.

The verdict carries nothing else: the RP is never told *which* check
failed. Reasons stay in the Verifier's log.

---

## 6. Testing and tooling

**`make test`** — 16 suites, **358 assertions**, no TPM or network
required. The list lives once in the Makefile's `TEST_SUITES`; the
`.PHONY` list, the per-suite shortcuts and the `test` target all derive
from it, and the run stops at the first failing suite.

| suite | assertions | covers |
|---|---|---|
| `test_event_log` | 29 | replay, entry parsing, hostile lengths |
| `test_synthetic_log` | 13 | challenge-log generation, determinism |
| `test_sdk` | 23 | redaction, salting, PCR divergence |
| `test_rp_qualification` | 32 | the golden-answer handshake |
| `test_marshaling_bounds` | 18 | oversized fields on the wire |
| `test_trusted_keys` | 9 | the trust anchor lookup |
| `test_qualified_rps` | 21 | the shared grant file |
| `test_get_verifiers_marshaling` | 17 | Trust Manager messages |
| `test_rp_evidence_marshaling` | 22 | the `/appraise` request |
| `test_verdict` | 27 | the signed verdict, byte-mutation sweep |
| `test_hex_util` | 25 | encoding, truncation, guard bytes |
| `test_pcr_selection` | 16 | the PCR bitmap and its bounds |
| `test_message_marshaling` | 47 | the six remaining wire messages |
| `test_key_mgr` | 13 | the signing-key name check |
| `test_crypto_util` | 22 | hash vectors, sign/verify, tamper sweeps |
| `test_parser_util` | 24 | reference-PCR file parsing |

Expected values are computed independently — hand-written reference
extends, hand-encoded CBOR — rather than by calling the code under test.

### `run_daemon.sh` — the one command you run

There is nothing to set up by hand. A run is:

```sh
./run_daemon.sh
```

It does everything, in order, inside the dev container:

1. Wipes each NVChip, starts **two** TPM simulators — `:2321` for the
   Attester, `:2325` for the RP, each with its own state directory under
   `.tpm-state/` — and runs `TPM2_Startup --clear` on both.
2. `make clean && make -j` inside the container.
3. Regenerates the trust anchor with `keys/gen-trusted-keys.sh`, reading
   each role's key from that role's own TPM via `--role`. This has to
   follow step 1: wiping an NVChip re-randomises the hierarchy seed and so
   changes that role's AK, which would otherwise leave every signature
   check failing as "key not in the trust anchor".
4. Wipes and recreates `logs/`.
5. Starts the Trust Manager, the Attester, and N Verifiers —
   `start_verifiers.sh` writes `verifiers_config.txt` for exactly those.
6. Runs the Relying Party's daemon loop until you stop it, or until
   `--cycles` / `--duration` is reached.

It also refuses to start if another container is already mounting the same
checkout, since two runs would share `logs/` and `keys/` and corrupt each
other.

**Every tunable is a variable at the top of the script**, in a block marked
`TUNABLES`, each one set to the binary's own built-in default — so the file
doubles as the list of what can actually be changed. Two ways to use it:

```sh
# override for one run, without editing anything
RP_INTERVAL=5 RP_VERIFIERS=3 ./run_daemon.sh
RP_CYCLES=2 ./run_daemon.sh                    # two cycles, then exit
RP_DURATION=120 ./run_daemon.sh                # stop cleanly after 2 minutes
VERIFIER_QUALIFICATION_VALIDITY=20 RP_CYCLES=8 ./run_daemon.sh   # watch it re-qualify mid-run

# or edit the defaults in the TUNABLES block if you want them to stick
```

Grouped as: **cadence** (`RP_INTERVAL`, `RP_VERIFIERS`, `RP_CYCLES`,
`RP_DURATION`) · **timeouts** (`RP_VERIFIER_TIMEOUT`,
`RP_ATTESTER_TIMEOUT`) · **the grant** (`VERIFIER_QUALIFICATION_VALIDITY`) ·
**TPMs** (`TWO_TPMS`, `ATTESTER_TPM_PORT`, `RP_TPM_PORT`, `TPM_STATE_DIR`,
`RESET_TPM`) · **topology** (`VERIFIER_START_PORT`, `VERIFIER_HOST`) ·
**logging** (`LOG_LEVEL`, `LOG_LEVEL_COAP`) · **environment** (`IMAGE`,
`CONTAINER_NAME`, `REBUILD`). Plus `RP_EXTRA_ARGS` / `VERIFIER_EXTRA_ARGS` /
`ATTESTER_EXTRA_ARGS` as free-form pass-through for any flag the script does
not name.

One option rather than a variable: `--keep-state` keeps each NVChip instead
of wiping it, so both AKs — and therefore `keys/trusted_keys.txt` — survive
the run. State lives in `.tpm-state/` under the checkout rather than in the
container, because the container is `--rm` and its `/tmp` dies with it.

**The other scripts**

| Script | Purpose |
|---|---|
| `start_verifiers.sh` | Spawns N Verifiers and writes `verifiers_config.txt`. Called by `run_daemon.sh`; standalone if you want Verifiers without the rest. |
| `run_live_test.sh` | The counterpart to `run_daemon.sh`: runs the bounded `--benchmark` sweep instead of the daemon loop. |
| `keys/gen-trusted-keys.sh` | Reads each role's AK from its own TPM and builds `keys/trusted_keys.txt`. |
| `docker/run.sh` | Interactive shell in the dev container, checkout bind-mounted. |

---

## 7. Where to read further

| For | See |
|---|---|
| The full cycle, every guard and abort path | `diagrams/rp_daemon_automaton.svg` |
| Key material and the trust anchor | `keys/README.md` |

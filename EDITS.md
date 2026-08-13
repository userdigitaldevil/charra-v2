# Edit log

A running, exhaustive record of every change made to this repository during
assisted sessions — down to single-character edits and file-permission
changes. Newest session at the bottom. Each entry states **what** changed,
**where**, **why**, and **what it affects**.

Baseline commit for this log: `8a4a293` ("charra_synth_log ->
charra_synthetic_log").

---

## Session 2026-08-10 — Getting the 4-party system running under Docker on macOS (Apple Silicon)

Context: building the `fraunhofer-sit/charra-dev-env:1.9.0` image on an
arm64 Mac (macOS 26.3), where the image is `linux/amd64` under Rosetta
emulation. Both code edits below are fixes for build failures caused by
macOS-specific values being passed into an Ubuntu container. No CHARRA
source file (`src/`, `tests/`, `Makefile`) has been touched.

### Summary

| # | File | Lines | Kind | One-line reason |
|---|---|---|---|---|
| 1 | `Dockerfile` | 240–243 | 1 line changed, 2 comment lines added | macOS `id -g` = 20 collides with Ubuntu's `dialout` group |
| 2 | `Dockerfile` | 276 | 1 line changed | no `bob` *group* exists after edit #1, so `chown bob:bob` failed |
| 3 | `docker/build.sh` | — | file mode `100644` → `100755` | script had no exec bit in the checkout |
| 4 | `docker/run.sh` | — | file mode `100644` → `100755` | same |
| 5 | `start_verifiers.sh` | — | file mode `100644` → `100755` | same |
| 6 | `src/relying_party.c` | 7 (include), 155–161 | 1 include + 7 lines added | RP ignored `LOG_LEVEL_CHARRA` and always logged at TRACE |
| 7 | `src/relying_party.c` | 29 | `10` → `2` | 50 attestations per run was unusably slow under emulation |
| 8 | `src/attester.c` | 68–71, 97–105, 298–430, 512–525 | 158 lines added | extend PCRs from `ima_test_logs.txt` before loading the TPM key |
| 9a | `src/attester.c` | — | ASCII→binary IMA log conversion, cached | `charra_event_log.c` parses binary TLV; the wire carried ASCII |
| 9b | `src/attester.c` | 573 | `path[len + 1] = '\n'` → `path[len] = '\0'` | one-byte heap overflow, path never NUL-terminated |
| 9c | `src/core/charra_event_log.{h,c}` | — | 3 renames + reshaped checks | `quote_r` naming obsolete; 1-PCR composite could never match |
| 9d | `src/core/charra_rim_mgr.{h,c}` | — | *(reverted — not modified)* | superseded by replaying every selected PCR in 9c |
| 9e | `src/relying_party.c` | — | `charra_rp_appraise_evidence()` | the five-step RP-side appraisal |
| 9f | `src/relying_party.c` | 73 | `use_ima_test_log_path` → `ima_test_log_path` | undeclared identifier; did not compile |
| 9g | `src/verifier.c` | — | *(reverted — not modified)* | comment-only rename touch-up, reverted on request |
| 10a | `src/core/charra_sdk.{h,c}` | — | rewritten | old code assumed the synthetic layout, not real ima-ng; path now salted |
| 10b | `src/util/crypto_util.{h,c}` | — | +3 functions | RP needs a keypair and a signature for Quote_r |
| 10c | `src/core/charra_dto.h` | — | new `msg_rp_evidence_dto` | the RP→Verifier message |
| 10d | `src/core/charra_marshaling.{h,c}` | — | +2 functions | marshal/unmarshal for it |
| 10e | `src/relying_party.c` | — | privacy-cleaning flow | nonce, redact, PCR_r, Quote_r, send |
| 11 | `src/attester.c`, `src/util/tpm2_util.{h,c}` | — | *(reverted — not modified)* | each run should start from a freshly booted TPM instead |

---

### Edit 1 — `Dockerfile`, tolerate a pre-existing GID

**Location:** `Dockerfile`, the "create non-root user and grant sudo
permission" block (was line 240, now 242).

**Trigger:** `./docker/build.sh` failed at step 42/53:

```
addgroup: The GID `20' is already in use.
```

`docker/build.sh` passes `--build-arg gid="$(id -g)"`. On macOS the primary
group of a normal user is `staff` = GID **20**, and GID 20 is already taken
by `dialout` in the Ubuntu 20.04 base image, so `addgroup --gid 20 bob`
aborts.

**Before:**

```dockerfile
## create non-root user and grant sudo permission
RUN export user="${user}" uid="${uid}" gid="${gid}" \
    && addgroup --gid "${gid}" "${user}" \
    && adduser --home /home/"${user}" --uid "${uid}" --gid "${gid}" \
```

**After:**

```dockerfile
## create non-root user and grant sudo permission
## (the GID may already exist in the base image -- e.g. macOS hosts pass
## gid=20, which Ubuntu already uses for 'dialout'; reuse it in that case)
RUN export user="${user}" uid="${uid}" gid="${gid}" \
    && { getent group "${gid}" > /dev/null || addgroup --gid "${gid}" "${user}" ; } \
    && adduser --home /home/"${user}" --uid "${uid}" --gid "${gid}" \
```

**Exact delta:** two `##` comment lines added; the single line
`&& addgroup --gid "${gid}" "${user}" \` replaced by
`&& { getent group "${gid}" > /dev/null || addgroup --gid "${gid}" "${user}" ; } \`.
The `adduser`, `mkdir`, `echo`, `chmod` and `chown` lines of the same `RUN`
are untouched.

**Why this shape rather than changing the build arg:** passing
`--build-arg gid=1000` would have been the other fix, but altering a build
arg risks invalidating BuildKit's cache from an early layer, which would
have re-run the ~30-minute tpm2-tss / tpm2-tools / libcoap / mbedTLS
compiles. Editing this line invalidates only step 42 onward, all of which
are cheap `COPY`/`ENV` steps.

**Behavioural consequence (deliberate, harmless here):** when the GID
already exists, no group named `bob` is created and `bob`'s primary group
becomes whatever already owns that GID — `dialout` on a macOS host. Nothing
in CHARRA depends on group ownership. The `--group-add tss` used at
`docker run` time is a separate supplementary group and is unaffected. On a
Linux host with `id -g` = 1000 the old and new behaviour are identical.

---

### Edit 2 — `Dockerfile`, chown code-examples by numeric ID

**Location:** `Dockerfile` line 276 (originally 274).

**Trigger:** with edit 1 in place the build got further and then failed at
step 49/53:

```
chown: invalid group: 'bob:bob'
```

Direct fallout from edit 1: `bob` exists as a *user* but no longer as a
*group*, so the `name:name` form no longer resolves.

**Before:**

```dockerfile
RUN chown -R "${user}:${user}" "/home/${user}/code-examples/"
```

**After:**

```dockerfile
RUN chown -R "${uid}:${gid}" "/home/${user}/code-examples/"
```

**Exact delta:** `"${user}:${user}"` → `"${uid}:${gid}"`. Nothing else on
the line changed; the surrounding `COPY` lines are untouched.

**Why:** numeric IDs are correct whichever group won, and this matches the
form already used on the analogous line inside the same file
(`&& chown "${uid}:${gid}" -R /home/"${user}"`, line 249). The only other
`chown`s in the file target `root:tss` (lines 191, 194) — `tss` is created
explicitly earlier in the Dockerfile, so those still resolve and were left
alone.

---

### Edits 3–5 — executable bits on three shell scripts

**Files:** `docker/build.sh`, `docker/run.sh`, `start_verifiers.sh`

**Change:** file mode `100644` → `100755`. **No content change whatsoever** —
`git diff --stat` reports `0 insertions(+), 0 deletions(-)` for all three.

**Command run:**

```bash
chmod +x docker/build.sh docker/run.sh start_verifiers.sh
```

**Why:** none of the three carried an exec bit in the checkout, so
`./docker/build.sh` would fail with "permission denied". Git tracks the
exec bit, so this shows up as a real (mode-only) modification in
`git status`.

---

### Edit 6 — `src/relying_party.c`, honour `LOG_LEVEL_CHARRA`

**Location:** `src/relying_party.c` — one line added to the include block,
seven lines (3 comment + 4 code) added inside `main()` right after
`signal(SIGINT, handle_sigint);`.

**Trigger:** running `LOG_LEVEL_CHARRA=DEBUG bin/relying_party` still emitted
`TRACE<ENTER> charra_marshal_*` lines, producing thousands of lines per run.
Setting the variable had no effect at all.

**Root cause:** the Relying Party declares
`charra_log_t charra_log_level = CHARRA_LOG_INFO;` (line 36) but — unlike
`attester.c` and `verifier.c`, which both call `charra_log_level_from_str()`
+ `charra_log_set_level()` in their `main()` — it never reads the environment
variable and never pushes the level into the log module. The log module's
state lives in a `static struct { ... } L;` in `src/common/charra_log.c:27`,
which is zero-initialized, so `L.level == 0 == CHARRA_LOG_TRACE`. The RP
therefore always logged at TRACE regardless of the environment.

**Added** (include block, after `#include <stdio.h>`) — needed for `getenv`:

```c
#include <stdlib.h>
```

**Added** (in `main()`, after the `signal()` call):

```c
    /* apply log level from environment (the other binaries do this in their
     * own main(); without it the log module keeps its zero-initialized
     * default of CHARRA_LOG_TRACE and LOG_LEVEL_CHARRA is ignored) */
    charra_log_level_from_str(
            (const char*)getenv("LOG_LEVEL_CHARRA"), &charra_log_level);
    charra_log_set_level(charra_log_level);
```

**Nothing removed or reordered.** Both functions were already declared in
`src/common/charra_log.h` (lines 70 and 91); no header change was needed.

**Effect:** `LOG_LEVEL_CHARRA=INFO bin/relying_party` now suppresses the
TRACE/DEBUG marshaling output. An unset or unrecognised value leaves
`charra_log_level` at its `CHARRA_LOG_INFO` initializer —
`charra_log_level_from_str()` returns `-1` without writing through the
pointer — so the default is now INFO rather than the previous accidental
TRACE. Its return value is deliberately ignored, matching how `attester.c`
and `verifier.c` call it.

**Deliberately not done:** `coap_log_level` (line 35) is likewise never
passed to `coap_set_log_level()` in the RP, so `LOG_LEVEL_COAP` is still
ignored there. Left alone to keep this edit minimal.

---

### Edit 7 — `src/relying_party.c`, shorten the benchmark sweep

**Location:** `src/relying_party.c` line 28 (now 29).

**Before:** `#define NUM_RUNS 10`
**After:** `#define NUM_RUNS 2`

**Exact delta:** the single character `10` → `2`.

**Why:** `main()` doubles as a benchmark harness, looping
`for (num_verifiers = 1; num_verifiers <= 5; ...)` × `NUM_RUNS`. At 10 that
is **50 complete attestations**, each with a real TPM quote against the
software TPM under x86-on-arm64 emulation — many minutes of runtime that
looks indistinguishable from a hang. At 2 it is 10 attestations.

**Consequence:** the standard deviations written to
`timings_RP_multi_verifiers.txt` are computed over 2 samples instead of 10
and are statistically meaningless. They were already meaningless under
emulation. **Restore this to 10 before collecting any real measurements**,
and ideally run those on native x86 Linux.

The sweep bound itself (`num_verifiers <= 5`, line ~160) was **not** changed,
so all five verifier instances are still exercised.

---

### Edit 8 — `src/attester.c`, extend PCRs from `ima_test_logs.txt` before the quote

**Requested:** before loading the TPM key, the Attester should update its PCRs
according to the entries parsed from `ima_test_logs.txt`.

**Location:** `src/attester.c` — 158 lines added across four places, no lines
removed or modified.

| Where | Lines | What |
|---|---|---|
| config block | 68–71 | new `char* ima_test_log_path = "ima_test_logs.txt";` + 3 comment lines |
| forward declarations | 97–105 | doc comment + `static CHARRA_RC charra_extend_pcrs_from_ima_log(ESYS_CONTEXT*);` |
| function definitions | 298–430 | `hex_nibble()`, `hex_str_to_bytes()`, `charra_extend_pcrs_from_ima_log()` |
| `coap_attest_handler()` | 512–525 | the call, guarded by a `static bool`, immediately before `Loading TPM key` |

**Input format.** `ima_test_logs.txt` is 32 lines of ASCII IMA measurements:

```
PCR 10 f889b3f33bc93d44a66a2567055c9214de4f11d3 ima-ng     sha256:61cee3…d541 /usr/lib/systemd/systemd
```

Only fields 2 and 3 are used — the PCR index and the **template digest**. The
`ima-ng` name, the file hash and the path are ignored: the template digest is
by definition the value the kernel extended, so re-deriving it from the other
fields would be redundant and would have to replicate the exact template
serialisation.

The parser accepts the line with or without the leading `PCR` token, since
the kernel's own `ascii_runtime_measurements` omits it.

**New helpers:**

| Function | Purpose |
|---|---|
| `hex_nibble(char)` *(static)* | One ASCII hex character → value, `-1` if not hex. |
| `hex_str_to_bytes(hex, hex_len, out, out_len)` *(static)* | Decodes hex to bytes; rejects a length mismatch or any non-hex character rather than producing garbage. |
| `charra_extend_pcrs_from_ima_log(esys_ctx)` *(static)* | Opens the log, parses each line, calls the **existing** `tpm2_pcr_extend()` from `src/util/tpm2_util.c:167` per entry. |

**Decision: SHA-256 bank only, with zero-padding.** The template digests in
this file are 40 hex characters — 20-byte SHA-1. They are zero-padded to 32
bytes and extended into the **SHA-256** bank only. Two reasons:

1. It matches `charra_pcr_extend()` in `src/core/charra_event_log.c`, which
   zero-pads short digests when replaying a log in software. The replayed
   value and the value in the TPM must agree or appraisal can never match.
2. The Relying Party requests `TPM2_ALG_SHA256` for PCRs {0-7, 10}
   (`src/relying_party.c:284`), so the SHA-256 bank is the only one the quote
   covers.

Extending the SHA-1 bank as well was considered and rejected: it would fail
outright if that bank is not allocated in the simulator, for no benefit to
the quote actually being requested. A 64-hex-character (SHA-256) template
digest is also accepted and used unpadded, so a SHA-256 log works unchanged.

**Decision: once per process, not once per request.** The call is guarded by
a function-local `static bool ima_log_extended`. PCRs 0-15 cannot be reset
without a reboot, so extending on every attestation request would keep
growing PCR 10 — after the Relying Party's 10 benchmark runs it would hold
the log folded in ten times, and no single replay of the log could ever
reproduce it. This is a deliberate deviation from a literal reading of
"before loading the TPM key" (which sits inside the per-request handler);
the guard is one line to remove if per-request extension is actually wanted.

**Error handling:**

- Log file missing → `charra_log_warn` and return `CHARRA_RC_SUCCESS`. The
  Attester still attests, just with unextended PCRs, rather than refusing to
  start.
- A line with a bad-length or non-hex digest → warned with its line number
  and skipped; parsing continues.
- `tpm2_pcr_extend()` failing → `CHARRA_RC_ERROR`, which aborts the
  attestation via the handler's existing `goto error`. A half-extended PCR is
  not something to continue from.
- The `FILE*` is closed on every path via a `cleanup:` label.

**Consequence — appraisal will now fail on the PCR check.** PCR 10 is no
longer all-zero, so the quote's composite `pcrDigest` changes and
`reference-pcrs.txt` no longer describes this Attester. That is inherent to
the request, not a defect in it: the point of extending the PCRs is that PCR
10 must be *derived* by replaying the log, which is the Verifier-side work
described in Part 2 of `CHARRA_V2_NOTES.md` and not yet built. Appraisal was
already failing for an unrelated reason (see the note below on the nine-way
AND in `verifier.c`).

**Not compiled.** No TSS2/libcoap headers exist on the macOS host, so this
was written against the headers and not built. Needs a `make` inside the
container to confirm.

---

### Edit 9 — RP-side appraisal of the Attester's evidence

**Requested:** on receiving the response DTO, the RP performs the Verifier's
appraisal job locally — (1) quote signature under the Attester's public key,
(2) nonce match, (3) per-entry `template_digest == hash(template_data)`,
(4) replay the log into expected PCRs and match the digest, (5) file hashes
not on `blacklist-hashes.txt` — printing "RP Appraisal Successful" or
"RP Appraisal Failed". Reuse `verifier.c` and `charra_event_log.c` where
sensible, after verifying the reused code is correct.

Touches six files. Summary of the audit that shaped it comes first, because
two findings changed what was built.

#### Audit findings that forced design changes

1. **The log on the wire was ASCII, not binary.** The Attester read
   `event_log_path` with `charra_io_read_continuous_binary_file()` and shipped
   the bytes verbatim, so the RP received the literal text of
   `ima_test_logs.txt`. Every function in `charra_event_log.c` parses the
   binary IMA TLV format and would have failed on it. **Resolved** by
   converting ASCII → binary in the Attester (edit 9a).
2. **The template digests in `ima_test_logs.txt` are not reproducible from
   the fields the file shows.** Fifteen-plus reconstructions of the `ima-ng`
   template data were tried against entry 1 and all 32 entries —
   `"<alg>" NUL + digest` / `"<alg>:" + hex` / bare digest, path with and
   without a NUL, little- and big-endian `u32` length prefixes, no prefixes,
   under both SHA-1 and SHA-256 — and none reproduce column 2. Step 1.3 was
   therefore **unsatisfiable** with the file as given: a correct check would
   have failed all 32 entries. **Resolved** by recomputing the template
   digest during conversion (edit 9a), which makes
   `template_digest == SHA256(template_data)` true by construction.
3. `verify_log_matches_quote_r_pcr()` composited a **single** PCR, but the
   Attester's quote covers nine ({0-7, 10}), so it could never match.
   **Resolved** by edit 9c.

#### 9a — `src/attester.c`: ASCII → binary conversion, and send what was extended

Replaces the ASCII-parsing PCR extension added in edit 8. New:

| Function | Purpose |
|---|---|
| `build_ima_ng_template_data()` *(static)* | Serializes one entry's `template_data` in the real `ima-ng` layout: `u32 d_len \| "<alg>" NUL <file-digest>` then `u32 n_len \| "<path>" NUL`. |
| `charra_ima_log_ascii_to_binary()` | Parses the ASCII log, rebuilds `template_data`, recomputes `template_digest = SHA256(template_data)`, emits binary TLV entries via the existing `charra_event_log_append_u32()` / `_append_bytes()`. Returns `CHARRA_RC_MARSHALING_ERROR` when no line parses, which is the signal that the file is not ASCII. |
| `charra_extend_pcrs_from_binary_log()` *(static)* | Walks the binary log with `charra_event_log_parse_entry()` and extends each entry's digest into the PCR the entry names. |
| `charra_get_ima_log()` *(static)* | Loads once and caches in `cached_ima_log`. Tries the ASCII conversion first and falls back to reading the file verbatim, so a real `binary_runtime_measurements` still works untouched. |

**Why the template digest is recomputed rather than carried over:** see
audit finding 2. The consequence is that the Attester's PCR 10 is built from
the *recomputed* digests, not the ones printed in the text file. That is
required for consistency — the RP replays the log it receives, and the
replay must reproduce what the TPM holds.

**Cache is load-bearing, not an optimisation.** The PCRs are extended from
these exact bytes once, so every response must return these exact bytes.
`charra_io_free_continuous_file_buffer(&ima_event_log)` was therefore
**removed** from the handler's cleanup — freeing it would dangle the cache
and silently change the log between attestations. The buffer now lives for
the process lifetime, which is deliberate. A `free(path)` was added, since
that allocation genuinely was leaking on every request.

#### 9b — `src/attester.c` bug fix (pre-existing, unrelated to this feature)

```c
- path[req.event_log_path_len + 1] = '\n';
+ path[req.event_log_path_len] = '\0';
```

The old line wrote **one byte past** a `malloc(len + 1)` allocation and never
NUL-terminated the path, so `fopen()` was reading whatever followed in the
heap. It happened to work.

#### 9c — `src/core/charra_event_log.{h,c}`: renames and reshaping

Renamed for accuracy now that these are RP-side checks against the
*Attester's* quote, not Quote_r (the `quote_r` naming no longer described
anything):

| Old | New |
|---|---|
| `verify_log_entries_self_consistent` | `charra_verify_log_entries_self_consistent` |
| `verify_log_matches_quote_r_pcr` | `charra_verify_log_matches_quote_pcr_digest` |
| `verify_log_file_hashes_against_policy` | `charra_verify_log_file_hashes_not_blacklisted` |

Behavioural changes:

- **Self-consistency now accepts SHA-1 digests.** It previously hard-required
  `template_digest_len == TPM2_SHA256_DIGEST_SIZE` and always hashed with
  SHA-256. It now picks SHA-1 or SHA-256 by digest length, since nothing in
  the format records which was used.
- **PCR check replays every selected PCR.** New
  `charra_replay_ima_log_pcrs()` keeps one `charra_pcr_accumulator` per
  entry of the requested PCR selection, all starting from the all-zero
  power-on value, and extends whichever PCR each log entry names. A selected
  PCR that no entry names simply stays zero.
  `charra_verify_log_matches_quote_pcr_digest()` then hashes all of them
  together, **in selection order** (the composite digest is order-sensitive),
  and compares against the quote's `pcrDigest` via
  `compute_and_check_PCR_digest()`. Entries naming an unselected PCR are
  parsed but skipped, since they cannot affect the digest.

  **No reference PCR file is consulted.** The replayed values *are* the
  expected values. This is valid only because the Attester's PCRs start from
  power-on zero and are extended solely from this log — true on the software
  TPM after `tpm2_startup --clear`. On a platform whose firmware extends PCRs
  0-7 at boot, those would need reference values instead, and this check
  would have to change.
- **Policy check is blacklist-only, allow-by-default.** The whitelist
  parameter and the default-deny behaviour are gone, per the request. An
  empty blacklist now passes everything, and the list is not even loaded into
  the entry loop when it has no entries. This is **weaker than the
  default-deny it replaced** — noted in the header comment.
- **New `charra_event_log_entry_file_digest()`** extracts the file digest by
  walking the real `ima-ng` `d-ng` field (NUL-terminated algorithm name, then
  the digest). The old code assumed a literal `"sha256:"` prefix at
  `template_data[0]`, which is the *redacted* SDK layout, not the raw one.

#### 9d — `src/core/charra_rim_mgr.{h,c}`: **reverted, no longer changed**

An earlier version of this edit added
`(const uint8_t* replayed_pcr_value, uint32_t replayed_pcr_index)` to
`charra_check_pcr_digest_against_reference()`, so a replayed PCR 10 could be
substituted into reference sets read from `reference-pcrs.txt`. That was the
wrong design: replaying *every* selected PCR from zero (see 9c) reproduces
the Attester's PCR state directly and needs no reference file at all.

`charra_rim_mgr.c`, `charra_rim_mgr.h` and the follow-on one-line change to
`src/verifier_old.c:697` were **reverted to HEAD**. Neither file is modified
by this session. The RP no longer has a `reference_pcr_file_path` setting.

#### 9e — `src/relying_party.c`: the appraisal itself

New `charra_rp_appraise_evidence()`, called from `coap_attester_handler()`
**before** `last_response = res` — evidence that fails appraisal is never
forwarded to the Verifiers. New config: `reference_pcr_file_path`,
`blacklist_hashes_path`.

The five checks run in order and **all of them run even after one fails**, so
one run reports everything that is wrong rather than stopping at the first
problem. Result is the AND of all five.

**Signature verified with mbedTLS, not the TPM.** `verifier.c` does both;
only the mbedTLS path is used here. Verifying an RSA-PSS signature needs no
TPM, and the IBM software TPM serves one client at a time — the RP opening
its own TPM session while fanning out to five verifiers is exactly the
contention that deadlocked the testbed earlier this session. Bounds on
`tpm2_signature_len`, `tpm2_public_key_len` and `attestation_data_len` are
re-checked before the `memcpy`s, in the same defense-in-depth style
`verifier.c` uses.

#### 9f — `src/relying_party.c` bug fix (pre-existing)

Line 73 declared `use_ima_test_log_path` while lines 291/293 referenced
`ima_test_log_path`. Renamed the declaration to `ima_test_log_path`. **This
did not compile before the fix.**

#### 9g — `src/verifier.c`: **reverted, no longer changed**

A comment block at lines 568-571 referenced the three function names renamed
in 9c. It was updated to the new names, then **reverted to HEAD on request**.
`src/verifier.c` is not modified by this session. The comment therefore now
names three functions that no longer exist — a known, accepted staleness.

#### Not compiled

No TSS2/libcoap/mbedTLS headers on the macOS host, so none of this was built.
Needs `make -j` in the container.

#### Expected behaviour on first run

All five checks should pass. If check 4 fails, run the RP at
`LOG_LEVEL_CHARRA=DEBUG`: it prints each replayed PCR value. Compare them
against `tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10` inside the container — every
one must match, and whichever differs points at the cause (a PCR extended by
something other than this log, or a replay that disagrees with what the
Attester extended).

---

### Edit 10 — RP privacy cleaning, Quote_r, and the RP -> Verifier message

**Requested:** after appraisal the RP requests a nonce from the Verifier,
redacts every log entry's path into log_r, replays log_r into PCR_r, signs
(PCR_r, nonce) with a freshly generated keypair to form Quote_r, and sends a
new DTO carrying Quote_r, the RP public key, log_r, the nonce sent to the
Attester, and the Attester's evidence minus its event log. `verifier.c` not
to be touched.

| Sub | File | What |
|---|---|---|
| 10a | `src/core/charra_sdk.{h,c}` | rewritten: salted path-only redaction |
| 10b | `src/util/crypto_util.{h,c}` | RSA keygen, DER export, RSA-PSS signing |
| 10c | `src/core/charra_dto.h` | new `msg_rp_evidence_dto` |
| 10d | `src/core/charra_marshaling.{h,c}` | `charra_{,un}marshal_rp_evidence()` |
| 10e | `src/relying_party.c` | the flow, and removal of the old forwarding |

#### 10a — `charra_sdk.{h,c}` rewritten

The previous implementation was **wrong for real ima-ng logs**. It assumed
template_data was `"sha256:" + digest + NUL + path` — the layout
`charra_synth_generate_ima_log()` produces — and replaced the whole field
with a fixed 71-byte blob. Real ima-ng template_data (which the Attester now
emits) is two length-prefixed fields, so the old code would have mis-parsed
every entry.

Now: the d-ng field (algorithm name + file-content digest) is copied through
**byte for byte**, and only the n-ng field's contents are replaced with
`SHA256(path || salt)` using a fresh 32-byte random salt per entry.
`pcr_index` and `template_name` are untouched; `template_digest` is
recomputed as SHA256 of the new template_data.

**The salt is per entry and never transmitted.** That is what the request
asked for, and it is stronger than the unsalted `SHA256(path)` it replaces —
irreversible against a dictionary of guessed paths, and identical paths no
longer redact to identical values.

**Consequence — this breaks two existing things**, deliberately and
visibly:
- `tests/test_sdk.c` asserts that redacting the same log twice produces
  identical bytes. It cannot, now, by design. That test needs rewriting to
  assert structure rather than equality.
- `src/core/charra_rp_qualification.c` compares the RP's redaction output
  byte-for-byte against a locally computed "golden" answer. Salting makes
  that comparison impossible. The qualification check needs a different
  shape (compare everything except the path hashes, or have the Verifier
  supply the salt).

Neither was changed here — flagging rather than silently reworking someone
else's design.

#### 10b — `crypto_util.{h,c}`

`charra_crypto_rsa_generate_keypair()` (RSA-2048, PSS/SHA-256 padding),
`charra_crypto_rsa_public_key_to_der()`, `charra_crypto_rsa_sign()`. Plus
`CHARRA_RSA_SIGNATURE_LEN` / `CHARRA_RSA_PUB_KEY_DER_MAX`, and
`<mbedtls/pk.h>`, `<mbedtls/entropy.h>`, `<mbedtls/ctr_drbg.h>`,
`<string.h>` includes.

Signing is RSA-PSS/SHA-256 so the Verifier can check it with the existing
`charra_crypto_rsa_verify_signature()` once it has parsed the DER key. Note
PSS salts are random: two signings over identical data never match
byte-for-byte, so a verifier must compare signed *values*, never raw
signature bytes.

#### 10c/10d — the new DTO and its wire format

`msg_rp_evidence_dto` carries, in this wire order: `pcr_r` (32 bytes),
`verifier_nonce`, `rp_signature`, `rp_public_key` (DER), `attester_nonce`,
`attestation_data`, `tpm2_signature`, `tpm2_public_key`, `log_r`. A plain
positional CBOR array, matching the rest of the protocol — **field order is
load-bearing**, and the marshal and unmarshal functions must never diverge.

Every length is bounds-checked against its fixed-size destination before the
copy. `log_r` borrows into the caller's buffer on unmarshal and must not be
freed.

The old `msg_rp_appraisal_dto` is left in place, untouched: `verifier.c`
still refers to it and that file is off-limits.

**Quote_r is not a TPM quote.** PCR_r is computed in software and signed
with a software keypair, so it proves "whoever holds rp_public_key produced
this PCR_r for this nonce" and nothing about the RP's own platform state.
The design in `CHARRA_V2_NOTES.md` Part 2 calls for a real `TPM2_Quote`
under a certified AK; this is the software stand-in.

#### 10e — `relying_party.c`

`charra_rp_prepare_evidence()` runs **once per attestation**, before any
verifier thread starts: redact -> log_r, replay log_r into the same PCR
selection -> PCR_r, generate the keypair. Once, not per thread, because the
redaction is randomised — per-thread redaction would hand each Verifier a
different log_r for the same attestation.

Per verifier thread: request a nonce (empty-payload FETCH to `nonce`), wait
for it via the new `coap_verifier_handler_nonce()`, sign
`(PCR_r || nonce)`, marshal `msg_rp_evidence_dto`, FETCH `appraise` with it.

**Removed:** the RP no longer marshals `last_request` and POSTs it as a
nonce *to* the Verifier, and no longer sends the Attester's
`msg_attestation_response_dto` — including the raw event log — for
appraisal. Both were what the request asked to remove; forwarding the raw
log would have defeated the redaction entirely.

#### Blocked on `verifier.c`, which was not to be touched

`coap_nonce_handler()` in `verifier.c` currently **receives and stores** a
nonce from the RP; it neither generates one nor puts anything in its
response. So step 1 cannot complete until that endpoint is inverted to
generate a nonce and return it. The RP side is written and will work
unchanged once it is; until then each thread logs "Verifier n did not supply
a nonce" and gives up before sending anything.

The wire contract the RP expects: FETCH `nonce` with an empty payload, and
the Verifier replies with the raw nonce bytes as the response payload
(1..`sizeof(TPMU_HA)` bytes, not CBOR-wrapped).

#### Not compiled

No TSS2/libcoap/mbedTLS headers on the macOS host. Also still true from
before: `bin/verifier` does not link, because
`charra_unmarshal_rp_appraisal()` is declared in `charra_marshaling.h` and
called from `verifier.c` but never defined.

---

### Edit 11 — **reverted, nothing changed**

Briefly, the Attester was made to read every selected PCR from the TPM before
extending, and to skip or refuse rather than extend on top of a non-zero
value; `tpm2_pcr_read()` was added to `src/util/tpm2_util.{h,c}` to support
it.

**Reverted in full on request.** The intended model is that each CHARRA run
starts as if the Attester's machine had just booted, so its PCRs are always
all-zero to begin with. Under that model the Attester does not need to
inspect PCR state at all — the once-per-process guard from edit 8 is correct,
and keeping the PCRs zero is the operator's job (restart `tpm_server`, not
just re-issue `tpm2_startup`).

`src/attester.c` is back to its committed state and
`src/util/tpm2_util.{h,c}` are untouched by this session.

**What still holds, and is worth remembering:** `tpm2_startup --clear` does
NOT reset PCRs on a TPM that is already running — only `_TPM_Init`, i.e.
restarting the simulator, does. So a run must begin with:

```
pkill -9 -f '^bin/'; pkill tpm_server
cd /tmp && rm -f NVChip && (tpm_server > /tmp/tpm_server.log 2>&1 &) && \
  sleep 3 && tpm2_startup --clear
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10   # must be all zeros
```

Skipping the simulator restart is what caused PCR 10 to accumulate the log
once per Attester process, and every RP PCR check after the first run to fail
against an unchanged replayed value.

---

### Not changed this session, but worth recording

- The Docker build emits three warnings that were **left as-is** because they
  are cosmetic and fixing them would invalidate build cache:
  `FromPlatformFlagConstDisallowed` (line 24, the pinned
  `--platform=linux/amd64`), `UndefinedVar` (line 80, `$LD_LIBRARY_PATH`),
  and `LegacyKeyValueFormat` (line 286, `ENV key value`).
- No fix was applied to the known inverted-`strcmp` bug at
  `src/relying_party.c:366`, which makes the Relying Party report the
  opposite of each Verifier's actual verdict. It is documented in
  `CHARRA_V2_NOTES.md` (bug #7) and was only flagged verbally, not patched.
- Five concurrently-running verifiers all `fopen("durations_verifier.txt",
  "w")` in the same working directory (`src/verifier.c:296`) and clobber each
  other. Not changed.
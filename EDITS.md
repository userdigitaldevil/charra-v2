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
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
# Measurements of Execution Time — CHARRA-v2

We recall the CHARRA-v2 interaction model below. It differs from the v1 model
measured in `charra_measurements_v1`: the Verifier no longer drives the
exchange, and a Relying Party sits between the Attester and a group of
Verifiers.

A cycle divides into **five operations**. They are listed here in execution
order, with the role that does the work — the split is by cost centre and
responsibility, which is also how they are measured:

1. **discoverVerifiers** *(RP ↔ Trust Manager)* — the Relying Party asks the
   Trust Manager which Verifiers to use, over `/get_verifiers`.
2. **getEvidence** *(RP ↔ Attester)* — the Relying Party sends an attestation
   request over `/attest` and receives `Quote_a` plus the IMA event log.
3. **appraiseEvidence_a** *(RP, local)* — the Relying Party appraises that
   evidence itself before forwarding any of it: `AK_a` against the trust
   anchor, the `Quote_a` signature, the nonce, the log's self-consistency, a
   software replay of the log against the quoted PCR digest, and the
   whitelist/blacklist policy.
4. **prepareEvidence_r** *(RP + its own TPM)* — the Relying Party redacts the
   log and replays the redacted log into its own TPM to rebuild `PCR_r`.
5. **submitAndCollect** *(RP ↔ N Verifiers)* — for each Verifier: fetch a
   challenge nonce over `/nonce`, produce a `Quote_r` over `PCR_r` under that
   nonce, submit over `/appraise`, and verify the signed verdict that comes
   back. The Relying Party then aggregates all verdicts by majority vote.

Operations 1–4 run **once per cycle**; operation 5 is charged **per Verifier**,
which is the whole reason cost scales with Verifier count.

Two of these deserve flagging up front, because a three-way split of the kind
used in v1 would hide both:

- **Operation 4 is 87 % of the cycle.** Rebuilding `PCR_r` in the RP's TPM costs
  more than everything else combined.
- **Operation 3 is not the only appraisal of `evidence_a`.** Each Verifier
  independently re-checks the same evidence inside operation 5, as Step 3b —
  `AK_a`, the `Quote_a` signature and `nonce_a` — rather than trusting the RP's
  verdict on it. So `evidence_a` is appraised twice per cycle, by two different
  roles: once by the RP in operation 3, then again by every Verifier in
  operation 5. Over this run that is 55 RP appraisals against 165 Verifier
  Step 3b checks.

A sixth operation establishes that the Relying Party is running the appraisal
code the Verifiers expect. **Which one runs is a choice**, set identically on
both roles by `TRUST_MODE`, and the three differ in cadence as much as in
cost:

| `TRUST_MODE` | what runs | cadence |
|---|---|---|
| `qualify` *(default)* | the `/qualify` + `/qualify_submit` handshake | once per cycle, and only when the previous grant has lapsed |
| `tee` | a simulated TEE Attestation Document | **once per Verifier** |
| `zk` | a zero-knowledge proof over the redacted log | once per cycle |

The tables in the next sections measure `qualify`, since it is the default and
the one the main sweep was taken under. The other two are measured separately
further down — *The alternative to /qualify: TEE mode* and *The third mode:
`zk`* — because their cadence is what makes them differ, not their size: `tee`
adds nothing per cycle and ~24 ms per Verifier, `zk` adds ~4.5 s per cycle and
nothing per Verifier.

The tables follow that order. The mapping to v1 is only approximate: v1's
*requestAttestation* and *tpmQuote* together correspond to **getEvidence** here;
v1's *appraiseEvidence* covers operations 3, 4 and 5, and is a far larger piece
of work in v2; and *discoverVerifiers* has no v1 counterpart at all.

---

## Measurement conditions

| | |
|---|---|
| Toolchain | gcc 9.4.0, Ubuntu 20.04.6 LTS (container) |
| TPM | Two IBM TPM 2.0 simulators, one per role (Attester `:2321`, RP `:2325`), both `TPM2_Startup(CLEAR)`ed |
| Samples (steady state) | 10 measured cycles per sweep step, plus 1 discarded warm-up; 55 attestation cycles in total. This describes the main sweep, taken with `NUM_RUNS = 10`; the trust-mode comparison sections were run later at `NUM_RUNS = 5` and say so. |
| Samples (one-off costs) | 10 independent cold starts, each wiping both NVChips, restarting both simulators, regenerating the trust anchor and clearing the qualification grant |
| Verifiers | Sweep of 1 to 5 |
| IMA log under test | **33 entries**, 4728 bytes raw → `log_r` 4257 bytes after redaction. **This is no longer the default log.** `ima_test_logs.txt` now holds the 167-entry vendor evidence, and every figure below that scales with entry count — the PCR extend, both replays, the redaction — is correspondingly larger on it: the extend alone measures ~14 s rather than the 2.7 s tabulated here. The tables are kept as the measurements they were; re-running the sweep against the 167-entry log is a separate exercise. |
| Qualification challenge log | **40 entries**, 5210 bytes (synthetic, generated fresh per handshake) |
| Evidence size | 6582 bytes on the wire |
| Trust mode | `TRUST_MODE=qualify`, the default. `tee` and `zk` are measured in their own sections; no figure outside those was taken under either. |
| Transport | Plain UDP — `DTLS_MODE=off`, the default. DTLS is now available (`psk`, `rpk`) but every figure below was taken without it; see the note under the caveats. |
| Instrumentation | 42 timing points. Steady-state figures all come from one single sweep run; the cold-start and `/qualify` figures come from one separate 10-iteration cold run, since neither is reachable more than once per process. No figure is pooled across runs. |
| Averaging | Every figure is a mean ± standard deviation over the stated `n`, with one clearly marked exception: the 1-Verifier first-cycle column below, which is a single measurement (`n = 1`). |

**A note on transport.** These were all measured over plain UDP. DTLS can now
be switched on for every role at once with `DTLS_MODE`, which was not possible
when this set was taken — the Relying Party had no flag for it. Measured
separately on one image over two cycles at five Verifiers, the cost is small
next to the figures below: the per-cycle fan-out went 3.916s (`off`) → 3.935s
(`psk`) → 4.067s (`rpk`). So encryption adds roughly 0.02s and mutual
authentication roughly 0.15s, against a fan-out of about four seconds. Those
three numbers are a single two-cycle comparison, not a full sweep, and should
not be read with the same confidence as the tables below.

**Two caveats, both material.**

The container image is `linux/amd64` and the host is an Apple M4 Pro (arm64), so
everything ran under emulation. **Absolute times are not comparable to the v1
baseline**, which was measured natively. Ratios between operations, and the
scaling behaviour across Verifier counts, remain meaningful.

Unlike v1, the Relying Party phase timings **include** communication time — they
bracket whole round trips, which is what the phase costs in practice. The
Attester-side and Verifier-side breakdowns exclude it, matching v1.

All figures are milliseconds, reported as mean ± standard deviation over the
`n` stated for each table — except the single 1-Verifier first-cycle column,
which is marked `n = 1` and carries no deviation because there is only one
sample to take.

---

## Main operations

An attestation cycle divides into **five operations**, each bracketed by its own
timer rather than derived by subtraction. They are listed in execution order,
measured at the Relying Party, steady state, with a single Verifier. `n = 10`.

| # | **Operation** | **Who does the work** | **Cadence** | **Time** | **% of cycle** |
|:--:|---|---|---|:--:|:--:|
| 1 | *discoverVerifiers* — ask the Trust Manager which Verifiers to use | RP ↔ Trust Manager | per cycle | 0.40 ms ± 0.52 | 0.01 % |
| 2 | *getEvidence* — request and receive `Quote_a` + the IMA log | RP ↔ Attester | per cycle | 212.29 ms ± 4.42 | 6.53 % |
| 3 | *appraiseEvidence_a* — the RP's own check of what the Attester sent | RP, local | per cycle | 1.02 ms ± 0.31 | 0.03 % |
| 4 | ***prepareEvidence_r*** — redact the log, replay it into the RP's TPM to rebuild `PCR_r` | RP + its own TPM | per cycle | **2820.84 ms ± 14.85** | **86.76 %** |
| 5 | *submitAndCollect* — `/nonce`, `Quote_r`, `/appraise`, verdict verification, majority vote | RP ↔ N Verifiers | **per Verifier** | 216.55 ms ± 5.03 | 6.66 % |
| | **Total attestation cycle** | | | **3251.22 ms ± 14.45** | **100 %** |

**The five sum to 3251.10 ms against a measured total of 3251.22 ms** — a
residual of 0.12 ms, or 0.004 %. Nothing of consequence falls outside them.

Two things this decomposition makes visible that a three-way split cannot:

- **One operation is 87 % of the cycle.** `prepareEvidence_r` is the RP
  rebuilding `PCR_r` in its own TPM, and it dominates everything else combined.
- **Operation 5 is charged per Verifier, the rest per cycle.** That single
  structural fact is why cost scales with Verifier count, and it is the whole
  content of *Scaling with the number of Verifiers*, near the end.

### The intermittent sixth: /qualify

A Relying Party must hold a qualification grant before any Verifier accepts its
evidence. The handshake is **not** part of every cycle: it runs only when the
previous grant has lapsed, and is otherwise a no-op costing 0.04 ms. It sits
inside the same window as operations 4 and 5, but outside both timers.

| **Case** | **Time** |
|---|:--:|
| Handshake performed (`/qualify` + `/qualify_submit`) | 238.3 ms ± 19.7 |
| Grant still valid — no exchange | 0.023 ms ± 0.011 |

This run caught it happening in the wild, which is also the one place the
arithmetic above does not close. At 5 Verifiers the five operations undershoot
the measured total by 21.75 ms — because the 180 s grant lapsed mid-sweep and
exactly one of that step's ten cycles paid for a real re-qualification of
218.0 ms. Spread over ten cycles that is 21.80 ms, against a 21.75 ms shortfall.
At 1 to 4 Verifiers, where no grant expired, the residuals are 0.12, 0.30, 0.06
and 0.20 ms.

The first cycle after start-up is far more expensive. Its `getEvidence` pays the
Attester's one-off IMA-log extension (≈ 2748 ms, below), and its
`appraiseEvidence` contains the `/qualify` handshake (≈ 233 ms) and the RP's own
cold key derivation. It is measured separately and excluded from the averages
above:

Broken down the same five ways, over **10 independent cold starts** at 5
Verifiers:

| **Operation (first cycle, 5 Verifiers)** | **Time** | **vs steady state** |
|---|:--:|:--:|
| discoverVerifiers | 18.00 ms ± 1.25 | 45× |
| getEvidence | 3075.09 ms ± 14.50 | 14× |
| appraiseEvidence_a | 10.92 ms ± 1.63 | 11× |
| prepareEvidence_r | 2844.12 ms ± 20.47 | 1.008× |
| submitAndCollect | 1038.54 ms ± 35.84 | 1.000× (at 5 V) |
| **Total first cycle** | **6986.68 ms ± 58.36** | 1.7× (vs 4097.2 ms, 5 V) |

The pattern is informative. **`prepareEvidence_r` and `submitAndCollect` are
already at steady-state cost on the very first cycle** — 2844.12 against
2820.84 ms, and 1038.54 against 1038.72 ms at 5 Verifiers. Neither has a warm-up: the TPM
replay costs the same every time, and so does the per-Verifier fan-out.

Everything expensive about a cold start is in `getEvidence`, which carries the
Attester's one-off IMA-log extension of ≈ 2748 ms. The other two inflations are
large as ratios but small in absolute terms — `discoverVerifiers` at 18 ms and
`appraiseEvidence_a` at 11 ms are first-call effects (CoAP session setup, page
faults, first-touch allocation) costing under 30 ms combined.

---

## Breakdown of *getEvidence* (Attester side)

Sub-operations of `/attest` handling, in the order they are carried out. These
exclude the network round trip, so they do not sum to the 212.29 ms above.
`n = 54`, the cold first cycle excluded.

| **Operation** | **Time** |
|---|:--:|
| Initializing the TCTI and ESYS | 2.32 ms ± 0.39 |
| Loading the TPM key | 33.30 ms ± 2.89 |
| tpm2_quote | 87.10 ms ± 2.81 |
| **Total /attest handling** | **122.78 ms ± 3.63** |

The three rows account for the total exactly (2.32 + 33.30 + 87.10 = 122.72 ms
against a measured 122.78 ms): unmarshalling the request and marshalling the
evidence are below the resolution of this measurement.

### The one-off cost of the first /attest

The Attester extends the IMA log into its TPM's PCRs **once per process**,
guarded by a `static bool` in `attester_attest.c` — PCRs 0–15 cannot be reset
without a reboot, so replaying the log per request would keep growing PCR 10.
That single operation is what makes the first request expensive.

Sampled over **10 independent cold starts** (each with both NVChips wiped, both
simulators restarted, and the trust anchor regenerated):

| **Operation (first /attest of a process)** | **Time** |
|---|:--:|
| Extending the IMA log into the TPM PCRs (**33 entries**) | 2748.3 ms ± 15.8 |
| Loading the TPM key (cold) | 145.7 ms ± 18.7 |
| tpm2_quote | 67.7 ms ± 22.1 |
| Initializing the TCTI and ESYS (cold) | 7.1 ms ± 0.3 |
| **Total /attest handling (cold)** | **2972.1 ms ± 14.6** |

The rows account for the total: 2748.3 + 145.7 + 67.7 + 7.1 = 2968.8 ms against
a measured 2972.1 ms.

These are the 10 cold-start samples rather than the sweep, since a steady-state
sweep reaches the cold path only once. For a like-for-like comparison, the
second cycle of those same processes gives 45.0 ms ± 16.0 for the key load and
108.9 ms ± 12.0 for `/attest` overall, against the sweep's 33.3 ms and 122.8 ms
— the cold harness restarts every role on each iteration, so its warm figures
are close to but not identical to the sweep's.

So the cold first cycle is **not** dominated by key derivation, as the
steady-state key-load figure might suggest. The IMA log extension is **92 %** of
it. Key derivation is real but small: 145.7 ms cold against 45.0 ms warm in the
same processes, a difference of about 101 ms.

---

## The RP's own appraisal of *evidence_a*

Before forwarding anything, the Relying Party appraises what the Attester sent.
This runs inside the **`getEvidence`** phase, not `appraiseEvidence`:
`charra_rp_appraise_evidence()` is called from `coap_attester_handler()`, the
`/attest` response handler, so it is already finished by the time the
`getEvidence` timer stops. Redaction is the opposite case — it belongs to
`appraiseEvidence`, see the next section. `n = 55`.

Counting the log lines per phase confirms the split exactly: **55** RP
appraisals inside `getEvidence` and **0** inside `appraiseEvidence`; **165**
Verifier Step 3b checks inside `appraiseEvidence` and **0** inside
`getEvidence`.

| **Operation** | **Time** |
|---|:--:|
| Verify `AK_a` against the trust anchor | 0.179 ms ± 0.332 |
| Verify `Quote_a` signature | 0.296 ms ± 0.332 |
| Unmarshal `Quote_a` | 0.109 ms ± 0.636 |
| Verify `nonce_a` | 0.006 ms ± 0.006 |
| Verify `log_a` self-consistency (**33 entries**) | 0.070 ms ± 0.045 |
| Replay `log_a` + rebuild PCR composite, software (**33 entries**) | 0.367 ms ± 0.079 |
| Whitelist/blacklist policy | 0.069 ms ± 0.112 |
| **Total appraisal of `evidence_a`** | **1.198 ms ± 1.494** |

The whole appraisal costs about 1.2 ms — 0.6 % of the 212.29 ms `getEvidence`
operation. Essentially all of that operation is the Attester's `/attest`
handling and the round trip, not the RP's verification of the answer.

The other RP-side cost inside this phase is generating `nonce_a`, the challenge
sent to the Attester, in `create_attestation_request()`: **0.053 ms ± 0.178**
using the software RNG. `USE_TPM_FOR_RANDOM_NONCE_GENERATION` would instead draw
it from the TPM; that path was not exercised in this run, and given every other
TPM round trip measured here, it would be expected to cost orders of magnitude
more.

---

## Building and submitting *evidence_r*

The work splits in two, and the distinction matters: some of it is done once
per cycle, the rest once **per Verifier**.

**Once per cycle** (`n = 55`) — `charra_rp_prepare_evidence()`, called from
`get_attestation_results()` and therefore inside the **`appraiseEvidence`**
phase, in execution order:

| **Operation** | **Time** |
|---|:--:|
| Redact the IMA log, **33 entries**, 4728 → 4257 bytes | 0.800 ms ± 0.404 |
| **Replay `log_r` into the RP's own TPM, 33 `TPM2_PCR_Extend` calls** | **2833.0 ms ± 24.9** |

These two are the whole of `prepareEvidence_r`, and sum to 2833.8 ms against the
2820.84 ms measured for the operation itself — 13 ms *more* than the operation
containing them. They are not from the same samples: this table is `n = 55` and
the cycle table is `n = 10`, and the standard deviations (± 24.9 and ± 14.85)
overlap comfortably. Treat agreement between the two tables as ± 15 ms, not as
the two decimals each prints.

### Redaction on its own, over the 167-entry vendor log

The row above prices redaction as it occurs inside a cycle, on the old 33-entry
log. This section prices the function directly, on the log now in use, over
**100 consecutive calls** — `bin/test_redaction_bench`, which links the same
objects a run does rather than a copy of them.

**Conditions.** Apple M4 Pro (8 performance + 4 efficiency cores), 24 GiB RAM,
macOS 26.6.2 on `arm64`. Docker Desktop 29.6.2 with 12 CPUs and 7.75 GiB
available to containers. CHARRA itself builds and runs in
`fraunhofer-sit/charra-dev-env:1.9.0`, which is a **`linux/amd64` image and is
therefore emulated on this host** — `uname -m` inside it reports `x86_64`.
Every figure here is emulated, not native, and would be faster on matching
hardware. gcc 9.4.0, Ubuntu 20.04.6 LTS. Input `ima_test_logs.txt`: 167
entries, 27,986 bytes as binary `log_a`, carrying 20-byte SHA-1 template
digests, which redaction preserves.

| **Commitment** | **Whole log (167 entries)** | **Per entry** | **`log_r`** |
|---|--:|--:|--:|
| SHA-256 — every ordinary cycle | **1.090 ms ± 0.215** | **0.0065 ms** | 29,644 B |
| Poseidon — `--trust-mode=zk` only | **370.584 ms ± 4.434** | **2.2191 ms** | 29,644 B |

Poseidon costs about **340× more per entry** than SHA-256 here, and that is the
expected direction rather than a defect: the commitment is chosen to be cheap
*inside* a circuit, where a SHA-256 would dominate the gate count, and it is
paid for outside one. It is still small beside the TPM replay that follows it,
and beside the ~39 s the proof itself takes. Both produce the same `log_r` size,
since both commitments are 32 bytes before hex.

Two cautions on reading these against the in-cycle row above. They are not the
same measurement: this one calls the function in a tight loop with everything
already warm, while the row above catches it once per cycle amid other work, so
the per-entry figures are not directly comparable (0.0065 ms against the older
0.024 ms implied by 0.800 ms over 33 entries). And the in-cycle SHA-256 figure
the RP logs — 0.002 s, printed to three decimals — agrees with 1.090 ms only to
within its own rounding. The Poseidon figures are a much sharper check: 370.6 ms
measured here against the 0.371 s and 0.395 s the RP logged in live ZK runs.

**Once per Verifier** (`n = 165`) — `charra_rp_build_evidence_message()` and the
submission that follows:

| **Operation** | **Time** |
|---|:--:|
| `/nonce` round trip (fetch the Verifier's challenge) | 1.190 ms ± 1.857 |
| **Produce `Quote_r` (derive key + `tpm2_quote`)** | **483.6 ms ± 257.7** |
| SHA-256 over the submission | 0.042 ms ± 0.010 |
| Verify the returned signed verdict | 2.131 ms ± 0.338 |

That ± 257.7 ms on `Quote_r` is not run-to-run noise: it is a mixture across the
sweep, where the per-call cost ranges from 210 ms at 1 Verifier to 620 ms at 5.
The per-count figures below are the meaningful ones.

Redaction is cheap — 0.800 ms to rewrite 4728 bytes of log down to 4257 — but
the TPM replay that must follow it is the single most expensive operation in the
entire system. The redaction is what forces it: because the log the Verifiers
appraise is *not* the log the Attester measured, the RP cannot forward
`Quote_a`'s PCR value and must rebuild `PCR_r` in its own TPM, one
`TPM2_PCR_Extend` per entry.

`Quote_r` is the other dominant cost, and it is charged **once per Verifier**:
each Verifier issues its own challenge nonce, so the RP must produce a separate
quote for each. `rp_quote_pcr_with_ak()` opens the TPM, derives the AK, quotes,
and tears the session down on every call.

Its cost grows with the number of Verifiers even though the work per call is
identical:

| **Verifiers** | **`Quote_r` per call** | **max** |
|:--:|:--:|:--:|
| 1 | 209.6 ms | 215.2 ms |
| 2 | 311.9 ms | 430.1 ms |
| 3 | 413.1 ms | 629.7 ms |
| 4 | 520.4 ms | 857.0 ms |
| 5 | 619.9 ms | 1041.5 ms |

That is **queueing, not extra work**: the software TPM serves one client at a
time, and the RP runs one thread per Verifier. A least-squares fit gives
102.9 ms per additional Verifier with a 106.2 ms intercept — each waiting thread
is delayed by roughly one other thread's quote. Note that a hardware TPM would
serialise the same way; the concurrency is in the RP, not the device.

Also worth noting: **verifying a signed verdict costs the RP more (2.13 ms) than
the `/appraise` handling it certifies costs the Verifier (1.02 ms)** — though
once the Verifier's out-of-window verdict signing is included (0.83 ms), the two
sides are close to even.

---

## Breakdown of *appraiseEvidence* (Verifier side)

Sub-operations of `/appraise` handling, in execution order, pooled across all
five Verifier instances. `n = 165`. Step numbers follow the DRA-TLS naming used
in the source.

**Step 3a — the Relying Party's own evidence (`evidence_r`):**

| **Operation** | **Time** |
|---|:--:|
| Unmarshal the evidence | 0.060 ms ± 0.022 |
| Verify `AK_r` + derive the RP fingerprint (3a.1) | 0.135 ms ± 0.297 |
| RP qualification lookup (3a.1b) | 0.070 ms ± 0.220 |
| Verify `Quote_r` signature (3a.2) | 0.238 ms ± 0.194 |
| Verify `nonce_r` (3a.3) | 0.010 ms ± 0.005 |
| Replay `log_r` into `PCR_r`, software (**33 entries**) (3a.4) | 0.054 ms ± 0.026 |

**Step 3b — the original Attester evidence (`evidence_a`), re-checked
independently:**

| **Operation** | **Time** |
|---|:--:|
| Verify `AK_a` against the trust anchor (3b.1) | 0.030 ms ± 0.006 |
| Verify `Quote_a` signature (3b.2) | 0.188 ms ± 0.035 |
| Verify `nonce_a` (3b.3) | 0.0004 ms ± 0.001 |
| **Total /appraise handling** | **1.020 ms ± 1.382** |

| **After the /appraise window closes** | **Time** |
|---|:--:|
| Sign the verdict | 0.833 ms ± 0.571 |

The nine listed steps sum to 0.785 ms against a measured total of 1.020 ms; the
0.235 ms difference is CoAP payload retrieval, the per-request timing-file open,
and the consolidated logging, none of which is separately instrumented.

Verdict signing happens in `send_verdict()`, which is called *after* the
`/appraise` timer stops, so it is not inside the 1.020 ms total. The Verifier's
full server-side cost is therefore about **1.85 ms**.

**The Verifier does not trust the RP's appraisal.** Steps 3b.1–3b.3 repeat
checks the RP already performed on `evidence_a`. What it does *not* repeat is
the log-integrity and policy work: `log_a` self-consistency, the PCR composite
rebuild, and the whitelist/blacklist check exist only on the RP side. Log policy
therefore has exactly one enforcement point in the system.

**The Verifier is not the bottleneck.** A whole appraisal costs about 1 ms,
against a 3251 ms attestation cycle. The dominant cost is the RP-side
preparation tabulated above — chiefly the 2833.0 ms TPM replay of `log_r`, which
alone is **87 %** of the entire cycle.

**Software replay is thousands of times cheaper than TPM replay.** Every replay
below walks the same **33-entry** log, which makes the per-entry cost directly
comparable:

| **Operation over the 33-entry log** | **Total** | **Per entry** |
|---|:--:|:--:|
| Attester: extend into TPM PCRs (once per process) | 2748.3 ms | 83.28 ms |
| RP: replay `log_r` into its TPM | 2833.0 ms | 85.85 ms |
| RP: redact | 0.800 ms | 0.0242 ms |
| RP: replay `log_a` + PCR composite, software | 0.367 ms | 0.0111 ms |
| Verifier: replay `log_r`, software | 0.054 ms | 0.0016 ms |

The two TPM replays agree closely on per-entry cost (83.3 and 85.9 ms), which is
what you would expect if the figure is dominated by one `TPM2_PCR_Extend` round
trip to the simulator per entry and almost nothing else. A software replay of
the same log costs 0.0016–0.0111 ms per entry: about **7700×** cheaper than the
TPM on the RP's own path, and about **54 000×** cheaper on the Verifier's.

(The Attester row comes from the cold run, the rest from the sweep — the two
TPM figures are therefore independent measurements on different TPMs, which is
what makes their agreement meaningful.)

The practical consequence: **cost here is driven by entry count, not byte
count.** A longer log costs the RP ~86 ms per additional entry, and that single
number governs 87 % of the attestation cycle.

---

## The /qualify handshake

**In `TRUST_MODE=qualify`, the default**, no Verifier will accept an
`/appraise` submission from a Relying Party that does not hold a qualification
grant. `rp_perform_qualification_handshake_once()` runs at the top of every
attestation run, but performs the `/qualify` + `/qualify_submit` exchange only
when the previous grant has lapsed — otherwise it returns immediately.

**In `TRUST_MODE=tee` and `TRUST_MODE=zk` there is no handshake at all**: the
RP is not asked to qualify, no grant is looked up, and the costs below do not
arise. It proves itself another way instead — a TEE Attestation Document per
Verifier, or one zero-knowledge proof per cycle — both measured in the sections
that follow.

Both cases, sampled over 10 cold starts (grant cleared by removing
`qualified_rps.txt`, then a second cycle run with the fresh grant still valid):

| **Case** | **Time** |
|---|:--:|
| Handshake performed (`/qualify` + `/qualify_submit`) | 238.3 ms ± 19.7 |
| Grant still valid — no exchange | 0.023 ms ± 0.011 |

The handshake costs more than a whole `getEvidence` round trip (212.29 ms), so
it is a significant one-off. It is charged to the first cycle after start-up and
then amortised across every cycle until the grant expires —
`VERIFIER_QUALIFICATION_VALIDITY`, 180 s by default. The no-op path is
essentially free, three to four orders of magnitude cheaper, so a held grant
costs nothing to re-check.

### What the handshake actually does

The exchange is a redaction competence test. The Verifier invents a log, redacts
it itself to produce a golden answer, and asks the RP to redact the same log; a
grant is issued only if the two come out byte-identical. `n = 10`, in execution
order, with **V:** marking Verifier-side work and **RP:** the Relying Party's:

| **Stage** | **Time** |
|---|:--:|
| V: random seed + salt, then generate the synthetic log | 5.638 ms ± 0.395 |
| V:  — of which, generating the **40-entry**, 5210-byte log + golden answer | 1.837 ms ± 0.280 |
| RP: `/qualify` round trip (fetch the challenge) | 19.019 ms ± 1.652 |
| RP: redact the synthetic log (**40 entries**, 5210 bytes) | 0.097 ms ± 0.010 |
| **RP: sign (redacted log ‖ salt) — derive AK + `Esys_Sign`** | **210.189 ms ± 17.215** |
| RP: `/qualify_submit` round trip | 8.403 ms ± 2.117 |
| V: verify the RP's signature over the submission | 1.753 ms ± 0.385 |
| V: compare golden answer vs submitted redaction | 0.084 ms ± 0.020 |
| **RP: total handshake** | **238.337 ms ± 19.737** |

The RP-side stages account for the total: 19.019 + 0.097 + 210.189 + 8.403 =
237.708 ms against a measured 238.337 ms, the remainder being marshalling.

**The handshake is one TPM signature with a protocol wrapped around it.**
Signing is 88 % of the cost, and it is expensive for the same reason `Quote_r`
is: `rp_sign_with_ak()` opens the TPM, derives the AK from the owner hierarchy,
signs, and tears the session down, every call. The cryptographic *test* — the
part that actually establishes competence — is almost free: generating the
synthetic log costs 1.8 ms and comparing the two redactions costs 0.08 ms.

Two things worth noting about the shape of this:

- **Redaction here costs 0.097 ms for 40 entries, against 0.800 ms for the
  33-entry real log** — the *larger* log redacts eight times faster. The cause
  is not non-linearity but a real difference in work. Given a caller-supplied
  salt, `charra_sdk_redact_ima_log()` reuses that one salt for every entry;
  given `salt == NULL`, which is what real evidence always uses, it draws a
  fresh 32-byte random salt **per entry**. The real path therefore pays 33 RNG
  draws and the qualification path pays none. Per entry that is 24.2 µs against
  2.4 µs, putting one 32-byte random draw at about 21.8 µs — so **roughly 90 %
  of what redacting real evidence costs is generating salt, not hashing.**
  Either way it is negligible beside the TPM replay the redaction forces
  afterwards.
- **Generating randomness costs more than generating the log.** Seed and salt
  together take about 3.5 ms of the 5.0 ms verifier-side preparation, against
  1.5 ms to build the log and its golden answer.

**No replay, no PCR.** Unlike the evidence path, the handshake never calls
`TPM2_PCR_Extend`: two identical logs replay identically, so a byte comparison
is sufficient. The signature is there to say *who* submitted, not *what state* —
the grant is recorded against the signing key's fingerprint. The salt is folded
into the signed data so a captured submission cannot be replayed into a later
round, and it is deliberately transmitted to the RP — the one exception to
"the salt is never sent" — so that a correctly-behaving RP's redaction is
byte-identical to the golden copy. That is safe only because this log is
synthetic.

---

## The alternatives to /qualify: TEE mode

The handshake above is one of three ways the RP can prove it is running the
expected appraisal code. The second, selected with `TRUST_MODE=tee`, replaces
it with a simulated TEE Attestation Document — a measurement of the RP's
appraisal sources bound to `hash(verifier_nonce || pcrdigest_a || log_r)` and
signed under a key certified by AK_r. See the manual for what each mechanism
does and does not establish; what matters here is what each costs.

The two are not interchangeable in cadence, and that is the whole result:
**the handshake is once per cycle and usually a no-op, while a TEE document is
built and signed once per Verifier.** Full 1..5 sweep, **five** measured cycles
at each step, same image, same TPM configuration:

| **Verifiers** | **`qualify`** | **`tee`** | **difference** |
|:--:|:--:|:--:|:--:|
| 1 | 3225.4 ms ± 19.2 | 3283.4 ms ± 17.8 | +58.1 ms (+1.8 %) |
| 2 | 3411.4 ms ± 33.9 | 3456.2 ms ± 17.9 | +44.8 ms (+1.3 %) |
| 3 | 3608.7 ms ± 19.8 | 3686.2 ms ± 10.0 | +77.5 ms (+2.1 %) |
| 4 | 3790.5 ms ± 24.7 | 3917.5 ms ± 27.6 | +126.9 ms (+3.3 %) |
| 5 | 3988.0 ms ± 24.8 | 4123.6 ms ± 20.7 | +135.6 ms (+3.4 %) |

**These are a separate run from the main sweep**, taken later and with
`NUM_RUNS` at 5 rather than the 10 the earlier tables were measured under. That
is why the `qualify` column here reads 3225.4 → 3988.0 ms where *Scaling with
the number of Verifiers* reports 3251.2 → 4097.2 ms for the same mode: 1-3 %
apart, consistent with the standard deviations, but not the same samples. Compare
columns within this table, not across to the earlier ones.

Least-squares over each column, on the same basis as the per-Verifier scaling
section near the end of this document:

| | **fixed cost** | **marginal cost per Verifier** |
|---|:--:|:--:|
| `qualify` | 3033.5 ms | 190.4 ms |
| `tee` | 3050.9 ms | 214.2 ms |

**The fixed cost is unchanged; the per-Verifier cost carries the whole
difference** — about 24 ms each. The fixed columns differ by 17 ms, well
inside the ± 15-25 ms band these tables agree to, so TEE mode adds nothing
measurable once per cycle. This is the expected shape rather than a surprise:
per-cycle work was removed and per-Verifier work added.

Where those 24 ms go, measured directly:

| **Operation** | **Time** |
|---|:--:|
| Verifier: check one Attestation Document (5 checks) | 2.25 ms ± 0.71 |
| RP: measure 3 source files, RSA-PSS sign, per Verifier | remainder, ≈ 22 ms |

The Verifier's side is cheap because all five of its checks are public-key
maths and hashing over a few hundred bytes — the same reason its `/appraise`
work is dominated by the `log_r` replay rather than by signatures. The RP's
side is the costly half: an RSA-2048 PSS signature plus three file reads and a
hash, repeated for every Verifier because each contributes its own nonce.

AK_r's certification of the TEE public key does **not** appear per Verifier.
The TEE keypair is generated once per process, so the certification is too,
and it is cached — without that, every Verifier thread would re-derive AK_r
from the TPM to sign a value that never changes, which would have put a
33 ms key load (see *getEvidence*, above) on the per-Verifier path.

For a five-Verifier deployment choosing `tee` over `qualify` costs 3.4 %. At one
Verifier it is 1.8 %, and those two are within about one standard deviation of
each other. The third mode is a different order of magnitude, and is measured
next.

### The third mode: `zk`

`TRUST_MODE=zk` replaces the handshake with a zero-knowledge proof that
`log_r`'s cleaned paths commit to paths the Attester really measured. Full
1..5 sweep, five measured cycles at each step, alongside the other two modes:

| **Verifiers** | **`qualify`** | **`tee`** | **`zk`** |
|:--:|:--:|:--:|:--:|
| 1 | 3225.4 ms ± 19.2 | 3283.4 ms ± 17.8 | 7758.5 ms ± 162.7 |
| 2 | 3411.4 ms ± 33.9 | 3456.2 ms ± 17.9 | 7937.6 ms ± 122.9 |
| 3 | 3608.7 ms ± 19.8 | 3686.2 ms ± 10.0 | 8052.7 ms ± 134.6 |
| 4 | 3790.5 ms ± 24.7 | 3917.5 ms ± 27.6 | 8340.1 ms ± 66.9 |
| 5 | 3988.0 ms ± 24.8 | 4123.6 ms ± 20.7 | 8548.5 ms ± 151.0 |

Least-squares over each column:

| | **fixed cost** | **marginal, per Verifier** |
|---|:--:|:--:|
| `qualify` | 3033.5 ms | 190.4 ms |
| `tee` | 3050.9 ms | 214.2 ms |
| `zk` | **7532.7 ms** | **198.2 ms** |

**`zk` adds 4499 ms to the fixed cost and 7.8 ms to the marginal** — that is
the whole result. The proof is produced once per cycle, because every
Verifier receives the same `log_r` and the same `Quote_a`, so its cost does
not scale with Verifier count. `tee` is the mirror image: nothing fixed, and
~24 ms on every Verifier.

Where the 4.5 s goes, measured over the 30 proofs of the sweep:

| **Operation** | **Time** | **Cadence** |
|---|:--:|:--:|
| RP: produce the proof, first of a run | 8.03 s | once |
| RP: produce the proof, thereafter | **4.13 s ± 0.11** | per cycle |
| Verifier: check it | **0.224 s** | per Verifier |

The first proof costs nearly twice the rest because the prover container
fetches and compiles the circuit's dependencies on first use; every later
proof reuses them. That one-off is why a single-cycle daemon run reports ~7.6 s
where the sweep settles at 4.1 s.

| | |
|---|---:|
| Circuit size | 839,117 gates |
| Proof on the wire | 14.6 KB |
| Public inputs (rebuilt by the Verifier, never sent) | 44 KB |
| Verification key | 3.7 KB |

Two figures bound what this can be used for. The circuit is compiled for a
fixed ceiling — `global N`, **167** at the time of writing, sized to the vendor
evidence log — and the cost grows linearly with it, so a real IMA log of
thousands of entries is out of reach. And proving runs in a native
`linux/arm64` container: under x86 emulation Barretenberg does not run at
all.

> **The figures in this section and the next were measured against the
> three-SHA-block circuit, compiled for 33 entries.** The circuit has since
> changed in two ways that raise the per-entry cost: it rebuilds the *whole*
> path — rejoining a private directory with a public filename — rather than
> hashing a single array, and the longest resulting record (185 B) no longer
> fits three SHA-256 blocks, so `sha256_var` now uses four. A single
> observed run of the current circuit at N = 167 took ~39 s to prove with
> 6.8 GiB peak. That is one shot, not the five-run average the tables below
> report, and it is not comparable to them; the tables are kept as the
> measurements they were rather than being overwritten with estimates.

---

## How the ZK proof scales with the log

The section above prices one circuit, compiled for 33 entries with the
three-block SHA. This one asks what happens as that ceiling moves — which is the question that decides
whether the approach could ever meet a real IMA log.

Nine circuits were compiled, each proved **five times**, so every row carries a
variance rather than being a single shot. All in one container run, so the
timings are comparable to each other.

**Entries** is the circuit's compiled ceiling — `global N` in
`zk/circuit/src/main.nr`, the most log entries that circuit can prove.

| **Entries** | **gates** | **prove, 5 runs** | **peak RAM, 5 runs** | **proof** | **vk** | **verify** |
|--:|--:|--:|--:|--:|--:|--:|
| 4 | 123,020 | 0.646 s ± 0.011 | 212.0 MiB ± 0.7 | 14,656 B | 3,680 B | 0.01 s |
| 8 | 221,792 | 1.002 s ± 0.012 | 367.4 MiB ± 1.7 | 14,656 B | 3,680 B | 0.01 s |
| 16 | 419,336 | 1.688 s ± 0.039 | 643.0 MiB ± 0.7 | 14,656 B | 3,680 B | 0.01 s |
| 33 | 839,117 | 3.101 s ± 0.056 | 1,249.2 MiB ± 1.1 | 14,656 B | 3,680 B | 0.01 s |
| 64 | 1,604,600 | 5.500 s ± 0.027 | 2,324.8 MiB ± 0.4 | 14,656 B | 3,680 B | 0.01 s |
| 96 | 2,394,776 | 8.036 s ± 0.082 | 3,476.6 MiB ± 1.3 | 14,656 B | 3,680 B | 0.01 s |
| 128 | 3,184,952 | 10.456 s ± 0.128 | 4,546.6 MiB ± 0.9 | 14,656 B | 3,680 B | 0.02 s |
| 160 | 3,975,128 | 13.008 s ± 0.264 | 5,592.4 MiB ± 2.6 | 14,656 B | 3,680 B | 0.02 s |
| 192 | 4,765,304 | 16.468 s ± 0.616 | 6,838.6 MiB ± 4.4 | 14,656 B | 3,680 B | 0.02 s |

**A 256-entry circuit could not be measured**: it needs about 9.1 GB and the OOM killer
took it at 17 s, exit 137. On this host — Docker Desktop with 7.75 GiB — 192
entries is the practical ceiling. That is the real limit, not an extrapolated
one.

### Complexity: linear in the entry count

Every doubling of the entry count roughly doubles gates, time and memory. The 128 → 192 step
is the cleanest, because by then the fixed overhead has amortised away:

| | **entry ratio** | **gates** | **time** | **memory** |
|---|:--:|:--:|:--:|:--:|
| 4 → 8 | ×2.00 | ×1.80 | ×1.55 | ×1.73 |
| 64 → 128 | ×2.00 | ×1.98 | ×1.90 | ×1.96 |
| **128 → 192** | **×1.50** | **×1.50** | **×1.58** | **×1.50** |

Least squares over the nine points, each a mean of five:

| | **per entry** | **intercept** | **R²** |
|---|:--:|:--:|:--:|
| gates | 24,693 | +24,248 | — |
| time | **81.54 ms** | +0.305 s | 0.99813 |
| peak RAM | **34.91 MiB** | +86.7 MiB | 0.99977 |

Per-entry cost *falls* as the ceiling grows — 165 ms and 53 MiB per entry at
4 entries, against 86 ms and 35.6 MiB at 192 — because that fixed intercept, the
final composite hash, amortises away. The asymptotic constants are the
per-entry figures above.

**Memory is linear to a stricter standard than time.** Its residuals sit far
outside the ±5 MiB measurement noise, while time's largest residual (0.507 s,
at 192 entries) is comparable to that point's own standard deviation. Proving
allocates deterministically; its *timing* is subject to scheduling.

Timing noise is 0.5-2.3 % of the mean at most sizes and **3.7 % at 192
entries** —
the largest circuit is the noisiest, plausibly memory pressure near the
ceiling. Memory noise never exceeds 0.06 %.

UltraHonk proving is theoretically O(N log N) in the entry count. Over 4 → 192,
log₂N runs 2 → 7.6, and its effect is smaller than the fixed overhead at the
bottom and the
timing noise at the top, so it cannot be separated here. Linear is the right
model at these sizes; it would eventually bend upward at scales this hardware
cannot reach.

### Three things that do not grow

**The proof is 14,656 bytes at every entry count.** So is the verification key, at
3,680 B, and so is verification, at about 0.01 s and 7.7 MiB. That is the
succinctness property: the verifier's cost does not depend on the size of the
computation proved. Every bit of the growth lands on the prover.

### What actually stops you: memory

Peak RAM is **34.91 MiB per entry**, and `bb`'s self-reported figure is honest
— for a 33-entry circuit it reports 1250.41 MiB against a measured maximum resident set of
1,280,416 kB, the same number.

**This is a measured wall, not a projected one.** A 256-entry circuit needs
about 9.1 GB;
the OOM killer took it after 17 seconds, exit 137. With 7.75 GiB available the
largest provable log is 192 entries.

Extrapolating beyond that:

| **entries** | **est. gates** | **est. prove** | **est. peak RAM** |
|--:|--:|--:|--:|
| 256 | 6.3 M | ~21 s | ~9 GB — **OOM here on 7.75 GiB** |
| 512 | 12.6 M | ~42 s | ~18 GB |
| 1,000 | 24.7 M | ~82 s | ~35 GB |
| 5,000 | 123 M | ~7 min | ~175 GB |

A real IMA log of a few thousand entries would need tens to hundreds of GB to
prove, held all at once, on the party doing the redaction, every cycle. Time
can be waited out; that memory is not a laptop, and at 5,000 entries not an
ordinary server either. It is the binding constraint, not proving time.

**What is stored, though, never grows.** The proof is 14,656 bytes whatever the
entry count,
and that is the only artefact that travels. The gigabytes are transient working
memory inside the prover, released as soon as the proof exists — there is no
point at which anything of that size is written or transmitted.

Standard techniques exist for this — proving in chunks and recursively
aggregating, which is what production systems do for exactly this reason —
but that is a different circuit, not a tuning knob.

### Caveats on the method

Each row is a **different circuit** compiled for that many entries, proved with
a witness of exactly that many real ones. Since the circuit pays for all its
slots whatever `n_real` says, this is also the cost of a partly-padded log: the ceiling is
what you pay for, not the fill.

**The measured range is 4 → 192; everything past it is extrapolation.** Within
it the ratios hold tightly and each point is a mean of five, so linear is well
supported there. But 5,000 entries is **26× beyond anything actually run**, and
a projection that far out should be read as an order of magnitude, not a
figure.

**The ceiling was probed, and it is 192 on this host.** The prover container
was given what Docker Desktop allocates by default, 7.75 GiB. A 256-entry
circuit was OOM-killed. A host with more memory would move that line proportionally —
34.91 MiB per entry is the number to divide by — but the shape of the limit
does not change.

---

## Trust Manager: splitting the round trip

Two exchanges have both ends instrumented, so transport can be separated from
the work done at the far end. `discoverVerifiers` is the cleaner of the two,
because
its payload is tiny:

| **Component** | **Time** |
|---|:--:|
| `/get_verifiers` server-side handling (Trust Manager) | 0.271 ms ± 0.480 |
| Round trip as seen by the RP | 0.515 ms ± 0.104 |
| **Implied network + CoAP overhead** | **≈ 0.24 ms** |

So roughly 53 % of this exchange is the Trust Manager doing work and 47 % is
transport. Both are negligible next to the rest of the cycle —
`discoverVerifiers` is 0.02 % of a full attestation.

A caveat on precision: the RP's *phase* log line prints with `%.3fs`, i.e.
millisecond granularity, which is too coarse here. The 0.515 ms figure comes
from `timings_RP_multi_verifiers.txt`, which records microseconds.

The same subtraction applied to `/attest` is far more striking:

| **Component** | **Time** |
|---|:--:|
| Attester-side `/attest` handling | 122.78 ms ± 3.63 |
| `getEvidence` as seen by the RP (round trip, appraisal already excluded) | 212.29 ms ± 4.42 |
| **Implied transport** | **≈ 89.5 ms** |

**Roughly 42 % of `getEvidence` is transport, not computation.** The `/attest`
response carries the full 4728-byte event log plus the quote, which exceeds a
single CoAP datagram and is delivered block-wise. That is the second-largest
transport cost in the system after the TPM work, and unlike the TPM replay it
would not shrink on faster hardware — it is bounded by round trips.

---

## Scaling with the number of Verifiers

Appraisal phase and total cycle, averaged over 10 runs at each step:

| **Verifiers** | **appraiseEvidence** | **Total attestation** |
|:--:|:--:|:--:|
| 1 | 3037.5 ms ± 17.9 | 3251.2 ms ± 19.7 |
| 2 | 3267.3 ms ± 33.6 | 3484.0 ms ± 38.2 |
| 3 | 3456.4 ms ± 28.2 | 3671.3 ms ± 29.8 |
| 4 | 3678.3 ms ± 25.7 | 3894.0 ms ± 25.7 |
| 5 | 3884.6 ms ± 66.0 | 4097.2 ms ± 66.9 |

Least-squares fit over the five steps:

- **fixed cost: 3048.9 ms** — matching the 3034.6 ms sum of the four
  Verifier-independent operations (0.40 + 212.29 + 1.02 + 2820.84) to within
  0.5 %. The dominant term is `prepareEvidence_r`, and within it the 2833.0 ms
  TPM replay of `log_r`: it happens once per cycle regardless of Verifier count
- **marginal cost: 210.2 ms per additional Verifier**

Both are the intercept and slope of the totals column above, so they can be
recomputed from the five printed rows. They differ slightly from the `qualify`
fit given in the trust-mode sections (3033.5 ms and 190.4 ms) because those come
from a separate, later run at `NUM_RUNS = 5`; see the note there.

The five-operation split localises that marginal cost precisely: it is entirely
`submitAndCollect`, the only per-Verifier operation, which grows 216.6 → 420.7 →
622.9 → 841.1 → 1038.7 ms across the sweep. The other four operations are flat,
as they should be — none of them depends on how many Verifiers are used.

Within `submitAndCollect`, the growth is overwhelmingly the extra `Quote_r` the
RP must produce for each Verifier's nonce, whose per-thread cost rises 102.9 ms
per Verifier through TPM queueing. `/nonce` (1.2 ms) and verdict verification
(2.1 ms) are the remainder. It is not appraisal work: a Verifier's own appraisal
costs about 1 ms.

---

## Functional verification

The exact source that produced these measurements — instrumentation included —
passes the full unit-test suite, all of it running without a TPM or network:

| **Suite** | **Assertions** | | **Suite** | **Assertions** |
|---|:--:|---|---|:--:|
| `test_event_log` | 29 | | `test_verdict` | 27 |
| `test_synthetic_log` | 13 | | `test_hex_util` | 25 |
| `test_sdk` | 23 | | `test_pcr_selection` | 16 |
| `test_rp_qualification` | 32 | | `test_message_marshaling` | 47 |
| `test_marshaling_bounds` | 18 | | `test_key_mgr` | 13 |
| `test_trusted_keys` | 9 | | `test_crypto_util` | 22 |
| `test_qualified_rps` | 21 | | `test_parser_util` | 24 |
| `test_get_verifiers_marshaling` | 17 | | `test_tee` | 32 |
| `test_rp_evidence_marshaling` | 41 | | `test_poseidon` | 9 |
| | | | **Total** | **418** |

**18 suites, 418 assertions, 0 failures.**

End-to-end behaviour was checked in the same run: all 55 cycles reached a
unanimous verdict (11 each at 1/1, 2/2, 3/3, 4/4 and 5/5 Verifiers passing),
with no rejected verdicts and no `/appraise` failures.

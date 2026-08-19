# CHARRA-v2 CLI Guide

How to build and run the four binaries, and every flag each one accepts.

For *why* the system is shaped this way, see `CHARRA_V2_NOTES.md`. This file
is purely operational.

---

## 1. The four binaries

| Binary | Role | Listens on | Initiates connections? |
|---|---|---|---|
| `bin/trust_manager` | Resolves Verifier IDs → `ip:port` | 6000 (fixed) | no |
| `bin/attester` | Produces evidence (`Quote_a`, IMA log) | 5683 | **never** |
| `bin/verifier` | Appraises evidence; acts as its own Privacy CA | 31415 (use `--port`) | **never** |
| `bin/relying_party` | Orchestrator + privacy-cleansing proxy | — (client) | yes, to all three |

**The RP is the only active party.** The Attester and every Verifier are pure
passive responders — they never call anyone. Starting `bin/attester` alone
does nothing until an RP talks to it.

Start order: `trust_manager` → `attester` → `verifier`(s) → `relying_party`.

---

## 2. Build

```bash
make -j            # all binaries into bin/
make clean && make -j
make test          # 11 unit-test suites
```

Everything runs from the **repository root** — paths to `keys/`, `state/`,
`verifiers_config.txt` and `reference-pcrs.txt` are relative.

### One-time key generation

```bash
cd keys && ./gen-ak-pki.sh && cd ..
```

Generates one **independent CA per Verifier port** (`verifier-ca-<port>.{key,crt}`,
one for every port in `verifiers_config.txt`), RP's own CA, a synthetic TPM
manufacturer root, and synthetic EK certificates. Test-only — never reuse in
production.

> If you add a port to `verifiers_config.txt`, re-run this script or that
> Verifier will have no CA to sign with.

---

## 3. Quickest way to run everything

```bash
./run_live_test.sh        # Docker: fresh TPM, clean build, full stack, benchmark sweep
```

Or by hand (each in its own shell, from the repo root):

```bash
bin/trust_manager &
bin/attester &
./start_verifiers.sh                       # 5 verifiers on ports 5684-5688
bin/relying_party --verifiers 5            # daemon; Ctrl+C to stop
```

For the same thing spelled out line by line, with every flag explained, see
**§4.1** (daemon mode) and **§4.2** (benchmark mode).

---

## 4. `bin/relying_party`

Runs a **continuous attestation daemon by default**: attest → sleep → repeat,
until stopped. Nothing happens during the sleep; a credential is re-provisioned
by the first cycle that finds it expired.

```bash
bin/relying_party [OPTIONS]
```

| Flag | Default | Meaning |
|---|---|---|
| `--help` | | Print help |
| `-v`, `--verbose` | | CHARRA log-level → DEBUG |
| `-l`, `--log-level=LEVEL` | INFO | `TRACE\|DEBUG\|INFO\|WARN\|ERROR\|FATAL`. Overrides `$LOG_LEVEL_CHARRA` |
| `-n`, `--verifiers=COUNT` | 5 | Verifiers per attestation cycle (1..10), taken from `verifiers_config.txt` |
| `-I`, `--interval=SECONDS` | 15 | Sleep **between** attestation cycles |
| `-D`, `--duration=SECONDS` | 0 | Stop cleanly after ~N seconds. 0 = run until signalled |
| `-C`, `--cycles=COUNT` | 0 | Stop cleanly after N attestation cycles. 0 = unbounded |
| `-A`, `--attester-ak-validity=SECONDS` | 157680000 (5 yr) | Lifetime of the Attester AK cert **RP** issues under its own CA |
| `-B`, `--benchmark` | off | Run the bounded 1→5-Verifier timing sweep and exit instead |
| `--verifier-timeout=SECONDS` | 6 | Wait for a Verifier's reply before giving up. Also bounds **every other** RP round trip — Trust Manager, `/certify_ak`, `/qualify`. A Verifier that times out counts against the majority exactly like a NO vote |
| `--attester-timeout=SECONDS` | 6 | Wait for the Attester's evidence before giving up, which ends the cycle |

Every run opens by naming its **mode** (`MODE: DAEMON` or `MODE: BENCHMARK`)
and listing all of the above, tagging each value it took from the table rather
than the command line with `(default)`. So a log file records what the run was
actually configured with, without needing the command that started it. A flag
that does not apply to the chosen mode — `--interval` under `--benchmark`, say
— is called out as having no effect rather than being ignored silently.

### Stopping it

```bash
Ctrl+C                                  # SIGINT
kill -TERM <pid>                        # SIGTERM — also clean
bin/relying_party --duration 300        # self-stops after ~5 min
bin/relying_party --cycles 10           # self-stops after 10 attestation cycles
```

All four reach the same clean shutdown path; the final log line says which
one ended it. Ctrl+C responds within ~1s (the sleep is interruptible).

### `--interval` vs attestation-cycle duration

`--interval` is a **sleep between attestation cycles, not a period**. Real
spacing is *attestation-cycle duration + interval*. One attestation cycle
costs roughly:

```
~0.4s  (Attester round trip + local appraisal)
+ ~0.9s x --verifiers    (threads serialise on the TPM to sign each Quote_r)
```

≈ 1.3s for one Verifier, ≈ 5s for five. Keep `--interval` comfortably above
that. The first attestation cycle is much slower (it pays `/certify_ak`,
`ActivateCredential` and `/qualify`); later ones reuse caches.

### Benchmark mode

```bash
bin/relying_party --benchmark      # writes timings_RP_multi_verifiers.txt, then exits
python3 plot_multi_verifiers.py    # chart from that file
```

Ignores `--interval`, `--duration`, `--cycles` and `--verifiers` — the sweep
is a fixed 1→5 Verifiers. See §4.2 for a full worked run.

---

## 4.1 Worked example — daemon mode, from nothing to a running daemon

Every line below, in order, from a clean checkout. Run each in the repo root.
Lines 1–2 are one-time setup; 3–6 are the stack.

```bash
# 1. Build everything into bin/.
make -j

# 2. Mint the test-only PKI: one CA per Verifier port listed in
#    verifiers_config.txt, RP's own CA, a synthetic TPM manufacturer root,
#    and synthetic EK certificates. One-time — skip on later runs.
cd keys && ./gen-ak-pki.sh && cd ..

# 3. Directory service on fixed port 6000. Maps Verifier IDs 1,2,3... to
#    ip:port using verifiers_config.txt. RP asks it who the Verifiers are.
bin/trust_manager &

# 4. The thing being attested. Passive: listens on 5683 and answers
#    /attest and /certify_ak_of_attester. Never calls anyone.
bin/attester &

# 5. Five passive appraisers on ports 5684-5688, each its own Privacy CA
#    with its own CA key, ledger and nonce. Equivalent to running
#    bin/verifier --port 5684 & ... --port 5688 & by hand.
./start_verifiers.sh

# 6. The only active party. Starts the attestation daemon.
bin/relying_party \
    --verifiers 3 \
    --interval 20 \
    --attester-ak-validity 600 \
    --duration 300 \
    --log-level INFO
```

What each RP flag on line 6 does:

| Flag | Effect here |
|---|---|
| `--verifiers 3` | Ask the Trust Manager for IDs 1,2,3 → ports 5684-5686. The other two Verifiers stay idle. Must be ≤ the number actually running, or RP waits on a dead port |
| `--interval 20` | Sleep 20s **after** each attestation cycle finishes. At ~3s per attestation cycle with 3 Verifiers, cycles start roughly every 23s |
| `--attester-ak-validity 600` | The Attester AK certificate **RP itself** signs lives 10 min. Only affects RP's own CA leg; each Verifier's leg uses that Verifier's `--ak-validity` |
| `--duration 300` | Exit cleanly after ~5 min. Drop it to run until Ctrl+C |
| `--log-level INFO` | Default. Use `DEBUG` (or `-v`) to see CoAP and TPM detail |

**What you should see.** Startup echoes the resolved configuration, so the
log is self-describing about which flags actually took effect. Each
attestation cycle then logs its phases (`get_verifiers`, `get_evidence`,
`get_attestation_results`) with timings, a per-Verifier pass/fail line, the
majority-vote tally, and the sleep before the next cycle.

The **first** attestation cycle is much slower and noisier than the rest — it
pays for `/certify_ak` (CHALLENGE → `ActivateCredential` → CONFIRM) against
each Verifier, provisions the Attester's identity under two CAs, and runs
`/qualify`. Later attestation cycles hit caches and go straight to
`/attest` → `/nonce` → `/appraise`. Renewals appear during the *sleep*, not
inside an attestation cycle.

To stop early: `Ctrl+C`, or `kill -TERM <pid>`. Both shut down cleanly.

Tear the background processes down with `pkill -f '^bin/'` — anchored on
purpose: an unanchored `pkill -f bin/verifier` also matches the command line
of whatever shell or script you typed it from, and kills that too.

---

## 4.2 Worked example — benchmark mode

Benchmark mode replaces the daemon with a **bounded 1→5-Verifier timing
sweep**, writes a stats file, and exits. It is what produced the CHES
poster's scaling numbers.

All five Verifiers must be running, since the sweep's last step asks for
five:

```bash
# Same stack as above (steps 1-5); all 5 verifiers are required here.
make -j
bin/trust_manager &
bin/attester &
./start_verifiers.sh

# The sweep: 1 Verifier, then 2, ... up to 5, timing each phase.
bin/relying_party --benchmark

# Turn the stats file into a chart. Takes no arguments — it reads
# timings_RP_multi_verifiers.txt from the repo root. Needs matplotlib.
python3 plot_multi_verifiers.py
```

| Flag | Effect |
|---|---|
| `--benchmark` (`-B`) | Run the fixed 1→5 sweep and **exit**, instead of the daemon. Writes `timings_RP_multi_verifiers.txt` |
| `-v` / `--log-level` | The only other flags that still apply |

`--verifiers`, `--interval`, `--duration` and `--cycles` are **ignored** —
the sweep's shape is fixed. Passing `--verifiers 3` alongside `--benchmark`
does nothing, which is the most common confusion here.

**Output** — `timings_RP_multi_verifiers.txt`, one block per sweep step:

```
Verifiers: 1
Average Getting verifiers: 0.014764 seconds (stddev: 0.000000)
Average Getting evidence: 3.217283 seconds (stddev: 0.000000)
Average Appraising evidence: 2.954350 seconds (stddev: 0.000000)
Average Total Attestation Duration: 6.186398 seconds (stddev: 0.000000)
Verifiers: 2
...
```

Reading it: *Getting verifiers* is the Trust Manager lookup (flat, ~ms),
*Getting evidence* is the Attester round trip plus RP's local Step 2a
appraisal (flat in Verifier count), and *Appraising evidence* is the fan-out
to N Verifiers — the term that actually scales. The **first block is
inflated** by all the one-time provisioning; for clean numbers, run the sweep
twice against a warm `state/` and keep the second.

> `stddev` is computed over `NUM_RUNS` measured cycles per step (a
> compile-time constant in `src/rp/rp_shared.h`, currently `5`), each step
> preceded by a discarded warm-up cycle so one-off onboarding cost is not
> blended into the steady state. Raise `NUM_RUNS` and rebuild for tighter
> deviations.

---

## 5. `bin/verifier`

Passive appraiser and its own Privacy CA. **Run one instance per port.**

```bash
bin/verifier --port 5684 [OPTIONS]
```

| Flag | Default | Meaning |
|---|---|---|
| `--help` | | Print help |
| `-v`, `--verbose` | | CHARRA + CoAP log-level → DEBUG |
| `-l`, `--log-level=LEVEL` | INFO | CHARRA log-level |
| `-c`, `--coap-log-level=LEVEL` | INFO | libcoap log-level |
| `--port=PORT` | 31415 | **Port to listen on** |
| `--qualification-validity=SECONDS` | 180 (3 min) | How long a passed RP qualification stays valid |
| `--ak-validity=SECONDS` | 157680000 (5 yr) | Lifetime of AK certs **this Verifier** issues, from issuance |
| `-f`, `--pcr-file=PATH` | `reference-pcrs.txt` | Reference PCRs. **Vestigial** — see below |
| `-s`, `--pcr-selection=X1[,X2…]` | 0,1,2,3,4,5,6,7,10 | PCRs to check. **Vestigial** — see below |
| `--ima[=PATH]` | kernel IMA log | Request an IMA event log. **Vestigial** — see below |

> These three parse and set their variables, but nothing in this Verifier
> reads them. Log-content verification (self-consistency, PCR replay,
> file-hash policy) is deliberately the **RP's** Step 2a gate, run against
> the raw log before cleansing — the Verifier only ever sees the redacted
> `log_r`. Inherited from upstream CHARRA, where the Verifier did this work.
>
> Passing any of them (or `--ip`) now logs a `NOT IMPLEMENTED` warning at
> startup, so the flag cannot look like it worked.

> The help text says "*Connect to* PORT" — inherited from upstream, where the
> Verifier was the client. This Verifier is passive: `--port` is the **listen**
> port. `--ip` is likewise vestigial here.

Like the RP, a Verifier opens by listing every setting above with `(default)`
against any it took from this table rather than the command line, followed by
the state files and CA this instance will use.

Each port has its **own CA key** (`keys/verifier-ca-<port>.key`), its own
issuance ledger and its own nonce, so Verifiers are genuinely independent —
one being compromised or down doesn't affect the others.

---

## 6. `bin/attester`

Pure responder. Provides `attest` and `certify_ak_of_attester`.

```bash
bin/attester [OPTIONS]
```

| Flag | Default | Meaning |
|---|---|---|
| `--help` | | Print help |
| `-v`, `--verbose` | | CHARRA + CoAP log-level → DEBUG |
| `-l`, `--log-level=LEVEL` | INFO | CHARRA log-level |
| `-c`, `--coap-log-level=LEVEL` | INFO | libcoap log-level |
| `--port=PORT` | 5683 | Port to listen on |

---

## 7. `bin/trust_manager`

**Takes no arguments.** Fixed port 6000; reads `verifiers_config.txt`.

```bash
bin/trust_manager
```

`verifiers_config.txt` is `<id> <ip> <port>` per line:

```
1 127.0.0.1 5684
2 127.0.0.1 5685
```

RP requests IDs `1..--verifiers`, so entries must be numbered from 1 upward.

---

## 8. DTLS (attester + verifier only)

Off by default (plain UDP). Mutually exclusive — enabling both is an error.

**PSK:**

| Flag | Notes |
|---|---|
| `-p`, `--psk` | Enable. Default key `Charra DTLS Key` |
| `-k`, `--key=KEY` | Set key; implies `-p` |
| `-i`, `--identity=ID` | Verifier only; implies `-p` |
| `-h`, `--hint=HINT` | Attester only; implies `-p` |

**RPK (raw public keys):**

| Flag | Notes |
|---|---|
| `-r`, `--rpk` | Enable |
| `--private-key=PATH` | DER only; implies `-r` |
| `--public-key=PATH` | DER only; implies `-r` |
| `--peer-public-key=PATH` | DER only; implies `-r` |
| `--verify-peer=[0,1]` | 1 = check peer key (default). **0 accepts any peer** |

Keys in `keys/` are test-only.

---

## 9. Environment variables

| Variable | Applies to | Meaning |
|---|---|---|
| `LOG_LEVEL_CHARRA` | all | `TRACE\|DEBUG\|INFO\|WARN\|ERROR\|FATAL`. CLI flags override |
| `LOG_LEVEL_COAP` | attester, verifier | libcoap log-level |
| `CHARRA_TCTI` | all TPM users | TPM TCTI string, e.g. `mssim:host=localhost,port=2321` |

```bash
LOG_LEVEL_CHARRA=DEBUG bin/verifier --port 5684
```

---

## 10. Tuning the timing flags

**There are no renewal margins.** Every credential is re-provisioned by the
first attestation cycle that finds it *already expired* — nothing renews
ahead of time, and nothing happens between cycles. That removes the coupling
this section used to be about; what is left is only the lifetimes themselves.

`--qualification-validity` lives on the **Verifier only** — it issues the
grant, and RP recomputes the same deadline locally (nothing on the wire
carries it, so both binaries must be given matching values).

AK validity is *per issuer*: `--ak-validity` on the Verifier,
`--attester-ak-validity` on RP. Each certificate carries its own `notAfter`,
so consumers read the real value and the two never need to agree.

Both AK lifetimes default to **5 years**. Renewal fires only on genuine
expiry, so a short lifetime buys nothing but a `/certify_ak` round trip per
Verifier inside an otherwise ordinary cycle. The qualification window stays
short (180s) on purpose: it answers *"is the RP still running the right
code"*, which does go stale — unlike identity, which does not.

**Consequence worth knowing.** With the 5-year defaults, the AK renewal path
effectively never runs. To exercise it, set a short `--ak-validity` /
`--attester-ak-validity` deliberately, as below.

### Short-lived setup, to watch renewal happen

```bash
bin/verifier --port 5684 --qualification-validity 90 --ak-validity 120 &
bin/relying_party --verifiers 1 --interval 15 --duration 300
```

Or, for the whole stack at once, `VERIFIER_AK_VALIDITY=60
VERIFIER_QUALIFICATION_VALIDITY=45 RP_ATTESTER_AK_VALIDITY=60
./run_daemon.sh`, which warns that these are short enough to hit the straddle.

**Expect an occasional failed cycle when you do this** — see the
troubleshooting row above. A 16-cycle run at these values lost one cycle and
recovered on the next; that is the design working, not a fault.

---

## 11. Runtime state

All under `state/`, gitignored, created on startup. Delete it to force full
re-provisioning:

```
state/verifier/ak-provisioning/rp/        AK issuance ledger, RP identities
state/verifier/ak-provisioning/attester/  AK issuance ledger, Attester identities
state/verifier/qualification/             RP qualification ledger (shared)
state/relying-party/identity/             RP's EK cert + AK keypair
state/relying-party/ak-certificates/      RP's AK cert, per Verifier port
state/relying-party/attester-ak-certificates/  Attester certs RP holds
state/relying-party/ak-provisioning/      RP's own issuance ledger
state/attester/                           Attester's EK/AK + its certs
```

> **After resetting the TPM simulator, delete `state/`.** Cached AK blobs no
> longer load against re-randomised seeds, and every attestation fails with a
> confusing cascade.

---

## 12. Docker

```bash
docker run -v "$PWD/:/home/bob/charra" -it --rm --group-add tss \
  fraunhofer-sit/charra-dev-env:1.9.0 bash
```

Inside: `cd ~/charra && make -j`. The TPM simulator starts automatically;
`tpm-reset` clears it (then delete `state/`).

`./run_live_test.sh` does all of this end to end.

---

## 13. Troubleshooting

| Symptom | Cause |
|---|---|
| RP exits immediately after one sweep | `--benchmark` is set; drop it for daemon mode |
| RP hangs, no verifier answers | Fewer Verifiers running than `--verifiers` |
| Every attestation fails after a TPM reset | Stale `state/` — delete it |
| `Esys_Create: 0x921`, Attester cannot create its AK | TPM is in dictionary-attack lockout; run `tpm2_dictionarylockout --clear-lockout`. Every later step fails in a confusing cascade from this one cause |
| `could not read keys/verifier-ca-<port>.crt` | Port not in `verifiers_config.txt` when `gen-ak-pki.sh` ran |
| One cycle fails with `serial is REVOKED or EXPIRED` (Step 2a item 1), next one passes | The straddle: a credential was valid when checked and lapsed during the round trip after. Expected with short `--ak-validity`; non-fatal, self-correcting. Unreachable at the 5-year default |
| RP re-qualifies on almost every cycle | `--qualification-validity` is at or below `--interval`, so the grant expires between cycles |
| RP re-provisions AK certs every cycle | `--ak-validity` / `--attester-ak-validity` shorter than `--interval` |
| `timeout`/`docker stop` kills RP mid-attestation-cycle | Fixed — SIGTERM now shuts down cleanly |
| A Verifier votes NO and RP doesn't say why | By design. `/appraise` always answers `2.05` with `Attestation successful!`/`Attestation failed!` — any failed check is just a NO. **The reasons are logged on the Verifier**, so read that Verifier's log, not RP's |

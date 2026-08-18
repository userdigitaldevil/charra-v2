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

---

## 4. `bin/relying_party`

Runs a **continuous attestation daemon by default**: attest → renew
qualification if near expiry → sleep → repeat, until stopped.

```bash
bin/relying_party [OPTIONS]
```

| Flag | Default | Meaning |
|---|---|---|
| `--help` | | Print help |
| `-v`, `--verbose` | | CHARRA log-level → DEBUG |
| `-l`, `--log-level=LEVEL` | INFO | `TRACE\|DEBUG\|INFO\|WARN\|ERROR\|FATAL`. Overrides `$LOG_LEVEL_CHARRA` |
| `-n`, `--verifiers=COUNT` | 5 | Verifiers per cycle (1..10), taken from `verifiers_config.txt` |
| `-I`, `--interval=SECONDS` | 60 | Sleep **between** cycles |
| `--qualify-margin=SECONDS` | 120 | Renew qualification when it expires within this, during idle time |
| `-D`, `--duration=SECONDS` | 0 | Stop cleanly after ~N seconds. 0 = run until signalled |
| `-C`, `--cycles=COUNT` | 0 | Stop cleanly after N cycles. 0 = unbounded |
| `-A`, `--attester-ak-validity=SECONDS` | 315360000 (10y) | Lifetime of the Attester AK cert **RP** issues under its own CA |
| `-B`, `--benchmark` | off | Run the bounded 1→5-Verifier timing sweep and exit instead |

### Stopping it

```bash
Ctrl+C                                  # SIGINT
kill -TERM <pid>                        # SIGTERM — also clean
bin/relying_party --duration 300        # self-stops after ~5 min
bin/relying_party --cycles 10           # self-stops after 10 attestations
```

All four reach the same clean shutdown path; the final log line says which
one ended it. Ctrl+C responds within ~1s (the sleep is interruptible).

### `--interval` vs cycle duration

`--interval` is a **sleep between cycles, not a period**. Real spacing is
*cycle duration + interval*. A cycle costs roughly:

```
~0.4s  (Attester round trip + local appraisal)
+ ~0.9s x --verifiers    (threads serialise on the TPM to sign each Quote_r)
```

≈ 1.3s for one Verifier, ≈ 5s for five. Keep `--interval` comfortably above
that. First-ever cycles are slower (they pay `/certify_ak`,
`ActivateCredential` and `/qualify`); later cycles reuse caches.

### Benchmark mode

```bash
bin/relying_party --benchmark      # writes timings_RP_multi_verifiers.txt, then exits
python3 plot_multi_verifiers.py    # chart from that file
```

Ignores `--interval`, `--duration`, `--cycles` and `--verifiers`.

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
| `--qualification-validity=SECONDS` | 300 | How long a passed RP qualification stays valid |
| `--ak-validity=SECONDS` | 315360000 (10y) | Lifetime of AK certs **this Verifier** issues, from issuance |
| `-f`, `--pcr-file=PATH` | `reference-pcrs.txt` | Reference PCRs. **Vestigial** — see below |
| `-s`, `--pcr-selection=X1[,X2…]` | 0,1,2,3,4,5,6,7,10 | PCRs to check. **Vestigial** — see below |
| `--ima[=PATH]` | kernel IMA log | Request an IMA event log. **Vestigial** — see below |

> These three parse and set their variables, but nothing in this Verifier
> reads them. Log-content verification (self-consistency, PCR replay,
> file-hash policy) is deliberately the **RP's** Step 2a gate, run against
> the raw log before cleansing — the Verifier only ever sees the redacted
> `log_r`. Inherited from upstream CHARRA, where the Verifier did this work.

> The help text says "*Connect to* PORT" — inherited from upstream, where the
> Verifier was the client. This Verifier is passive: `--port` is the **listen**
> port. `--ip` is likewise vestigial here.

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

Three durations are **coupled** and must satisfy:

```
--interval  <  --qualify-margin  <  --qualification-validity
    60      <        120         <           300              (defaults)
```

- **margin > interval** — the renewal check runs once per cycle; a smaller
  margin lets the loop step over the window and land past expiry.
- **margin < validity** — a margin covering the whole window can never be
  satisfied, so RP re-qualifies on every idle pass.

RP warns at startup and again once it learns the window from the Verifier.

`--qualification-validity` lives on the **Verifier only** — it issues the
grant, and reports the deadline to RP on the wire.

AK validity is *per issuer* and needs no coordination: `--ak-validity` on the
Verifier, `--attester-ak-validity` on RP. Each certificate carries its own
`notAfter`, so consumers read the real value.

### Short-lived setup, to watch renewal happen

```bash
bin/verifier --port 5684 --qualification-validity 90 --ak-validity 600 &
bin/relying_party --verifiers 1 --interval 15 --qualify-margin 40 --duration 300
```

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
| RP re-qualifies every cycle | `--qualify-margin` ≥ the Verifier's validity window |
| `timeout`/`docker stop` kills RP mid-cycle | Fixed — SIGTERM now shuts down cleanly |
| Verifier rejects with `4.01` | RP's AK cert invalid/expired; RP retries once automatically |
| Verifier rejects with `4.03` | RP not qualified / expired; RP re-qualifies and retries once |

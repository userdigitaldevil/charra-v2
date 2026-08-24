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

`bin/relying_party` runs **exactly one attestation cycle and exits** — it is
not a long-running process. Restart it whenever you want another cycle.

Start order: `trust_manager` → `attester` → `verifier`(s) → `relying_party`.

---

## 2. Build

```bash
make -j            # all binaries into bin/
make clean && make -j
make test          # unit-test suites
```

Everything runs from the **repository root** — paths to `keys/`, `state/`,
`verifiers_config.txt` and `reference-pcrs.txt` are relative.

### One-time trust anchor generation

```bash
make provision_trusted_keys
./keys/gen-trusted-keys.sh
```

Writes `keys/trusted_keys.txt`: the public halves of the Attester's and the
RP's TPM-resident signing keys, read straight off the (single, shared) TPM
simulator. There is no CA and no certificate here — a signing key is trusted
if and only if it appears in this file. See `keys/README.md` and
`src/core/charra_trusted_keys.h`.

> **Re-run this after every TPM reset.** Both keys are derived from the
> TPM's owner-hierarchy seed, so wiping the simulator's NVChip changes them
> and invalidates this file. Skipping this step fails every later
> attestation as "key not in the trust anchor."

---

## 3. Quickest way to run everything

```bash
./run_live_test.sh        # Docker: fresh TPM, clean build, full stack, one cycle
```

Or by hand (each in its own shell, from the repo root):

```bash
bin/trust_manager &
bin/attester &
./start_verifiers.sh                       # 1 verifier on port 5684
bin/relying_party                          # one attestation cycle, then exits
```

For the same thing spelled out line by line, with every flag explained, see
**§4.1**.

---

## 4. `bin/relying_party`

Runs **one attestation cycle** -- resolve Verifiers, fetch and locally
appraise the Attester's evidence, privacy-clean it, then forward to every
Verifier and tally the majority vote -- and exits.

```bash
bin/relying_party [OPTIONS]
```

| Flag | Default | Meaning |
|---|---|---|
| `--help` | | Print help |
| `-v`, `--verbose` | | CHARRA log-level → DEBUG |
| `-l`, `--log-level=LEVEL` | INFO | `TRACE\|DEBUG\|INFO\|WARN\|ERROR\|FATAL`. Overrides `$LOG_LEVEL_CHARRA` |
| `-n`, `--verifiers=COUNT` | 1 | Verifiers to attest against (1..10), taken from `verifiers_config.txt` |
| `--verifier-timeout=SECONDS` | 6 | Wait for a Verifier's reply before giving up. Also bounds **every other** RP round trip — the Trust Manager included. A Verifier that times out counts against the majority exactly like a NO vote |
| `--attester-timeout=SECONDS` | 6 | Wait for the Attester's evidence before giving up, which ends the run |

Every run opens by listing all of the above, tagging each value it took from
the table rather than the command line with `(default)`. So a log file
records what the run was actually configured with, without needing the
command that started it.

---

## 4.1 Worked example — from nothing to one attestation cycle

Every line below, in order, from a clean checkout. Run each in the repo root.
Lines 1–2 are one-time setup; 3–6 run one cycle.

```bash
# 1. Build everything into bin/.
make -j

# 2. Regenerate the trust anchor from this TPM's own signing keys.
#    One-time per TPM reset — skip if keys/trusted_keys.txt is already
#    current for this TPM.
make provision_trusted_keys
./keys/gen-trusted-keys.sh

# 3. Directory service on fixed port 6000. Maps Verifier IDs 1,2,3... to
#    ip:port using verifiers_config.txt. RP asks it who the Verifiers are.
bin/trust_manager &

# 4. The thing being attested. Passive: listens on 5683 and answers
#    /attest. Never calls anyone.
bin/attester &

# 5. One passive appraiser on port 5684. Pass a count to start more, e.g.
#    ./start_verifiers.sh 3.
./start_verifiers.sh

# 6. The only active party. Runs one attestation cycle and exits.
bin/relying_party \
    --verifiers 1 \
    --log-level INFO
```

What each RP flag on line 6 does:

| Flag | Effect here |
|---|---|
| `--verifiers 1` | Ask the Trust Manager for ID 1 → port 5684. Must be ≤ the number actually running, or RP waits on a dead port |
| `--log-level INFO` | Default. Use `DEBUG` (or `-v`) to see CoAP and TPM detail |

**What you should see.** Startup echoes the resolved configuration, so the
log is self-describing about which flags actually took effect. The run then
logs its phases (`get_verifiers`, `get_evidence`, `get_attestation_results`)
with timings, a per-Verifier pass/fail line, the majority-vote tally, and
exits.

**Every run costs the same** — nothing is cached or provisioned on disk, so
there is no "slow first run": every cycle derives both signing keys fresh
from their TPMs, the same as the one before it.

Tear the background processes down with `pkill -f '^bin/'` — anchored on
purpose: an unanchored `pkill -f bin/verifier` also matches the command line
of whatever shell or script you typed it from, and kills that too.

---

## 5. `bin/verifier`

Passive appraiser. **Run one instance per port.**

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
the trust anchor path it will read.

A Verifier holds no key and issues nothing, so every instance reads the same
`keys/trusted_keys.txt` and needs nothing of its own beyond `--port`.

---

## 6. `bin/attester`

Pure responder. Provides `attest`.

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

## 10. Runtime state

There is none. No role provisions, caches or renews anything on disk: every
signing key is derived fresh from its TPM on every use (see
`src/rp/rp_signing_key.h` for the RP, and `charra_load_tpm2_key()` for the
Attester), and the one thing that *does* need to persist across process
restarts -- which keys are trusted -- lives in the single file
`keys/trusted_keys.txt`, generated offline (see §2) rather than provisioned
at runtime.

> **After resetting the TPM simulator, regenerate the trust anchor**
> (`make provision_trusted_keys && ./keys/gen-trusted-keys.sh`). Both
> signing keys are derived from the TPM's owner-hierarchy seed, so a reset
> changes them and invalidates the old file -- every attestation then fails
> as "key not in the trust anchor" until it's regenerated.

---

## 11. Docker

```bash
docker run -v "$PWD/:/home/bob/charra" -it --rm --group-add tss \
  fraunhofer-sit/charra-dev-env:1.9.0 bash
```

Inside: `cd ~/charra && make -j`. The TPM simulator starts automatically;
`tpm-reset` clears it (then regenerate `keys/trusted_keys.txt`, see §10).

`./run_live_test.sh` does all of this end to end.

---

## 12. Troubleshooting

| Symptom | Cause |
|---|---|
| RP hangs, no verifier answers | Fewer Verifiers running than `--verifiers` |
| Every attestation fails as "key not in the trust anchor" | Stale `keys/trusted_keys.txt` after a TPM reset -- regenerate it (§2, §10) |
| `Esys_Create: 0x921`, Attester cannot create its AK | TPM is in dictionary-attack lockout; run `tpm2_dictionarylockout --clear-lockout`. Every later step fails in a confusing cascade from this one cause |
| `timeout`/`docker stop` kills RP mid-run | Expected — a single cycle installs no signal handler, so SIGTERM terminates immediately, same as any short-lived CLI command. Give it longer than `--verifier-timeout` + `--attester-timeout` if you need it to finish cleanly |
| A Verifier votes NO and RP doesn't say why | By design. `/appraise` always answers `2.05` with `Attestation successful!`/`Attestation failed!` — any failed check is just a NO. **The reasons are logged on the Verifier**, so read that Verifier's log, not RP's |

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
| `-R`, `--ak-renew-margin=SECONDS` | 45 | Renew an **AK certificate** once it is within this long of expiring. Covers all three: RP's own (per Verifier), and the Attester's from RP's CA and from each Verifier's CA |
| `-A`, `--attester-ak-validity=SECONDS` | 300 (5 min) | Lifetime of the Attester AK cert **RP** issues under its own CA |
| `--verifier-timeout=SECONDS` | 6 | Wait for a Verifier's reply before giving up. Also bounds **every other** RP round trip — Trust Manager, `/certify_ak`. A Verifier that times out counts against the majority exactly like a NO vote |
| `--attester-timeout=SECONDS` | 6 | Wait for the Attester's evidence before giving up, which ends the run |

Every run opens by listing all of the above, tagging each value it took from
the table rather than the command line with `(default)`. So a log file
records what the run was actually configured with, without needing the
command that started it.

### `--ak-renew-margin`

Checked once, synchronously, while this cycle is provisioning each
certificate — not on a timer. If a cached AK certificate is already within
the margin of expiring, this run re-provisions it via `/certify_ak` before
using it, instead of using a certificate that would be rejected moments
later. Must stay comfortably below whatever validity the issuer set
(`--ak-validity` on the Verifier, `--attester-ak-validity` here), or every
run re-provisions every certificate regardless of how recently it was
issued.

---

## 4.1 Worked example — from nothing to one attestation cycle

Every line below, in order, from a clean checkout. Run each in the repo root.
Lines 1–2 are one-time setup; 3–6 run one cycle.

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

# 5. One passive appraiser on port 5684, its own Privacy CA with its own
#    CA key, ledger and nonce. Pass a count to start more, e.g.
#    ./start_verifiers.sh 3.
./start_verifiers.sh

# 6. The only active party. Runs one attestation cycle and exits.
bin/relying_party \
    --verifiers 1 \
    --ak-renew-margin 60 \
    --attester-ak-validity 600 \
    --log-level INFO
```

What each RP flag on line 6 does:

| Flag | Effect here |
|---|---|
| `--verifiers 1` | Ask the Trust Manager for ID 1 → port 5684. Must be ≤ the number actually running, or RP waits on a dead port |
| `--ak-renew-margin 60` | Re-provision an AK certificate (RP's own, plus both of the Attester's) if the cached one is within 60s of expiring. Must be < the shortest certificate lifetime in play (default: 300) |
| `--attester-ak-validity 600` | The Attester AK certificate **RP itself** signs lives 10 min. Only affects RP's own CA leg; each Verifier's leg uses that Verifier's `--ak-validity` |
| `--log-level INFO` | Default. Use `DEBUG` (or `-v`) to see CoAP and TPM detail |

**What you should see.** Startup echoes the resolved configuration, so the
log is self-describing about which flags actually took effect. The run then
logs its phases (`get_verifiers`, `get_evidence`, `get_attestation_results`)
with timings, a per-Verifier pass/fail line, the majority-vote tally, and
exits.

**The first run against a fresh `state/` is much slower and noisier than a
later one** — it pays for `/certify_ak` (CHALLENGE → `ActivateCredential` →
CONFIRM) against each Verifier and provisions the Attester's identity under
two CAs. A second run reuses those cached credentials and goes straight to
`/attest` → `/nonce` → `/appraise`.

Tear the background processes down with `pkill -f '^bin/'` — anchored on
purpose: an unanchored `pkill -f bin/verifier` also matches the command line
of whatever shell or script you typed it from, and kills that too.

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
| `--ak-validity=SECONDS` | 300 (5 min) | Lifetime of AK certs **this Verifier** issues, from issuance |
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

## 10. Tuning `--ak-renew-margin`

`--ak-renew-margin` (RP) must stay **smaller than the shortest AK certificate
lifetime in play**:

```
--ak-renew-margin  <  --ak-validity / --attester-ak-validity
       45           <              300                    (defaults)
```

Otherwise every certificate is always "about to expire" and RP re-provisions
it on every single run — a `/certify_ak` round trip per Verifier, every time.

AK validity is *per issuer*: `--ak-validity` on the Verifier,
`--attester-ak-validity` on RP. Each certificate carries its own `notAfter`,
so consumers read the real value; RP cannot check the margin against it at
startup, only once it has actually parsed an issued certificate.

### Short-lived setup, to watch renewal happen

```bash
bin/verifier --port 5684 --ak-validity 90 &
bin/relying_party --verifiers 1 --ak-renew-margin 60
# run it again a minute later -- the cached cert is now within the margin,
# so this run re-provisions it instead of reusing it
```

---

## 11. Runtime state

All under `state/`, gitignored, created on startup. Delete it to force full
re-provisioning:

```
state/verifier/ak-provisioning/rp/        AK issuance ledger, RP identities
state/verifier/ak-provisioning/attester/  AK issuance ledger, Attester identities
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
| RP hangs, no verifier answers | Fewer Verifiers running than `--verifiers` |
| Every attestation fails after a TPM reset | Stale `state/` — delete it |
| `Esys_Create: 0x921`, Attester cannot create its AK | TPM is in dictionary-attack lockout; run `tpm2_dictionarylockout --clear-lockout`. Every later step fails in a confusing cascade from this one cause |
| `could not read keys/verifier-ca-<port>.crt` | Port not in `verifiers_config.txt` when `gen-ak-pki.sh` ran |
| RP re-provisions AK certs every run | `--ak-renew-margin` ≥ the certificate lifetime (`--ak-validity` / `--attester-ak-validity`) |
| `timeout`/`docker stop` kills RP mid-run | Expected — a single cycle installs no signal handler, so SIGTERM terminates immediately, same as any short-lived CLI command. Give it longer than `--verifier-timeout` + `--attester-timeout` if you need it to finish cleanly |
| A Verifier votes NO and RP doesn't say why | By design. `/appraise` always answers `2.05` with `Attestation successful!`/`Attestation failed!` — any failed check is just a NO. **The reasons are logged on the Verifier**, so read that Verifier's log, not RP's |

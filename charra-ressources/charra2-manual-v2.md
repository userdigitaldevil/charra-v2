# CHARRA-v2 Manual

This supersedes `charra2-manual.md`, which describes an earlier layout.

---

# Installation Tips

1. **Download Extensions:**
    - Download and install the Docker extension and the Dev Container extension
      for VS Code.

2. **Attach VS Code to Container:**
    - After following the installation steps in `INSTALL.md`, and once your
      container is running:
    - Click on the Docker extension icon in the left sidebar of VS Code.
    - Right-click on your running container and select "Attach Visual Studio
      Code" to connect a VS Code instance to it.

---

# First: build the container image, once

Everything runs inside a Docker image that carries the toolchain, the TPM
simulator and the libraries CHARRA links against — tpm2-tss, tpm2-tools,
libcoap, mbedTLS, QCBOR. **The run scripts do not build it; they only run in
it.** On a fresh clone you have to build it once:

    ./docker/build.sh

That takes a while — roughly 25–45 minutes on an Apple-silicon Mac, where the
`linux/amd64` image runs under emulation, and closer to 10 minutes natively.
It compiles six projects from source. You do this **once**; every later run
reuses the image.

Build it again only when the `Dockerfile` changes. It last changed to pin
libcoap `v4.3.5b` with `--enable-thread-safe`, which DTLS-RPK needs.

If you skip this step the scripts stop with a clear message rather than a
confusing Docker error:

    ERROR: image 'fraunhofer-sit/charra-dev-env:1.9.0' does not exist locally.
           These scripts run in it, they do not build it. Build once:
               ./docker/build.sh

To run a different image — say while comparing two — both scripts take
`IMAGE`:

    IMAGE=charra-dev:experimental ./run_daemon.sh

---

# Normal use: one script, one command

**You do not need the multi-terminal procedure below.** For everyday runs there
is one command, from the repository root:

    ./run_daemon.sh

That single script does all of it: starts a TPM simulator per role and wipes
each `NVChip`, recompiles CHARRA, regenerates the trust anchor from the fresh TPMs, drops
the stale `qualified_rps.txt`, writes `verifiers_config.txt`, launches the Trust
Manager, the Attester and every Verifier, and then runs the Relying Party
looping until you press Ctrl-C. Logs land in `logs/`.

Its counterpart is `./run_benchmark_mode.sh`, which performs the same cold setup but
runs the bounded `--benchmark` sweep and exits, writing
`timings_RP_multi_verifiers.txt`. Use that one when you want measurements.

## Tuning it

**Everything worth changing is a variable at the top of the script**, in a block
headed `TUNABLES`, each set to the binary's own built-in default — so that block
doubles as the list of what is actually adjustable.

You can either edit those values in place, or override any of them from the
environment **without editing the file at all**:

    RP_INTERVAL=5 RP_VERIFIERS=3 ./run_daemon.sh
    RP_DURATION=120 ./run_daemon.sh                        # stop after 2 minutes
    VERIFIER_QUALIFICATION_VALIDITY=20 RP_CYCLES=8 ./run_daemon.sh   # watch re-qualification

| Variable                            |   Default    | Effect                                                                            |
| ----------------------------------- | :----------: | --------------------------------------------------------------------------------- |
| `RP_INTERVAL`                       |      15      | Seconds between attestation cycles                                                |
| `RP_VERIFIERS`                      |      5       | How many Verifiers to use — and how many get started (1..10)                      |
| `RP_DURATION`                       |      0       | Stop after N seconds; 0 = until Ctrl-C                                            |
| `RP_CYCLES`                         |      0       | Stop after N cycles; 0 = unbounded                                                |
| `RP_VERIFIER_TIMEOUT`               |      6       | Per Verifier round trip; a timeout counts as a NO vote                            |
| `RP_ATTESTER_TIMEOUT`               |      6       | Attester round trip; exceeding it abandons the cycle                              |
| `VERIFIER_QUALIFICATION_VALIDITY`   |     180      | How long a passing `/qualify` is honoured                                         |
| `TWO_TPMS`                          |      1       | One simulator per role; `0` falls back to a single shared TPM                     |
| `ATTESTER_TPM_PORT` / `RP_TPM_PORT` | 2321 / 2325  | Simulator ports (each binds `PORT` and `PORT+1`)                                  |
| `TPM_STATE_DIR`                     | `.tpm-state` | Where each `NVChip` lives, under the checkout so it survives the `--rm` container |
| `VERIFIER_START_PORT`               |     5684     | First Verifier port; the rest follow consecutively                                |
| `VERIFIER_HOST`                     |  127.0.0.1   | Address written into `verifiers_config.txt`                                       |
| `IMAGE`                             | `…charra-dev-env:1.9.0` | Which image to run in; build it with `./docker/build.sh`                |
| `DTLS_MODE`                         |     `off`    | `off` \| `psk` \| `rpk`. Sets all four roles at once — they must agree             |
| `LOG_LEVEL`                         |     INFO     | `TRACE` `DEBUG` `INFO` `WARN` `ERROR` `FATAL`                                     |
| `LOG_LEVEL_COAP`                    |  _(empty)_   | Empty leaves libcoap at its own default                                           |
| `RECOMPILE`                         |      1       | `make clean && make -j` on the C code **inside** the container — not the image     |
| `CONTAINER_NAME`                    | `charra-daemon` | Name of the container the run uses                                             |
| `RESET_TPM`                         |      1       | Wipe each `NVChip`; `0` keeps the AKs identical across runs                       |
| `RP_EXTRA_ARGS` etc.                |  _(empty)_   | Free-form pass-through for a flag the script does not name                        |

Two script options rather than variables:

| Option         | Effect                                                                                                         |
| -------------- | -------------------------------------------------------------------------------------------------------------- |
| `--keep-state` | Keep each `NVChip` instead of wiping it, so both AKs — and therefore `keys/trusted_keys.txt` — survive the run |
| `-h`, `--help` | Print the full option list                                                                                     |

Because the script wipes the TPMs and regenerates the trust anchor on every run,
the two failure modes that bite people using the manual procedure — a stale
trust anchor and a stale qualification grant — cannot occur.

**The rest of this manual describes the manual procedure.** Read it when you
need to run roles on separate hosts, drive one role under a debugger, or vary
something the script does not expose.

---

# Preparing the TPMs and the trust anchor

**This step is new and is not optional.** The trust anchor did not exist in the
earlier manual's version of the system.

`keys/trusted_keys.txt` holds the public halves of the two TPM-resident signing
keys. There is no CA and there are no certificates: **the file is the trust
decision.** Every role reads it, and a signature from a key not listed in it is
rejected.

1.  **Start one TPM simulator per role.** The Attester and the Relying Party each
    need their own — not because a shared TPM would collide their keys (it would
    not: the two identities use different key templates), but because on a shared
    TPM the RP can derive the Attester's *restricted* primary, which is the key
    the anchor labels `attester`. `TPM2_Quote` accepts a restricted key, so the RP
    could produce a genuine hardware quote as the Attester and nothing would look
    wrong. The
    convention used throughout the scripts is Attester on `:2321`, RP on `:2325`,
    each started in its own working directory so their `NVChip` files stay
    separate.

2.  **Regenerate the anchor after any TPM reset:**

        ATTESTER_TCTI="mssim:host=127.0.0.1,port=2321" \
        RP_TCTI="mssim:host=127.0.0.1,port=2325" \
        ./keys/gen-trusted-keys.sh

    This calls `bin/provision_trusted_keys --role attester|relying-party`, reads
    each role's public key out of the corresponding TPM, and writes
    `keys/trusted_keys.txt`.

    Wiping an `NVChip` changes the hierarchy seed and therefore every derived
    key, so a stale anchor makes every signature check fail — reported as "this
    key is not a trusted identity", which reads like a rejected peer rather than
    a stale file. Regenerate unconditionally after a reset.

3.  **Also delete `qualified_rps.txt` after a reset.** Every fingerprint in it
    names an RP identity that no longer exists.

**Note on `CHARRA_TCTI`.** In the source, every role reads the same
`CHARRA_TCTI` environment variable; `ATTESTER_TCTI` and `RP_TCTI` are variables
in the scripts only. The separation is achieved by launching each process with a
different `CHARRA_TCTI` value, not by different code paths.

---

# Remote Attestation Process

To complete a full round of remote attestation:

1.  **Start the Attester:**

    bin/attester # default port 5683
    bin/attester --port <port_number>

2.  **Start the Trust Manager:**

        bin/trust_manager                  # default port 6000
        bin/trust_manager --port=<port_number>

    Note the `=`: the Trust Manager parses `--opt=VALUE` only, not
    `--opt VALUE`. It also takes the DTLS options — `--psk`, `--key=`,
    `--hint=`, `--rpk`, `--private-key=`, `--public-key=`,
    `--peer-public-key=`, `--verify-peer=` — which `run_daemon.sh` sets for
    you from `DTLS_MODE`. `bin/trust_manager --help` lists them all.

3.  **Start the Verifier(s):**

        bin/verifier                       # default port 31415
        bin/verifier --port <port_number>
        ./start_verifiers.sh               # 5 Verifiers from port 5684 upward
        ./start_verifiers.sh <COUNT>       # COUNT Verifiers, consecutive ports

    `start_verifiers.sh` also writes `verifiers_config.txt` for exactly the
    Verifiers it starts, which is what the Trust Manager reads to resolve
    Verifier IDs into `{ip, port}`.

4.  **Start the Relying Party:**

    bin/relying_party

**Note:** Steps 1 to 3 can be performed in any order, but all must be completed
before starting the Relying Party.

**The Relying Party now loops by default.** It runs as a daemon until it is
signalled, rather than performing one attestation and exiting. The flags that
bound it:

| Flag                   | Default | Meaning                                                 |
| ---------------------- | :-----: | ------------------------------------------------------- |
| `--verifiers N`        |    5    | How many Verifiers to use (1..10)                       |
| `--interval S`         |  15 s   | Sleep between cycles                                    |
| `--cycles N`           |    0    | Stop after N cycles; 0 = unbounded                      |
| `--duration S`         |    0    | Stop after roughly S seconds; 0 = until SIGINT          |
| `--verifier-timeout S` |   6 s   | Per Verifier-bound round trip; a timeout counts as a NO |
| `--attester-timeout S` |   6 s   | Attester round trip; exceeding it abandons the cycle    |
| `--benchmark` / `-B`   |   off   | Run the bounded 1..5-Verifier sweep, then exit          |
| `--log-level L`        |  INFO   | Also settable as `LOG_LEVEL_CHARRA`                     |

`bin/relying_party --help` lists every flag with its accepted range.

**A Verifier will not accept evidence from an unqualified RP.** Before its first
submission the RP performs a `/qualify` + `/qualify_submit` handshake: the
Verifier sends a synthetic IMA log, and grants the RP a time-limited
qualification only if the RP's redaction of that log matches the Verifier's own
byte for byte. The grant lasts **180 seconds** by default
(`bin/verifier --qualification-validity SECONDS` changes it) and is shared
between Verifiers through `qualified_rps.txt`. This happens automatically; it is
described here because it is why a run can fail with "RP is NOT qualified"
after a TPM reset.

---

# Running the tests

    make test

16 suites, 358 assertions. They need **neither a TPM nor a network** — verified
by running them in a container with `--network none` and no `tpm_server`. The
suite list lives once, in the Makefile's `TEST_SUITES` variable; the `.PHONY`
list, the per-suite shortcuts and the `test` target are all derived from it, so
adding a suite there is the only edit needed. A single suite can be built and
run on its own, e.g. `make test_verdict && ./bin/test_verdict`.

---

# Generating Measurements

The old `timing_atomic.py` has been removed. It drove `bin/verifier_old` (the v1
active-client baseline) and read `timings_verifier.txt`, a file the current
passive Verifier never writes, so it could not measure the v2 design at all.

**Where timings are written now:**

| File                             | Written by                      | Contents                                                              |
| -------------------------------- | ------------------------------- | --------------------------------------------------------------------- |
| `timings_RP_multi_verifiers.txt` | `bin/relying_party --benchmark` | Per-step averages and standard deviations for the 1..5-Verifier sweep |
| `timings_attester.txt`           | `bin/attester`                  | One line per `/attest`: total handling time                           |
| `durations_verifier-<port>.txt`  | `bin/verifier`                  | Per-`/appraise` phase breakdown, one file per Verifier                |

All three are **append-only**. A file left over from an earlier run will silently
pool old samples with new ones, so delete them before a measurement run. All
three are covered by `.gitignore`.

**To measure the overall process, use the script:**

    ./run_benchmark_mode.sh

It performs the whole cold setup and then runs the bounded sweep, so there is
nothing to start by hand and no flag to remember. It takes the same environment
overrides as `run_daemon.sh`. When it finishes, plot the result **on the host**
(matplotlib is not installed in the container image):

    python3 plot_multi_verifiers.py

Only two things are not environment-tunable, because they are compile-time
constants in **`src/rp/rp_shared.h`**:

| Constant                 | Current | Meaning                                                    |
| ------------------------ | :-----: | ---------------------------------------------------------- |
| `NUM_RUNS`               |    5    | Measured cycles per sweep step, plus one discarded warm-up |
| `RP_MAX_SWEEP_VERIFIERS` |    5    | Sweep width — the sweep runs 1..N Verifiers                |

Change either one, then rebuild with `make`.

**If you do drive it by hand**, start **at least `RP_MAX_SWEEP_VERIFIERS`
Verifiers** and pass `--benchmark`:

    bin/relying_party --benchmark

`--benchmark` is required, not cosmetic: without it the RP runs as a daemon and
never returns. With fewer Verifiers running than the sweep width, it hangs
waiting on ports nobody is listening on.

For a per-operation breakdown rather than per-phase totals, the roles log
`Timing:` lines at INFO level; there are 42 such points across the tree. See
`charra_measurements_v2` for a full analysis.

---

# Other notes

- To change the IP addresses and port numbers of the Verifiers, modify
  `verifiers_config.txt`. Note that `start_verifiers.sh` and `run_benchmark_mode.sh`
  both rewrite this file for the Verifiers they start, so hand edits are lost
  on the next scripted run.
- `verifier.der` has two unrelated jobs: it is a DTLS raw-public-key identity,
  and it is also the key every Verifier signs its `/appraise` verdict with. The
  second is independent of whether DTLS is on.
- **DTLS** is off by default and turned on with one setting:

  ```sh
  DTLS_MODE=psk ./run_daemon.sh     # encrypted, one shared secret
  DTLS_MODE=rpk ./run_daemon.sh     # encrypted and mutually authenticated
  ```

  One setting for all four roles, because they must agree. A mismatch does not
  raise an error — the request times out, and a timeout counts as a NO vote, so
  it presents as a failed attestation rather than a misconfiguration.

  Under `rpk` each role proves possession of its keypair in `keys/` and checks
  its peer against the reference copy. It costs roughly 0.15s per cycle; `psk`
  costs about 0.02s.

  `rpk` needs a libcoap built `--enable-thread-safe`, which the image provides
  from `v4.3.5b`. On an older image the script refuses it rather than hanging.
  If you see that error, rebuild with `./docker/build.sh`, or use `psk`, which
  works on either.

---

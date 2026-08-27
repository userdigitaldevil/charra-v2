
# Build and Run CHARRA

CHARRA ships a Docker development environment and helper scripts. Building
and running outside Docker is possible but not the tested path.
All commands are for [Bash](https://www.gnu.org/software/bash/).

**This file covers getting CHARRA to build and to prove it works.** For what
the system actually does, how to configure a run, and the four roles it is
made of, see `charra-ressources/charra2-manual-v2.md`.

## The Docker Way

### Preparation

Docker (and optionally Docker Compose) must be installed. These commands are
for Ubuntu (amd64).

1. Install [Docker](https://docs.docker.com/get-docker/) (and
   [Docker Compose](https://docs.docker.com/compose/install/)):

       sudo apt update
       sudo apt install docker.io docker-compose

2. Set group membership to run containers as a non-root user:

       sudo groupadd docker
       sudo usermod -aG docker "${USER}"

3. Restart, to activate the group membership:

       sudo reboot

### Using Docker

1. Build the CHARRA container image:

       ./docker/build.sh

   This compiles tpm2-tss, tpm2-tools, libcoap, mbedTLS, QCBOR and t_cose
   from source, so it takes a while — roughly 25-45 minutes on an
   Apple-silicon Mac, where the `linux/amd64` image runs emulated, and closer
   to 10 natively. **You do this once**; every later run reuses the image.

   Rebuild only when the `Dockerfile` changes. It pins libcoap `v4.3.5b` with
   `--enable-thread-safe`, which DTLS-RPK needs — an older libcoap makes RPK
   hang rather than fail.

2. Run the interactive development environment:

       ./docker/run.sh

   This mounts your checkout at `/home/bob/charra` inside the container, so
   edits on the host are live inside it with no restart.

### Which container am I in?

Three different things start a container, and they are not the same one.
Knowing which is which saves a lot of confusion:

| You run | It starts | For |
| --- | --- | --- |
| `./docker/run.sh` | an unnamed, interactive container | editing, debugging, attaching VS Code, running `make` by hand |
| `./run_daemon.sh` | one named `charra-daemon` | a normal attestation run |
| `./run_benchmark_mode.sh` | one named `charra` | the timing sweep |

**The run scripts are launched from the host, not from inside a container.**
They start, use and remove their own container automatically, so a normal run
never needs `./docker/run.sh` at all. Use that one when you want a shell in
the environment — to attach an editor, run a single test, or drive one role
under a debugger.

All three mount this same checkout, which is why only one may run at a time:
they share `logs/`, `keys/trusted_keys.txt` and `qualified_rps.txt`, and a
second container's TPM resets would rewrite the trust anchor underneath the
first. Both run scripts refuse to start if another container already has this
directory mounted.

### Using Docker Compose

The image name and the `user`/`uid`/`gid` build arguments are already in
`docker-compose.yml`, so no `--build-arg` is needed:

    docker-compose build
    docker-compose run --rm charra-dev-env

## The Manual Way

Follow the steps in the `Dockerfile` to install the dependencies directly.
The versions it pins are load-bearing, libcoap especially.

## Compile

In the container, or on a system with the dependencies installed, from the
root of your checkout (`cd ~/charra/` in the container):

    make -j

That produces the binaries in `bin/`. The four that make up a run are
`attester`, `verifier`, `relying_party` and `trust_manager`; the fifth,
`provision_trusted_keys`, is an offline tool used once per TPM.

## Check that it works

Two checks, cheapest first.

1. **The unit tests.** They need **neither a TPM nor a network**, so they
   isolate build problems from environment problems:

       make test

   Expect `17 suites, 407 assertions, 0 failures`. Any single suite can be
   run alone, e.g. `make test_tee && ./bin/test_tee`.

2. **An end-to-end attestation.** From the **host**, not inside the
   container — the script starts the container itself:

       RP_CYCLES=1 ./run_daemon.sh

   It starts a TPM simulator per role, wipes each `NVChip`, regenerates the
   trust anchor from the fresh TPMs, launches all four roles, runs one
   attestation cycle and stops. Success looks like:

       Attestation successful by majority vote! (5/5 Verifiers passed)

   Logs land in `logs/`.

**There is no two-binary smoke test.** The Verifier is a passive CoAP server
that never initiates anything, so starting it beside an Attester attests
nothing — it simply waits. A full round needs all four roles, a TPM per
signing role, and a trust anchor generated from those TPMs, which is exactly
what `run_daemon.sh` sets up.

**The trust anchor is not optional.** `keys/trusted_keys.txt` holds the
public halves of the two TPM-resident signing keys and is the entire identity
mechanism; a signing key is trusted if and only if it appears there. It is
generated, never committed, and **wiping either TPM's `NVChip` invalidates
it**, because each key is derived from that TPM's hierarchy seed.
`run_daemon.sh` regenerates it after every reset. By hand:

    make provision_trusted_keys
    ./keys/gen-trusted-keys.sh

Skipping that produces signature checks that fail as "key not in the trust
anchor", which reads as a rejected identity rather than a stale file.

## Build Arguments

| Argument | Default | Options | Description |
| --- | --- | --- | --- |
| `TCTI_MODULE` | `tcti-mssim` | `tcti-default`, `tcti-cmd`, `tcti-device`, `tcti-libtpms`, `tcti-mssim`, `tcti-pcap`, `tcti-swtpm`, `tctildr` | TCTI module used to reach the TPM. The default targets the software simulator |
| `ENABLE_LOGGING` | `1` | `0`, `!= 0` | Log output |
| `ENABLE_LOGGING_COLOR` | `1` | `0`, `!= 0` | Coloured log output |
| `ENABLE_ADDRESS_SANITIZER` | `0` | `0`, `!= 0` | AddressSanitizer (ASan) |
| `ENABLE_LEAK_SANITIZER` | `0` | `0`, `!= 0` | LeakSanitizer (LSan) |
| `ENABLE_PIC` | `1` | `0`, `!= 0` | Position-independent code |
| `ENABLE_STRIPPING` | `1` | `0`, `!= 0` | Strip symbols not needed for relocation |
| `LINK_MODE` | `dynamic` | `dynamic`, `static` (*not working*) | Static or dynamic linking |

Example:

    make TCTI_MODULE=tcti-mssim ENABLE_LOGGING_COLOR=0 ENABLE_STRIPPING=0

## Troubleshooting and Advanced Usage

### TPM simulators

`run_daemon.sh` starts and resets these for you; do it by hand only when
driving a role under a debugger.

The Attester and the Relying Party each need **their own** simulator, as they
would on real hardware. `TPM2_CreatePrimary` *derives* a key from the
hierarchy seed rather than generating one, so a single shared TPM would make
both signing keys two templates over the same secret, and either role could
derive the other's.

Each `tpm_server` binds **two** consecutive ports — N for commands, N+1 for
the platform channel — so the two base ports must differ by at least 2:

    (cd /tmp/tpm_a && rm -f NVChip && tpm_server -port 2321 > /dev/null &)
    (cd /tmp/tpm_r && rm -f NVChip && tpm_server -port 2325 > /dev/null &)
    TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2321" tpm2_startup --clear
    TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=2325" tpm2_startup --clear

Each role is then pointed at its own simulator with `CHARRA_TCTI`.
Regenerate the trust anchor afterwards — a wiped `NVChip` changes both keys.

A second `TPM2_Startup --clear` is a silent no-op: it exits 0 and resets PCRs
but preserves the hierarchy seeds, so it does **not** change the keys. Only
deleting `NVChip` does.

### Debugging

* Clang `scan-build`:

      make clean ; scan-build make

* AddressSanitizer:

      make clean ; make ENABLE_ADDRESS_SANITIZER=1
      RP_CYCLES=1 ./run_daemon.sh

* Valgrind — attach it to one role rather than the whole run, since
  `run_daemon.sh` starts four:

      valgrind --leak-check=full --show-leak-kinds=all -v \
          bin/verifier --port 5684 2> verifier-valgrind.log

**A note on `pkill`.** `pkill -f <pattern>` matches the **full command line**,
including that of the shell that invoked it — so a script containing the
pattern kills itself. Use `pkill -x <name>` or an exact PID.

### Running the roles on different hosts

The four roles talk over CoAP/UDP and can run on separate machines, but two
addresses are compile-time constants rather than flags: `attester_host` and
`trust_manager_host` in `src/relying_party.c`, both `127.0.0.1`. Change them
and rebuild the Relying Party.

Verifier addresses need no rebuild — they are read from `verifiers_config.txt`
as `id ip port` rows, which `run_daemon.sh` writes from `VERIFIER_HOST` and
`VERIFIER_START_PORT`.

If the roles are containerised on different devices, give the container an
external network, e.g. a
[macvlan](https://docs.docker.com/network/macvlan/), and add `--network` to
the `docker run` invocation in `docker/run.sh`:

    docker network create -d macvlan \
        --subnet=192.168.x.0/24 \
        --gateway=192.168.x.1 \
        -o parent=eth0 pub_net

Every role must also agree on `DTLS_MODE` and `TRUST_MODE`; see the manual.

#!/usr/bin/env bash
#
# Full daemon-mode run: fresh TPMs, clean state, trust_manager + attester +
# N verifiers + relying_party looping until you stop it (Ctrl-C).
#
# The counterpart to run_benchmark_mode.sh, which runs the bounded --benchmark
# sweep instead. Everything the two processes can disagree about is a
# variable below, set to the binary's own built-in default, so this file
# doubles as the list of what is actually tunable.
#
# EVERY setting can also be overridden from the environment without editing
# this file:
#
#   RP_INTERVAL=5 RP_VERIFIERS=3 ./scripts/run_daemon.sh
#   RP_DURATION=120 ./scripts/run_daemon.sh            # stop cleanly after 2 minutes
#
# The Attester and the Relying Party each get their OWN TPM simulator, as
# they would on real hardware. Each role's AK is derived by, and read from,
# its own TPM.
#
# Identities are not provisioned at runtime and never expire: there are no
# certificates at all, just a file of trusted public keys
# (keys/trusted_keys.txt) written from the TPMs by keys/gen-trusted-keys.sh,
# which this script re-runs after every TPM reset.
#
# Qualification is the one thing that DOES expire -- identity does not go
# stale, but behaviour can. Shorten the window to watch the RP re-qualify
# mid-run:
#
#   VERIFIER_QUALIFICATION_VALIDITY=20 RP_CYCLES=8 ./scripts/run_daemon.sh
#
# DTLS is off by default. ONE variable turns it on for every role at once,
# because they must agree -- a mismatch does not error, it times out, and a
# timeout counts as a NO vote, so the run reports 0/N as a failed attestation:
#
#   DTLS_MODE=rpk ./scripts/run_daemon.sh     # mutual auth, keypairs from keys/
#   DTLS_MODE=psk ./scripts/run_daemon.sh     # one shared secret, no peer identity
#
# TRUST_MODE picks how the RP proves it runs the expected appraisal code, and
# likewise sets the RP and every Verifier at once. Unlike DTLS a mismatch here
# does NOT time out: the RP states its mode on the wire, so a Verifier set the
# other way votes NO and says MODE MISMATCH.
#
# The three differ in what they prove and what they cost: qualify proves the
# redaction OUTPUT once per cycle, tee names the CODE once per Verifier, and
# zk proves the redaction itself, once per cycle, in about 8 seconds.
#
#   TRUST_MODE=qualify ./scripts/run_daemon.sh   # /qualify handshake (default)
#   TRUST_MODE=tee ./scripts/run_daemon.sh       # simulated TEE Attestation Document
#   TRUST_MODE=zk ./scripts/run_daemon.sh        # zero-knowledge proof over log_r
#
# zk additionally needs the prover image, built once with ./docker/build-zk.sh.
# This script starts and stops that container itself; it holds Noir and
# Barretenberg, which cannot run inside the charra image.
#
# Options:
#   --keep-state   keep each TPM NVChip instead of wiping it, so both AKs --
#                  and therefore keys/trusted_keys.txt -- survive the run.
#                  State lives in .tpm-state/ under this checkout, not in the
#                  container, so it outlives the --rm container.
#   -h, --help     this message
#
set -euo pipefail

# Every path below is relative to the repository root, and these scripts live
# one level under it, so anchor there rather than trusting the caller's cwd.
# This is what lets ./scripts/run_daemon.sh work from anywhere.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# =============================================================================
#  TUNABLES -- all set to the binaries' own defaults
# =============================================================================

# --- Relying Party: cadence -------------------------------------------------
RP_INTERVAL="${RP_INTERVAL:-8}"                 # --interval, seconds between cycles
RP_VERIFIERS="${RP_VERIFIERS:-5}"                # --verifiers, 1..10; also how many get started
RP_DURATION="${RP_DURATION:-0}"                  # --duration, 0 = run until SIGINT
RP_CYCLES="${RP_CYCLES:-0}"                      # --cycles, 0 = unbounded

# --- Relying Party: timeouts ------------------------------------------------
# A Verifier that times out counts against the majority exactly like a NO vote.
RP_VERIFIER_TIMEOUT="${RP_VERIFIER_TIMEOUT:-30}"  # --verifier-timeout, seconds
RP_ATTESTER_TIMEOUT="${RP_ATTESTER_TIMEOUT:-30}"  # --attester-timeout, seconds

# --- Verifier: what IT grants -----------------------------------------------
# How long a passing /qualify is honoured for. The Verifier that runs the
# handshake stamps this deadline into qualified_rps.txt, every Verifier
# reads that same number, and the RP re-qualifies on the first cycle after
# it lapses.
VERIFIER_QUALIFICATION_VALIDITY="${VERIFIER_QUALIFICATION_VALIDITY:-180}"  # --qualification-validity

# --- TPMs -------------------------------------------------------------------
# One simulator per role, which is what real hardware looks like. It is not
# only realism:
#   - the two roles stop queueing behind a simulator that serves one client
#     at a time;
#   - their AKs come from different hierarchy seeds, so they are distinct by
#     construction rather than by a one-bit template difference;
#   - TPM2_Clear needs no authorization here, so on a shared TPM either role
#     could silently destroy both identities. Separate TPMs contain that.
# Each simulator binds PORT and PORT+1, and keeps its NVChip in its own
# directory -- sharing one would have them clobber each other.
#
# TWO_TPMS=0 falls back to a single shared TPM on ATTESTER_TPM_PORT.
TWO_TPMS="${TWO_TPMS:-1}"
ATTESTER_TPM_PORT="${ATTESTER_TPM_PORT:-2321}"
RP_TPM_PORT="${RP_TPM_PORT:-2325}"
# Each simulator keeps its NVChip here, under the bind-mounted checkout rather
# than in the container /tmp. The container is --rm, so /tmp dies with it --
# state kept there could not survive a run, which made --keep-state
# meaningless. Repo-relative, and gitignored.
TPM_STATE_DIR="${TPM_STATE_DIR:-.tpm-state}"

# --- Topology ---------------------------------------------------------------
VERIFIER_START_PORT="${VERIFIER_START_PORT:-5684}"   # first Verifier port; rest follow
VERIFIER_HOST="${VERIFIER_HOST:-127.0.0.1}"          # address written into verifiers_config.txt

# --- DTLS -------------------------------------------------------------------
# off | psk | rpk.  ONE variable for all four roles on purpose: they must
# agree, and a mismatch does NOT error -- the request times out, a timeout
# counts as a NO vote, and the run reports 0/N as though attestation failed.
#
#   psk  one shared secret. Every role holds the same key, so it encrypts
#        but authenticates nobody in particular.
#   rpk  raw public keys, mutual: each role proves possession of its own
#        keypair in keys/ and checks its peer against the reference copy.
#
# Default off, so every timing figure in the docs stays comparable.
DTLS_MODE="${DTLS_MODE:-off}"

# --- Trust mode: how the RP proves it runs the expected appraisal code -------
# qualify = the /qualify + /qualify_submit handshake (the default; proves the
#           redaction OUTPUT matches, not which code produced it)
# tee     = a simulated TEE Attestation Document per Verifier, naming the code
#           that ran and binding it to that Verifier's challenge
# Set here for BOTH roles at once, because they must agree. Unlike DTLS a
# mismatch does not time out -- the Verifier names it and votes NO.
TRUST_MODE="${TRUST_MODE:-qualify}"

# Image holding Noir + Barretenberg, used only by TRUST_MODE=zk. Separate
# from IMAGE because it is a different architecture: bb needs x86 ADX
# instructions Rosetta does not emulate, so it cannot run in the linux/amd64
# charra image on Apple silicon. Build once with ./docker/build-zk.sh.
ZK_IMAGE="${ZK_IMAGE:-charra-zk:arm64}"
ZK_PLATFORM="${ZK_PLATFORM:-linux/arm64}"
ZK_CONTAINER_NAME="${ZK_CONTAINER_NAME:-charra-zk-prover}"

# --- Logging ----------------------------------------------------------------
LOG_LEVEL="${LOG_LEVEL:-INFO}"                   # TRACE DEBUG INFO WARN ERROR FATAL
LOG_LEVEL_COAP="${LOG_LEVEL_COAP:-}"             # empty = leave libcoap at its default

# --- Anything else ----------------------------------------------------------
# Free-form pass-through, in case you want a flag this file does not name.
RP_EXTRA_ARGS="${RP_EXTRA_ARGS:-}"
VERIFIER_EXTRA_ARGS="${VERIFIER_EXTRA_ARGS:-}"
ATTESTER_EXTRA_ARGS="${ATTESTER_EXTRA_ARGS:-}"

# --- Environment ------------------------------------------------------------
IMAGE="${IMAGE:-fraunhofer-sit/charra-dev-env:1.9.0}"
CONTAINER_NAME="${CONTAINER_NAME:-charra-daemon}"
# `make clean && make -j` on CHARRA's C code INSIDE the container. Named
# RECOMPILE, not REBUILD, because "rebuild" reads as the Docker image -- which
# nothing here touches. Only ./docker/build.sh does that.
RECOMPILE="${RECOMPILE:-1}"
# 1 = wipe each TPM's NVChip, which re-randomizes the hierarchy seeds and so
# changes every AK -- which is why the trust anchor is regenerated afterwards.
# 0 (--keep-state) keeps NVChip, so the AKs come back identical.
# TPM2_Startup(CLEAR) runs either way and does NOT affect this: it resets PCRs
# and leaves the seeds alone.
RESET_TPM="${RESET_TPM:-1}"

# =============================================================================
#  end of tunables
# =============================================================================

# Prints the whole comment header, however long it grows. It used to be
# `sed -n '3,34p'`, a hard-coded range that silently stopped covering the
# header as it gained sections -- --help ended mid-sentence, omitting the
# DTLS examples and the Options block below.
usage() {
    sed -n '3,/^[^#]/p' "$0" | sed '/^[^#]/d; s/^#\{1,\} \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --keep-state) RESET_TPM=0; shift ;;
        -h|--help)    usage 0 ;;
        *)            echo "Unknown option '$1'." >&2; usage 1 ;;
    esac
done

# The run scripts do not build the image, they only run in it -- RECOMPILE
# above is `make` inside the container, not `docker build`. On a fresh clone,
# or after the Dockerfile changes, the image has to be built once first.
# Without this check docker would try to PULL a name that exists only
# locally, and fail with "pull access denied", which reads as an
# authentication problem rather than a missing build.
if [ -n "${REBUILD-}" ]; then
    echo "NOTE: REBUILD has been renamed RECOMPILE -- it was read as meaning" >&2
    echo "      the Docker image, which it never was. Using RECOMPILE=$REBUILD." >&2
    RECOMPILE="$REBUILD"
fi

# Three different failures used to report as "the image is missing", which
# sent you off to run a 20-minute build that was never the problem. Separate
# them: no client, no daemon, then genuinely no image.
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: 'docker' is not on your PATH." >&2
    echo >&2
    echo "       On macOS the client lives inside the app bundle:" >&2
    echo >&2
    echo "           export PATH=\"\$PATH:/Applications/Docker.app/Contents/Resources/bin\"" >&2
    echo >&2
    echo "       Add that line to ~/.zshrc to make it stick. If" >&2
    echo "       /usr/local/bin/docker exists but is a dangling symlink into" >&2
    echo "       /Volumes/Docker, Docker was launched from the installer disk" >&2
    echo "       image once; the PATH line above sidesteps it." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: the Docker daemon is not running (the client is installed)." >&2
    echo >&2
    echo "           open -a Docker        # then wait for it to finish starting" >&2
    echo >&2
    echo "       Your images are not lost -- they live in the Docker VM's disk" >&2
    echo "       and come back with it." >&2
    exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "ERROR: image '$IMAGE' does not exist locally." >&2
    echo "       These scripts run in it, they do not build it. Build once:" >&2
    echo >&2
    echo "           ./docker/build.sh" >&2
    echo >&2
    echo "       That takes a while -- it compiles tpm2-tss, libcoap and the" >&2
    echo "       rest from source. Afterwards this script reuses it, and" >&2
    echo "       RECOMPILE=1 only re-runs make inside it." >&2
    exit 1
fi

# --- DTLS mode -> the flags each role gets ----------------------------------
# Built once, here, so no role can be launched with a different mode from
# its peers. Each role names its own keypair; the RP additionally names one
# peer key per kind of peer it talks to.
case "$DTLS_MODE" in
    off) DTLS_TM= ; DTLS_ATT= ; DTLS_VER= ; DTLS_RP= ;;
    psk)
        DTLS_TM="--psk"
        DTLS_ATT="--psk"
        DTLS_VER="--psk"
        DTLS_RP="--psk"
        ;;
    rpk)
        DTLS_TM="--rpk --private-key=keys/trust_manager.der \
                 --public-key=keys/trust_manager.pub.der \
                 --peer-public-key=keys/relying_party.pub.der"
        DTLS_ATT="--rpk --private-key=keys/attester.der \
                  --public-key=keys/attester.pub.der \
                  --peer-public-key=keys/relying_party.pub.der"
        DTLS_VER="--rpk --private-key=keys/verifier.der \
                  --public-key=keys/verifier.pub.der \
                  --peer-public-key=keys/relying_party.pub.der"
        DTLS_RP="--rpk --private-key=keys/relying_party.der \
                 --public-key=keys/relying_party.pub.der \
                 --attester-public-key=keys/attester.pub.der \
                 --verifier-public-key=keys/verifier.pub.der \
                 --trust-manager-public-key=keys/trust_manager.pub.der"
        ;;
    *)
        echo "ERROR: DTLS_MODE must be off, psk or rpk (got '$DTLS_MODE')." >&2
        exit 1
        ;;
esac

# --- trust mode -> the flags the two roles get ------------------------------
# Same reasoning as DTLS above: built once so the RP and every Verifier cannot
# be launched requiring different proofs of each other.
case "$TRUST_MODE" in
    qualify|tee|zk)
        TRUST_RP="--trust-mode=$TRUST_MODE"
        TRUST_VER="--trust-mode=$TRUST_MODE"
        # One line for the run summary. Built here rather than inside the
        # summary heredoc, where a case statement does not survive.
        case "$TRUST_MODE" in
            qualify) TRUST_DESC="the RP must hold a /qualify grant" ;;
            tee)     TRUST_DESC="a TEE Attestation Document per Verifier" ;;
            zk)      TRUST_DESC="one zero-knowledge proof per cycle, proved in a second container" ;;
        esac
        ;;
    *)
        echo "ERROR: TRUST_MODE must be qualify, tee or zk (got '$TRUST_MODE')." >&2
        exit 1
        ;;
esac

# The prover runs in its own container, alongside the charra one, sharing this
# checkout: that shared mount IS the job queue (src/core/charra_zk_job.h). It
# is started here rather than left to the user because it has the same
# lifetime as the run, like the TPM simulators.
if [ "$TRUST_MODE" = "zk" ]; then
    if ! docker image inspect "$ZK_IMAGE" >/dev/null 2>&1; then
        echo "ERROR: TRUST_MODE=zk needs the prover image '$ZK_IMAGE'." >&2
        echo "       It carries Noir and Barretenberg, which cannot run in" >&2
        echo "       the charra image. Build it once (about two minutes):" >&2
        echo >&2
        echo "           ./docker/build-zk.sh" >&2
        exit 1
    fi
    if [ ! -s zk/vk ]; then
        echo "ERROR: zk/vk is missing. Verifiers check every proof against" >&2
        echo "       it, and it must match the compiled circuit." >&2
        exit 1
    fi
fi

# --- sanity checks that span two processes ----------------------------------
# None of these are fatal on their own; the run still works, it just stops
# behaving the way the settings suggest. Say so rather than letting it look
# like a bug later.
warned=0
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$1" >&2; warned=1; }

if [ "$RP_VERIFIERS" -lt 1 ] || [ "$RP_VERIFIERS" -gt 10 ]; then
    echo "ERROR: RP_VERIFIERS must be 1..10 (got $RP_VERIFIERS)." >&2; exit 1
fi
# Each tpm_server binds PORT and PORT+1, so the two must differ by at least 2.
# Overlapping them makes the second simulator die with "Address already in use"
# and the run then fails much later, against a TPM that is simply not there.
if [ "$TWO_TPMS" -eq 1 ]; then
    gap=$(( ATTESTER_TPM_PORT > RP_TPM_PORT \
            ? ATTESTER_TPM_PORT - RP_TPM_PORT : RP_TPM_PORT - ATTESTER_TPM_PORT ))
    if [ "$gap" -lt 2 ]; then
        echo "ERROR: ATTESTER_TPM_PORT ($ATTESTER_TPM_PORT) and RP_TPM_PORT ($RP_TPM_PORT) must" >&2
        echo "       differ by at least 2 -- each simulator binds PORT and PORT+1." >&2
        exit 1
    fi
fi
if [ "$RP_INTERVAL" -gt "$VERIFIER_QUALIFICATION_VALIDITY" ]; then
    warn "RP_INTERVAL ($RP_INTERVAL s) is longer than the qualification window
         ($VERIFIER_QUALIFICATION_VALIDITY s), so a grant expires between cycles and
         the RP re-qualifies inside almost every one -- a note, not a fault."
fi
# Qualification is the only thing left with a lifetime. The RP renews at the
# start of the first cycle where its grant has lapsed, so renewal normally
# costs no cycle at all -- but there is no margin, so a grant that is still
# valid at that check and lapses during the round trip that follows costs
# that one cycle. The next cycle renews and it self-corrects.
if [ "$VERIFIER_QUALIFICATION_VALIDITY" -lt 120 ]; then
    warn "VERIFIER_QUALIFICATION_VALIDITY is ${VERIFIER_QUALIFICATION_VALIDITY}s -- short enough that a grant can
         lapse between the RP's check and its use, costing an occasional
         cycle. Expected when deliberately exercising renewal; not a fault."
fi
[ "$warned" -eq 1 ] && echo

# --- refuse to share this checkout with another running container -----------
# Two containers on one checkout fight over the same ports, logs/ and
# keys/trusted_keys.txt, which surfaces only as unexplained failures much later.
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker rm -f "$ZK_CONTAINER_NAME" >/dev/null 2>&1 || true
mine=${PWD%/}
others=""
for cid in $(docker ps -q); do
    cname=$(docker inspect -f "{{.Name}}" "$cid" 2>/dev/null | sed "s#^/##")
    # Our own prover mounts this checkout on purpose -- the shared mount is
    # how it and the RP exchange jobs -- so it must not count as a stray.
    [ "$cname" = "$ZK_CONTAINER_NAME" ] && continue
    for src in $(docker inspect -f "{{range .Mounts}}{{.Source}}{{println}}{{end}}" "$cid" 2>/dev/null); do
        if [ "${src%/}" = "$mine" ]; then others="$others $cname"; break; fi
    done
done
if [ -n "$others" ]; then
    echo "ERROR: these running containers already mount $mine:$others" >&2
    echo "They share logs/ and keys/ with this run and will corrupt it." >&2
    echo "Stop them first:  docker stop$others" >&2
    exit 1
fi

# --- report the effective settings before anything starts -------------------
cat <<EOF
--- daemon run ------------------------------------------------------------
  Verifiers          $RP_VERIFIERS on ports $VERIFIER_START_PORT..$((VERIFIER_START_PORT + RP_VERIFIERS - 1)) ($VERIFIER_HOST)
  Cycle interval     ${RP_INTERVAL}s
  Stop after         $([ "$RP_DURATION" -gt 0 ] && echo "${RP_DURATION}s" || echo "never (Ctrl-C)")$([ "$RP_CYCLES" -gt 0 ] && echo " / $RP_CYCLES cycles" || echo "")
  Timeouts           verifier ${RP_VERIFIER_TIMEOUT}s, attester ${RP_ATTESTER_TIMEOUT}s
  TPMs               $([ "$TWO_TPMS" -eq 1 ] \
                        && echo "one each -- attester :$ATTESTER_TPM_PORT, RP :$RP_TPM_PORT" \
                        || echo "one shared on :$ATTESTER_TPM_PORT (TWO_TPMS=0)")
  Trusted keys       keys/trusted_keys.txt, written before any role starts;
                     $([ "$TWO_TPMS" -eq 1 ] \
                        && echo "each AK read from its own role's TPM" \
                        || echo "both AKs read from the one shared TPM")
                     no certificates, no expiry, no renewal
  Trust mode         $TRUST_MODE -- $TRUST_DESC
$(if [ "$TRUST_MODE" = "qualify" ]; then cat <<QUAL
  Qualification      granted for ${VERIFIER_QUALIFICATION_VALIDITY}s, recorded with its deadline in
                     qualified_rps.txt (shared by every Verifier); the RP
                     re-qualifies on the first cycle after it lapses
QUAL
fi)
  Fresh TPM          $([ "$RESET_TPM" -eq 1 ] && echo "yes (trust anchor regenerated)" || echo "no (--keep-state)")
  Log level          $LOG_LEVEL
---------------------------------------------------------------------------
EOF

tty_flags=""
[ -t 0 ] && tty_flags="-it"

if [ "$TRUST_MODE" = "zk" ]; then
    echo "--- starting the ZK prover ($ZK_IMAGE, $ZK_PLATFORM)"
    rm -rf zk/jobs
    docker run -d --rm --name "$ZK_CONTAINER_NAME" \
        --platform "$ZK_PLATFORM" \
        -v "$PWD/:/home/bob/charra" -w /home/bob/charra \
        "$ZK_IMAGE" ./zk/proof_watcher.sh
    # Removed however this script exits, so a killed run does not leave a
    # watcher behind holding the checkout and blocking the next one.
    trap 'docker rm -f "$ZK_CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT
    sleep 1
    if ! docker ps --filter "name=$ZK_CONTAINER_NAME" --format '{{.Names}}' \
            | grep -q .; then
        echo "ERROR: the prover container exited immediately. Its output:" >&2
        docker logs "$ZK_CONTAINER_NAME" 2>&1 | tail -20 >&2
        exit 1
    fi
    echo "    prover ready; one proof per cycle, shared by every Verifier"
fi

docker run -v "$PWD/:/home/bob/charra" $tty_flags --rm --init \
  --name "$CONTAINER_NAME" --group-add tss \
  -e RP_INTERVAL="$RP_INTERVAL" \
  -e RP_VERIFIERS="$RP_VERIFIERS" \
  -e RP_DURATION="$RP_DURATION" \
  -e RP_CYCLES="$RP_CYCLES" \
  -e RP_VERIFIER_TIMEOUT="$RP_VERIFIER_TIMEOUT" \
  -e RP_ATTESTER_TIMEOUT="$RP_ATTESTER_TIMEOUT" \
  -e VERIFIER_QUALIFICATION_VALIDITY="$VERIFIER_QUALIFICATION_VALIDITY" \
  -e TWO_TPMS="$TWO_TPMS" \
  -e ATTESTER_TPM_PORT="$ATTESTER_TPM_PORT" \
  -e RP_TPM_PORT="$RP_TPM_PORT" \
  -e TPM_STATE_DIR="$TPM_STATE_DIR" \
  -e VERIFIER_START_PORT="$VERIFIER_START_PORT" \
  -e VERIFIER_HOST="$VERIFIER_HOST" \
  -e LOG_LEVEL="$LOG_LEVEL" \
  -e LOG_LEVEL_COAP="$LOG_LEVEL_COAP" \
  -e RP_EXTRA_ARGS="$RP_EXTRA_ARGS" \
  -e VERIFIER_EXTRA_ARGS="$VERIFIER_EXTRA_ARGS" \
  -e ATTESTER_EXTRA_ARGS="$ATTESTER_EXTRA_ARGS" \
  -e RECOMPILE="$RECOMPILE" \
  -e RESET_TPM="$RESET_TPM" \
  -e DTLS_MODE="$DTLS_MODE" \
  -e DTLS_TM="$DTLS_TM" \
  -e DTLS_ATT="$DTLS_ATT" \
  -e DTLS_VER="$DTLS_VER" \
  -e DTLS_RP="$DTLS_RP" \
  -e TRUST_MODE="$TRUST_MODE" \
  -e TRUST_RP="$TRUST_RP" \
  -e TRUST_VER="$TRUST_VER" \
  -e CHARRA_ZK_JOBS="zk/jobs" \
  "$IMAGE" \
  bash -lc '
    set -e
    cd ~/charra

    pkill -9 -f "^bin/" || true

    # DTLS-RPK needs a libcoap built --enable-thread-safe. Without it a
    # session opened from one of the RP per-Verifier threads never finishes
    # its handshake -- and the failure is a HANG, not an error, so it looks
    # like a stuck attestation rather than a missing library feature. Refuse
    # up front instead. PSK is unaffected: it opens fine from a thread.
    if [ "$DTLS_MODE" = "rpk" ] &&
       ! grep -q "COAP_THREAD_SAFE" /usr/local/include/coap3/coap_defines.h \
             2>/dev/null; then
        echo
        echo "ERROR: DTLS_MODE=rpk needs libcoap built --enable-thread-safe," >&2
        echo "       and the libcoap in this image was not. It would hang" >&2
        echo "       at the first /nonce rather than fail." >&2
        echo >&2
        echo "       Rebuild the image (./docker/build.sh) -- the Dockerfile" >&2
        echo "       now pins libcoap v4.3.5b with that option -- or use" >&2
        echo "       DTLS_MODE=psk, which works on either." >&2
        exit 1
    fi

    ATTESTER_TCTI="mssim:host=127.0.0.1,port=$ATTESTER_TPM_PORT"
    if [ "$TWO_TPMS" = "1" ]; then
        RP_TCTI="mssim:host=127.0.0.1,port=$RP_TPM_PORT"
    else
        RP_TCTI="$ATTESTER_TCTI"
    fi

    # NVChip lives under the mounted checkout, so it outlives this --rm
    # container and RESET_TPM=0 can genuinely keep the AKs across runs.
    ATT_DIR="$HOME/charra/$TPM_STATE_DIR/attester"
    RP_DIR="$HOME/charra/$TPM_STATE_DIR/rp"
    [ "$TWO_TPMS" = "1" ] || RP_DIR="$ATT_DIR"

    start_tpm() {   # $1 = port, $2 = state dir
        mkdir -p "$2"
        # Deleting NVChip is what discards the hierarchy seeds, and therefore
        # the AKs. TPM2_Startup(CLEAR) below does NOT -- it resets PCRs and
        # leaves the seeds alone -- so this line, not that one, is what
        # RESET_TPM actually controls.
        [ "$RESET_TPM" = "1" ] && rm -f "$2/NVChip"
        ( cd "$2" && tpm_server -port "$1" > "/tmp/tpm_server_$1.log" 2>&1 & )
    }

    # The image entrypoint starts its OWN tpm_server on the default port,
    # with its own NVChip in /tmp, and never issues TPM2_Startup. It is never
    # the simulator we want, so it always goes. Killing it is unrelated to
    # keeping state: that is decided by whether NVChip is deleted above.
    #
    # The previous guard asked "is A tpm_server running" and so concluded, on
    # every single run, that ours were already up -- they never were.
    pkill tpm_server || true
    sleep 1

    start_tpm "$ATTESTER_TPM_PORT" "$ATT_DIR"
    [ "$TWO_TPMS" = "1" ] && start_tpm "$RP_TPM_PORT" "$RP_DIR"
    sleep 3

    # Every TPM needs its own TPM2_Startup: one with power but no startup
    # rejects everything with 0x100 (TPM_RC_INITIALIZE), which the tools
    # report as an ordinary command failure. CLEAR resets PCRs but preserves
    # the seeds, so it is correct whether or not NVChip was kept.
    TPM2TOOLS_TCTI="$ATTESTER_TCTI" tpm2_startup --clear
    if [ "$TWO_TPMS" = "1" ]; then
        TPM2TOOLS_TCTI="$RP_TCTI" tpm2_startup --clear
    fi

    # Refuse to continue on a TPM that cannot answer -- otherwise the failure
    # surfaces much later as an unexplained provisioning error.
    for p in $ATTESTER_TPM_PORT $([ "$TWO_TPMS" = "1" ] && echo $RP_TPM_PORT); do
        TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=$p" tpm2_pcrread sha256:0 >/dev/null 2>&1 \
            || { echo "ERROR: TPM on port $p is not answering." >&2; exit 1; }
    done

    cd ~/charra

    if [ "$RECOMPILE" = "1" ]; then
        make clean && make -j
    else
        # The trust anchor is written by bin/provision_trusted_keys, so it
        # has to exist before the step below can run.
        make -j provision_trusted_keys
    fi

    # A TPM reset changes the AK the RP signs with, so every fingerprint in
    # the shared qualified-RP list names an identity that no longer exists.
    # Left in place they are merely dead weight, but clearing them also
    # means a fresh run actually exercises the /qualify handshake.
    if [ "$RESET_TPM" = "1" ]; then
        rm -f qualified_rps.txt
    fi

    # Regenerate the trust anchor AFTER any TPM reset and BEFORE any role
    # starts. Both signing keys are derived from the hierarchy seed, so
    # wiping the NVChip silently changes them -- and every signature check
    # would then fail against a stale keys/trusted_keys.txt, in a way that
    # reads as a rejected identity rather than a stale file.
    if [ "$TWO_TPMS" = "1" ]; then
        ATTESTER_TCTI="$ATTESTER_TCTI" RP_TCTI="$RP_TCTI" \
            ./keys/gen-trusted-keys.sh
    else
        CHARRA_TCTI="$ATTESTER_TCTI" ./keys/gen-trusted-keys.sh
    fi

    # Wipe logs/ and recreate it, every run. Not tidiness: the per-Verifier
    # files are named by port, so a 3-Verifier run would otherwise leave
    # verifier_5687.log and verifier_5688.log lying around from an earlier
    # 5-Verifier one, looking exactly like part of this run. It also means
    # logs/ exists at all on a fresh clone, which the redirects below need.
    rm -rf logs && mkdir -p logs


    export LOG_LEVEL_CHARRA="$LOG_LEVEL"
    [ -n "$LOG_LEVEL_COAP" ] && export LOG_LEVEL_COAP

    # Only these two open a TPM. The Verifiers never do -- every check they
    # run is public-key math in mbedTLS -- and neither does trust_manager.
    bin/trust_manager --log-level=$LOG_LEVEL $DTLS_TM \
        > logs/trust_manager.log 2>&1 &
    CHARRA_TCTI="$ATTESTER_TCTI" bin/attester $DTLS_ATT $ATTESTER_EXTRA_ARGS \
        > logs/attester.log 2>&1 &

    # start_verifiers.sh also generates verifiers_config.txt for exactly these
    # ports, which is what the Trust Manager resolves the RP requests against.
    ./scripts/start_verifiers.sh "$RP_VERIFIERS" \
        --startingport "$VERIFIER_START_PORT" \
        --host "$VERIFIER_HOST" \
        --logdir logs \
        --qualification-validity "$VERIFIER_QUALIFICATION_VALIDITY" \
        $DTLS_VER $TRUST_VER $VERIFIER_EXTRA_ARGS
    sleep 2

    rp_args="--verifiers $RP_VERIFIERS \
             --interval $RP_INTERVAL \
             --verifier-timeout $RP_VERIFIER_TIMEOUT \
             --attester-timeout $RP_ATTESTER_TIMEOUT"
    [ "$RP_DURATION" -gt 0 ] && rp_args="$rp_args --duration $RP_DURATION"
    [ "$RP_CYCLES"   -gt 0 ] && rp_args="$rp_args --cycles $RP_CYCLES"
    rp_args="$rp_args $DTLS_RP $TRUST_RP"

    echo "--- relying_party $rp_args $RP_EXTRA_ARGS"
    echo

    # Foreground and tee-ed: Ctrl-C stops the daemon, the container exits.
    CHARRA_TCTI="$RP_TCTI" bin/relying_party $rp_args $RP_EXTRA_ARGS 2>&1 \
        | tee logs/relying_party.log

    # A log that is mostly NUL bytes means two processes shared the file: one
    # truncated it while the other held a descriptor at a large offset. That
    # invalidates the run, so say so rather than letting it look healthy.
    for f in logs/*.log; do
        if [ "$(wc -c < "$f")" -ne "$(tr -d "\0" < "$f" | wc -c)" ]; then
            echo "WARNING: $f contains NUL padding -- more than one process"
            echo "         wrote it. Treat this run as contaminated."
        fi
    done

    echo
    echo "--- logs in logs/ : relying_party, attester, trust_manager, verifier_<port>"
  '

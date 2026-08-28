#!/usr/bin/env bash
# BENCHMARK mode: the bounded 1..5-Verifier timing sweep, then exit. Fresh
# TPM simulator state, clean rebuild, trust_manager + attester + 5 verifiers
# (ports 5684-5688) + relying_party --benchmark, with DEBUG logging. Writes
# timings_RP_multi_verifiers.txt.
#
# The counterpart to run_daemon.sh, which loops instead of sweeping. Run this
# from the repository root.
#
# What it does, step by step:
#   1. Removes any leftover container named "charra" from a previous run
#      (docker run --name would otherwise refuse to start with a name
#      already in use).
#   2. Starts a fresh charra-dev-env container (same image docker-compose.yml
#      builds/uses), mounting this repo into /home/bob/charra, with
#      --group-add tss so the container user can talk to the TPM simulator
#      device group.
#   3. Inside the container: kills any stray bin/* processes and tpm_server
#      from a previous run, then starts TWO simulators -- one for the
#      Attester (:2321) and one for the RP (:2325), each in its own
#      directory so their NVChip files stay separate -- wiping both and
#      TPM2_Startup(CLEAR)ing each. Two genuinely cold, independent TPMs.
#   4. Rebuilds keys/trusted_keys.txt, reading each role's AK from ITS OWN
#      TPM, and drops qualified_rps.txt. Both are consequences of step 3:
#      an AK is derived from its TPM's hierarchy seed, so wiping NVChip
#      gives that role a new key. Against a stale trust anchor every
#      signature check then fails -- as "this key is not a trusted
#      identity", which reads like a rejected peer rather than a stale
#      file, so it is worth doing unconditionally. qualified_rps.txt goes
#      for the same reason: every fingerprint in it names an RP identity
#      that no longer exists.
#   5. Sanity-checks that PCRs 0-7 and 10 read back all-zero -- confirms the
#      TPM really is freshly reset before anything starts touching it.
#   6. Clean rebuild (make clean && make -j).
#   7. Wipes logs/ entirely and recreates it empty -- so logs/ always
#      reflects exactly this run, nothing left over from some earlier
#      one-off script with a different naming scheme (that's how
#      rp_run1.log/rp_run2.log/rp_run3.log/verifier_5684_restarted.log
#      ended up sitting there stale after unrelated scratch-test scripts).
#   8. Launches trust_manager, attester, and verifier instances on ports
#      5684-5688 (all 5, matching relying_party's own num_verifiers=1..5
#      benchmark loop -- with fewer than 5 real Verifiers running, that loop
#      hangs waiting on whichever ports aren't listening), all backgrounded
#      with DEBUG logging to logs/.
#   9. Runs relying_party in the foreground (tee'd to logs/relying_party.log
#      too), which is the actual multi-verifier attestation run.
#      --benchmark is required, not cosmetic: relying_party's default mode
#      is now a daemon that loops until signalled, so without it this script
#      would never return. --benchmark runs the bounded 1..5-verifier sweep
#      and exits, which is what this script has always meant to do (and it
#      is what writes timings_RP_multi_verifiers.txt for
#      plot_multi_verifiers.py). For a bounded *daemon* smoke test instead,
#      swap it for e.g. --duration 120.
#
# Tunables, all overridable from the environment without editing this file
# and all matching run_daemon.sh's, so the two measure the same stack:
#
#   IMAGE=...            which container image to run in
#   DTLS_MODE=off|psk|rpk    transport security, all four roles at once
#   TRUST_MODE=qualify|tee|zk  how the RP proves it runs the expected appraisal
#                            code, the RP and every Verifier at once. zk needs
#                            the prover container (./docker/build-zk.sh) and
#                            adds about 8 s to every cycle.
#
#   TRUST_MODE=tee ./run_benchmark_mode.sh
#
# Both mode settings default to the value that keeps figures comparable with
# those already recorded (off, and qualify).
#
# Logs land in logs/*.log either way; Ctrl-C stops relying_party, the
# container itself is --rm'd on exit but the background bin/* processes
# inside it are not explicitly killed by this script if you Ctrl-C early --
# re-running the script kills them itself (step 3) before starting fresh.

set -e

docker rm -f charra >/dev/null 2>&1 || true

# Refuse to run while ANOTHER container has this same directory mounted.
# Removing the "charra" container above only handles our own leftovers; a
# container under any other name sharing this checkout shares logs/,
# keys/trusted_keys.txt and qualified_rps.txt too. Worse, its own TPM
# resets would rewrite the trust anchor underneath this run -- silently,
# surfacing only as unexplained attestation failures much later.
mine=${PWD%/}
others=""
for cid in $(docker ps -q); do
    cname=$(docker inspect -f "{{.Name}}" "$cid" 2>/dev/null | sed "s#^/##")
    # Our own prover mounts this checkout on purpose -- that shared mount is
    # how it and the RP exchange jobs -- so it is not a stray.
    [ "$cname" = "${ZK_CONTAINER_NAME:-charra-zk-prover}" ] && continue
    for src in $(docker inspect -f "{{range .Mounts}}{{.Source}}{{println}}{{end}}" "$cid" 2>/dev/null); do
        if [ "${src%/}" = "$mine" ]; then
            others="$others $cname"
            break
        fi
    done
done
if [ -n "$others" ]; then
    echo "ERROR: these running containers already mount $mine:$others" >&2
    echo "They share logs/ and keys/ with this run and will corrupt it." >&2
    echo "Stop them first:  docker stop$others" >&2
    exit 1
fi

# -t only when there is a terminal, so this stays runnable from CI or a
# non-interactive shell (docker run -t without a TTY fails outright).
tty_flags=""
[ -t 0 ] && tty_flags="-it"

# Which image to run in. Same default as run_daemon.sh, so the two always
# measure the same stack unless you deliberately point them apart.
IMAGE="${IMAGE:-fraunhofer-sit/charra-dev-env:1.9.0}"

# The run scripts do not build the image, they only run in it -- RECOMPILE
# above is `make` inside the container, not `docker build`. On a fresh clone,
# or after the Dockerfile changes, the image has to be built once first.
# Without this check docker would try to PULL a name that exists only
# locally, and fail with "pull access denied", which reads as an
# authentication problem rather than a missing build.
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

# Same three values as run_daemon.sh, and the same rule: one setting for all
# four roles, because they must agree. Default off keeps every benchmark
# figure comparable with the ones already recorded.
# How the RP proves it runs the expected appraisal code: qualify (the
# /qualify handshake, default) or tee (a TEE Attestation Document). Set for
# BOTH roles at once -- they must agree, and a mismatch is a named NO vote.
TRUST_MODE="${TRUST_MODE:-qualify}"
case "$TRUST_MODE" in
    qualify|tee|zk) TRUST_RP="--trust-mode=$TRUST_MODE"
                    TRUST_VER="--trust-mode=$TRUST_MODE" ;;
    *)  echo "ERROR: TRUST_MODE must be qualify, tee or zk (got '$TRUST_MODE')." >&2
        exit 1 ;;
esac

# Same prover lifecycle as run_daemon.sh: its own linux/arm64 container next
# to this one, sharing the checkout, which is also the job queue. Started here
# rather than left to the user because it lasts exactly as long as the sweep.
ZK_IMAGE="${ZK_IMAGE:-charra-zk:arm64}"
ZK_PLATFORM="${ZK_PLATFORM:-linux/arm64}"
ZK_CONTAINER_NAME="${ZK_CONTAINER_NAME:-charra-zk-prover}"
if [ "$TRUST_MODE" = "zk" ]; then
    if ! docker image inspect "$ZK_IMAGE" >/dev/null 2>&1; then
        echo "ERROR: TRUST_MODE=zk needs the prover image '$ZK_IMAGE'." >&2
        echo "       Build it once (about two minutes):" >&2
        echo "           ./docker/build-zk.sh" >&2
        exit 1
    fi
    docker rm -f "$ZK_CONTAINER_NAME" >/dev/null 2>&1 || true
    rm -rf zk/jobs
    echo "--- starting the ZK prover ($ZK_IMAGE, $ZK_PLATFORM)"
    docker run -d --rm --name "$ZK_CONTAINER_NAME" \
        --platform "$ZK_PLATFORM" \
        -v "$PWD/:/home/bob/charra" -w /home/bob/charra \
        "$ZK_IMAGE" ./zk/proof_watcher.sh >/dev/null
    trap 'docker rm -f "$ZK_CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT
    sleep 1
    if ! docker ps --filter "name=$ZK_CONTAINER_NAME" --format '{{.Names}}' \
            | grep -q .; then
        echo "ERROR: the prover container exited immediately." >&2
        exit 1
    fi
    echo "    prover ready; proving adds about 8 s to every cycle of the sweep"
fi

DTLS_MODE="${DTLS_MODE:-off}"
case "$DTLS_MODE" in
    off) DTLS_TM= ; DTLS_ATT= ; DTLS_VER= ; DTLS_RP= ;;
    psk) DTLS_TM="--psk" ; DTLS_ATT="--psk" ; DTLS_VER="--psk" ; DTLS_RP="--psk" ;;
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
    *)  echo "ERROR: DTLS_MODE must be off, psk or rpk (got '$DTLS_MODE')." >&2
        exit 1 ;;
esac

docker run -v "$PWD/:/home/bob/charra" $tty_flags --rm --init \
  -e DTLS_MODE="$DTLS_MODE" \
  -e DTLS_TM="$DTLS_TM" -e DTLS_ATT="$DTLS_ATT" \
  -e DTLS_VER="$DTLS_VER" -e DTLS_RP="$DTLS_RP" \
  -e TRUST_MODE="$TRUST_MODE" \
  -e TRUST_RP="$TRUST_RP" -e TRUST_VER="$TRUST_VER" \
  -e CHARRA_ZK_JOBS="zk/jobs" \
  --name charra --group-add tss \
  "$IMAGE" \
  bash -lc '
    set -e
    pkill -9 -f "^bin/" || true
    pkill tpm_server || true

    # One simulator per role, as on real hardware: each AK is derived by
    # the TPM of the role that owns it, from that TPM hierarchy seed.
    # Separate working directories, because tpm_server writes NVChip into
    # whatever directory it was started in.
    # Held in variables so the port number never appears next to the
    # simulator name anywhere in this script -- not even in a comment, which
    # is why this one does not spell it out. The image entrypoint backgrounds
    # tpm-reset, which pkills that exact pattern with -f, and -f matches the
    # whole command line -- which for bash -lc includes the script text
    # itself. A script that spells the pattern out therefore kills the shell
    # running it: SIGTERM, exit 143, right after the banner. run_daemon.sh
    # passes the port as a variable and survives; this script did not.
    ATT_PORT=2321
    RP_PORT=2325
    ATTESTER_TCTI="mssim:host=127.0.0.1,port=$ATT_PORT"
    RP_TCTI="mssim:host=127.0.0.1,port=$RP_PORT"
    rm -rf /tmp/tpm_attester /tmp/tpm_rp
    mkdir -p /tmp/tpm_attester /tmp/tpm_rp
    (cd /tmp/tpm_attester && tpm_server -port "$ATT_PORT" \
        > "/tmp/tpm_server_$ATT_PORT.log" 2>&1 &)
    (cd /tmp/tpm_rp && tpm_server -port "$RP_PORT" \
        > "/tmp/tpm_server_$RP_PORT.log" 2>&1 &)
    sleep 3
    TPM2TOOLS_TCTI="$ATTESTER_TCTI" tpm2_startup --clear
    TPM2TOOLS_TCTI="$RP_TCTI"       tpm2_startup --clear
    cd ~/charra

    echo "--- PCRs before anything starts (expect all zero, both TPMs) ---"
    echo "  attester TPM (:2321):"
    TPM2TOOLS_TCTI="$ATTESTER_TCTI" tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10
    echo "  RP TPM (:2325):"
    TPM2TOOLS_TCTI="$RP_TCTI" tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10

    cd ~/charra
    make clean
    make -j

    # Every fingerprint on file names an RP identity the reset above just
    # destroyed. Clearing them also means this run actually exercises the
    # /qualify handshake rather than coasting on a stale grant.
    rm -f qualified_rps.txt

    # Regenerate the trust anchor AFTER the TPM resets and BEFORE any role
    # starts -- see step 4 in the comment block at the top of this file.
    # This needs bin/provision_trusted_keys, hence after the build.
    ATTESTER_TCTI="$ATTESTER_TCTI" RP_TCTI="$RP_TCTI" ./keys/gen-trusted-keys.sh

    rm -rf logs
    mkdir -p logs

    # Regenerate verifiers_config.txt for exactly the five ports started
    # below. start_verifiers.sh writes this file too, so a previous
    # "./start_verifiers.sh 3" would otherwise leave a three-row config here
    # and the sweep would fail at 4 and 5 Verifiers with "Verifier ID not
    # found" rather than anything pointing at the config.
    # Derived from the RP binary itself, not hardcoded: the sweep runs
    # 1..RP_MAX_SWEEP_VERIFIERS, and starting fewer Verifiers than that makes
    # the sweep hang on ports nobody is listening on.
    SWEEP=$(grep -oE "define RP_MAX_SWEEP_VERIFIERS [0-9]+" src/rp/rp_shared.h \
            | grep -oE "[0-9]+$")
    : "${SWEEP:=5}"
    echo "--- sweep width from rp_shared.h: $SWEEP Verifier(s)"
    for i in $(seq 1 "$SWEEP"); do
      echo "$i 127.0.0.1 $((5683 + i))"
    done > verifiers_config.txt

    # Same refusal as run_daemon.sh: DTLS-RPK needs a libcoap built
    # --enable-thread-safe, and without it the run hangs at the first
    # /nonce rather than failing.
    if [ "$DTLS_MODE" = "rpk" ] &&
       ! grep -q "COAP_THREAD_SAFE" /usr/local/include/coap3/coap_defines.h \
             2>/dev/null; then
        echo "ERROR: DTLS_MODE=rpk needs libcoap built --enable-thread-safe," >&2
        echo "       which the libcoap in this image lacks. Rebuild with" >&2
        echo "       ./docker/build.sh, or use DTLS_MODE=psk." >&2
        exit 1
    fi

    LOG_LEVEL_CHARRA=DEBUG bin/trust_manager $DTLS_TM \
        > logs/trust_manager.log 2>&1 &
    LOG_LEVEL_CHARRA=DEBUG CHARRA_TCTI="$ATTESTER_TCTI" \
        bin/attester $DTLS_ATT > logs/attester.log 2>&1 &
    for i in $(seq 1 "$SWEEP"); do
      p=$((5683 + i))
      LOG_LEVEL_CHARRA=DEBUG bin/verifier --port $p $DTLS_VER $TRUST_VER \
          > logs/verifier_$p.log 2>&1 &
    done
    sleep 2

    LOG_LEVEL_CHARRA=DEBUG CHARRA_TCTI="$RP_TCTI" \
        bin/relying_party --benchmark $DTLS_RP $TRUST_RP 2>&1 \
        | tee logs/relying_party.log

    # A log that is mostly NUL bytes means two processes shared the file:
    # one truncated it while the other held a descriptor at a large offset.
    # That is the fingerprint of a second instance running against this
    # checkout, and it invalidates the whole run -- so say so rather than
    # letting the timings look trustworthy.
    for f in logs/*.log; do
        if [ "$(wc -c < "$f")" -ne "$(tr -d "\0" < "$f" | wc -c)" ]; then
            echo "WARNING: $f contains NUL padding -- more than one process"
            echo "         wrote it. Treat this run as contaminated."
        fi
    done

    echo "--- timings written to timings_RP_multi_verifiers.txt"
    echo "--- plot them on the HOST (matplotlib is not in this image):"
    echo "      python3 plot_multi_verifiers.py"
  '

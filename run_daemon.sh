#!/usr/bin/env bash
#
# Full daemon-mode run: fresh TPM, clean state, trust_manager + attester +
# N verifiers + relying_party looping until you stop it (Ctrl-C).
#
# The counterpart to run_live_test.sh, which runs the bounded --benchmark
# sweep instead. Everything the two processes can disagree about is a
# variable below, set to the binary's own built-in default, so this file
# doubles as the list of what is actually tunable.
#
# EVERY setting can also be overridden from the environment without editing
# this file:
#
#   RP_INTERVAL=5 RP_VERIFIERS=3 ./run_daemon.sh
#   RP_DURATION=120 ./run_daemon.sh            # stop cleanly after 2 minutes
#   VERIFIER_AK_VALIDITY=60 RP_AK_RENEW_MARGIN=20 ./run_daemon.sh
#
# Options:
#   --keep-state   do NOT reset the TPM or delete state/ (see the warning
#                  next to RESET_TPM below before using this)
#   -h, --help     this message
#
set -euo pipefail

# =============================================================================
#  TUNABLES -- all set to the binaries' own defaults
# =============================================================================

# --- Relying Party: cadence -------------------------------------------------
RP_INTERVAL="${RP_INTERVAL:-15}"                 # --interval, seconds between cycles
RP_VERIFIERS="${RP_VERIFIERS:-5}"                # --verifiers, 1..10; also how many get started
RP_DURATION="${RP_DURATION:-0}"                  # --duration, 0 = run until SIGINT
RP_CYCLES="${RP_CYCLES:-0}"                      # --cycles, 0 = unbounded

# --- Relying Party: renewal margins -----------------------------------------
# How long BEFORE a credential expires the RP renews it, from its idle window
# rather than inside an attestation. Each must stay below the lifetime it is
# a margin on, or the RP renews on every idle pass and the cache stops meaning
# anything -- checked at the bottom of this section.
RP_QUALIFY_RENEW_MARGIN="${RP_QUALIFY_RENEW_MARGIN:-30}"   # --qualify-renew-margin
RP_AK_RENEW_MARGIN="${RP_AK_RENEW_MARGIN:-45}"             # --ak-renew-margin

# --- Relying Party: what IT issues ------------------------------------------
RP_ATTESTER_AK_VALIDITY="${RP_ATTESTER_AK_VALIDITY:-300}"  # --attester-ak-validity, seconds

# --- Relying Party: timeouts ------------------------------------------------
# A Verifier that times out counts against the majority exactly like a NO vote.
RP_VERIFIER_TIMEOUT="${RP_VERIFIER_TIMEOUT:-6}"  # --verifier-timeout, seconds
RP_ATTESTER_TIMEOUT="${RP_ATTESTER_TIMEOUT:-6}"  # --attester-timeout, seconds

# --- Verifier: what IT grants -----------------------------------------------
# These are the lifetimes the RP's margins above are measured against. The RP
# learns the qualification window from the /qualify/submit response, so it does
# not need a matching flag of its own -- but the margins do have to fit.
VERIFIER_QUALIFICATION_VALIDITY="${VERIFIER_QUALIFICATION_VALIDITY:-180}"  # --qualification-validity
VERIFIER_AK_VALIDITY="${VERIFIER_AK_VALIDITY:-300}"                        # --ak-validity

# --- Topology ---------------------------------------------------------------
VERIFIER_START_PORT="${VERIFIER_START_PORT:-5684}"   # first Verifier port; rest follow
VERIFIER_HOST="${VERIFIER_HOST:-127.0.0.1}"          # address written into verifiers_config.txt

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
REBUILD="${REBUILD:-1}"          # 1 = make clean && make -j inside the container
RESET_TPM="${RESET_TPM:-1}"      # 1 = wipe NVChip, TPM2_Startup(CLEAR), delete state/

# =============================================================================
#  end of tunables
# =============================================================================

usage() { sed -n '3,22p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --keep-state) RESET_TPM=0; shift ;;
        -h|--help)    usage 0 ;;
        *)            echo "Unknown option '$1'." >&2; usage 1 ;;
    esac
done

# --- sanity checks that span two processes ----------------------------------
# None of these are fatal on their own; the run still works, it just stops
# behaving the way the settings suggest. Say so rather than letting it look
# like a bug later.
warned=0
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$1" >&2; warned=1; }

if [ "$RP_VERIFIERS" -lt 1 ] || [ "$RP_VERIFIERS" -gt 10 ]; then
    echo "ERROR: RP_VERIFIERS must be 1..10 (got $RP_VERIFIERS)." >&2; exit 1
fi
if [ "$RP_QUALIFY_RENEW_MARGIN" -ge "$VERIFIER_QUALIFICATION_VALIDITY" ]; then
    warn "RP_QUALIFY_RENEW_MARGIN ($RP_QUALIFY_RENEW_MARGIN s) is not smaller than
         VERIFIER_QUALIFICATION_VALIDITY ($VERIFIER_QUALIFICATION_VALIDITY s).
         The RP will re-qualify on every idle pass and the cache stops meaning anything."
fi
if [ "$RP_AK_RENEW_MARGIN" -ge "$VERIFIER_AK_VALIDITY" ]; then
    warn "RP_AK_RENEW_MARGIN ($RP_AK_RENEW_MARGIN s) is not smaller than
         VERIFIER_AK_VALIDITY ($VERIFIER_AK_VALIDITY s).
         The RP's own AK certificate is renewed on every idle pass."
fi
if [ "$RP_AK_RENEW_MARGIN" -ge "$RP_ATTESTER_AK_VALIDITY" ]; then
    warn "RP_AK_RENEW_MARGIN ($RP_AK_RENEW_MARGIN s) is not smaller than
         RP_ATTESTER_AK_VALIDITY ($RP_ATTESTER_AK_VALIDITY s).
         The Attester's RP-issued certificate is renewed on every idle pass."
fi
if [ "$RP_INTERVAL" -gt "$VERIFIER_QUALIFICATION_VALIDITY" ]; then
    warn "RP_INTERVAL ($RP_INTERVAL s) is longer than the qualification window
         ($VERIFIER_QUALIFICATION_VALIDITY s), so a grant can expire between cycles.
         The idle window still renews it -- this is a note, not a fault."
fi
[ "$warned" -eq 1 ] && echo

# --- refuse to share this checkout with another running container -----------
# Two processes on one state/ revoke each other's certificates, which surfaces
# only as unexplained attestation failures much later. The binaries refuse to
# start in that case; catching it here names the container instead of the lock.
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
mine=${PWD%/}
others=""
for cid in $(docker ps -q); do
    cname=$(docker inspect -f "{{.Name}}" "$cid" 2>/dev/null | sed "s#^/##")
    for src in $(docker inspect -f "{{range .Mounts}}{{.Source}}{{println}}{{end}}" "$cid" 2>/dev/null); do
        if [ "${src%/}" = "$mine" ]; then others="$others $cname"; break; fi
    done
done
if [ -n "$others" ]; then
    echo "ERROR: these running containers already mount $mine:$others" >&2
    echo "They share state/ and logs/ with this run and will corrupt it." >&2
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
  Qualification      granted ${VERIFIER_QUALIFICATION_VALIDITY}s, renewed at ${RP_QUALIFY_RENEW_MARGIN}s remaining
  AK cert (RP's)     granted ${VERIFIER_AK_VALIDITY}s, renewed at ${RP_AK_RENEW_MARGIN}s remaining
  AK cert (Attester) granted ${RP_ATTESTER_AK_VALIDITY}s by the RP's own CA
  Fresh TPM/state    $([ "$RESET_TPM" -eq 1 ] && echo yes || echo "no (--keep-state)")
  Log level          $LOG_LEVEL
---------------------------------------------------------------------------
EOF

tty_flags=""
[ -t 0 ] && tty_flags="-it"

docker run -v "$PWD/:/home/bob/charra" $tty_flags --rm --init \
  --name "$CONTAINER_NAME" --group-add tss \
  -e RP_INTERVAL="$RP_INTERVAL" \
  -e RP_VERIFIERS="$RP_VERIFIERS" \
  -e RP_DURATION="$RP_DURATION" \
  -e RP_CYCLES="$RP_CYCLES" \
  -e RP_QUALIFY_RENEW_MARGIN="$RP_QUALIFY_RENEW_MARGIN" \
  -e RP_AK_RENEW_MARGIN="$RP_AK_RENEW_MARGIN" \
  -e RP_ATTESTER_AK_VALIDITY="$RP_ATTESTER_AK_VALIDITY" \
  -e RP_VERIFIER_TIMEOUT="$RP_VERIFIER_TIMEOUT" \
  -e RP_ATTESTER_TIMEOUT="$RP_ATTESTER_TIMEOUT" \
  -e VERIFIER_QUALIFICATION_VALIDITY="$VERIFIER_QUALIFICATION_VALIDITY" \
  -e VERIFIER_AK_VALIDITY="$VERIFIER_AK_VALIDITY" \
  -e VERIFIER_START_PORT="$VERIFIER_START_PORT" \
  -e VERIFIER_HOST="$VERIFIER_HOST" \
  -e LOG_LEVEL="$LOG_LEVEL" \
  -e LOG_LEVEL_COAP="$LOG_LEVEL_COAP" \
  -e RP_EXTRA_ARGS="$RP_EXTRA_ARGS" \
  -e VERIFIER_EXTRA_ARGS="$VERIFIER_EXTRA_ARGS" \
  -e ATTESTER_EXTRA_ARGS="$ATTESTER_EXTRA_ARGS" \
  -e REBUILD="$REBUILD" \
  -e RESET_TPM="$RESET_TPM" \
  "$IMAGE" \
  bash -lc '
    set -e
    cd ~/charra

    pkill -9 -f "^bin/" || true

    if [ "$RESET_TPM" = "1" ]; then
        # The TPM reset and the state/ wipe are ONE step, not two: resetting
        # re-randomizes the storage-hierarchy seeds, so any cached AK private
        # blob no longer loads (Esys_Load fails) and every attestation fails
        # in a way that blames revoked certificates instead.
        pkill tpm_server || true
        cd /tmp && rm -f NVChip
        (tpm_server > /tmp/tpm_server.log 2>&1 &)
        sleep 3
        tpm2_startup --clear
        cd ~/charra
        rm -rf state
    else
        pgrep tpm_server >/dev/null || { cd /tmp && (tpm_server > /tmp/tpm_server.log 2>&1 &); sleep 3; tpm2_startup --clear; cd ~/charra; }
    fi

    if [ "$REBUILD" = "1" ]; then
        make clean && make -j
    fi

    rm -rf logs && mkdir -p logs

    export LOG_LEVEL_CHARRA="$LOG_LEVEL"
    [ -n "$LOG_LEVEL_COAP" ] && export LOG_LEVEL_COAP

    bin/trust_manager > logs/trust_manager.log 2>&1 &
    bin/attester $ATTESTER_EXTRA_ARGS > logs/attester.log 2>&1 &

    # start_verifiers.sh also generates verifiers_config.txt for exactly these
    # ports, which is what the Trust Manager resolves the RP requests against.
    ./start_verifiers.sh "$RP_VERIFIERS" \
        --startingport "$VERIFIER_START_PORT" \
        --host "$VERIFIER_HOST" \
        --logdir logs \
        --qualification-validity "$VERIFIER_QUALIFICATION_VALIDITY" \
        --ak-validity "$VERIFIER_AK_VALIDITY" \
        $VERIFIER_EXTRA_ARGS
    sleep 2

    rp_args="--verifiers $RP_VERIFIERS \
             --interval $RP_INTERVAL \
             --qualify-renew-margin $RP_QUALIFY_RENEW_MARGIN \
             --ak-renew-margin $RP_AK_RENEW_MARGIN \
             --attester-ak-validity $RP_ATTESTER_AK_VALIDITY \
             --verifier-timeout $RP_VERIFIER_TIMEOUT \
             --attester-timeout $RP_ATTESTER_TIMEOUT"
    [ "$RP_DURATION" -gt 0 ] && rp_args="$rp_args --duration $RP_DURATION"
    [ "$RP_CYCLES"   -gt 0 ] && rp_args="$rp_args --cycles $RP_CYCLES"

    echo "--- relying_party $rp_args $RP_EXTRA_ARGS"
    echo

    # Foreground and tee-ed: Ctrl-C stops the daemon, the container exits.
    bin/relying_party $rp_args $RP_EXTRA_ARGS 2>&1 | tee logs/relying_party.log

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

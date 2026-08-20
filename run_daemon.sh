#!/usr/bin/env bash
#
# Full daemon-mode run: fresh TPMs, clean state, trust_manager + attester +
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
#   VERIFIER_QUALIFICATION_VALIDITY=20 RP_CYCLES=8 ./run_daemon.sh
#
# Options:
#   --keep-state   do NOT reset the TPMs (see RESET_TPM below)
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

# --- Relying Party: timeouts ------------------------------------------------
# A Verifier that times out counts against the majority exactly like a NO vote.
RP_VERIFIER_TIMEOUT="${RP_VERIFIER_TIMEOUT:-6}"  # --verifier-timeout, seconds
RP_ATTESTER_TIMEOUT="${RP_ATTESTER_TIMEOUT:-6}"  # --attester-timeout, seconds

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
# 1 = wipe each TPM's NVChip and TPM2_Startup(CLEAR) it. Note this changes
# every AK, which is why the trust anchor is regenerated afterwards,
# in-container. (TPM2_Startup alone would NOT change them -- deleting the
# NVChip is what re-randomizes the hierarchy seeds.)
RESET_TPM="${RESET_TPM:-1}"

# =============================================================================
#  end of tunables
# =============================================================================

usage() { sed -n '3,34p' "$0" | sed 's/^#\{1,\} \{0,1\}//'; exit "${1:-0}"; }

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
  Qualification      granted for ${VERIFIER_QUALIFICATION_VALIDITY}s, recorded with its deadline in
                     qualified_rps.txt (shared by every Verifier); the RP
                     re-qualifies on the first cycle after it lapses
  Fresh TPM          $([ "$RESET_TPM" -eq 1 ] && echo "yes (trust anchor regenerated)" || echo "no (--keep-state)")
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
  -e RP_VERIFIER_TIMEOUT="$RP_VERIFIER_TIMEOUT" \
  -e RP_ATTESTER_TIMEOUT="$RP_ATTESTER_TIMEOUT" \
  -e VERIFIER_QUALIFICATION_VALIDITY="$VERIFIER_QUALIFICATION_VALIDITY" \
  -e TWO_TPMS="$TWO_TPMS" \
  -e ATTESTER_TPM_PORT="$ATTESTER_TPM_PORT" \
  -e RP_TPM_PORT="$RP_TPM_PORT" \
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

    ATTESTER_TCTI="mssim:host=127.0.0.1,port=$ATTESTER_TPM_PORT"
    if [ "$TWO_TPMS" = "1" ]; then
        RP_TCTI="mssim:host=127.0.0.1,port=$RP_TPM_PORT"
    else
        RP_TCTI="$ATTESTER_TCTI"
    fi

    # Each simulator gets its own directory: tpm_server writes NVChip into
    # its working directory, so a shared one means the two corrupt each
    # other -- surfacing much later as keys that stop matching the anchor.
    start_tpm() {   # $1 = port, $2 = state dir
        mkdir -p "$2"
        [ "$RESET_TPM" = "1" ] && rm -f "$2/NVChip"
        ( cd "$2" && tpm_server -port "$1" > "/tmp/tpm_server_$1.log" 2>&1 & )
    }

    if [ "$RESET_TPM" = "1" ] || ! pgrep tpm_server >/dev/null; then
        pkill tpm_server || true
        sleep 1
        start_tpm "$ATTESTER_TPM_PORT" /tmp/tpm_attester
        [ "$TWO_TPMS" = "1" ] && start_tpm "$RP_TPM_PORT" /tmp/tpm_rp
        sleep 3
        # Every TPM needs its own TPM2_Startup: one that has power but was
        # never started rejects everything with 0x100 (TPM_RC_INITIALIZE),
        # and the tools report that as an ordinary command failure.
        TPM2TOOLS_TCTI="$ATTESTER_TCTI" tpm2_startup --clear
        if [ "$TWO_TPMS" = "1" ]; then
            TPM2TOOLS_TCTI="$RP_TCTI" tpm2_startup --clear
        fi
    fi
    cd ~/charra

    if [ "$REBUILD" = "1" ]; then
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

    rm -rf logs && mkdir -p logs

    export LOG_LEVEL_CHARRA="$LOG_LEVEL"
    [ -n "$LOG_LEVEL_COAP" ] && export LOG_LEVEL_COAP

    # Only these two open a TPM. The Verifiers never do -- every check they
    # run is public-key math in mbedTLS -- and neither does trust_manager.
    bin/trust_manager > logs/trust_manager.log 2>&1 &
    CHARRA_TCTI="$ATTESTER_TCTI" bin/attester $ATTESTER_EXTRA_ARGS \
        > logs/attester.log 2>&1 &

    # start_verifiers.sh also generates verifiers_config.txt for exactly these
    # ports, which is what the Trust Manager resolves the RP requests against.
    ./start_verifiers.sh "$RP_VERIFIERS" \
        --startingport "$VERIFIER_START_PORT" \
        --host "$VERIFIER_HOST" \
        --logdir logs \
        --qualification-validity "$VERIFIER_QUALIFICATION_VALIDITY" \
        $VERIFIER_EXTRA_ARGS
    sleep 2

    rp_args="--verifiers $RP_VERIFIERS \
             --interval $RP_INTERVAL \
             --verifier-timeout $RP_VERIFIER_TIMEOUT \
             --attester-timeout $RP_ATTESTER_TIMEOUT"
    [ "$RP_DURATION" -gt 0 ] && rp_args="$rp_args --duration $RP_DURATION"
    [ "$RP_CYCLES"   -gt 0 ] && rp_args="$rp_args --cycles $RP_CYCLES"

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

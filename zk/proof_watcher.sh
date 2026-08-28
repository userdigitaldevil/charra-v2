#!/bin/sh
# Runs bb on behalf of the RP and the Verifier, which cannot run it themselves.
#
# Why this exists: the charra container is x86_64 under Rosetta, and Rosetta
# does not emulate ADX, which barretenberg requires -- so bb dies with SIGILL
# in there no matter which version or libraries are used (ZK_REDACTION.md §5).
# In a native linux/arm64 container it runs without emulation, so that is where
# this lives -- a sibling of the charra container, started by run_daemon.sh.
# It watches a bind-mounted job directory and does the proving and verifying
# the containerised RP and Verifier ask for.
#
# It is a scaffold for a real deployment's local `bb`, not a component of the
# design. The seam is honest and documented; nothing about the protocol below
# is load-bearing for security. What IS load-bearing is that the Verifier
# checks the proof against a vk it already trusts (zk/vk) and against public
# inputs it derives itself -- neither of which this process supplies.
#
#     ./zk/proof_watcher.sh          # run until interrupted
#     ./zk/proof_watcher.sh --once   # drain the queue and exit (for tests)
#
# Protocol. A requester builds its job under zk/jobs/.staging/<id>/ and then
# renames it into zk/jobs/<id>/. Rename is atomic, so the watcher never sees a
# half-written job and no locking is needed.
#
#   zk/jobs/<id>/kind           "prove" or "verify"
#   prove:  witness.json  in    ->  proof, public_inputs  out
#   verify: proof, public_inputs in ->  result ("verified" / "rejected")
#   both:   status  ("ok" or "error: ...")   log  (tool output)
#           done    written LAST -- the requester polls for this and nothing else
#
# A rejected proof is a SUCCESSFUL job with a "rejected" verdict, not a failed
# one. status says whether the tooling worked; result says what it concluded.
# Conflating them would turn a crashed prover into a passing attestation.

set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
JOBS="$ROOT/zk/jobs"
STAGING="$JOBS/.staging"
CIRCUIT="$ROOT/zk/circuit"
VK="$ROOT/zk/vk"
POLL=${CHARRA_ZK_POLL:-0.25}

ONCE=0
[ "${1:-}" = "--once" ] && ONCE=1

log() { printf '%s  %s\n' "$(date +%H:%M:%S)" "$1"; }

finish_ok()   { echo ok > "$1/status"; : > "$1/done"; }
finish_fail() { printf 'error: %s\n' "$2" > "$1/status"; : > "$1/done"; }

# --- preflight ---------------------------------------------------------
for tool in nargo bb; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "$tool not on PATH. Try:" >&2
        echo '    export PATH="$HOME/.nargo/bin:$HOME/.bb-native:$PATH"' >&2
        exit 1
    }
done

mkdir -p "$STAGING"

if [ ! -f "$CIRCUIT/target/charra_zk.json" ]; then
    log "compiling circuit"
    (cd "$CIRCUIT" && nargo compile) || exit 1
fi

# The vk is the Verifier's trust anchor for the circuit -- the ZK counterpart
# of keys/trusted_keys.txt, distributed out of band rather than fetched from
# whoever is being verified. Generated once and committed.
if [ ! -f "$VK" ]; then
    log "writing verification key to zk/vk"
    (cd "$CIRCUIT" && bb write_vk -b target/charra_zk.json -o target) || exit 1
    cp "$CIRCUIT/target/vk" "$VK" || exit 1
fi

# --- handlers ----------------------------------------------------------
do_prove() {
    job=$1
    [ -f "$job/witness.json" ] || { finish_fail "$job" "no witness.json"; return; }

    if ! CHARRA_ZK_WITNESS="$job/witness.json" \
         CHARRA_ZK_PROVER="$CIRCUIT/Prover.toml" \
         "$ROOT/zk/gen_prover_toml.py" --full >"$job/log" 2>&1; then
        finish_fail "$job" "witness rejected by generator -- see log"
        return
    fi

    # A failure here is an ATTESTATION failure, not a tooling failure: the
    # only way the witness does not solve is that the log handed in does not
    # replay to the pcrdigest_a the Attester's TPM signed.
    if ! (cd "$CIRCUIT" && nargo execute) >>"$job/log" 2>&1; then
        finish_fail "$job" "log does not replay to pcrdigest_a"
        return
    fi

    if ! (cd "$CIRCUIT" && bb prove \
            -b target/charra_zk.json \
            -w target/charra_zk.gz \
            -o target) >>"$job/log" 2>&1; then
        finish_fail "$job" "bb prove failed -- see log"
        return
    fi

    cp "$CIRCUIT/target/proof" "$job/proof" &&
    cp "$CIRCUIT/target/public_inputs" "$job/public_inputs" || {
        finish_fail "$job" "could not copy proof out"
        return
    }
    finish_ok "$job"
}

do_verify() {
    job=$1
    for f in proof public_inputs; do
        [ -f "$job/$f" ] || { finish_fail "$job" "no $f"; return; }
    done

    # -i is passed explicitly. bb defaults it to the proof's directory, which
    # happens to work, but relying on a default for the input that decides
    # WHAT is being proved is not something to leave implicit.
    # The Verifier names the key it trusts, in the job. Falls back to the
    # repository's own only when the job does not say -- a Verifier that has
    # been pointed at a different key must be checked against that one, or
    # the flag would be decorative.
    job_vk="$VK"
    [ -s "$job/vk" ] && job_vk="$job/vk"
    if bb verify -k "$job_vk" -p "$job/proof" -i "$job/public_inputs" \
            >"$job/log" 2>&1; then
        echo verified > "$job/result"
    else
        echo rejected > "$job/result"
    fi
    finish_ok "$job"
}

# --- loop --------------------------------------------------------------
drain() {
    found=0
    for job in "$JOBS"/*/; do
        [ -d "$job" ] || continue
        [ -f "$job/done" ] && continue
        found=1
        name=$(basename "$job")
        kind=$(cat "$job/kind" 2>/dev/null || echo "")
        start=$(date +%s)
        case "$kind" in
            prove)  log "prove  $name"; do_prove "$job" ;;
            verify) log "verify $name"; do_verify "$job" ;;
            *)      log "?????  $name"; finish_fail "$job" "unknown kind '$kind'" ;;
        esac
        log "  -> $(cat "$job/status" 2>/dev/null)$(
              [ -f "$job/result" ] && printf ' (%s)' "$(cat "$job/result")"
            ) in $(( $(date +%s) - start ))s"
    done
    return $found
}

log "watching $JOBS  (vk: $VK)"
if [ "$ONCE" = 1 ]; then
    drain
    log "drained"
    exit 0
fi

trap 'log "stopped"; exit 0' INT TERM
while :; do
    drain
    sleep "$POLL"
done

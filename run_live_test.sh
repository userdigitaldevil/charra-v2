#!/usr/bin/env bash
# Full live end-to-end run: fresh TPM simulator state, clean rebuild,
# trust_manager + attester + 5 verifiers (ports 5684-5688) + relying_party,
# with DEBUG logging. Run this from the repo root, in a real terminal (it
# uses `docker run -it`, so it needs one).
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
#      from a previous run, wipes the TPM simulator's persistent NVRAM
#      (NVChip) and restarts it fresh, then TPM2_Startup(CLEAR) -- a genuine
#      cold TPM, nothing measured yet.
#   4. Deletes all of state/ -- RP's own cached TPM identity
#      (state/relying-party/identity/), its per-Verifier AK certificates and
#      qualification cache, and both Verifier-side ledgers
#      (state/verifier/). This step matters: step 3 just re-randomized the
#      TPM simulator's storage-hierarchy seeds, so any *old* cached AK
#      private blob no longer loads under the *new* TPM state (Esys_Load
#      fails) -- skipping this step is what made the first run of this
#      script fail every single attestation, cascading from one TPM load
#      error into "no AK certificate" into every evidence build failing. A
#      stale ledger would be similarly meaningless against a freshly-reset
#      TPM's identities.
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
#      hangs waiting on whichever ports aren't listening, see
#      CHARRA_V2_NOTES.md), all backgrounded with DEBUG logging to logs/.
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
# Logs land in logs/*.log either way; Ctrl-C stops relying_party, the
# container itself is --rm'd on exit but the background bin/* processes
# inside it are not explicitly killed by this script if you Ctrl-C early --
# re-running the script kills them itself (step 3) before starting fresh.

set -e

docker rm -f charra >/dev/null 2>&1 || true

# Refuse to run while ANOTHER container has this same directory mounted.
# Removing the "charra" container above only handles our own leftovers; a
# container under any other name sharing this checkout shares state/ and
# logs/ too, and its relying_party will revoke ours in the Verifiers'
# issuance ledgers -- silently, surfacing only as unexplained attestation
# failures much later. See CHARRA_V2_NOTES.md, "One state directory, many
# owners". The binaries now refuse to start in that situation, but catching
# it here names the container instead of just the lock file.
mine=${PWD%/}
others=""
for cid in $(docker ps -q); do
    cname=$(docker inspect -f "{{.Name}}" "$cid" 2>/dev/null | sed "s#^/##")
    for src in $(docker inspect -f "{{range .Mounts}}{{.Source}}{{println}}{{end}}" "$cid" 2>/dev/null); do
        if [ "${src%/}" = "$mine" ]; then
            others="$others $cname"
            break
        fi
    done
done
if [ -n "$others" ]; then
    echo "ERROR: these running containers already mount $mine:$others" >&2
    echo "They share state/ and logs/ with this run and will corrupt it." >&2
    echo "Stop them first:  docker stop$others" >&2
    exit 1
fi

# -t only when there is a terminal, so this stays runnable from CI or a
# non-interactive shell (docker run -t without a TTY fails outright).
tty_flags=""
[ -t 0 ] && tty_flags="-it"

docker run -v "$PWD/:/home/bob/charra" $tty_flags --rm --init \
  --name charra --group-add tss \
  fraunhofer-sit/charra-dev-env:1.9.0 \
  bash -lc '
    set -e
    pkill -9 -f "^bin/" || true
    pkill tpm_server || true

    cd /tmp && rm -f NVChip
    (tpm_server > /tmp/tpm_server.log 2>&1 &)
    sleep 3
    tpm2_startup --clear
    cd ~/charra

    # All of state/ is meaningless (and breaks outright, Esys_Load failing)
    # against a TPM state that was just re-randomized above -- see the
    # comment block at the top of this file.
    rm -rf state

    echo "--- PCRs before anything starts (expect all zero) ---"
    tpm2_pcrread sha256:0,1,2,3,4,5,6,7,10

    cd ~/charra
    make clean
    make -j

    rm -rf logs
    mkdir -p logs

    # Regenerate verifiers_config.txt for exactly the five ports started
    # below. start_verifiers.sh writes this file too, so a previous
    # "./start_verifiers.sh 3" would otherwise leave a three-row config here
    # and the sweep would fail at 4 and 5 Verifiers with "Verifier ID not
    # found" rather than anything pointing at the config.
    for i in 1 2 3 4 5; do
      echo "$i 127.0.0.1 $((5683 + i))"
    done > verifiers_config.txt

    LOG_LEVEL_CHARRA=DEBUG bin/trust_manager > logs/trust_manager.log 2>&1 &
    LOG_LEVEL_CHARRA=DEBUG bin/attester      > logs/attester.log      2>&1 &
    for p in 5684 5685 5686 5687 5688; do
      LOG_LEVEL_CHARRA=DEBUG bin/verifier --port $p > logs/verifier_$p.log 2>&1 &
    done
    sleep 2

    LOG_LEVEL_CHARRA=DEBUG bin/relying_party --benchmark 2>&1 \
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
